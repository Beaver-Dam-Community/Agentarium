package ingest

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

// KernelSourceSAN is the only kernel source (COMMON "Kernel source authentication
// and epoch"): the TASK-09 exporter's exact service SAN, also its sensor_id.
const KernelSourceSAN = "spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon"

// KernelIdentity resolves the verified mTLS leaf to the registered kernel
// source and its current node/boot. It never reads body or header identity.
type KernelIdentity interface {
	ResolveKernel(context.Context, *x509.Certificate) (LifecycleSource, error)
}

// KernelValidator applies installation policy to the envelope. Per-record
// validation, provenance binding and rejection semantics stay in SQL.
type KernelValidator interface {
	ValidateKernel(context.Context, LifecycleSource, KernelEnvelope) error
}
type KernelStore interface {
	IngestKernel(context.Context, LifecycleSource, []byte) (json.RawMessage, error)
}

// KernelHandler serves POST /internal/kernel/events:batch (TASK-07 3.3).
// The exporter is hostNetwork, so callers must also come from a node CIDR.
type KernelHandler struct {
	Identity  KernelIdentity
	Validator KernelValidator
	Store     KernelStore
	NodeCIDRs []netip.Prefix
}

func (h KernelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/internal/kernel/events:batch" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(405)
		return
	}
	requestID := uuid.NewString()
	san, err := peerSAN(r.TLS)
	if err != nil {
		writeError(w, 401, requestID, "AUTH_REQUIRED")
		return
	}
	if san != KernelSourceSAN {
		writeError(w, 403, requestID, "")
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip, ipErr := netip.ParseAddr(host)
	allowed := false
	if err == nil && ipErr == nil {
		for _, prefix := range h.NodeCIDRs {
			if prefix.Contains(ip.Unmap()) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		writeError(w, 403, requestID, "")
		return
	}
	if h.Identity == nil || h.Validator == nil || h.Store == nil {
		writeError(w, 503, requestID, "STATE_STORE_UNAVAILABLE")
		return
	}
	leaf := r.TLS.VerifiedChains[0][0]
	source, err := h.Identity.ResolveKernel(r.Context(), leaf)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if source.SourceID != san || source.Kind != "runtime" || !canonicalUUID(source.NodeUID) || !validLifecycleText(source.BootID) {
		writeError(w, 503, requestID, "STATE_STORE_UNAVAILABLE")
		return
	}
	// Authentication arguments always come from the verified TLS leaf.
	source.CertificateSerial = hex.EncodeToString(leaf.SerialNumber.Bytes())
	source.ExactSAN = san
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, canonical.MaxBodyBytes))
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			writeError(w, 413, requestID, "BODY_TOO_LARGE")
		} else {
			writeError(w, 422, requestID, "SCHEMA_INVALID")
		}
		return
	}
	b, err := DecodeKernelEnvelope(raw)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if err = h.Validator.ValidateKernel(r.Context(), source, b); err != nil {
		h.fail(w, requestID, err)
		return
	}
	ack, err := h.Store.IngestKernel(r.Context(), source, raw)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if err = ValidateKernelAck(ack, b); err != nil {
		h.fail(w, requestID, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(ack)
}

func (h KernelHandler) fail(w http.ResponseWriter, id string, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		writeError(w, 403, id, "")
	case errors.Is(err, ErrSchema):
		writeError(w, 422, id, "SCHEMA_INVALID")
	default:
		writeError(w, 503, id, "STATE_STORE_UNAVAILABLE")
	}
}

var ErrKernelResult = errors.New("invalid kernel ingest result")

// ValidateKernelAck is also used inside the store transaction, so malformed
// function output rolls back instead of committing an unusable response.
// Every submitted record and range must appear in exactly one collection.
func ValidateKernelAck(raw []byte, b KernelEnvelope) error {
	var a struct {
		BatchID    string               `json:"batch_id"`
		Accepted   []string             `json:"accepted_ids"`
		Duplicates []string             `json:"duplicate_ids"`
		Rejected   []LifecycleRejection `json:"rejected"`
		Watermarks []struct {
			Epoch   string `json:"source_epoch"`
			Through int64  `json:"acked_through"`
		} `json:"watermarks"`
	}
	if len(raw) > canonical.MaxBodyBytes || strictObject(raw, &a) != nil || a.BatchID != b.BatchID || a.Accepted == nil || a.Duplicates == nil || a.Rejected == nil ||
		len(a.Watermarks) != 1 || a.Watermarks[0].Epoch != b.Epoch || a.Watermarks[0].Through < 0 {
		return ErrKernelResult
	}
	expected := map[string]bool{}
	for _, raw := range b.Records {
		var r struct {
			ID any `json:"source_event_id"`
		}
		_ = json.Unmarshal(raw, &r)
		id, _ := r.ID.(string)
		expected[id] = true
	}
	for _, r := range b.Abandoned {
		expected[fmt.Sprintf("%s:%d-%d", b.Epoch, r.From, r.To)] = true
	}
	seen := map[string]bool{}
	for _, ids := range [][]string{a.Accepted, a.Duplicates} {
		for _, id := range ids {
			if !expected[id] || seen[id] {
				return ErrKernelResult
			}
			seen[id] = true
		}
	}
	for _, rejected := range a.Rejected {
		if !expected[rejected.ID] || seen[rejected.ID] || len(rejected.ReasonCodes) == 0 {
			return ErrKernelResult
		}
		for _, reason := range rejected.ReasonCodes {
			if reason != "SCHEMA_INVALID" && reason != "EVENT_ID_CONFLICT" {
				return ErrKernelResult
			}
		}
		seen[rejected.ID] = true
	}
	for id := range expected {
		if !seen[id] {
			return ErrKernelResult
		}
	}
	return nil
}
