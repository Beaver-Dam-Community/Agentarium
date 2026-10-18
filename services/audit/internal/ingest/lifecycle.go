package ingest

import (
	"bytes"
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
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

// LifecycleEnvelope preserves the original record bytes. DecodeLifecycleEnvelope
// validates the outer request; DecodeLifecycleRecord validates individual records
// using the owner-approved wire clarification in shared spec PR #87.
type LifecycleEnvelope struct {
	BatchID   string            `json:"batch_id"`
	Epoch     string            `json:"source_epoch"`
	Scope     string            `json:"scope,omitempty"`
	Records   []json.RawMessage `json:"records"`
	Abandoned []LifecycleRange  `json:"sequence_range_abandoned"`
	Cursor    *LifecycleCursor  `json:"cursor,omitempty"`
	Digest    string            `json:"batch_digest"`
}
type LifecycleRange struct {
	From   int64  `json:"from_seq"`
	To     int64  `json:"to_seq"`
	Reason string `json:"reason"`
	Digest string `json:"range_digest"`
}
type LifecycleCursor struct {
	Scope            string `json:"scope"`
	ResourceVersion  string `json:"resource_version"`
	ExpectedRevision int64  `json:"expected_checkpoint_revision"`
}

type LifecycleCheckpoint struct {
	Scope           string `json:"scope"`
	ResourceVersion string `json:"resource_version"`
	Revision        int64  `json:"checkpoint_revision"`
}
type LifecycleCheckpointResult struct {
	Scope           string    `json:"scope"`
	ResourceVersion string    `json:"resource_version"`
	CommittedAt     time.Time `json:"committed_at"`
	Revision        int64     `json:"checkpoint_revision"`
}
type LifecycleRejection struct {
	ID          string   `json:"id"`
	ReasonCodes []string `json:"reason_codes"`
}

func strictObject(raw []byte, target any) error {
	if canonical.CheckStrictJSON(raw) != nil {
		return ErrSchema
	}
	// TASK-07 limits apply even inside RawMessage record/evidence fields.
	// UseNumber preserves the already-validated integers during this walk.
	var value any
	scan := json.NewDecoder(bytes.NewReader(raw))
	scan.UseNumber()
	if scan.Decode(&value) != nil || limits(value) != nil {
		return ErrSchema
	}
	if err := lifecycleShape(raw, reflect.TypeOf(target).Elem()); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return ErrSchema
	}
	return nil
}

// encoding/json otherwise accepts case-insensitive field names and null for
// scalar values. Raw records remain opaque to this envelope-only check.
func lifecycleShape(raw []byte, typ reflect.Type) error {
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if typ.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return lifecycleShape(raw, typ.Elem())
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrSchema
	}
	switch typ.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil || obj == nil {
			return ErrSchema
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			value, exists := obj[tag[0]]
			if !exists {
				if len(tag) > 1 && tag[1] == "omitempty" {
					continue
				}
				return ErrSchema
			}
			if err := lifecycleShape(value, field.Type); err != nil {
				return err
			}
			delete(obj, tag[0])
		}
		if len(obj) != 0 {
			return ErrSchema
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return ErrSchema
		}
		for _, value := range values {
			if err := lifecycleShape(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
func validLifecycleText(s string) bool { return s != "" && len(s) <= 16384 }
func canonicalUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s
}

// DecodeLifecycleEnvelope checks the request-wide contract only. Bad record
// identities and range digests are individual rejections, never whole-batch 422.
func DecodeLifecycleEnvelope(raw []byte) (LifecycleEnvelope, error) {
	var b LifecycleEnvelope
	if len(raw) > canonical.MaxBodyBytes || strictObject(raw, &b) != nil ||
		!canonicalUUID(b.BatchID) || !validLifecycleText(b.Epoch) || strings.Contains(b.Epoch, "/") ||
		b.Records == nil || b.Abandoned == nil || len(b.Records)+len(b.Abandoned) > 100 {
		return b, ErrSchema
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if scope, present := fields["scope"]; present && (bytes.Equal(scope, []byte("null")) || !validLifecycleText(b.Scope)) {
		return b, ErrSchema
	}
	if cursor, present := fields["cursor"]; present && bytes.Equal(cursor, []byte("null")) {
		return b, ErrSchema
	}
	if b.Cursor != nil && (!validLifecycleText(b.Cursor.Scope) || b.Cursor.Scope != b.Scope || !validLifecycleText(b.Cursor.ResourceVersion) || b.Cursor.ExpectedRevision < 0 || b.Cursor.ExpectedRevision > 9007199254740991) {
		return b, ErrSchema
	}
	digest, err := canonical.BatchDigest(raw)
	if err != nil || digest != b.Digest {
		return b, ErrSchema
	}
	return b, nil
}

// CheckLifecycleIdentities verifies only merged namespace/range contracts.
// Complete per-record validation remains mandatory through LifecycleValidator.
func CheckLifecycleIdentities(source string, b LifecycleEnvelope) []LifecycleRejection {
	bad := []LifecycleRejection{}
	for _, raw := range b.Records {
		var fields map[string]json.RawMessage
		var id, epoch, recordSource string
		var sequence int64
		_ = json.Unmarshal(raw, &fields)
		_ = json.Unmarshal(fields["lifecycle_event_id"], &id)
		_ = json.Unmarshal(fields["source_epoch"], &epoch)
		_ = json.Unmarshal(fields["source_id"], &recordSource)
		err := json.Unmarshal(fields["source_sequence"], &sequence)
		want, idErr := canonical.LifecycleEventID(source, epoch, sequence)
		if err != nil || idErr != nil || want != id || recordSource != source || epoch != b.Epoch {
			bad = append(bad, LifecycleRejection{id, []string{"SCHEMA_INVALID"}})
		}
	}
	for _, a := range b.Abandoned {
		digest, err := canonical.AbandonedRangeDigest(source, "lifecycle", b.Epoch, a.From, a.To, a.Reason)
		if err != nil || digest != a.Digest {
			bad = append(bad, LifecycleRejection{fmt.Sprintf("%s:%d-%d", b.Epoch, a.From, a.To), []string{"SCHEMA_INVALID"}})
		}
	}
	return bad
}

// LifecycleSource must come from authenticated installation state, never body
// fields or forwarding headers. A runtime binding must prove the current boot.
type LifecycleSource struct{ SourceID, Kind, NodeUID, BootID, CertificateSerial, ExactSAN string }
type LifecycleIdentity interface {
	ResolveLifecycle(context.Context, *x509.Certificate, netip.Addr) (LifecycleSource, error)
}

// LifecycleValidator is a mandatory policy gate for producer grants, trusted
// source/node/boot bindings and atomic gap writes. Source kind derives from the
// registered caller KSA, not the request. Implementations must preserve the
// request and enforce individual rejection semantics in the SQL ingest function;
// a validator cannot quietly discard rejected records.
type LifecycleValidator interface {
	ValidateLifecycle(context.Context, LifecycleSource, LifecycleEnvelope) error
}
type LifecycleStore interface {
	IngestLifecycle(context.Context, LifecycleSource, []byte) (json.RawMessage, error)
	LifecycleCheckpoint(context.Context, string, string) (LifecycleCheckpointResult, error)
}

// LifecycleHandler requires current identity and local source policy as well as
// the SQL store. Writer startup explicitly opts into the installed SQL contracts.
type LifecycleHandler struct {
	Identity  LifecycleIdentity
	Validator LifecycleValidator
	Store     LifecycleStore
	// NodeCIDRs restricts hostNetwork lifecycle recorders only. Pod watchers use
	// ordinary Pod ingress selected by namespace/label in TASK-06 NetworkPolicy,
	// plus the registered service identity resolver below.
	NodeCIDRs []netip.Prefix
}

func (h LifecycleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	checkpointRequest := r.URL.Path == "/internal/lifecycle/checkpoints"
	if r.URL.Path != "/internal/lifecycle/events:batch" && !checkpointRequest {
		http.NotFound(w, r)
		return
	}
	method := http.MethodPost
	if checkpointRequest {
		method = http.MethodGet
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		w.WriteHeader(405)
		return
	}
	requestID := uuid.NewString()
	san, err := peerSAN(r.TLS)
	if err != nil {
		writeError(w, 401, requestID, "AUTH_REQUIRED")
		return
	}
	ns, ksa, _ := ParseServiceSAN(san)
	if !(ns == "agent-sensors" && ksa == "lifecycle-recorder") && !(ns == "agent-observe" && ksa == "pod-watcher") {
		writeError(w, 403, requestID, "")
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip, ipErr := netip.ParseAddr(host)
	if err != nil || ipErr != nil {
		writeError(w, 403, requestID, "")
		return
	}
	if ksa == "lifecycle-recorder" {
		allowed := false
		for _, prefix := range h.NodeCIDRs {
			if prefix.Contains(ip.Unmap()) {
				allowed = true
				break
			}
		}
		if !allowed {
			writeError(w, 403, requestID, "")
			return
		}
	}
	if h.Identity == nil || h.Validator == nil || h.Store == nil {
		writeError(w, 503, requestID, "STATE_STORE_UNAVAILABLE")
		return
	}
	source, err := h.Identity.ResolveLifecycle(r.Context(), r.TLS.VerifiedChains[0][0], ip.Unmap())
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if source.SourceID != san || (ksa == "pod-watcher" && source.Kind != "pod_watcher") ||
		(ksa == "lifecycle-recorder" && (source.Kind != "runtime" || !canonicalUUID(source.NodeUID) || !validLifecycleText(source.BootID))) {
		writeError(w, 503, requestID, "STATE_STORE_UNAVAILABLE")
		return
	}
	// Authentication arguments always come from the verified TLS leaf, never a body/header or resolver override.
	source.CertificateSerial = hex.EncodeToString(r.TLS.VerifiedChains[0][0].SerialNumber.Bytes())
	source.ExactSAN = san
	if checkpointRequest {
		query, queryErr := url.ParseQuery(r.URL.RawQuery)
		scopes := query["scope"]
		if source.Kind != "pod_watcher" || queryErr != nil || len(query) != 1 || len(scopes) != 1 || !validLifecycleText(scopes[0]) {
			writeError(w, 404, requestID, "RESOURCE_NOT_FOUND")
			return
		}
		scope := scopes[0]
		if err := h.Validator.ValidateLifecycle(r.Context(), source, LifecycleEnvelope{Scope: scope}); err != nil {
			if errors.Is(err, ErrForbidden) || errors.Is(err, ErrSchema) {
				writeError(w, 404, requestID, "RESOURCE_NOT_FOUND")
			} else {
				h.fail(w, requestID, err)
			}
			return
		}
		result, err := h.Store.LifecycleCheckpoint(r.Context(), source.SourceID, scope)
		if errors.Is(err, ErrLifecycleCheckpointNotFound) {
			writeError(w, 404, requestID, "RESOURCE_NOT_FOUND")
			return
		}
		if err != nil {
			h.fail(w, requestID, err)
			return
		}
		if result.Scope != scope || !validLifecycleText(result.ResourceVersion) || result.Revision < 1 || result.Revision > 9007199254740991 || result.CommittedAt.IsZero() {
			h.fail(w, requestID, ErrLifecycleResult)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
		return
	}
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
	b, err := DecodeLifecycleEnvelope(raw)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if (source.Kind == "runtime" && (b.Cursor != nil || b.Scope != "")) || (source.Kind == "pod_watcher" && b.Scope == "") {
		writeError(w, 422, requestID, "SCHEMA_INVALID")
		return
	}
	if err = h.Validator.ValidateLifecycle(r.Context(), source, b); err != nil {
		h.fail(w, requestID, err)
		return
	}
	ack, err := h.Store.IngestLifecycle(r.Context(), source, raw)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if err = ValidateLifecycleAck(ack, b); err != nil {
		h.fail(w, requestID, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(ack)
}
func (h LifecycleHandler) fail(w http.ResponseWriter, id string, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		writeError(w, 403, id, "")
	case errors.Is(err, ErrSchema):
		writeError(w, 422, id, "SCHEMA_INVALID")
	default:
		writeError(w, 503, id, "STATE_STORE_UNAVAILABLE")
	}
}

var ErrLifecycleResult = errors.New("invalid lifecycle ingest result")
var ErrLifecycleCheckpointNotFound = errors.New("lifecycle checkpoint not found")

// ValidateLifecycleAck is also used inside the store transaction: malformed
// function output must roll back rather than commit an unusable response.
func ValidateLifecycleAck(raw []byte, b LifecycleEnvelope) error {
	var a struct {
		BatchID    string               `json:"batch_id"`
		Accepted   []string             `json:"accepted_ids"`
		Duplicates []string             `json:"duplicate_ids"`
		Rejected   []LifecycleRejection `json:"rejected"`
		Watermarks []struct {
			Epoch   string `json:"source_epoch"`
			Through int64  `json:"acked_through"`
		} `json:"watermarks"`
		Checkpoint *LifecycleCheckpoint `json:"checkpoint,omitempty"`
	}
	if len(raw) > canonical.MaxBodyBytes || strictObject(raw, &a) != nil || a.BatchID != b.BatchID || a.Accepted == nil || a.Duplicates == nil || a.Rejected == nil || len(a.Watermarks) != 1 || a.Watermarks[0].Epoch != b.Epoch || a.Watermarks[0].Through < 0 {
		return ErrLifecycleResult
	}
	if a.Checkpoint != nil && (b.Cursor == nil || a.Checkpoint.Scope != b.Cursor.Scope || a.Checkpoint.ResourceVersion != b.Cursor.ResourceVersion || a.Checkpoint.Revision < 1 || a.Checkpoint.Revision > 9007199254740991 || a.Checkpoint.Revision != b.Cursor.ExpectedRevision+1 || len(a.Rejected) > 0) {
		return ErrLifecycleResult
	}
	records := map[string]bool{}
	ranges := map[string]bool{}
	var lastSequence int64
	for _, raw := range b.Records {
		var r struct {
			ID       string `json:"lifecycle_event_id"`
			Sequence int64  `json:"source_sequence"`
		}
		_ = json.Unmarshal(raw, &r)
		records[r.ID] = true
		if r.Sequence > lastSequence {
			lastSequence = r.Sequence
		}
	}
	for _, r := range b.Abandoned {
		ranges[fmt.Sprintf("%s:%d-%d", b.Epoch, r.From, r.To)] = true
		if r.To > lastSequence {
			lastSequence = r.To
		}
	}
	seen := map[string]bool{}
	for _, ids := range [][]string{a.Accepted, a.Duplicates} {
		for _, id := range ids {
			if (!records[id] && !ranges[id]) || seen[id] {
				return ErrLifecycleResult
			}
			seen[id] = true
		}
	}
	for _, rejected := range a.Rejected {
		if (!records[rejected.ID] && !ranges[rejected.ID]) || seen[rejected.ID] || len(rejected.ReasonCodes) == 0 {
			return ErrLifecycleResult
		}
		for _, reason := range rejected.ReasonCodes {
			if reason != "SCHEMA_INVALID" && reason != "EVENT_ID_CONFLICT" {
				return ErrLifecycleResult
			}
		}
		seen[rejected.ID] = true
	}
	for id := range records {
		if !seen[id] {
			return ErrLifecycleResult
		}
	}
	for id := range ranges {
		if !seen[id] {
			return ErrLifecycleResult
		}
	}
	if a.Checkpoint != nil && a.Watermarks[0].Through < lastSequence {
		return ErrLifecycleResult
	}
	return nil
}
