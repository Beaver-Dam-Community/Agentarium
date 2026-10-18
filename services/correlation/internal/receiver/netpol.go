// Package receiver is the TASK-10 3.7 collector batch endpoint
// `POST /internal/network-policy/records:batch`. The node is taken from the
// verified collector certificate through the restricted identity lookup,
// never from the request body.
package receiver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/netpol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const Path = "/internal/network-policy/records:batch"

var (
	ErrForbidden = errors.New("collector not allowed")
	errSchema    = errors.New("invalid batch")
	epochPattern = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// Certificate is the identity lookup result for the verified leaf.
type Certificate struct {
	Namespace, KSA string
	NodeUID        *uuid.UUID
	BootID         *string
	HistoricalBoot *string
}

// Identity resolves a verified leaf serial and exact SAN; ok is false when
// the certificate is not current, revoked or not an enabled service.
type Identity interface {
	Lookup(ctx context.Context, serial, san, bootHash string) (Certificate, bool, error)
}

// Ingester is netpol.Store.
type Ingester interface {
	Ingest(context.Context, netpol.NodeIdentity, netpol.Batch) (netpol.Ack, error)
}

type Handler struct {
	ClusterUID uuid.UUID
	Identity   Identity
	Store      Ingester
}

// PoolIdentity calls identity.audit_source_certificate (EXECUTE only).
type PoolIdentity struct{ Pool *pgxpool.Pool }

func (p PoolIdentity) Lookup(ctx context.Context, serial, san, bootHash string) (Certificate, bool, error) {
	var c Certificate
	err := p.Pool.QueryRow(ctx, `SELECT namespace, ksa, node_uid, certificate_boot_id, historical_boot_id
		FROM identity.audit_source_certificate($1, $2, $3)`, serial, san, bootHash).Scan(&c.Namespace, &c.KSA, &c.NodeUID, &c.BootID, &c.HistoricalBoot)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, false, nil
	}
	return c, err == nil, err
}

type wireRange struct {
	From   int64  `json:"from_seq"`
	To     int64  `json:"to_seq"`
	Reason string `json:"reason"`
	Digest string `json:"range_digest"`
}
type wireFlush struct {
	Through    int64  `json:"through_sequence"`
	CaughtUpAt string `json:"caught_up_at"`
}
type wireLoss struct {
	DetectedAt string `json:"detected_at"`
	After      int64  `json:"after_sequence"`
}
type envelope struct {
	BatchID      string            `json:"batch_id"`
	Epoch        string            `json:"source_epoch"`
	Records      []json.RawMessage `json:"records"`
	Abandoned    []json.RawMessage `json:"sequence_range_abandoned"`
	CaughtUpAt   *string           `json:"caught_up_at"`
	FinalFlush   *json.RawMessage  `json:"final_flush"`
	RotationLoss *json.RawMessage  `json:"rotation_loss"`
	Digest       string            `json:"batch_digest"`
}

// wireRecord is NetworkPolicyRecord without received_at.
type wireRecord struct {
	RecordID             string              `json:"record_id"`
	ClusterUID           string              `json:"cluster_uid"`
	NodeUID              string              `json:"node_uid"`
	Epoch                string              `json:"source_epoch"`
	Sequence             int64               `json:"source_sequence"`
	NodeName             string              `json:"node_name"`
	SourceTime           string              `json:"source_time"`
	Disposition          string              `json:"disposition"`
	Direction            string              `json:"direction"`
	Protocol             string              `json:"protocol"`
	SrcIP                string              `json:"src_ip"`
	SrcPort              *int                `json:"src_port"`
	DestIP               string              `json:"dest_ip"`
	DestPort             *int                `json:"dest_port"`
	SrcEndpoint          *netpol.EndpointRef `json:"src_endpoint"`
	DestEndpoint         *netpol.EndpointRef `json:"dest_endpoint"`
	Policies             *[]netpol.PolicyRef `json:"policies"`
	Count                int                 `json:"count"`
	NormalizationVersion string              `json:"normalization_version"`
}

// strict decodes one JSON object with exact field names, requiring the given
// keys to be present and non-null.
func strict(raw []byte, v any, required ...string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errSchema
	}
	shape, _ := json.Marshal(v)
	var allowed map[string]json.RawMessage
	_ = json.Unmarshal(shape, &allowed)
	for k := range fields {
		if _, ok := allowed[k]; !ok {
			return errSchema
		}
	}
	for _, k := range required {
		if f, ok := fields[k]; !ok || bytes.Equal(bytes.TrimSpace(f), []byte("null")) {
			return errSchema
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errSchema
	}
	return nil
}

func timestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return t, errSchema
	}
	return t, nil
}

func addr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return a, errSchema
	}
	return a, nil
}

// record checks one record against the authenticated node, the batch epoch
// and the installation cluster. A failure is an individual SCHEMA_INVALID.
func (h Handler) record(raw []byte, node uuid.UUID, epoch string) (netpol.BatchRecord, string, error) {
	var w wireRecord
	id := ""
	var probe struct {
		RecordID string `json:"record_id"`
		Sequence int64  `json:"source_sequence"`
	}
	if json.Unmarshal(raw, &probe) == nil {
		id = probe.RecordID
		if id == "" {
			id = epoch + ":" + strconv.FormatInt(probe.Sequence, 10)
		}
	}
	if err := strict(raw, &w, "record_id", "cluster_uid", "node_uid", "source_epoch", "source_sequence", "node_name", "source_time",
		"disposition", "direction", "protocol", "src_ip", "dest_ip", "count", "normalization_version"); err != nil {
		return netpol.BatchRecord{}, id, err
	}
	want, err := canonical.NetworkPolicyRecordID(h.ClusterUID.String(), node.String(), epoch, w.Sequence)
	if err != nil || w.RecordID != want || w.ClusterUID != h.ClusterUID.String() || w.NodeUID != node.String() || w.Epoch != epoch {
		return netpol.BatchRecord{}, id, errSchema
	}
	r := netpol.BatchRecord{RecordID: uuid.MustParse(want), SourceSequence: w.Sequence, NodeName: w.NodeName, Disposition: w.Disposition, Direction: w.Direction,
		Protocol: w.Protocol, SrcPort: w.SrcPort, DestPort: w.DestPort, SrcEndpoint: w.SrcEndpoint, DestEndpoint: w.DestEndpoint, Count: &w.Count,
		NormalizationVersion: w.NormalizationVersion}
	if w.Policies != nil {
		r.Policies = *w.Policies
	}
	if r.SourceTime, err = timestamp(w.SourceTime); err != nil {
		return r, id, err
	}
	if r.SrcIP, err = addr(w.SrcIP); err != nil {
		return r, id, err
	}
	if r.DestIP, err = addr(w.DestIP); err != nil {
		return r, id, err
	}
	if !netpol.ValidRecord(r) {
		return r, id, errSchema
	}
	return r, id, nil
}

type rejection struct {
	ID          string   `json:"id"`
	ReasonCodes []string `json:"reason_codes"`
}
type watermark struct {
	Epoch        string `json:"source_epoch"`
	AckedThrough int64  `json:"acked_through"`
}
type response struct {
	BatchID            string      `json:"batch_id"`
	AcceptedIDs        []string    `json:"accepted_ids"`
	DuplicateIDs       []string    `json:"duplicate_ids"`
	Rejected           []rejection `json:"rejected"`
	Watermarks         []watermark `json:"watermarks"`
	FinalFlushRecorded bool        `json:"final_flush_recorded"`
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	requestID := uuid.NewString()
	serial, err := collector(r.TLS)
	if err != nil {
		writeError(w, http.StatusForbidden, requestID, "")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, canonical.MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, requestID, "BODY_TOO_LARGE")
		} else {
			writeError(w, http.StatusUnprocessableEntity, requestID, "SCHEMA_INVALID")
		}
		return
	}
	var env envelope
	if canonical.CheckStrictJSON(raw) != nil || strict(raw, &env, "batch_id", "source_epoch", "records", "sequence_range_abandoned", "batch_digest") != nil ||
		uuid.Validate(env.BatchID) != nil || !epochPattern.MatchString(env.Epoch) || len(env.Records)+len(env.Abandoned) > 100 ||
		(env.RotationLoss != nil && env.CaughtUpAt != nil) {
		writeError(w, http.StatusUnprocessableEntity, requestID, "SCHEMA_INVALID")
		return
	}
	if digest, err := canonical.BatchDigest(raw); err != nil || digest != env.Digest {
		writeError(w, http.StatusUnprocessableEntity, requestID, "SCHEMA_INVALID")
		return
	}
	batch := netpol.Batch{SourceEpoch: env.Epoch}
	if env.CaughtUpAt != nil {
		t, err := timestamp(*env.CaughtUpAt)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, requestID, "SCHEMA_INVALID")
			return
		}
		batch.CaughtUpAt = &t
	}
	if env.FinalFlush != nil {
		var f wireFlush
		t, err := time.Time{}, strict(*env.FinalFlush, &f, "through_sequence", "caught_up_at")
		if err == nil {
			t, err = timestamp(f.CaughtUpAt)
		}
		if err != nil || f.Through < 1 {
			writeError(w, http.StatusUnprocessableEntity, requestID, "SCHEMA_INVALID")
			return
		}
		batch.FinalFlush = &netpol.FinalFlush{ThroughSequence: f.Through, CaughtUpAt: t}
	}
	if env.RotationLoss != nil {
		var l wireLoss
		t, err := time.Time{}, strict(*env.RotationLoss, &l, "detected_at", "after_sequence")
		if err == nil {
			t, err = timestamp(l.DetectedAt)
		}
		if err != nil || l.After < 0 {
			writeError(w, http.StatusUnprocessableEntity, requestID, "SCHEMA_INVALID")
			return
		}
		batch.RotationLoss = &netpol.RotationLoss{DetectedAt: t, AfterSequence: l.After}
	}
	// The node and boot come from the certificate: the epoch's node UUID must
	// be the certificate's node and its boot hash the certificate's boot or a
	// retained prior-issued boot of the same node.
	node, err := uuid.Parse(env.Epoch[:32])
	bootHash := env.Epoch[32:96]
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, requestID, "SCHEMA_INVALID")
		return
	}
	cert, ok, err := h.Identity.Lookup(r.Context(), serial, netpol.CollectorSAN, bootHash)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, requestID, "STATE_STORE_UNAVAILABLE")
		return
	}
	matchedBoot := bootForHash(cert, bootHash)
	if !ok || cert.Namespace != "agent-sensors" || cert.KSA != "netpol-collector" || cert.NodeUID == nil || *cert.NodeUID != node || matchedBoot == nil {
		writeError(w, http.StatusForbidden, requestID, "")
		return
	}
	resp := response{BatchID: env.BatchID, AcceptedIDs: []string{}, DuplicateIDs: []string{}, Rejected: []rejection{}}
	invalid := []string{}
	for _, raw := range env.Records {
		rec, id, err := h.record(raw, node, env.Epoch)
		if err != nil {
			invalid = append(invalid, id)
			continue
		}
		batch.Records = append(batch.Records, rec)
	}
	for _, raw := range env.Abandoned {
		var a wireRange
		if strict(raw, &a, "from_seq", "to_seq", "reason", "range_digest") != nil {
			invalid = append(invalid, env.Epoch+":range")
			continue
		}
		digest, err := canonical.AbandonedRangeDigest(netpol.CollectorSAN, "network_policy", env.Epoch, a.From, a.To, a.Reason)
		if err != nil || digest != a.Digest {
			invalid = append(invalid, netpol.RangeID(env.Epoch, a.From, a.To))
			continue
		}
		batch.Abandoned = append(batch.Abandoned, netpol.AbandonedRange{From: a.From, To: a.To, Reason: a.Reason, Digest: a.Digest})
	}
	ack, err := h.Store.Ingest(r.Context(), netpol.NodeIdentity{ClusterUID: h.ClusterUID, NodeUID: node, BootID: matchedBoot}, batch)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, requestID, "STATE_STORE_UNAVAILABLE")
		return
	}
	for _, id := range ack.AcceptedIDs {
		resp.AcceptedIDs = append(resp.AcceptedIDs, id.String())
	}
	for _, id := range ack.DuplicateIDs {
		resp.DuplicateIDs = append(resp.DuplicateIDs, id.String())
	}
	for _, id := range invalid {
		resp.Rejected = append(resp.Rejected, rejection{ID: id, ReasonCodes: []string{"SCHEMA_INVALID"}})
	}
	for _, rj := range ack.Rejected {
		resp.Rejected = append(resp.Rejected, rejection{ID: rj.ID, ReasonCodes: rj.ReasonCodes})
	}
	resp.Watermarks = []watermark{{Epoch: env.Epoch, AckedThrough: ack.AckedThrough}}
	resp.FinalFlushRecorded = ack.FinalFlushRecorded
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func bootForHash(c Certificate, hash string) *string {
	for _, b := range []*string{c.BootID, c.HistoricalBoot} {
		if b != nil && *b != "" {
			sum := sha256.Sum256([]byte(*b))
			if hex.EncodeToString(sum[:]) == hash {
				return b
			}
		}
	}
	return nil
}

// collector returns the verified leaf serial when its only URI SAN is the
// netpol-collector identity.
func collector(state *tls.ConnectionState) (string, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", ErrForbidden
	}
	leaf := state.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != netpol.CollectorSAN || leaf.SerialNumber == nil {
		return "", ErrForbidden
	}
	return hex.EncodeToString(leaf.SerialNumber.Bytes()), nil
}

func writeError(w http.ResponseWriter, status int, id, code string) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "2")
	}
	w.WriteHeader(status)
	codes := []string{}
	if code != "" {
		codes = append(codes, code)
	}
	_ = json.NewEncoder(w).Encode(struct {
		RequestID   string   `json:"request_id"`
		ReasonCodes []string `json:"reason_codes"`
	}{id, codes})
}
