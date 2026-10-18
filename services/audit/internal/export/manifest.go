// Package export implements TASK-07's canonical export and signed manifest
// formats. A verified signature is not an outbox acknowledgement: Verify also
// checks the pinned object generation and every fixed batch member's DB ack.
package export

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"

	"cloud.google.com/go/storage"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

const MaxSequence int64 = 9007199254740991
const MaxManifestBytes = 1 << 20
const MaxBatchBytes = 128 << 20

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Record struct {
	Kind      string          `json:"record_kind"`
	EventType string          `json:"event_type"`
	Body      json.RawMessage `json:"record"`
}
type Source struct {
	ID    string `json:"source_id"`
	Epoch string `json:"source_epoch"`
	First int64  `json:"first_sequence"`
	Last  int64  `json:"last_sequence"`
}

// OutboxRange is the min/max outbox_id of the fixed batch members. It is
// storage order, not a source sequence, and does not claim contiguity.
type OutboxRange struct {
	First int64 `json:"first_outbox_id"`
	Last  int64 `json:"last_outbox_id"`
}
type Manifest struct {
	Sequence    int64       `json:"manifest_seq"`
	BatchID     string      `json:"batch_id"`
	ObjectKey   string      `json:"object_key"`
	Generation  int64       `json:"object_generation"`
	BatchDigest string      `json:"batch_digest"`
	RecordCount int         `json:"record_count"`
	OutboxRange OutboxRange `json:"outbox_range"`
	Sources     []Source    `json:"sources"`
	Previous    *string     `json:"prev_manifest_digest"`
	CreatedAt   string      `json:"created_at"`
}

// Member is one fixed batch member as stored in PostgreSQL, in ordinal order.
type Member struct {
	Kind     string
	ID       string
	OutboxID int64
}

// Failure codes reported by the verifier (TASK-07 3.2.1).
const (
	FailManifestMissing    = "MANIFEST_MISSING"
	FailChainDiscontinuity = "CHAIN_DISCONTINUITY"
	FailUntrustedKey       = "UNTRUSTED_KEY"
	FailSignatureInvalid   = "SIGNATURE_INVALID"
	FailManifestInvalid    = "MANIFEST_INVALID"
	FailObjectMissing      = "OBJECT_MISSING"
	FailDigestMismatch     = "DIGEST_MISMATCH"
	FailRecordInvalid      = "RECORD_INVALID"
	FailCoverageMismatch   = "COVERAGE_MISMATCH"
	FailAckMismatch        = "ACK_MISMATCH"
)

// VerificationError carries the registered failure code for incident reports.
type VerificationError struct {
	Code string
	Err  error
}

func (e *VerificationError) Error() string { return e.Err.Error() }
func (e *VerificationError) Unwrap() error { return e.Err }
func fail(code string, err error) error    { return &VerificationError{Code: code, Err: err} }

// FailureCode returns the registered code of a definite verification
// failure. It is empty for nil and for incomplete checks (network, permission
// or DB errors), which must not be reported as integrity incidents.
func FailureCode(err error) string {
	var v *VerificationError
	if errors.As(err, &v) {
		return v.Code
	}
	return ""
}

type Envelope struct {
	Manifest   Manifest `json:"manifest"`
	Signature  string   `json:"signature_b64"`
	KeyVersion string   `json:"kms_key_version"`
}

// Objects must read exactly the requested generation, never the current object.
type Objects interface {
	Read(context.Context, string, int64) ([]byte, error)
}
type Acks interface {
	Check(context.Context, string, string, int) error
	Members(context.Context, string) ([]Member, error)
}
type Signer interface {
	Sign(context.Context, []byte) ([]byte, error)
}

func Digest(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func canonicalJSON(v any) ([]byte, error) {
	b, e := canonical.CanonicalJSON(v)
	if e != nil {
		return nil, e
	}
	if e = canonical.CheckStrictJSON(b); e != nil {
		return nil, e
	}
	return b, nil
}
func validUUID(id string) bool {
	u, e := uuid.Parse(id)
	return e == nil && u != uuid.Nil && u.String() == id
}
func validClass(class string) bool {
	switch class {
	case "business", "kernel", "lifecycle", "decision_input":
		return true
	}
	return false
}
func ObjectKey(batchID, class string, created time.Time) (string, error) {
	if !validUUID(batchID) || !validClass(class) || created.IsZero() {
		return "", errors.New("invalid batch identity")
	}
	return Digest([]byte(batchID))[:4] + "/" + class + "/" + created.UTC().Format("2006-01-02") + "/" + batchID + ".ndjson", nil
}
func NDJSON(records []Record) ([]byte, error) {
	if len(records) < 1 || len(records) > 100 {
		return nil, errors.New("batch size outside 1..100")
	}
	var out bytes.Buffer
	for _, r := range records {
		switch r.Kind {
		case "audit_event":
			if r.EventType == "" {
				return nil, errors.New("missing event type")
			}
		case "kernel_event":
			if r.EventType != "kernel_event_observed" {
				return nil, errors.New("kernel event type mismatch")
			}
		case "lifecycle_event":
			if r.EventType != "lifecycle_recorded" {
				return nil, errors.New("lifecycle event type mismatch")
			}
		default:
			return nil, errors.New("invalid record kind")
		}
		body := bytes.TrimSpace(r.Body)
		if len(body) == 0 || body[0] != '{' {
			return nil, errors.New("record must be object")
		}
		if e := canonical.CheckStrictJSON(body); e != nil {
			return nil, e
		}
		b, e := canonical.CanonicalJSON(r)
		if e != nil {
			return nil, e
		}
		if out.Len()+len(b)+1 > MaxBatchBytes {
			return nil, errors.New("batch exceeds verification limit")
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// DecisionNDJSON uses the distinct TASK-04 decision-input row format, without
// the business/kernel/lifecycle wrapper. Fields are constrained by that schema.
func DecisionNDJSON(rows []json.RawMessage) ([]byte, error) {
	if len(rows) < 1 || len(rows) > 100 {
		return nil, errors.New("batch size outside 1..100")
	}
	var out bytes.Buffer
	for _, row := range rows {
		var fields map[string]json.RawMessage
		if e := canonical.CheckStrictJSON(row); e != nil {
			return nil, e
		}
		if e := json.Unmarshal(row, &fields); e != nil {
			return nil, e
		}
		if len(fields) != 5 {
			return nil, errors.New("invalid decision input row")
		}
		for _, k := range []string{"decision_input_digest", "tenant", "sanitized_input", "policy_bundle_id", "created_at"} {
			if _, ok := fields[k]; !ok {
				return nil, errors.New("missing decision input field")
			}
		}
		// Preserve the stored tenant value. Never derive it from sanitized_input,
		// a caller identity, or another row. null is not a PostgreSQL text value.
		var tenant *string
		if json.Unmarshal(fields["tenant"], &tenant) != nil || tenant == nil {
			return nil, errors.New("invalid decision tenant")
		}
		var digest, bundle, created string
		if json.Unmarshal(fields["decision_input_digest"], &digest) != nil || !digestPattern.MatchString(digest) || json.Unmarshal(fields["policy_bundle_id"], &bundle) != nil || bundle == "" || json.Unmarshal(fields["created_at"], &created) != nil {
			return nil, errors.New("invalid decision row fields")
		}
		if _, e := time.Parse(time.RFC3339Nano, created); e != nil {
			return nil, e
		}
		input := bytes.TrimSpace(fields["sanitized_input"])
		if len(input) == 0 || input[0] != '{' {
			return nil, errors.New("invalid sanitized input")
		}
		b, e := canonical.JCS(row)
		if e != nil {
			return nil, e
		}
		if out.Len()+len(b)+1 > MaxBatchBytes {
			return nil, errors.New("batch exceeds verification limit")
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}
func (m Manifest) Validate() error {
	if m.Sequence < 1 || m.Sequence > MaxSequence || !validUUID(m.BatchID) || m.Generation < 1 || m.Generation > MaxSequence || !digestPattern.MatchString(m.BatchDigest) || m.RecordCount < 1 || m.RecordCount > 100 || m.Sources == nil || len(m.Sources) > m.RecordCount {
		return errors.New("invalid manifest fields")
	}
	if r := m.OutboxRange; r.First < 1 || r.Last < r.First || r.Last > MaxSequence || r.Last-r.First+1 < int64(m.RecordCount) {
		return errors.New("invalid outbox range")
	}
	if (m.Sequence == 1) != (m.Previous == nil) || m.Previous != nil && !digestPattern.MatchString(*m.Previous) {
		return errors.New("invalid previous digest")
	}
	t, e := time.Parse(time.RFC3339Nano, m.CreatedAt)
	if e != nil || t.IsZero() {
		return errors.New("invalid manifest time")
	}
	// Key dates refer to the fixed batch's creation day, which can precede signing.
	parts := bytes.Split([]byte(m.ObjectKey), []byte("/"))
	if len(parts) != 4 || !validClass(string(parts[1])) {
		return errors.New("invalid object key")
	}
	date, e := time.Parse("2006-01-02", string(parts[2]))
	if e != nil {
		return errors.New("invalid object date")
	}
	key, e := ObjectKey(m.BatchID, string(parts[1]), date)
	if e != nil || key != m.ObjectKey {
		return errors.New("object key does not match batch")
	}
	seen := map[[2]string]bool{}
	for _, s := range m.Sources {
		pair := [2]string{s.ID, s.Epoch}
		if s.ID == "" || s.Epoch == "" || s.First < 1 || s.Last < s.First || s.Last > MaxSequence || seen[pair] {
			return errors.New("invalid source range")
		}
		seen[pair] = true
	}
	return nil
}
func Sign(ctx context.Context, m Manifest, keyVersion string, signer Signer) ([]byte, error) {
	if e := m.Validate(); e != nil {
		return nil, e
	}
	if keyVersion == "" || signer == nil {
		return nil, errors.New("missing signer")
	}
	b, e := canonicalJSON(m)
	if e != nil {
		return nil, e
	}
	d := sha256.Sum256(b)
	sig, e := signer.Sign(ctx, d[:])
	if e != nil {
		return nil, e
	}
	return canonicalJSON(Envelope{m, base64.StdEncoding.EncodeToString(sig), keyVersion})
}
func Decode(raw []byte) (Envelope, error) {
	var env Envelope
	if len(raw) > MaxManifestBytes {
		return env, errors.New("manifest too large")
	}
	if e := canonical.CheckStrictJSON(raw); e != nil {
		return env, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&env); e != nil {
		return env, e
	}
	if d.Decode(new(any)) != io.EOF {
		return env, errors.New("trailing data")
	}
	if e := env.Manifest.Validate(); e != nil {
		return env, e
	}
	if env.KeyVersion == "" || env.Signature == "" {
		return env, errors.New("missing signature")
	}
	// Nullable previous digest must still be an explicit wire field.
	var fields map[string]json.RawMessage
	var outer map[string]json.RawMessage
	_ = json.Unmarshal(raw, &outer)
	_ = json.Unmarshal(outer["manifest"], &fields)
	if len(fields) != 10 {
		return env, errors.New("missing manifest field")
	}
	return env, nil
}

// Verify returns the manifest digest only after signature, chain, object bytes,
// record framing, outbox coverage and DB acknowledgement all pass. Keys come
// from trusted config; an envelope cannot supply or fetch its own key. Errors
// are *VerificationError values carrying the registered failure code.
func Verify(ctx context.Context, raw []byte, sequence int64, previous *string, keys map[string]*ecdsa.PublicKey, objects Objects, acks Acks) (string, error) {
	if acks == nil {
		return "", errors.New("object and outbox verification required")
	}
	return verifyManifest(ctx, raw, sequence, previous, keys, objects, acks)
}

// VerifyDetached checks signature, chain, pinned object and record framing
// without the DB coverage/ACK comparison. It is for manifests outside the
// 30-day verification window, whose DB rows the retention job may have
// purged (TASK-07 3.2.1); it never replaces Verify inside the window.
func VerifyDetached(ctx context.Context, raw []byte, sequence int64, previous *string, keys map[string]*ecdsa.PublicKey, objects Objects) (string, error) {
	return verifyManifest(ctx, raw, sequence, previous, keys, objects, nil)
}

func verifyManifest(ctx context.Context, raw []byte, sequence int64, previous *string, keys map[string]*ecdsa.PublicKey, objects Objects, acks Acks) (string, error) {
	env, e := Decode(raw)
	if e != nil {
		return "", fail(FailManifestInvalid, e)
	}
	m := env.Manifest
	if m.Sequence != sequence || (previous == nil) != (m.Previous == nil) || previous != nil && *previous != *m.Previous {
		return "", fail(FailChainDiscontinuity, errors.New("manifest chain discontinuity"))
	}
	key := keys[env.KeyVersion]
	if key == nil || key.Curve != elliptic.P256() {
		return "", fail(FailUntrustedKey, errors.New("untrusted signing key"))
	}
	body, e := canonicalJSON(m)
	if e != nil {
		return "", fail(FailManifestInvalid, e)
	}
	d := sha256.Sum256(body)
	sig, e := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if e != nil || !ecdsa.VerifyASN1(key, d[:], sig) {
		return "", fail(FailSignatureInvalid, errors.New("invalid manifest signature"))
	}
	if objects == nil {
		return "", errors.New("object verification required")
	}
	data, e := objects.Read(ctx, m.ObjectKey, m.Generation)
	if errors.Is(e, storage.ErrObjectNotExist) {
		return "", fail(FailObjectMissing, fmt.Errorf("read pinned object: %w", e))
	}
	if e != nil {
		return "", fmt.Errorf("read pinned object: %w", e)
	}
	if len(data) > MaxBatchBytes || Digest(data) != m.BatchDigest {
		return "", fail(FailDigestMismatch, errors.New("batch digest mismatch"))
	}
	ids, sources, e := verifyRecords(data, m)
	if e != nil {
		return "", fail(FailRecordInvalid, e)
	}
	if !sameSources(m.Sources, sources) {
		return "", fail(FailCoverageMismatch, errors.New("manifest source ranges differ from batch records"))
	}
	if acks == nil {
		return hex.EncodeToString(d[:]), nil
	}
	members, e := acks.Members(ctx, m.BatchID)
	if e != nil {
		return "", fmt.Errorf("outbox coverage unavailable: %w", e)
	}
	if e = sameCoverage(m, ids, members); e != nil {
		return "", fail(FailCoverageMismatch, e)
	}
	ackRef := m.ObjectKey + "#" + strconv.FormatInt(m.Generation, 10)
	if e = acks.Check(ctx, m.BatchID, ackRef, m.RecordCount); errors.Is(e, ErrAckMismatch) {
		return "", fail(FailAckMismatch, fmt.Errorf("outbox mismatch: %w", e))
	} else if e != nil {
		return "", fmt.Errorf("outbox acknowledgement unavailable: %w", e)
	}
	return hex.EncodeToString(d[:]), nil
}

// verifyRecords checks canonical NDJSON framing and class, and returns each
// line's (record_kind, record_id) plus source ranges of sequenced records.
func verifyRecords(data []byte, m Manifest) ([][2]string, []Source, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, nil, errors.New("incomplete NDJSON")
	}
	lines := bytes.Split(data[:len(data)-1], []byte("\n"))
	if len(lines) != m.RecordCount {
		return nil, nil, errors.New("record count mismatch")
	}
	for _, line := range lines {
		if e := canonical.CheckJSONForJCS(line); e != nil {
			return nil, nil, errors.New("invalid NDJSON record")
		}
		canonicalLine, err := canonical.JCS(line)
		if err != nil || !bytes.Equal(canonicalLine, line) {
			return nil, nil, errors.New("noncanonical NDJSON record")
		}
	}
	class := string(bytes.Split([]byte(m.ObjectKey), []byte("/"))[1])
	ids := make([][2]string, 0, len(lines))
	if class == "decision_input" {
		for _, line := range lines {
			if _, e := DecisionNDJSON([]json.RawMessage{line}); e != nil {
				return nil, nil, e
			}
			var row struct {
				Digest string `json:"decision_input_digest"`
			}
			if e := json.Unmarshal(line, &row); e != nil {
				return nil, nil, e
			}
			ids = append(ids, [2]string{"decision_input", row.Digest})
		}
		return ids, []Source{}, nil
	}
	expectedKind := map[string]string{"business": "audit_event", "kernel": "kernel_event", "lifecycle": "lifecycle_event"}[class]
	records := make([]Record, 0, len(lines))
	for _, line := range lines {
		var r Record
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if e := decoder.Decode(&r); e != nil {
			return nil, nil, e
		}
		if r.Kind != expectedKind {
			return nil, nil, errors.New("record class mismatch")
		}
		if _, e := NDJSON([]Record{r}); e != nil {
			return nil, nil, e
		}
		id, e := recordID(r)
		if e != nil {
			return nil, nil, e
		}
		ids = append(ids, [2]string{r.Kind, id})
		records = append(records, r)
	}
	sources, e := recordSources(records)
	return ids, sources, e
}

// sameCoverage requires the DB's fixed members to match the NDJSON line by
// line and the signed outbox_range to equal their exact min/max outbox_id.
func sameCoverage(m Manifest, ids [][2]string, members []Member) error {
	if len(members) != m.RecordCount || len(ids) != m.RecordCount {
		return errors.New("batch member count differs from manifest")
	}
	first, last := members[0].OutboxID, members[0].OutboxID
	for i, member := range members {
		if member.Kind != ids[i][0] || member.ID != ids[i][1] {
			return errors.New("batch member differs from NDJSON record")
		}
		first, last = min(first, member.OutboxID), max(last, member.OutboxID)
	}
	if first != m.OutboxRange.First || last != m.OutboxRange.Last {
		return errors.New("manifest outbox range differs from batch members")
	}
	return nil
}
