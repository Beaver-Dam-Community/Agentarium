package export

import (
	"cloud.google.com/go/storage"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"strings"
	"testing"
	"time"
)

type signer struct{ key *ecdsa.PrivateKey }

func (s signer) Sign(_ context.Context, d []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, d)
}

type objects struct {
	key   string
	gen   int64
	data  []byte
	err   error
	calls int
}

func (s *objects) Read(_ context.Context, k string, g int64) ([]byte, error) {
	s.calls++
	if k != s.key || g != s.gen {
		return nil, errors.New("generation mismatch")
	}
	return s.data, s.err
}

type acks struct {
	id, ref string
	count   int
	err     error
	calls   int
	members []Member
}

func (s *acks) Members(_ context.Context, id string) ([]Member, error) {
	if id != s.id {
		return nil, errors.New("wrong batch")
	}
	return s.members, nil
}

const fixtureEventID = "0e5bb0e6-7a8c-4f5c-9a43-3d7f0a0d5e11"

func (s *acks) Check(_ context.Context, id, ref string, count int) error {
	s.calls++
	if id != s.id || ref != s.ref || count != s.count {
		return errors.New("wrong ack binding")
	}
	return s.err
}
func fixture(t *testing.T) (Manifest, signer, *objects, *acks) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	data, e := NDJSON([]Record{{"audit_event", "session_created", json.RawMessage(`{"event_id":"` + fixtureEventID + `","source_id":"source","source_epoch":"epoch","source_sequence":1}`)}})
	if e != nil {
		t.Fatal(e)
	}
	id := "61041562-9572-4f87-a24c-f4842fe35177"
	date := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	path, e := ObjectKey(id, "business", date)
	if e != nil {
		t.Fatal(e)
	}
	m := Manifest{1, id, path, 123, Digest(data), 1, OutboxRange{7, 7}, []Source{{"source", "epoch", 1, 1}}, nil, date.Format(time.RFC3339)}
	return m, signer{key}, &objects{key: path, gen: 123, data: data}, &acks{id: id, ref: path + "#123", count: 1, members: []Member{{"audit_event", fixtureEventID, 7}}}
}
func signed(t *testing.T, m Manifest, s signer) []byte {
	t.Helper()
	b, e := Sign(context.Background(), m, "pinned-version", s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestManifestSignaturePinnedGenerationAndOutbox(t *testing.T) {
	m, s, o, a := fixture(t)
	raw := signed(t, m, s)
	keys := map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}
	digest, e := Verify(context.Background(), raw, 1, nil, keys, o, a)
	if e != nil || len(digest) != 64 || o.calls != 1 || a.calls != 1 {
		t.Fatalf("%s %v", digest, e)
	}
	m.Sequence = 2
	m.Previous = &digest
	second := signed(t, m, s)
	if _, e = Verify(context.Background(), second, 2, &digest, keys, o, a); e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(context.Background(), second, 1, nil, keys, o, a); e == nil {
		t.Fatal("missing prefix accepted")
	}
}
func TestVerificationRejectsTamperingAndMissingEvidence(t *testing.T) {
	for _, mode := range []string{"body", "signature", "key", "generation", "object-missing", "object-digest", "outbox-missing", "wrong-sequence", "wrong-previous", "duplicate-key", "unknown-field", "missing-null"} {
		t.Run(mode, func(t *testing.T) {
			m, s, o, a := fixture(t)
			raw := signed(t, m, s)
			keys := map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}
			seq := int64(1)
			var prev *string
			switch mode {
			case "body":
				raw = []byte(strings.Replace(string(raw), `"record_count":1`, `"record_count":2`, 1))
			case "signature":
				var env Envelope
				_ = json.Unmarshal(raw, &env)
				env.Signature = "AA=="
				raw, _ = json.Marshal(env)
			case "key":
				keys = map[string]*ecdsa.PublicKey{}
			case "generation":
				o.gen++
			case "object-missing":
				o.err = storage.ErrObjectNotExist
			case "object-digest":
				o.data = append([]byte{}, o.data...)
				o.data[0] = '['
			case "outbox-missing":
				a.err = ErrAckMismatch
			case "wrong-sequence":
				seq = 2
			case "wrong-previous":
				p := strings.Repeat("a", 64)
				prev = &p
			case "duplicate-key":
				raw = []byte(strings.Replace(string(raw), `"record_count":1`, `"record_count":1,"record_count":1`, 1))
			case "unknown-field":
				raw = []byte(strings.Replace(string(raw), `"record_count":1`, `"record_count":1,"extra":true`, 1))
			case "missing-null":
				raw = []byte(strings.Replace(string(raw), `"prev_manifest_digest":null,`, "", 1))
			}
			if _, e := Verify(context.Background(), raw, seq, prev, keys, o, a); e == nil {
				t.Fatal("bad evidence accepted")
			}
		})
	}
}
func TestSignedMalformedObjectRejected(t *testing.T) {
	for _, data := range []string{"{}\n", "{}", "{}\n{}\n", "{ \"a\":1 }\n", "{\"a\":1,\"a\":2}\n"} {
		m, s, o, a := fixture(t)
		o.data = []byte(data)
		m.BatchDigest = Digest(o.data)
		if _, e := Verify(context.Background(), signed(t, m, s), 1, nil, map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}, o, a); e == nil {
			t.Fatalf("accepted %q", data)
		}
	}
}
func TestNDJSONAndObjectKeyContract(t *testing.T) {
	b, e := NDJSON([]Record{{"kernel_event", "kernel_event_observed", json.RawMessage(`{"z":2,"a":1}`)}})
	if e != nil || string(b) != "{\"event_type\":\"kernel_event_observed\",\"record\":{\"a\":1,\"z\":2},\"record_kind\":\"kernel_event\"}\n" {
		t.Fatalf("%s %v", b, e)
	}
	if _, e = NDJSON([]Record{{"kernel_event", "session_created", json.RawMessage(`{}`)}}); e == nil {
		t.Fatal("bad registry wrapper")
	}
	if _, e = NDJSON([]Record{{"audit_event", "created", json.RawMessage(`{"x":1,"x":2}`)}}); e == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, e = ObjectKey("../escape", "business", time.Now()); e == nil {
		t.Fatal("unsafe ID accepted")
	}
	if _, e = ObjectKey("61041562-9572-4f87-a24c-f4842fe35177", "../escape", time.Now()); e == nil {
		t.Fatal("unsafe class accepted")
	}
	if _, e = DecisionNDJSON([]json.RawMessage{json.RawMessage(`{"decision_input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tenant":"tenant-a","sanitized_input":{},"policy_bundle_id":"p","created_at":"2026-10-16T00:00:00Z"}`)}); e != nil {
		t.Fatal(e)
	}
}

func TestNDJSONRejectsInvalidUTF8WithoutReplacement(t *testing.T) {
	if _, e := NDJSON([]Record{{"audit_event", string([]byte{255}), json.RawMessage(`{}`)}}); e == nil {
		t.Fatal("invalid UTF-8 was silently replaced")
	}
}

func TestDepth16RecordSurvivesExportWrapper(t *testing.T) {
	// Build the maximum accepted record depth rather than counting wrapper
	// depth as producer-controlled record depth.
	body := `{"leaf":1}`
	for {
		next := `{"nested":` + body + `}`
		if canonical.CheckStrictJSON([]byte(next)) != nil {
			break
		}
		body = next
	}
	body = `{"event_id":"` + fixtureEventID + `","source_id":"source","source_epoch":"epoch","source_sequence":1,` + body[1:]
	data, err := NDJSON([]Record{{Kind: "audit_event", EventType: "session_created", Body: json.RawMessage(body)}})
	if err != nil {
		t.Fatal(err)
	}
	m, s, o, a := fixture(t)
	o.data = data
	m.BatchDigest = Digest(data)
	if _, err = Verify(context.Background(), signed(t, m, s), 1, nil, map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}, o, a); err != nil {
		t.Fatal(err)
	}
	if _, err = NDJSON([]Record{{Kind: "audit_event", EventType: "session_created", Body: json.RawMessage(`{"nested":` + body + `}`)}}); err == nil {
		t.Fatal("depth17 record accepted")
	}
}

func TestVerifierRejectsSignedWrongSourceRanges(t *testing.T) {
	for _, change := range []string{"source", "epoch", "first", "last", "omitted"} {
		t.Run(change, func(t *testing.T) {
			m, s, o, a := fixture(t)
			switch change {
			case "source":
				m.Sources[0].ID = "other"
			case "epoch":
				m.Sources[0].Epoch = "other"
			case "first":
				m.Sources[0].First = 2
				m.Sources[0].Last = 2
			case "last":
				m.Sources[0].Last = 10
			case "omitted":
				m.Sources = []Source{}
			}
			if _, err := Verify(context.Background(), signed(t, m, s), 1, nil, map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}, o, a); err == nil {
				t.Fatal("signed manifest source claim did not match its records")
			}
			if a.calls != 0 {
				t.Fatal("invalid source ranges reached acknowledgement verification")
			}
		})
	}
}

func TestDecisionInputTenantPreservedAndVerified(t *testing.T) {
	row := json.RawMessage(`{"decision_input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tenant":"tenant/한글","sanitized_input":{"tenant":"not-the-row-tenant"},"policy_bundle_id":"p","created_at":"2026-10-16T00:00:00Z"}`)
	data, err := DecisionNDJSON([]json.RawMessage{row})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	var tenant string
	if err := json.Unmarshal(got["tenant"], &tenant); err != nil || tenant != "tenant/한글" || len(got) != 5 {
		t.Fatalf("stored tenant was changed or lost: %s, %v", data, err)
	}
	m, s, o, a := fixture(t)
	m.ObjectKey = strings.Replace(m.ObjectKey, "/business/", "/decision_input/", 1)
	m.Sources = []Source{}
	m.BatchDigest = Digest(data)
	o.key, o.data = m.ObjectKey, data
	a.ref = m.ObjectKey + "#123"
	a.members = []Member{{"decision_input", strings.Repeat("a", 64), 7}}
	if _, err := Verify(context.Background(), signed(t, m, s), 1, nil, map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}, o, a); err != nil {
		t.Fatal(err)
	}

	m.Sources = []Source{{ID: "invented", Epoch: "invented", First: 1, Last: 1}}
	if _, err := Verify(context.Background(), signed(t, m, s), 1, nil, map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}, o, a); err == nil {
		t.Fatal("signed decision input claimed nonexistent source metadata")
	}
	m.Sources = []Source{}

	for name, replacement := range map[string]string{
		"missing": "", "null": `"tenant":null,`, "number": `"tenant":1,`,
		"object": `"tenant":{},`, "unknown": `"tenant":"tenant-a","extra":true,`,
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(string(row), `"tenant":"tenant/한글",`, replacement, 1)
			if _, err := DecisionNDJSON([]json.RawMessage{json.RawMessage(bad)}); err == nil {
				t.Fatal("invalid tenant row accepted")
			}
			// Even a correctly signed, canonical object must satisfy the row schema.
			canonicalBad, err := canonical.JCS([]byte(bad))
			if err != nil {
				t.Fatal(err)
			}
			o.data = append(canonicalBad, '\n')
			m.BatchDigest = Digest(o.data)
			if _, err := Verify(context.Background(), signed(t, m, s), 1, nil, map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}, o, a); err == nil {
				t.Fatal("signed invalid tenant row accepted")
			}
		})
	}
}

// Unsequenced business events (COMMON source_sequence=null) are exported
// without inventing a sequence: sources[] lists only sequenced records and the
// outbox_range covers every member (TASK-07 3.2.1).
func TestUnsequencedBusinessCoverage(t *testing.T) {
	ids := []string{fixtureEventID, "6a6f2b8e-34c1-4d55-8a0c-0b6f0f2f7a10", "9d1e7c3a-1f0b-4c7e-bb52-5f3c2a9e4d21"}
	data, err := NDJSON([]Record{
		{"audit_event", "observation_gap_recorded", json.RawMessage(`{"event_id":"` + ids[0] + `","source_id":"receiver","source_epoch":"e1","source_sequence":null}`)},
		{"audit_event", "approval_revoked", json.RawMessage(`{"event_id":"` + ids[1] + `","source_id":"coordinator","source_epoch":"e2","source_sequence":4}`)},
		{"audit_event", "approval_revoked", json.RawMessage(`{"event_id":"` + ids[2] + `","source_id":"coordinator","source_epoch":"e2","source_sequence":9}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := func() (Manifest, signer, *objects, *acks) {
		m, s, o, a := fixture(t)
		o.data, m.BatchDigest, m.RecordCount, a.count = data, Digest(data), 3, 3
		m.Sources = []Source{{"coordinator", "e2", 4, 9}}
		m.OutboxRange = OutboxRange{10, 31}
		a.members = []Member{{"audit_event", ids[0], 31}, {"audit_event", ids[1], 10}, {"audit_event", ids[2], 20}}
		return m, s, o, a
	}
	m, s, o, a := base()
	keys := map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}
	if _, err := Verify(context.Background(), signed(t, m, s), 1, nil, keys, o, a); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Manifest, *acks){
		"invented unsequenced source": func(m *Manifest, _ *acks) { m.Sources = append(m.Sources, Source{"receiver", "e1", 1, 1}) },
		"range first":                 func(m *Manifest, _ *acks) { m.OutboxRange.First = 9 },
		"range last":                  func(m *Manifest, _ *acks) { m.OutboxRange.Last = 30 },
		"missing member":              func(_ *Manifest, a *acks) { a.members = a.members[:2] },
		"reordered member":            func(_ *Manifest, a *acks) { a.members[0], a.members[1] = a.members[1], a.members[0] },
		"foreign member":              func(_ *Manifest, a *acks) { a.members[2].ID = "11111111-2222-4333-8444-555555555555" },
	} {
		t.Run(name, func(t *testing.T) {
			m, s, o, a := base()
			mutate(&m, a)
			_, err := Verify(context.Background(), signed(t, m, s), 1, nil, map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}, o, a)
			if FailureCode(err) != FailCoverageMismatch {
				t.Fatalf("coverage mismatch not reported: %v", err)
			}
			if a.calls != 0 {
				t.Fatal("coverage mismatch reached acknowledgement verification")
			}
		})
	}
	m, s, _, _ = base()
	m.OutboxRange = OutboxRange{10, 11} // narrower than three distinct IDs
	if _, err := Sign(context.Background(), m, "pinned-version", s); err == nil {
		t.Fatal("impossible outbox range signed")
	}
}

func TestVerificationFailureCodes(t *testing.T) {
	for mode, want := range map[string]string{
		"signature": FailSignatureInvalid, "key": FailUntrustedKey, "object-missing": FailObjectMissing,
		"object-digest": FailDigestMismatch, "outbox-missing": FailAckMismatch, "wrong-sequence": FailChainDiscontinuity,
		"unknown-field": FailManifestInvalid,
	} {
		t.Run(mode, func(t *testing.T) {
			m, s, o, a := fixture(t)
			raw := signed(t, m, s)
			keys := map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}
			seq := int64(1)
			switch mode {
			case "signature":
				var env Envelope
				_ = json.Unmarshal(raw, &env)
				env.Signature = "AA=="
				raw, _ = canonical.CanonicalJSON(env)
			case "key":
				keys = map[string]*ecdsa.PublicKey{}
			case "object-missing":
				o.err = storage.ErrObjectNotExist
			case "object-digest":
				o.data = append([]byte{}, o.data...)
				o.data[0] = '['
			case "outbox-missing":
				a.err = ErrAckMismatch
			case "wrong-sequence":
				seq = 2
			case "unknown-field":
				raw = []byte(strings.Replace(string(raw), `"record_count":1`, `"record_count":1,"extra":true`, 1))
			}
			if _, err := Verify(context.Background(), raw, seq, nil, keys, o, a); FailureCode(err) != want {
				t.Fatalf("code %q for %v, want %s", FailureCode(err), err, want)
			}
		})
	}
}

func TestIncompleteChecksAreNotIntegrityFailures(t *testing.T) {
	m, s, o, a := fixture(t)
	o.err = errors.New("network unavailable")
	if _, err := Verify(context.Background(), signed(t, m, s), 1, nil, map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}, o, a); err == nil || FailureCode(err) != "" {
		t.Fatalf("transient read classified as incident: %v %q", err, FailureCode(err))
	}
	m, s, o, a = fixture(t)
	a.err = errors.New("connection reset")
	if _, err := Verify(context.Background(), signed(t, m, s), 1, nil, map[string]*ecdsa.PublicKey{"pinned-version": &s.key.PublicKey}, o, a); err == nil || FailureCode(err) != "" {
		t.Fatalf("DB failure classified as incident: %v", err)
	}
}
