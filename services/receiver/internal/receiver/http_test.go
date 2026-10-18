package receiver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

const (
	keyA     = "0b6b2f4e-3c1d-4d7e-9a1b-2c3d4e5f6a7b"
	attemptA = "9f0e8d7c-6b5a-4c3d-8e2f-1a0b9c8d7e6f"
	goodBody = `{"email":null,"summary":"3 pods restarted"}`
)

// fakeStore records calls and returns canned results.
type fakeStore struct {
	submits    []Submission
	missing    []Submission
	result     SubmitResult
	err        error
	receipt    ReceiptRecords
	receiptKey string
}

func (f *fakeStore) Submit(_ context.Context, s Submission) (SubmitResult, error) {
	f.submits = append(f.submits, s)
	if f.err != nil {
		return SubmitResult{}, f.err
	}
	r := f.result
	if r.Outcome != OutcomeKeyBodyConflict {
		r.ActionKey, r.WireBodyDigest, r.BodyBytes = s.ActionKey, s.WireBodyDigest, s.BodyBytes
	}
	return r, nil
}

func (f *fakeStore) RecordKeyMissing(_ context.Context, s Submission) (string, error) {
	f.missing = append(f.missing, s)
	if f.err != nil {
		return "", f.err
	}
	return "11111111-1111-4111-8111-111111111111", nil
}

func (f *fakeStore) Receipt(_ context.Context, k string) (ReceiptRecords, error) {
	f.receiptKey = k
	return f.receipt, f.err
}

func newHandler(mode Mode, st Store) http.Handler {
	mux := http.NewServeMux()
	(&Handler{Store: st, Cfg: Config{Mode: mode, TargetID: "receiver-primary", RouteID: "submissions-v1", TargetVersion: "t1"}, Keys: testKeys()}).Register(mux)
	return mux
}

// testKey is version "1" of testKeys; post sends it unless the test sets
// HeaderReceiverKey itself ("" removes the header).
const testKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

func testKeys() *KeySet {
	k, ok := decodeKey(testKey)
	if !ok {
		panic("bad test key")
	}
	return &KeySet{keys: []apiKey{{version: "1", key: k}}}
}

func withPeer(r *http.Request, san string) *http.Request {
	if san == "" {
		return r
	}
	u, err := url.Parse(san)
	if err != nil {
		panic(err)
	}
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
	return r
}

func post(h http.Handler, san, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := withPeer(httptest.NewRequest(http.MethodPost, "/test/v1/submissions", strings.NewReader(body)), san)
	r.Header.Set(HeaderReceiverKey, testKey)
	for k, v := range headers {
		if v == "" && k == HeaderReceiverKey {
			r.Header.Del(k)
			continue
		}
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decodeMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return m
}

func keys(m map[string]any) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

func reasons(t *testing.T, m map[string]any) string {
	t.Helper()
	rc, ok := m["reason_codes"].([]any)
	if !ok || len(rc) != 1 {
		t.Fatalf("reason_codes = %v", m["reason_codes"])
	}
	return rc[0].(string)
}

func TestSubmitCreated(t *testing.T) {
	st := &fakeStore{result: SubmitResult{Outcome: OutcomeEffectCreated, ReceiptAttemptID: "a1", EffectID: "e1"}}
	w := post(newHandler(ModeIdempotent, st), SubmitterSAN, goodBody, map[string]string{
		HeaderIdempotencyKey: strings.ToUpper(keyA), HeaderAttemptID: attemptA,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	m := decodeMap(t, w)
	if got := keys(m); got != "action_key,body_bytes,effect_id,receipt_attempt_id,wire_body_digest" {
		t.Fatalf("fields %s", got)
	}
	if m["action_key"] != keyA || m["effect_id"] != "e1" || m["receipt_attempt_id"] != "a1" {
		t.Fatalf("body %v", m)
	}
	if len(st.submits) != 1 {
		t.Fatalf("submits %d", len(st.submits))
	}
	s := st.submits[0]
	want := canonical.SHA256Hex([]byte(goodBody))
	if s.WireBodyDigest != want || m["wire_body_digest"] != want || s.BodyBytes != len(goodBody) || m["body_bytes"] != float64(len(goodBody)) {
		t.Fatalf("digest/bytes %+v %v", s, m)
	}
	if s.ClientPrincipal != SubmitterSAN || *s.ClientAttemptID != attemptA || *s.ActionKey != keyA || s.Mode != ModeIdempotent {
		t.Fatalf("submission %+v", s)
	}
	if s.ContentDigestServer == nil || *s.ContentDigestServer != want {
		// goodBody is already JCS, so the canonical digest equals the wire digest.
		t.Fatalf("content digest %v", s.ContentDigestServer)
	}
}

func TestSubmitWireDigestIsOverReceivedBytes(t *testing.T) {
	// The same payload in non-JCS form: the wire digest is over the bytes as
	// received; the canonical digest is not.
	body := `{ "summary": "3 pods restarted", "email": null }`
	st := &fakeStore{result: SubmitResult{Outcome: OutcomeEffectCreated}}
	w := post(newHandler(ModeIdempotent, st), SubmitterSAN, body, map[string]string{HeaderIdempotencyKey: keyA})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d", w.Code)
	}
	s := st.submits[0]
	if s.WireBodyDigest != canonical.SHA256Hex([]byte(body)) || *s.ContentDigestServer != canonical.SHA256Hex([]byte(goodBody)) {
		t.Fatalf("digests %s %s", s.WireBodyDigest, *s.ContentDigestServer)
	}
}

func TestSubmitDuplicate(t *testing.T) {
	st := &fakeStore{result: SubmitResult{Outcome: OutcomeDuplicateReturned, ReceiptAttemptID: "a2", EffectID: "e1"}}
	w := post(newHandler(ModeIdempotent, st), SubmitterSAN, goodBody, map[string]string{HeaderIdempotencyKey: keyA})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	m := decodeMap(t, w)
	if keys(m) != "action_key,body_bytes,duplicate,effect_id,receipt_attempt_id,wire_body_digest" || m["duplicate"] != true {
		t.Fatalf("body %v", m)
	}
}

func TestSubmitConflict(t *testing.T) {
	st := &fakeStore{result: SubmitResult{Outcome: OutcomeKeyBodyConflict, ReceiptAttemptID: "a3"}}
	w := post(newHandler(ModeIdempotent, st), SubmitterSAN, goodBody, map[string]string{HeaderIdempotencyKey: keyA})
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d", w.Code)
	}
	m := decodeMap(t, w)
	if keys(m) != "reason_codes,receipt_attempt_id,request_id" || reasons(t, m) != ReasonTargetKeyBodyConflict || m["receipt_attempt_id"] != "a3" {
		t.Fatalf("body %v", m)
	}
}

func TestSubmitKeyMissingIdempotent(t *testing.T) {
	st := &fakeStore{}
	// The body is invalid too: a missing key is recorded first.
	w := post(newHandler(ModeIdempotent, st), SubmitterSAN, `{"bad":1}`, map[string]string{HeaderAttemptID: attemptA})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d", w.Code)
	}
	m := decodeMap(t, w)
	if reasons(t, m) != ReasonSchemaInvalid || m["receipt_attempt_id"] != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("body %v", m)
	}
	if len(st.missing) != 1 || len(st.submits) != 0 || st.missing[0].ActionKey != nil || *st.missing[0].ClientAttemptID != attemptA {
		t.Fatalf("store calls %+v %+v", st.missing, st.submits)
	}
}

func TestSubmitKeylessNonIdempotent(t *testing.T) {
	st := &fakeStore{result: SubmitResult{Outcome: OutcomeEffectCreated, ReceiptAttemptID: "a1", EffectID: "e1"}}
	w := post(newHandler(ModeNonIdempotent, st), SubmitterSAN, goodBody, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d", w.Code)
	}
	m := decodeMap(t, w)
	if v, ok := m["action_key"]; !ok || v != nil {
		t.Fatalf("action_key %v", m)
	}
	if len(st.submits) != 1 || st.submits[0].Mode != ModeNonIdempotent || len(st.missing) != 0 {
		t.Fatalf("store calls %+v", st)
	}
}

func TestSubmitSchemaInvalid(t *testing.T) {
	cases := map[string]string{
		"not json":            `nope`,
		"array":               `[]`,
		"null":                `null`,
		"duplicate key":       `{"summary":"a","summary":"b","email":null}`,
		"case-only duplicate": `{"summary":"x","Summary":"y","email":null}`,
		"case mismatch":       `{"Summary":"x","email":null}`,
		"unknown key":         `{"summary":"x","email":null,"extra":1}`,
		"missing email":       `{"summary":"x"}`,
		"missing summary":     `{"email":null}`,
		"empty summary":       `{"summary":"","email":null}`,
		"long summary":        `{"summary":"` + strings.Repeat("a", 4097) + `","email":null}`,
		"summary not string":  `{"summary":1,"email":null}`,
		"short email":         `{"summary":"x","email":"ab"}`,
		"email not string":    `{"summary":"x","email":true}`,
		// unknown fields
		"unknown key null":   `{"summary":"x","email":null,"note":null}`,
		"unknown nested key": `{"summary":"x","email":null,"meta":{"a":"b"}}`,
		// case-variant keys (encoding/json alone would match these)
		"EMAIL case variant": `{"summary":"x","EMAIL":null}`,
		"Email case variant": `{"summary":"x","Email":"a@b"}`,
		"both case variants": `{"SUMMARY":"x","Email":null}`,
		// duplicate keys
		"duplicate email":     `{"summary":"x","email":null,"email":"a@b"}`,
		"case-only dup email": `{"summary":"x","email":null,"eMail":null}`,
		// numeric or other values where a string is expected
		"summary float":       `{"summary":1.5,"email":null}`,
		"summary big integer": `{"summary":12345678901234567890,"email":null}`,
		"summary exponent":    `{"summary":1e3,"email":null}`,
		"email number":        `{"summary":"x","email":42}`,
		"summary null":        `{"summary":null,"email":null}`,
		"summary array":       `{"summary":["x"],"email":null}`,
		"summary object":      `{"summary":{"x":1},"email":null}`,
		"email object":        `{"summary":"x","email":{}}`,
		"lone surrogate":      `{"summary":"\ud800","email":null}`,
		"invalid utf8":        "{\"summary\":\"\xff\",\"email\":null}",
		"trailing token":      `{"summary":"x","email":null} {}`,
		"empty":               ``,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			st := &fakeStore{}
			w := post(newHandler(ModeIdempotent, st), SubmitterSAN, body, map[string]string{HeaderIdempotencyKey: keyA})
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d", w.Code)
			}
			m := decodeMap(t, w)
			if keys(m) != "reason_codes,request_id" || reasons(t, m) != ReasonSchemaInvalid {
				t.Fatalf("body %v", m)
			}
			if len(st.submits)+len(st.missing) != 0 {
				t.Fatal("schema violation reached the store")
			}
		})
	}
}

func TestSubmitBoundaryBodies(t *testing.T) {
	ok := []string{
		`{"summary":"` + strings.Repeat("a", 4096) + `","email":null}`,
		`{"summary":"x","email":"a@b"}`,
		`{"summary":"x","email":"` + strings.Repeat("e", 254) + `"}`,
	}
	for _, body := range ok {
		st := &fakeStore{result: SubmitResult{Outcome: OutcomeEffectCreated}}
		if w := post(newHandler(ModeIdempotent, st), SubmitterSAN, body, map[string]string{HeaderIdempotencyKey: keyA}); w.Code != http.StatusCreated {
			t.Fatalf("%d for %.40s", w.Code, body)
		}
	}
}

func TestValidatePayload(t *testing.T) {
	for _, body := range []string{
		goodBody,
		`{"summary":"x","email":"a@b"}`,
		` { "email" : null , "summary" : "x" } `,
		`{"summary":"é😀","email":null}`,
	} {
		if err := validatePayload([]byte(body)); err != nil {
			t.Errorf("%s: %v", body, err)
		}
	}
	for _, body := range []string{
		`{"summary":"x","email":null,"extra":"y"}`,
		`{"summary":"x","Email":null}`,
		`{"summary":"x","summary":"y","email":null}`,
		`{"summary":7,"email":null}`,
		`{"summary":"x","email":7}`,
	} {
		if err := validatePayload([]byte(body)); err == nil {
			t.Errorf("%s accepted", body)
		}
	}
}

func TestSubmitHeaders(t *testing.T) {
	cases := map[string]http.Header{
		"key not uuid":      {HeaderIdempotencyKey: {"action-1"}},
		"key braces":        {HeaderIdempotencyKey: {"{" + keyA + "}"}},
		"key urn":           {HeaderIdempotencyKey: {"urn:uuid:" + keyA}},
		"key repeated":      {HeaderIdempotencyKey: {keyA, keyA}},
		"attempt not uuid":  {HeaderIdempotencyKey: {keyA}, HeaderAttemptID: {"x"}},
		"attempt repeated":  {HeaderIdempotencyKey: {keyA}, HeaderAttemptID: {attemptA, attemptA}},
		"key empty":         {HeaderIdempotencyKey: {""}},
		"key no hyphens 32": {HeaderIdempotencyKey: {strings.ReplaceAll(keyA, "-", "")}},
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			st := &fakeStore{}
			r := withPeer(httptest.NewRequest(http.MethodPost, "/test/v1/submissions", strings.NewReader(goodBody)), SubmitterSAN)
			r.Header.Set(HeaderReceiverKey, testKey)
			for k, vs := range hdr {
				for _, v := range vs {
					r.Header.Add(k, v)
				}
			}
			w := httptest.NewRecorder()
			newHandler(ModeIdempotent, st).ServeHTTP(w, r)
			if w.Code != http.StatusUnprocessableEntity || len(st.submits)+len(st.missing) != 0 {
				t.Fatalf("status %d, store calls %d", w.Code, len(st.submits)+len(st.missing))
			}
		})
	}
}

func TestSubmitTooLarge(t *testing.T) {
	st := &fakeStore{}
	body := `{"summary":"` + strings.Repeat("a", MaxBodyBytes) + `","email":null}`
	w := post(newHandler(ModeNonIdempotent, st), SubmitterSAN, body, nil)
	if w.Code != http.StatusRequestEntityTooLarge || reasons(t, decodeMap(t, w)) != ReasonBodyTooLarge {
		t.Fatalf("status %d", w.Code)
	}
	if len(st.submits) != 0 {
		t.Fatal("oversized body reached the store")
	}
}

func TestSubmitStoreFailure(t *testing.T) {
	st := &fakeStore{err: errors.New("db down")}
	w := post(newHandler(ModeIdempotent, st), SubmitterSAN, goodBody, map[string]string{HeaderIdempotencyKey: keyA})
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "2" || reasons(t, decodeMap(t, w)) != ReasonStateStoreUnavailable {
		t.Fatalf("status %d", w.Code)
	}
	w = post(newHandler(ModeIdempotent, st), SubmitterSAN, goodBody, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("key-missing path status %d", w.Code)
	}
}

func TestAuthFailures(t *testing.T) {
	adapterSAN := "spiffe://agentarium.internal/ns/agent-adapters/sa/kubernetes-reader"
	cases := []struct {
		name   string
		method string
		path   string
		san    string
	}{
		{"submit without client cert", http.MethodPost, "/test/v1/submissions", ""},
		{"submit by other adapter", http.MethodPost, "/test/v1/submissions", adapterSAN},
		{"submit by collector", http.MethodPost, "/test/v1/submissions", ReceiptReaderSAN},
		{"submit by exec pod SAN", http.MethodPost, "/test/v1/submissions", SubmitterSAN + "/pod/abc"},
		{"receipt without client cert", http.MethodGet, "/test/v1/receipts/" + keyA, ""},
		{"receipt by receiver-sender adapter", http.MethodGet, "/test/v1/receipts/" + keyA, SubmitterSAN},
		{"receipt by other workload", http.MethodGet, "/test/v1/receipts/" + keyA, adapterSAN},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := &fakeStore{}
			r := withPeer(httptest.NewRequest(c.method, c.path, strings.NewReader(goodBody)), c.san)
			r.Header.Set(HeaderIdempotencyKey, keyA)
			w := httptest.NewRecorder()
			newHandler(ModeIdempotent, st).ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized || reasons(t, decodeMap(t, w)) != ReasonAuthRequired {
				t.Fatalf("status %d", w.Code)
			}
			if len(st.submits)+len(st.missing) != 0 || st.receiptKey != "" {
				t.Fatal("unauthorized request reached the store")
			}
		})
	}
}

func TestAuthRejectsTwoURISANs(t *testing.T) {
	u1, _ := url.Parse(SubmitterSAN)
	u2, _ := url.Parse(ReceiptReaderSAN)
	r := httptest.NewRequest(http.MethodPost, "/test/v1/submissions", strings.NewReader(goodBody))
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u1, u2}}}}}
	w := httptest.NewRecorder()
	newHandler(ModeNonIdempotent, &fakeStore{}).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestReceipt(t *testing.T) {
	cd := "c" + strings.Repeat("0", 63)
	ca := attemptA
	ts := time.Date(2026, 10, 15, 6, 0, 0, 123456000, time.FixedZone("KST", 9*3600))
	st := &fakeStore{receipt: ReceiptRecords{
		Effects: []ReceiptEffect{{EffectID: "e1", WireBodyDigest: strings.Repeat("a", 64), ContentDigestServer: &cd, BodyBytes: 42, CommittedAt: ts}},
		Attempts: []ReceiptAttempt{
			{ReceiptAttemptID: "a1", ClientAttemptID: &ca, ReceivedAt: ts, WireBodyDigest: strings.Repeat("a", 64), Outcome: OutcomeEffectCreated},
			{ReceiptAttemptID: "a2", ReceivedAt: ts.Add(time.Second), WireBodyDigest: strings.Repeat("a", 64), Outcome: OutcomeDuplicateReturned},
		},
	}}
	r := withPeer(httptest.NewRequest(http.MethodGet, "/test/v1/receipts/"+strings.ToUpper(keyA), nil), ReceiptReaderSAN)
	w := httptest.NewRecorder()
	newHandler(ModeIdempotent, st).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if st.receiptKey != keyA {
		t.Fatalf("store key %q", st.receiptKey)
	}
	want := `{"action_key":"` + keyA + `","target_identity":"receiver-primary","route":"submissions-v1","receiver_mode":"idempotent",` +
		`"effects":[{"effect_id":"e1","wire_body_digest":"` + strings.Repeat("a", 64) + `","content_digest_server":"` + cd + `","body_bytes":42,"committed_at":"2026-10-14T21:00:00.123456Z"}],` +
		`"effect_count":1,"receiver_attempts":[` +
		`{"receipt_attempt_id":"a1","client_attempt_id":"` + attemptA + `","received_at":"2026-10-14T21:00:00.123456Z","wire_body_digest":"` + strings.Repeat("a", 64) + `","outcome":"effect_created"},` +
		`{"receipt_attempt_id":"a2","client_attempt_id":null,"received_at":"2026-10-14T21:00:01.123456Z","wire_body_digest":"` + strings.Repeat("a", 64) + `","outcome":"duplicate_returned"}],` +
		`"target_version":"t1"}`
	if got := strings.TrimSpace(w.Body.String()); got != want {
		t.Fatalf("receipt\n got %s\nwant %s", got, want)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("summary")) {
		t.Fatal("receipt carries body content")
	}
	if _, err := canonical.JCS(w.Body.Bytes()); err != nil {
		t.Fatalf("receipt is not JCS-able: %v", err)
	}
}

func TestReceiptUnknownKeyIsEmpty(t *testing.T) {
	r := withPeer(httptest.NewRequest(http.MethodGet, "/test/v1/receipts/"+keyA, nil), ReceiptReaderSAN)
	w := httptest.NewRecorder()
	newHandler(ModeNonIdempotent, &fakeStore{}).ServeHTTP(w, r)
	m := decodeMap(t, w)
	if w.Code != http.StatusOK || m["effect_count"] != float64(0) || len(m["effects"].([]any)) != 0 || len(m["receiver_attempts"].([]any)) != 0 {
		t.Fatalf("status %d body %v", w.Code, m)
	}
}

func TestReceiptBadIDAndStoreFailure(t *testing.T) {
	r := withPeer(httptest.NewRequest(http.MethodGet, "/test/v1/receipts/not-a-uuid", nil), ReceiptReaderSAN)
	w := httptest.NewRecorder()
	newHandler(ModeIdempotent, &fakeStore{}).ServeHTTP(w, r)
	if w.Code != http.StatusNotFound || reasons(t, decodeMap(t, w)) != ReasonResourceNotFound {
		t.Fatalf("status %d", w.Code)
	}
	r = withPeer(httptest.NewRequest(http.MethodGet, "/test/v1/receipts/"+keyA, nil), ReceiptReaderSAN)
	w = httptest.NewRecorder()
	newHandler(ModeIdempotent, &fakeStore{err: errors.New("down")}).ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "2" {
		t.Fatalf("status %d", w.Code)
	}
}

func TestParseMode(t *testing.T) {
	for _, s := range []string{"idempotent", "non_idempotent"} {
		if _, err := ParseMode(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{"", "Idempotent", "both"} {
		if _, err := ParseMode(s); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}
