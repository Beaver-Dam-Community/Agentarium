package ingest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	return sign(t, map[string]any{
		"event_id": "5a6c71f8-765a-43b0-8065-f378cd1f65c5", "event_type": "approval_revoked", "tenant": "tenant-a", "source_id": "source-a", "source_version": "v1", "source_epoch": "epoch-1", "source_time": "2026-10-15T00:00:00Z", "schema_version": 1, "evidence_refs": []any{}, "safe_payload": map[string]any{"approval_id": "a", "revoke_reason": "user"},
	})
}
func sign(t *testing.T, v map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonical.PayloadDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	v["payload_digest"] = digest
	raw, err = json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestStrictBoundary(t *testing.T) {
	raw := fixture(t)
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"duplicate":      bytes.Replace(raw, []byte(`"tenant":"tenant-a"`), []byte(`"tenant":"tenant-a","tenant":"tenant-a"`), 1),
		"case_duplicate": bytes.Replace(raw, []byte(`"tenant":"tenant-a"`), []byte(`"tenant":"tenant-a","Tenant":"tenant-a"`), 1),
		"case_alias":     bytes.Replace(raw, []byte(`"tenant"`), []byte(`"Tenant"`), 1),
		"server_time":    bytes.Replace(raw, []byte(`"tenant"`), []byte(`"received_at":null,"tenant"`), 1),
		"fraction":       bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1.0`), 1),
		"exponent":       bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1e0`), 1),
		"unsafe_number":  bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"source_sequence":9007199254740992,"schema_version":1`), 1),
		"trailing":       append(bytes.Clone(raw), []byte(` {}`)...),
		"digest":         bytes.Replace(raw, []byte(`"source-a"`), []byte(`"source-b"`), 1),
		"invalid_utf8":   []byte("{\"x\":\"\xff\"}"),
		"surrogate":      []byte(`{"x":"\ud800"}`),
		"deep":           []byte(strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17)),
		"null":           []byte(`null`),
		"long_string":    []byte(`{"x":"` + strings.Repeat("a", 16385) + `"}`),
		"long_array":     []byte(`{"x":[` + strings.Repeat("0,", 1000) + `0]}`),
	}
	var keys []string
	for i := 0; i < 257; i++ {
		keys = append(keys, fmt.Sprintf(`"k%d":0`, i))
	}
	cases["many_keys"] = []byte("{" + strings.Join(keys, ",") + "}")
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(raw); err == nil {
				t.Fatal("accepted invalid event")
			}
		})
	}
	for name, value := range map[string]any{"bad_uuid": "x", "bad_time": "infinity", "bad_version": "v1", "bad_sequence": 0} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			key := map[string]string{"bad_uuid": "event_id", "bad_time": "source_time", "bad_version": "schema_version", "bad_sequence": "source_sequence"}[name]
			m[key] = value
			if _, err := Decode(sign(t, m)); err == nil {
				t.Fatal("accepted invalid field")
			}
		})
	}
}

type fakeStore struct {
	calls  int
	result string
	err    error
}

func (s *fakeStore) Append(_ context.Context, e Event, _ []byte) (Ack, error) {
	s.calls++
	return Ack{EventID: e.EventID, Result: s.result, ReceivedAt: time.Now()}, s.err
}

type fakeAuth struct{ err error }

func (a fakeAuth) Authorize(context.Context, string, string) error { return a.err }
func TestHTTPBoundary(t *testing.T) {
	san, _ := url.Parse("spiffe://agentarium.internal/ns/agent-control/sa/coordinator")
	for _, tt := range []struct {
		name, result      string
		authErr, storeErr error
		tls               bool
		want              int
	}{
		{"created", "created", nil, nil, true, 201}, {"duplicate", "duplicate", nil, nil, true, 200}, {"conflict", "conflict", nil, nil, true, 409},
		{"no_tls", "created", nil, nil, false, 401}, {"wrong_source", "created", ErrForbidden, nil, true, 403}, {"bad_grant", "created", nil, ErrForbidden, true, 403}, {"bad_registry", "created", nil, ErrSchema, true, 422}, {"db_unavailable", "", nil, context.DeadlineExceeded, true, 503},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := &fakeStore{result: tt.result, err: tt.storeErr}
			h := Handler{s, fakeAuth{tt.authErr}}
			r := httptest.NewRequest("POST", "/internal/audit/events", bytes.NewReader(fixture(t)))
			r.Header.Set("X-Agentarium-Peer-Identity", san.String())
			if tt.tls {
				r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{san}}}}}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if (!tt.tls || tt.authErr != nil) && s.calls != 0 {
				t.Fatal("unauthenticated write")
			}
			if tt.want == 503 && w.Header().Get("Retry-After") != "2" {
				t.Fatal("no retry hint")
			}
		})
	}
}
func TestServiceSAN(t *testing.T) {
	for _, s := range []string{"spiffe://agentarium.internal/ns/agent-control/sa/coordinator?x=1", "spiffe://evil/ns/agent-control/sa/coordinator", "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime", "spiffe://agentarium.internal/node-bridge/n/b"} {
		u, _ := url.Parse(s)
		if _, err := ServiceSAN(&x509.Certificate{URIs: []*url.URL{u}}); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
