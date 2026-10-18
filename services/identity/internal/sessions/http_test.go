package sessions

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func withPeer(r *http.Request, san string) *http.Request {
	u, _ := url.Parse(san)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
	return r
}

const gw = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"

func TestRuntimePrincipal(t *testing.T) {
	h := &Handler{GatewaySAN: gw}
	pod := "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/1b2c"
	cases := []struct {
		name   string
		peer   string
		header string
		want   string
	}{
		{"direct", pod, "", pod},
		{"gateway relays", gw, pod, pod},
		{"header from non-gateway ignored", pod, "spiffe://agentarium.internal/ns/agent-exec/sa/other/pod/x", pod},
		{"gateway without header", gw, "", ""},
		{"no client cert", "", "", ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/v1/runtime/assignments", nil)
		if c.peer != "" {
			r = withPeer(r, c.peer)
		}
		if c.header != "" {
			r.Header.Set(PeerIdentityHeader, c.header)
		}
		w := httptest.NewRecorder()
		p, ok := h.runtime(w, r)
		if c.want == "" {
			if ok || w.Code != http.StatusUnauthorized {
				t.Errorf("%s: accepted %+v", c.name, p)
			}
			continue
		}
		if !ok || p.SAN != c.want {
			t.Errorf("%s: got %+v ok=%v", c.name, p, ok)
		}
	}
}

func TestParseSAN(t *testing.T) {
	good := map[string][2]string{
		"spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/u1": {"agent-exec", "agent-runtime"},
		"spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway":    {"agent-control", "policy-gateway"},
	}
	for san, want := range good {
		p, err := ParseSAN(san)
		if err != nil || p.Namespace != want[0] || p.KSA != want[1] {
			t.Errorf("%s: %+v %v", san, p, err)
		}
	}
	for _, bad := range []string{
		"", "spiffe://other/ns/a/sa/b", "spiffe://agentarium.internal/ns/a/b/c",
		"spiffe://agentarium.internal/ns//sa/b", "spiffe://agentarium.internal/ns/a/sa/b/pod/",
		"spiffe://agentarium.internal/node-bridge/n/b", "spiffe://agentarium.internal/ns/a/sa/b/x/y",
	} {
		if _, err := ParseSAN(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestConsoleRoutesFailClosed(t *testing.T) {
	mux := http.NewServeMux()
	(&Handler{Svc: &Service{}}).Register(mux)
	for _, path := range []string{"/v1/sessions", "/v1/sessions/0d8c0c5e-3e6b-4b1a-9f1c-000000000000:revoke"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Agentarium-Console-Actor", "google:alice")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s without ConsoleAuth: %d", path, w.Code)
		}
	}
}

func TestStrictJSON(t *testing.T) {
	var req CreateRequest
	if err := strictInto([]byte(`{"workload_id":"a/b","task_statement":"x","requested_scope":{"operation_ids":["o"],"target_ids":["t"]}}`), &req); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown key":    `{"workload_id":"a/b","extra":1}`,
		"case variant":   `{"Workload_ID":"a/b"}`,
		"duplicate key":  `{"workload_id":"a/b","workload_id":"c/d"}`,
		"trailing data":  `{"workload_id":"a/b"} {}`,
		"nested unknown": `{"requested_scope":{"operation_ids":[],"target_ids":[],"x":1}}`,
	} {
		var r CreateRequest
		if err := strictInto([]byte(body), &r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
