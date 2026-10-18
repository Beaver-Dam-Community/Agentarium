package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/healthlease"
)

// The relay tests run three real TLS 1.3 servers on 127.0.0.1: fake
// workload-identity and control-health that require the gateway's client
// certificate (management mTLS), and the gateway front with
// VerifyClientCertIfGiven + RequireClientCert, exactly as cmd/gateway wires
// it. No PostgreSQL: Live and Auth are stubs.

const (
	relayRuntimeSAN = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/0f1e2d3c-4b5a-4968-8776-655443322110"
	probeRunnerSAN  = "spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner/pod/1f1e2d3c-4b5a-4968-8776-655443322110"
	controlSAN      = "spiffe://agentarium.internal/ns/agent-control/sa/coordinator"
	revokedSAN      = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/2f1e2d3c-4b5a-4968-8776-655443322110"
	relaySessionA   = "11111111-1111-4111-8111-111111111111"
	relaySessionB   = "22222222-2222-4222-8222-222222222222"
	relayBindingID  = "33333333-3333-4333-8333-333333333333"
	relayCheckID    = "44444444-4444-4444-8444-444444444444"
)

// runtimeRelaySeen is one request an upstream received.
type runtimeRelaySeen struct {
	method, path, query string
	peer                []string // X-Agentarium-Peer-Identity values
	auth                string
	peerSession         string
	peerSerial          string
	contentType         string
	body                []byte
	client              string // verified client SAN (the gateway's)
}

type fakeUpstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	reqs  []runtimeRelaySeen
	reply func(runtimeRelaySeen) (int, string, http.Header)
}

func (f *fakeUpstream) got() []runtimeRelaySeen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]runtimeRelaySeen(nil), f.reqs...)
}

func (p *pki) upstream(t *testing.T, san string) *fakeUpstream {
	t.Helper()
	f := &fakeUpstream{reply: func(runtimeRelaySeen) (int, string, http.Header) { return 200, `{"ok":true}`, nil }}
	leaf, key := p.root.issue(t, leafSpec{uris: []string{san}, eku: serviceEKU})
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s := runtimeRelaySeen{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, peer: r.Header.Values(PeerIdentityHeader),
			peerSession: r.Header.Get("X-Agentarium-Peer-Session"), peerSerial: r.Header.Get("X-Agentarium-Peer-Certificate-Serial"), auth: r.Header.Get("Authorization"), contentType: r.Header.Get("Content-Type"), body: body}
		if len(r.TLS.VerifiedChains) > 0 {
			s.client = r.TLS.VerifiedChains[0][0].URIs[0].String()
		}
		f.mu.Lock()
		f.reqs = append(f.reqs, s)
		f.mu.Unlock()
		status, out, h := f.reply(s)
		for k, v := range h {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, out)
	}))
	f.srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.roots,
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

type runtimeRelayEnv struct {
	p                *pki
	identity, health *fakeUpstream
	audit            *fakeUpstream
	gw               *httptest.Server
	relay            *Relay
}

func newRuntimeRelayEnv(t *testing.T) *runtimeRelayEnv {
	t.Helper()
	p := newPKI(t)
	e := &runtimeRelayEnv{p: p, identity: p.upstream(t, IdentitySAN), health: p.upstream(t, healthlease.ControlHealthSAN), audit: p.upstream(t, AuditWriterSAN)}
	ac, err := NewRelayClient(p.roots, AuditWriterSAN, p.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	idc, err := NewRelayClient(p.roots, IdentitySAN, p.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := NewRelayClient(p.roots, healthlease.ControlHealthSAN, p.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	e.relay = &Relay{
		IdentityURL: e.identity.srv.URL, Identity: idc,
		HealthURL: e.health.srv.URL, Health: hc,
		AuditURL: e.audit.srv.URL, Audit: ac,
		Live: func(_ context.Context, leaf *x509.Certificate) error {
			if leaf.URIs[0].String() == revokedSAN {
				return authRequired
			}
			return nil
		},
		Auth: func(_ context.Context, leaf *x509.Certificate, tok string) (Caller, error) {
			san := leaf.URIs[0].String()
			ns, ksa, _, _ := parseSAN(san)
			c := Caller{Kind: KindUser, SAN: san, Namespace: ns, KSA: ksa, WorkloadID: ns + "/" + ksa}
			switch tok {
			case "tok-a":
				c.SessionID, c.Tenant, c.AuthenticatedActor = relaySessionA, "tenant-a", "user:alice@example.com"
			case "tok-svc":
				c.Kind = KindService
				c.SessionID = relaySessionB
			default:
				return Caller{}, authRequired
			}
			return c, nil
		},
	}
	mux := http.NewServeMux()
	e.relay.Register(mux)
	(&Handler{Svc: &Service{}}).Register(mux)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	gwLeaf, gwKey := p.root.issue(t, leafSpec{uris: []string{gatewayTestSAN}, eku: serviceEKU})
	e.gw = httptest.NewUnstartedServer(http.MaxBytesHandler(RequireClientCert(mux), 2<<20))
	e.gw.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{gwLeaf.Raw}, PrivateKey: gwKey, Leaf: gwLeaf}},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    p.roots,
	}
	e.gw.StartTLS()
	t.Cleanup(e.gw.Close)
	return e
}

// client returns a runtime-side client presenting a certificate for san, or
// none when san is "". It verifies the gateway's service certificate.
func (e *runtimeRelayEnv) client(t *testing.T, san string) *http.Client {
	t.Helper()
	var cert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	if san != "" {
		leaf, key := e.p.root.issue(t, leafSpec{uris: []string{san}, eku: serviceEKU})
		c := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
		cert = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil }
	} else {
		cert = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	}
	cfg, err := ServiceClientTLS(e.p.roots, gatewayTestSAN, cert)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
}

type answer struct {
	status int
	body   []byte
	header http.Header
}

func (a answer) codes(t *testing.T) []string {
	t.Helper()
	var b struct {
		ReasonCodes []string `json:"reason_codes"`
	}
	if err := json.Unmarshal(a.body, &b); err != nil {
		t.Fatalf("error body %q: %v", a.body, err)
	}
	return b.ReasonCodes
}

func (e *runtimeRelayEnv) do(t *testing.T, c *http.Client, method, path, body string, h map[string]string) answer {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.gw.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return answer{status: res.StatusCode, body: out, header: res.Header}
}

const relaySpoof = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"

func TestRelayBootstrapWithoutClientCertificate(t *testing.T) {
	e := newRuntimeRelayEnv(t)
	e.identity.reply = func(runtimeRelaySeen) (int, string, http.Header) {
		return 200, `{"certificate":"PEM","certificate_chain":[],"serial":"01","expires_at":"2026-10-19T00:00:00Z"}`, nil
	}
	body := `{"csr":"-----BEGIN CERTIFICATE REQUEST-----","token":"projected"}`
	a := e.do(t, e.client(t, ""), "POST", BootstrapPath, body,
		map[string]string{PeerIdentityHeader: relaySpoof, "Authorization": "Bearer stolen"})
	if a.status != 200 || !strings.Contains(string(a.body), `"serial":"01"`) {
		t.Fatalf("bootstrap = %d %s", a.status, a.body)
	}
	got := e.identity.got()
	if len(got) != 1 {
		t.Fatalf("identity saw %d requests", len(got))
	}
	s := got[0]
	if s.method != "POST" || s.path != BootstrapPath || string(s.body) != body || s.contentType != "application/json" {
		t.Fatalf("forwarded %+v", s)
	}
	if len(s.peer) != 0 || s.auth != "" {
		t.Fatalf("bootstrap forwarded identity headers: peer=%v auth=%q", s.peer, s.auth)
	}
	if s.client != gatewayTestSAN {
		t.Fatalf("upstream client SAN %q", s.client)
	}
	// A client that presents a certificate may bootstrap too (renewal); the
	// header is still not sent.
	e.do(t, e.client(t, relayRuntimeSAN), "POST", BootstrapPath, body, map[string]string{PeerIdentityHeader: relaySpoof})
	if got := e.identity.got(); len(got) != 2 || len(got[1].peer) != 0 {
		t.Fatalf("bootstrap with certificate: %+v", got)
	}
}

func TestRelayClientCertificateRequiredElsewhere(t *testing.T) {
	e := newRuntimeRelayEnv(t)
	anon := e.client(t, "")
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/v1/runtime/assignments", ""},
		{"POST", "/v1/sessions/" + relaySessionA + ":claim", `{"claim_code":"x"}`},
		{"POST", "/v1/runtime/session-workers", `{}`},
		{"GET", "/v1/runtime/work-readiness/checks/" + relayCheckID, ""},
		{"POST", "/v1/runtime/probe-reports", `{}`},
		{"POST", "/v1/actions", `{}`},
		{"GET", "/healthz", ""},
		{"GET", BootstrapPath, ""},
		{"POST", BootstrapPath + "/", `{}`},
		{"POST", "/internal//workload-certificates", `{}`},
		{"POST", "/internal/workload%2Dcertificates", `{}`},
		{"POST", "/internal/./workload-certificates", `{}`},
	} {
		a := e.do(t, anon, c.method, c.path, c.body, nil)
		if a.status != 401 || a.codes(t)[0] != "AUTH_REQUIRED" {
			t.Errorf("%s %s without certificate = %d %s", c.method, c.path, a.status, a.body)
		}
	}
	if n := len(e.identity.got()) + len(e.health.got()); n != 0 {
		t.Fatalf("%d requests reached an upstream without a client certificate", n)
	}
}

func TestRelayIdentityPaths(t *testing.T) {
	e := newRuntimeRelayEnv(t)
	rt := e.client(t, relayRuntimeSAN)
	e.identity.reply = func(s runtimeRelaySeen) (int, string, http.Header) { return 200, `{"assignments":[]}`, nil }

	a := e.do(t, rt, "GET", "/v1/runtime/assignments", "", map[string]string{PeerIdentityHeader: relaySpoof, "Authorization": "Bearer x"})
	if a.status != 200 || string(a.body) != `{"assignments":[]}` {
		t.Fatalf("assignments = %d %s", a.status, a.body)
	}
	s := e.identity.got()[0]
	if s.method != "GET" || s.path != "/v1/runtime/assignments" || len(s.peer) != 1 || s.peer[0] != relayRuntimeSAN || s.auth != "" {
		t.Fatalf("assignments forwarded %+v", s)
	}

	claim := `{"claim_code":"abc"}`
	e.do(t, rt, "POST", "/v1/sessions/"+relaySessionA+":claim", claim, map[string]string{PeerIdentityHeader: relaySpoof, "Authorization": "Bearer x"})
	s = e.identity.got()[1]
	if s.path != "/v1/sessions/"+relaySessionA+":claim" || string(s.body) != claim || len(s.peer) != 1 || s.peer[0] != relayRuntimeSAN || s.auth != "" {
		t.Fatalf("claim forwarded %+v", s)
	}

	e.do(t, rt, "POST", "/v1/sessions/"+relaySessionA+":refresh", `{}`, map[string]string{"Authorization": "Bearer tok-a"})
	s = e.identity.got()[2]
	if s.path != "/v1/sessions/"+relaySessionA+":refresh" || s.auth != "Bearer tok-a" || s.peer[0] != relayRuntimeSAN {
		t.Fatalf("refresh forwarded %+v", s)
	}

	// Refused before any upstream call.
	before := len(e.identity.got())
	for _, c := range []struct {
		client       *http.Client
		method, path string
		body         string
		h            map[string]string
		status       int
		code         string
	}{
		{rt, "POST", "/v1/sessions/" + relaySessionA + ":refresh", `{}`, nil, 401, "AUTH_REQUIRED"},
		{rt, "POST", "/v1/sessions/" + relaySessionA + ":revoke", `{"reason":"x"}`, nil, 404, "RESOURCE_NOT_FOUND"},
		{rt, "POST", "/v1/sessions/not-a-uuid:claim", `{}`, nil, 422, "SCHEMA_INVALID"},
		{rt, "GET", "/v1/runtime/assignments?workload=x", "", nil, 422, "SCHEMA_INVALID"},
		{rt, "POST", "/v1/sessions/" + relaySessionA + ":claim", `x`, map[string]string{"Content-Type": "text/plain"}, 415, "SCHEMA_INVALID"},
		{rt, "POST", "/v1/sessions/" + relaySessionA + ":claim", `"` + strings.Repeat("a", maxIdentityRelayBody) + `"`, nil, 413, "BODY_TOO_LARGE"},
		{e.client(t, controlSAN), "GET", "/v1/runtime/assignments", "", nil, 401, "AUTH_REQUIRED"},
		{e.client(t, "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime"), "GET", "/v1/runtime/assignments", "", nil, 401, "AUTH_REQUIRED"},
		{e.client(t, revokedSAN), "GET", "/v1/runtime/assignments", "", nil, 401, "AUTH_REQUIRED"},
	} {
		a := e.do(t, c.client, c.method, c.path, c.body, c.h)
		if a.status != c.status || a.codes(t)[0] != c.code {
			t.Errorf("%s %s = %d %s, want %d %s", c.method, c.path, a.status, a.body, c.status, c.code)
		}
	}
	if n := len(e.identity.got()); n != before {
		t.Fatalf("refused requests reached identity: %d", n-before)
	}
}

func TestRelaySessionWorkersAndReadiness(t *testing.T) {
	e := newRuntimeRelayEnv(t)
	rt := e.client(t, relayRuntimeSAN)
	owner := relaySessionA
	e.health.reply = func(s runtimeRelaySeen) (int, string, http.Header) {
		if s.peerSession != relaySessionA {
			return 422, `{"reason_codes":["SCHEMA_INVALID"]}`, nil
		}
		switch {
		case s.method == "POST" && (s.path == internalWorkers || s.path == internalChecks):
			return 202, `{"session_id":"` + relaySessionA + `","state":"pending"}`, nil
		case s.method == "GET":
			return 200, `{"session_id":"` + owner + `","state":"observed","remaining_valid_ms":2500}`, nil
		case strings.HasSuffix(s.path, ":close"):
			return 200, `{"session_id":"` + relaySessionA + `","state":"closed"}`, nil
		}
		return 404, `{"request_id":"x","reason_codes":["RESOURCE_NOT_FOUND"]}`, nil
	}
	tokA := map[string]string{"Authorization": "Bearer tok-a", PeerIdentityHeader: relaySpoof, "X-Agentarium-Peer-Session": relaySessionB}

	reg := `{"worker_instance_id":"55555555-5555-4555-8555-555555555555","controls_report":{}}`
	a := e.do(t, rt, "POST", "/v1/runtime/session-workers", reg, tokA)
	if a.status != 202 {
		t.Fatalf("register = %d %s", a.status, a.body)
	}
	s := e.health.got()[0]
	var fwd map[string]json.RawMessage
	if err := json.Unmarshal(s.body, &fwd); err != nil {
		t.Fatal(err)
	}
	if s.path != internalWorkers || string(s.body) != reg || s.peerSession != relaySessionA || string(fwd["controls_report"]) != `{}` ||
		len(s.peer) != 1 || s.peer[0] != relayRuntimeSAN || s.auth != "" || s.client != gatewayTestSAN {
		t.Fatalf("register forwarded %+v %s", s, s.body)
	}

	chk := `{"work_run_id":"66666666-6666-4666-8666-666666666666","checkpoint":"start"}`
	if a := e.do(t, rt, "POST", "/v1/runtime/work-readiness/checks", chk, tokA); a.status != 202 {
		t.Fatalf("check = %d %s", a.status, a.body)
	}
	s = e.health.got()[1]
	if s.path != internalChecks || string(s.body) != chk || s.peerSession != relaySessionA || s.peer[0] != relayRuntimeSAN || s.auth != "" {
		t.Fatalf("check forwarded %+v %s", s, s.body)
	}

	if a := e.do(t, rt, "GET", "/v1/runtime/session-workers/"+relayBindingID, "", tokA); a.status != 200 || !strings.Contains(string(a.body), "observed") {
		t.Fatalf("get worker = %d %s", a.status, a.body)
	}
	if a := e.do(t, rt, "GET", "/v1/runtime/work-readiness/checks/"+relayCheckID, "", tokA); a.status != 200 || !strings.Contains(string(a.body), "remaining_valid_ms") {
		t.Fatalf("get check = %d %s", a.status, a.body)
	}
	if got := e.health.got(); got[2].path != internalWorkers+"/"+relayBindingID || got[3].path != internalChecks+"/"+relayCheckID || got[3].peer[0] != relayRuntimeSAN {
		t.Fatalf("GET forwarded %+v", got[2:])
	}

	closeBody := `{"reason":"done","evidence_refs":[]}`
	if a := e.do(t, rt, "POST", "/v1/runtime/session-workers/"+relayBindingID+":close", closeBody, tokA); a.status != 200 {
		t.Fatalf("close = %d %s", a.status, a.body)
	}
	got := e.health.got()
	if got[4].method != "GET" || got[5].path != internalWorkers+"/"+relayBindingID+":close" || string(got[5].body) != closeBody || got[5].peer[0] != relayRuntimeSAN {
		t.Fatalf("close forwarded %+v", got[4:])
	}

	// Another session's resources: 403, and close never reaches control-health.
	owner = relaySessionB
	n := len(e.health.got())
	if a := e.do(t, rt, "GET", "/v1/runtime/session-workers/"+relayBindingID, "", tokA); a.status != 403 || a.codes(t)[0] != "SESSION_BINDING_INVALID" {
		t.Errorf("other session worker = %d %s", a.status, a.body)
	}
	if a := e.do(t, rt, "GET", "/v1/runtime/work-readiness/checks/"+relayCheckID, "", tokA); a.status != 403 || a.codes(t)[0] != "WORK_READINESS_BINDING_MISMATCH" {
		t.Errorf("other session check = %d %s", a.status, a.body)
	}
	if a := e.do(t, rt, "POST", "/v1/runtime/session-workers/"+relayBindingID+":close", closeBody, tokA); a.status != 403 {
		t.Errorf("other session close = %d %s", a.status, a.body)
	}
	for _, s := range e.health.got()[n:] {
		if s.method != "GET" {
			t.Fatalf("close of another session's binding was relayed: %+v", s)
		}
	}

	// Refused before any upstream call.
	n = len(e.health.got())
	for _, c := range []struct {
		client       *http.Client
		method, path string
		body         string
		h            map[string]string
		status       int
		code         string
	}{
		{rt, "POST", "/v1/runtime/session-workers", reg, nil, 401, "AUTH_REQUIRED"},
		{rt, "POST", "/v1/runtime/session-workers", reg, map[string]string{"Authorization": "Bearer nope"}, 401, "AUTH_REQUIRED"},
		{rt, "POST", "/v1/runtime/session-workers", reg, map[string]string{"Authorization": "Bearer tok-svc"}, 401, "AUTH_REQUIRED"},
		{rt, "POST", "/v1/runtime/session-workers", `{"session_id":"` + relaySessionB + `"}`, tokA, 422, "SCHEMA_INVALID"},
		{rt, "POST", "/v1/runtime/work-readiness/checks", `{"a":1,"a":2}`, tokA, 422, "SCHEMA_INVALID"},
		{rt, "POST", "/v1/runtime/work-readiness/checks", `[]`, tokA, 422, "SCHEMA_INVALID"},
		{rt, "GET", "/v1/runtime/work-readiness/checks/not-a-uuid", "", tokA, 422, "SCHEMA_INVALID"},
		{rt, "POST", "/v1/runtime/session-workers/" + relayBindingID + ":open", `{}`, tokA, 404, "RESOURCE_NOT_FOUND"},
		{e.client(t, controlSAN), "POST", "/v1/runtime/work-readiness/checks", chk, tokA, 401, "AUTH_REQUIRED"},
	} {
		a := e.do(t, c.client, c.method, c.path, c.body, c.h)
		if a.status != c.status || a.codes(t)[0] != c.code {
			t.Errorf("%s %s = %d %s, want %d %s", c.method, c.path, a.status, a.body, c.status, c.code)
		}
	}
	if m := len(e.health.got()); m != n {
		t.Fatalf("refused requests reached control-health: %d", m-n)
	}
}

func TestRelayProbeReports(t *testing.T) {
	e := newRuntimeRelayEnv(t)
	body := `{"probe_kind":"export"}`
	client := e.client(t, probeRunnerSAN)
	cert, err := client.Transport.(*http.Transport).TLSClientConfig.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	wantSerial := hex.EncodeToString(cert.Leaf.SerialNumber.Bytes())
	a := e.do(t, client, "POST", "/v1/runtime/probe-reports", body, map[string]string{PeerIdentityHeader: relaySpoof, "X-Agentarium-Peer-Certificate-Serial": "spoof"})
	if a.status != 200 {
		t.Fatalf("probe report = %d %s", a.status, a.body)
	}
	s := e.health.got()[0]
	if s.path != "/internal/control-health/probe-results" || string(s.body) != body || len(s.peer) != 1 || s.peer[0] != probeRunnerSAN || s.peerSerial != wantSerial {
		t.Fatalf("probe report forwarded %+v", s)
	}
	if a := e.do(t, e.client(t, relayRuntimeSAN), "POST", "/v1/runtime/probe-reports", body, nil); a.status != 401 {
		t.Fatalf("runtime probe report = %d %s", a.status, a.body)
	}
	if len(e.health.got()) != 1 {
		t.Fatal("runtime probe report reached control-health")
	}
}

func TestRelayUpstreamErrors(t *testing.T) {
	e := newRuntimeRelayEnv(t)
	rt := e.client(t, relayRuntimeSAN)
	tokA := map[string]string{"Authorization": "Bearer tok-a"}
	chk := `{"work_run_id":"66666666-6666-4666-8666-666666666666"}`

	// Upstream COMMON envelopes pass through, with Retry-After on 503.
	for _, c := range []struct {
		status int
		body   string
		retry  string
	}{
		{503, `{"request_id":"r","reason_codes":["CONTROL_HEALTH_UNAVAILABLE"]}`, "2"},
		{409, `{"request_id":"r","reason_codes":["WORKER_REGISTRATION_CONFLICT"]}`, ""},
		{403, `{"request_id":"r","reason_codes":["SESSION_BINDING_INVALID"]}`, ""},
		{404, `{"request_id":"r","reason_codes":["RESOURCE_NOT_FOUND"]}`, ""},
		{422, `{"request_id":"r","reason_codes":["SCHEMA_INVALID"]}`, ""},
	} {
		e.health.reply = func(runtimeRelaySeen) (int, string, http.Header) { return c.status, c.body, nil }
		a := e.do(t, rt, "POST", "/v1/runtime/work-readiness/checks", chk, tokA)
		if a.status != c.status || string(a.body) != c.body || a.header.Get("Retry-After") != c.retry {
			t.Errorf("upstream %d = %d %s retry %q", c.status, a.status, a.body, a.header.Get("Retry-After"))
		}
	}
	// The GET of another session's 404 is not rewritten.
	e.health.reply = func(runtimeRelaySeen) (int, string, http.Header) {
		return 404, `{"request_id":"r","reason_codes":["RESOURCE_NOT_FOUND"]}`, nil
	}
	if a := e.do(t, rt, "GET", "/v1/runtime/work-readiness/checks/"+relayCheckID, "", tokA); a.status != 404 {
		t.Errorf("GET 404 = %d", a.status)
	}
	// control-health 401 refuses the gateway's connection: a relay failure.
	e.health.reply = func(runtimeRelaySeen) (int, string, http.Header) {
		return 401, `{"request_id":"r","reason_codes":["AUTH_REQUIRED"]}`, nil
	}
	if a := e.do(t, rt, "POST", "/v1/runtime/work-readiness/checks", chk, tokA); a.status != 503 || a.codes(t)[0] != "CONTROL_HEALTH_UNAVAILABLE" || a.header.Get("Retry-After") != "2" {
		t.Errorf("health 401 = %d %s", a.status, a.body)
	}
	// identity 401 concerns the relayed principal and passes through.
	e.identity.reply = func(runtimeRelaySeen) (int, string, http.Header) {
		return 401, `{"request_id":"r","reason_codes":["AUTH_REQUIRED"]}`, nil
	}
	if a := e.do(t, rt, "GET", "/v1/runtime/assignments", "", nil); a.status != 401 {
		t.Errorf("identity 401 = %d", a.status)
	}
	// A non-JSON 5xx is a relay failure.
	e.identity.reply = func(runtimeRelaySeen) (int, string, http.Header) { return 502, `bad gateway`, nil }
	if a := e.do(t, rt, "GET", "/v1/runtime/assignments", "", nil); a.status != 503 || a.codes(t)[0] != "STATE_STORE_UNAVAILABLE" {
		t.Errorf("identity 502 = %d %s", a.status, a.body)
	}
	// A GET 200 that is not JSON is not passed on.
	e.health.reply = func(runtimeRelaySeen) (int, string, http.Header) { return 200, `nope`, nil }
	if a := e.do(t, rt, "GET", "/v1/runtime/work-readiness/checks/"+relayCheckID, "", tokA); a.status != 503 || a.codes(t)[0] != "CONTROL_HEALTH_UNAVAILABLE" {
		t.Errorf("GET invalid = %d %s", a.status, a.body)
	}

	// Unreachable upstreams.
	e.identity.srv.Close()
	e.health.srv.Close()
	if a := e.do(t, rt, "GET", "/v1/runtime/assignments", "", nil); a.status != 503 || a.codes(t)[0] != "STATE_STORE_UNAVAILABLE" || a.header.Get("Retry-After") != "2" {
		t.Errorf("identity down = %d %s", a.status, a.body)
	}
	if a := e.do(t, e.client(t, ""), "POST", BootstrapPath, `{}`, nil); a.status != 503 {
		t.Errorf("bootstrap identity down = %d %s", a.status, a.body)
	}
	if a := e.do(t, rt, "POST", "/v1/runtime/work-readiness/checks", chk, tokA); a.status != 503 || a.codes(t)[0] != "CONTROL_HEALTH_UNAVAILABLE" {
		t.Errorf("health down = %d %s", a.status, a.body)
	}
}

// The relay client accepts only the expected upstream SAN: an upstream
// presenting another service's certificate gets nothing.
func TestRelayUpstreamIdentityPinned(t *testing.T) {
	e := newRuntimeRelayEnv(t)
	impostor := e.p.upstream(t, "spiffe://agentarium.internal/ns/agent-control/sa/coordinator")
	e.relay.IdentityURL = impostor.srv.URL
	a := e.do(t, e.client(t, ""), "POST", BootstrapPath, `{"csr":"x","token":"secret"}`, nil)
	if a.status != 503 || a.codes(t)[0] != "STATE_STORE_UNAVAILABLE" {
		t.Fatalf("impostor identity = %d %s", a.status, a.body)
	}
	if len(impostor.got()) != 0 {
		t.Fatal("the bootstrap token reached a server with the wrong SAN")
	}
}

func TestSessionBody(t *testing.T) {
	out, err := sessionBody([]byte(`{"b":1,"a":{"x":[1,2]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"b":1,"a":{"x":[1,2]}}` {
		t.Fatalf("withSession = %s", out)
	}
	for _, in := range []string{`{"session_id":null}`, `{"Session_ID":"x"}`, `null`, `[]`, `1`, `{"a":1,"a":1}`, `{} {}`, `{"a":1}x`} {
		if _, err := sessionBody([]byte(in)); err == nil {
			t.Errorf("withSession(%s) accepted", in)
		}
	}
}
