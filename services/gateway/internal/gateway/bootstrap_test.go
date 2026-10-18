package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The bootstrap relay runs on real TLS: a fake identity service that requires
// the gateway client certificate, and a gateway listener with
// VerifyClientCertIfGiven behind RequireClientCert, as cmd/gateway wires it.

// seen is what the fake identity service received.
type seen struct {
	mu      sync.Mutex
	hits    int
	header  http.Header
	body    []byte
	path    string
	query   string
	host    string
	peerSAN string
}

func (s *seen) get() seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return seen{hits: s.hits, header: s.header, body: s.body, path: s.path, query: s.query, host: s.host, peerSAN: s.peerSAN}
}

type relayEnv struct {
	p        *pki
	identity *httptest.Server
	seen     *seen
	reply    http.HandlerFunc
	gateway  *httptest.Server
	relay    *BootstrapRelay
	// caller is a workload client certificate the gateway trusts.
	caller tls.Certificate
}

const runtimeTestSAN = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime"

func newRelayEnv(t *testing.T, identitySAN string) *relayEnv {
	t.Helper()
	e := &relayEnv{p: newPKI(t), seen: &seen{}}
	e.reply = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"certificate":"c","certificate_chain":[],"serial":"01","expires_at":"2026-10-19T00:00:00Z"}`)
	}
	leaf, key := e.p.root.issue(t, leafSpec{uris: []string{identitySAN}, eku: serviceEKU})
	e.identity = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.seen.mu.Lock()
		e.seen.hits++
		e.seen.header, e.seen.body, e.seen.path, e.seen.query, e.seen.host = r.Header.Clone(), b, r.URL.Path, r.URL.RawQuery, r.Host
		if verifiedPeer(r) {
			e.seen.peerSAN = r.TLS.VerifiedChains[0][0].URIs[0].String()
		}
		e.seen.mu.Unlock()
		e.reply(w, r)
	}))
	e.identity.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    e.p.roots,
	}
	e.identity.StartTLS()
	t.Cleanup(e.identity.Close)

	client, err := NewIdentityClient(e.p.roots, IdentitySAN, e.p.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	e.relay = &BootstrapRelay{IdentityURL: e.identity.URL, Client: client}
	mux := http.NewServeMux()
	mux.Handle(BootstrapPath, e.relay)
	mux.HandleFunc("POST /v1/actions", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	gwLeaf, gwKey := e.p.root.issue(t, leafSpec{uris: []string{gatewayTestSAN}, eku: serviceEKU})
	e.gateway = httptest.NewUnstartedServer(http.MaxBytesHandler(RequireClientCert(mux), 2<<20))
	e.gateway.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{gwLeaf.Raw}, PrivateKey: gwKey, Leaf: gwLeaf}},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    e.p.roots,
	}
	e.gateway.StartTLS()
	t.Cleanup(e.gateway.Close)

	c, k := e.p.root.issue(t, leafSpec{uris: []string{runtimeTestSAN}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	e.caller = tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: k, Leaf: c}
	return e
}

// call sends one request to the gateway, with the caller certificate when
// withCert is set. The gateway server certificate is trusted through roots;
// host name checks do not apply to these URI-SAN-only certificates.
func (e *relayEnv) call(t *testing.T, method, path string, header http.Header, body []byte, withCert bool) (*http.Response, []byte) {
	t.Helper()
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	if withCert {
		cfg.Certificates = []tls.Certificate{e.caller}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
	req, err := http.NewRequest(method, e.gateway.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, b
}

func jsonHeader(extra ...string) http.Header {
	h := http.Header{"Content-Type": {"application/json"}}
	for i := 0; i+1 < len(extra); i += 2 {
		h.Add(extra[i], extra[i+1])
	}
	return h
}

func reasonCodes(t *testing.T, b []byte) []string {
	t.Helper()
	var e struct {
		RequestID   string   `json:"request_id"`
		ReasonCodes []string `json:"reason_codes"`
	}
	if err := json.Unmarshal(b, &e); err != nil || e.RequestID == "" {
		t.Fatalf("error body %q: %v", b, err)
	}
	return e.ReasonCodes
}

func TestBootstrapRelayForwardsBodyOnly(t *testing.T) {
	e := newRelayEnv(t, IdentitySAN)
	body := []byte(`{"csr":"-----BEGIN CERTIFICATE REQUEST-----\nx\n-----END CERTIFICATE REQUEST-----\n","token":"t"}`)
	forged := jsonHeader(
		"X-Agentarium-Peer-Identity", "spiffe://agentarium.internal/ns/agent-control/sa/coordinator",
		"Authorization", "Bearer stolen",
		"Forwarded", "for=10.0.0.1",
		"X-Forwarded-For", "10.0.0.1",
		"X-Forwarded-Host", "evil",
		"Cookie", "a=b",
		"X-Agentarium-Console-Actor", "user:x",
	)
	for _, withCert := range []bool{false, true} {
		res, out := e.call(t, http.MethodPost, BootstrapPath+"?x=1", forged, body, withCert)
		if res.StatusCode != http.StatusOK || !strings.Contains(string(out), `"serial":"01"`) {
			t.Fatalf("withCert=%v: %d %s", withCert, res.StatusCode, out)
		}
		if ct := res.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content type %q", ct)
		}
		got := e.seen.get()
		if !bytes.Equal(got.body, body) {
			t.Errorf("withCert=%v: body %q, want byte for byte %q", withCert, got.body, body)
		}
		if got.path != BootstrapPath || got.query != "" {
			t.Errorf("forwarded to %q?%q", got.path, got.query)
		}
		if got.host != strings.TrimPrefix(e.identity.URL, "https://") {
			t.Errorf("host %q", got.host)
		}
		// Only the relay's own Content-Type and the headers Go's transport
		// adds itself reach the identity service.
		for k := range got.header {
			switch k {
			case "Content-Type", "Content-Length", "Accept-Encoding", "User-Agent", "Connection":
			default:
				t.Errorf("withCert=%v: forwarded header %s=%q", withCert, k, got.header[k])
			}
		}
		if got.header.Get("Content-Type") != "application/json" {
			t.Errorf("upstream content type %q", got.header.Get("Content-Type"))
		}
		if got.peerSAN != gatewayTestSAN {
			t.Errorf("identity saw client %q, want the gateway certificate", got.peerSAN)
		}
	}
}

func TestRequireClientCert(t *testing.T) {
	e := newRelayEnv(t, IdentitySAN)
	for _, path := range []string{"/v1/actions", "/healthz", "/readyz", "/unknown", BootstrapPath + "/", "/internal/workload-certificates/x", "//internal/workload-certificates"} {
		res, out := e.call(t, http.MethodPost, path, jsonHeader(), []byte(`{}`), false)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without certificate: %d %s", path, res.StatusCode, out)
			continue
		}
		if c := reasonCodes(t, out); len(c) != 1 || c[0] != "AUTH_REQUIRED" {
			t.Errorf("%s: codes %v", path, c)
		}
	}
	if res, _ := e.call(t, http.MethodPost, "/v1/actions", jsonHeader(), []byte(`{}`), true); res.StatusCode != http.StatusAccepted {
		t.Errorf("/v1/actions with certificate: %d", res.StatusCode)
	}
	if res, _ := e.call(t, http.MethodGet, "/healthz", nil, nil, true); res.StatusCode != http.StatusNoContent {
		t.Errorf("/healthz with certificate: %d", res.StatusCode)
	}
	if got := e.seen.get(); got.hits != 0 {
		t.Errorf("identity reached %d times", got.hits)
	}
}

func TestBootstrapRelayGatewayClientCertificateMustVerify(t *testing.T) {
	e := newRelayEnv(t, IdentitySAN)
	other := newPKI(t)
	c, k := other.root.issue(t, leafSpec{uris: []string{runtimeTestSAN}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	e.caller = tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: k, Leaf: c}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, Certificates: []tls.Certificate{e.caller}}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
	req, _ := http.NewRequest(http.MethodPost, e.gateway.URL+BootstrapPath, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if res, err := client.Do(req); err == nil {
		res.Body.Close()
		t.Fatalf("untrusted client certificate accepted: %d", res.StatusCode)
	}
	if got := e.seen.get(); got.hits != 0 {
		t.Errorf("identity reached %d times", got.hits)
	}
}

func TestBootstrapRelayRejectsBeforeForwarding(t *testing.T) {
	e := newRelayEnv(t, IdentitySAN)
	for name, c := range map[string]struct {
		method string
		header http.Header
		body   []byte
		status int
		codes  []string
	}{
		"get":        {http.MethodGet, jsonHeader(), nil, http.StatusUnauthorized, []string{"AUTH_REQUIRED"}},
		"put":        {http.MethodPut, jsonHeader(), []byte(`{}`), http.StatusUnauthorized, []string{"AUTH_REQUIRED"}},
		"no type":    {http.MethodPost, nil, []byte(`{}`), http.StatusUnsupportedMediaType, []string{"SCHEMA_INVALID"}},
		"text":       {http.MethodPost, http.Header{"Content-Type": {"text/plain"}}, []byte(`{}`), http.StatusUnsupportedMediaType, []string{"SCHEMA_INVALID"}},
		"64 KiB + 1": {http.MethodPost, jsonHeader(), bytes.Repeat([]byte("a"), MaxBootstrapBody+1), http.StatusRequestEntityTooLarge, []string{"BODY_TOO_LARGE"}},
	} {
		res, out := e.call(t, c.method, BootstrapPath, c.header, c.body, false)
		if res.StatusCode != c.status {
			t.Errorf("%s: %d %s, want %d", name, res.StatusCode, out, c.status)
			continue
		}
		if got := reasonCodes(t, out); strings.Join(got, ",") != strings.Join(c.codes, ",") {
			t.Errorf("%s: codes %v, want %v", name, got, c.codes)
		}
	}
	if got := e.seen.get(); got.hits != 0 {
		t.Errorf("identity reached %d times", got.hits)
	}
	// Exactly 64 KiB is forwarded unchanged.
	body := bytes.Repeat([]byte("a"), MaxBootstrapBody)
	if res, out := e.call(t, http.MethodPost, BootstrapPath, jsonHeader(), body, false); res.StatusCode != http.StatusOK {
		t.Fatalf("64 KiB: %d %s", res.StatusCode, out)
	}
	if got := e.seen.get(); !bytes.Equal(got.body, body) {
		t.Errorf("64 KiB body changed: %d bytes", len(got.body))
	}
}

func TestBootstrapRelayPassesIdentityAnswer(t *testing.T) {
	e := newRelayEnv(t, IdentitySAN)
	for _, c := range []struct {
		status     int
		retryAfter string
		body       string
	}{
		{http.StatusUnauthorized, "", `{"request_id":"r","reason_codes":["AUTH_REQUIRED"]}`},
		{http.StatusUnprocessableEntity, "", `{"request_id":"r","reason_codes":["SCHEMA_INVALID"]}`},
		{http.StatusServiceUnavailable, "2", `{"request_id":"r","reason_codes":["CREDENTIAL_UNAVAILABLE"]}`},
		{http.StatusServiceUnavailable, "7", `{"request_id":"r","reason_codes":["STATE_STORE_UNAVAILABLE"]}`},
		{http.StatusFound, "", `{}`},
	} {
		e.reply = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Set-Cookie", "s=1")
			w.Header().Set("Location", "https://elsewhere/")
			w.Header().Set("X-Upstream", "1")
			if c.retryAfter != "" {
				w.Header().Set("Retry-After", c.retryAfter)
			}
			w.WriteHeader(c.status)
			_, _ = io.WriteString(w, c.body)
		}
		res, out := e.call(t, http.MethodPost, BootstrapPath, jsonHeader(), []byte(`{}`), false)
		if res.StatusCode != c.status || string(out) != c.body {
			t.Errorf("got %d %s, want %d %s", res.StatusCode, out, c.status, c.body)
		}
		if res.Header.Get("Retry-After") != c.retryAfter || res.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%d: headers %v", c.status, res.Header)
		}
		for _, h := range []string{"Set-Cookie", "Location", "X-Upstream"} {
			if v := res.Header.Get(h); v != "" {
				t.Errorf("%d: passed %s=%q", c.status, h, v)
			}
		}
	}
	// The relay did not follow the 302.
	if got := e.seen.get(); got.hits != 5 {
		t.Errorf("identity reached %d times, want 5", got.hits)
	}
}

func expectUnavailable(t *testing.T, name string, res *http.Response, out []byte) {
	t.Helper()
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") != "2" {
		t.Errorf("%s: %d Retry-After %q %s", name, res.StatusCode, res.Header.Get("Retry-After"), out)
		return
	}
	if c := reasonCodes(t, out); len(c) != 1 || c[0] != "STATE_STORE_UNAVAILABLE" {
		t.Errorf("%s: codes %v", name, c)
	}
}

func TestBootstrapRelayIdentityResponseLimit(t *testing.T) {
	e := newRelayEnv(t, IdentitySAN)
	for _, n := range []int{MaxBootstrapBody, MaxBootstrapBody + 1} {
		e.reply = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(bytes.Repeat([]byte("a"), n))
		}
		res, out := e.call(t, http.MethodPost, BootstrapPath, jsonHeader(), []byte(`{}`), false)
		if n == MaxBootstrapBody {
			if res.StatusCode != http.StatusOK || len(out) != n {
				t.Errorf("%d bytes: %d, %d bytes", n, res.StatusCode, len(out))
			}
			continue
		}
		expectUnavailable(t, strconv.Itoa(n)+" bytes", res, out)
	}
}

func TestBootstrapRelayBrokenIdentityResponse(t *testing.T) {
	e := newRelayEnv(t, IdentitySAN)
	e.reply = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"certificate":`)
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	res, out := e.call(t, http.MethodPost, BootstrapPath, jsonHeader(), []byte(`{}`), false)
	expectUnavailable(t, "partial", res, out)
	if strings.Contains(string(out), "certificate") {
		t.Errorf("partial identity response exposed: %s", out)
	}
}

func TestBootstrapRelayTimeout(t *testing.T) {
	e := newRelayEnv(t, IdentitySAN)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	canceled := make(chan struct{}, 1)
	e.reply = func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			canceled <- struct{}{}
		case <-done:
		}
	}
	e.relay.Client.Timeout = 200 * time.Millisecond
	start := time.Now()
	res, out := e.call(t, http.MethodPost, BootstrapPath, jsonHeader(), []byte(`{}`), false)
	expectUnavailable(t, "timeout", res, out)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("relay answered after %v", d)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Error("identity request was not canceled")
	}
}

func TestBootstrapRelayIdentityPeer(t *testing.T) {
	// The identity origin presents another service's certificate.
	e := newRelayEnv(t, "spiffe://agentarium.internal/ns/agent-control/sa/coordinator")
	res, out := e.call(t, http.MethodPost, BootstrapPath, jsonHeader(), []byte(`{}`), false)
	expectUnavailable(t, "wrong SAN", res, out)
	if got := e.seen.get(); got.hits != 0 {
		t.Errorf("identity handler reached %d times", got.hits)
	}
	// Nothing listens there.
	e = newRelayEnv(t, IdentitySAN)
	e.relay.IdentityURL = "https://127.0.0.1:1"
	res, out = e.call(t, http.MethodPost, BootstrapPath, jsonHeader(), []byte(`{}`), false)
	expectUnavailable(t, "refused", res, out)
}

func TestNewIdentityClientNeedsTrustAndSAN(t *testing.T) {
	p := newPKI(t)
	if _, err := NewIdentityClient(nil, IdentitySAN, p.clientCert); err == nil {
		t.Error("nil roots accepted")
	}
	if _, err := NewIdentityClient(p.roots, "", p.clientCert); err == nil {
		t.Error("empty SAN accepted")
	}
}
