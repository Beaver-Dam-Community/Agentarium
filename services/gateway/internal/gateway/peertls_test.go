package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real TLS servers (httptest) with generated certificates check the execute
// client against TASK-03 style service certificates: one URI SAN and no
// DNS/IP SAN, served on 127.0.0.1.

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var testSerial atomic.Int64

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mkCA(t *testing.T, name string, parent *testCA) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(testSerial.Add(1)), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: key}
}

type leafSpec struct {
	uris      []string
	dns       []string
	ips       []net.IP
	emails    []string
	eku       []x509.ExtKeyUsage
	notBefore time.Time
	notAfter  time.Time
}

func (ca *testCA) issue(t *testing.T, s leafSpec) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := newKey(t)
	var uris []*url.URL
	for _, u := range s.uris {
		p, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, p)
	}
	if s.notBefore.IsZero() {
		s.notBefore = time.Now().Add(-time.Hour)
	}
	if s.notAfter.IsZero() {
		s.notAfter = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(testSerial.Add(1)), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: s.notBefore, NotAfter: s.notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: s.eku,
		URIs: uris, DNSNames: s.dns, IPAddresses: s.ips, EmailAddresses: s.emails,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

var serviceEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

const (
	gatewayTestSAN  = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"
	receiverSAN     = "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender"
	evidenceSAN     = "spiffe://agentarium.internal/ns/agent-adapters/sa/evidence-reader"
	modelAdapterSAN = "spiffe://agentarium.internal/ns/agent-adapters/sa/model-adapter"
)

// pki is one trust domain: root (the trust bundle), an intermediate, and the
// gateway client certificate.
type pki struct {
	root, inter *testCA
	roots       *x509.CertPool
	client      tls.Certificate
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{root: mkCA(t, "root", nil)}
	p.inter = mkCA(t, "intermediate", p.root)
	p.roots = x509.NewCertPool()
	p.roots.AddCert(p.root.cert)
	c, k := p.root.issue(t, leafSpec{uris: []string{gatewayTestSAN}, eku: serviceEKU})
	p.client = tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: k, Leaf: c}
	return p
}

func (p *pki) clientCert(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return &p.client, nil
}

// serve starts a TLS 1.3 server on 127.0.0.1 presenting chain (leaf first)
// and requiring a client certificate from p's root. It counts the requests
// that reached the handler and records the client SAN it saw: only when the
// server verified the client chain and the client leaf has exactly one URI
// SAN and no DNS, IP or email SAN.
func (p *pki) serve(t *testing.T, chain []*x509.Certificate, key *ecdsa.PrivateKey) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var hits atomic.Int32
	var peer atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
			leaf := r.TLS.VerifiedChains[0][0]
			if len(leaf.URIs) == 1 && len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) == 0 {
				peer.Store(leaf.URIs[0].String())
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	raw := make([][]byte, len(chain))
	for i, c := range chain {
		raw[i] = c.Raw
	}
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: raw, PrivateKey: key, Leaf: chain[0]}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.roots,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &hits, &peer
}

func TestAdapterSAN(t *testing.T) {
	for id, want := range map[string]string{
		"receiver-sender": receiverSAN, "evidence-reader": evidenceSAN, "model": modelAdapterSAN,
		"kubernetes-reader": "spiffe://agentarium.internal/ns/agent-adapters/sa/kubernetes-reader",
	} {
		if got, ok := AdapterSAN(id); !ok || got != want {
			t.Errorf("AdapterSAN(%q) = %q, %v; want %q", id, got, ok, want)
		}
	}
	for _, id := range []string{"", "model-adapter", "probe-runner", "Receiver-Sender", "receiver-sender/x"} {
		if got, ok := AdapterSAN(id); ok {
			t.Errorf("AdapterSAN(%q) = %q, want unknown", id, got)
		}
	}
}

func TestAdapterClientUnknownAdapter(t *testing.T) {
	p := newPKI(t)
	for _, id := range []string{"", "model-adapter", "probe-runner", "unknown"} {
		if c, err := NewAdapterClient(id, p.roots, p.clientCert); err == nil || c != nil {
			t.Errorf("NewAdapterClient(%q) = %v, %v; want error", id, c, err)
		}
	}
	if _, err := NewAdapterClient("receiver-sender", nil, p.clientCert); err == nil {
		t.Error("NewAdapterClient without a trust bundle succeeded")
	}
}

func TestAdapterClientServerCertificate(t *testing.T) {
	p := newPKI(t)
	other := newPKI(t) // a CA outside the trust bundle
	loop := []net.IP{net.ParseIP("127.0.0.1")}

	type tc struct {
		name    string
		adapter string
		chain   func() ([]*x509.Certificate, *ecdsa.PrivateKey)
		ok      bool
		errHas  string
	}
	direct := func(ca *testCA, s leafSpec) func() ([]*x509.Certificate, *ecdsa.PrivateKey) {
		return func() ([]*x509.Certificate, *ecdsa.PrivateKey) {
			c, k := ca.issue(t, s)
			return []*x509.Certificate{c}, k
		}
	}
	cases := []tc{
		{name: "uri only", adapter: "receiver-sender", ok: true,
			chain: direct(p.root, leafSpec{uris: []string{receiverSAN}, eku: serviceEKU})},
		{name: "model adapter KSA", adapter: "model", ok: true,
			chain: direct(p.root, leafSpec{uris: []string{modelAdapterSAN}, eku: serviceEKU})},
		{name: "uri only via presented intermediate", adapter: "receiver-sender", ok: true,
			chain: func() ([]*x509.Certificate, *ecdsa.PrivateKey) {
				c, k := p.inter.issue(t, leafSpec{uris: []string{receiverSAN}, eku: serviceEKU})
				return []*x509.Certificate{c, p.inter.cert}, k
			}},
		{name: "serverAuth only", adapter: "receiver-sender", ok: true,
			chain: direct(p.root, leafSpec{uris: []string{receiverSAN}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})},
		{name: "another adapter's SAN", adapter: "receiver-sender", errHas: "URI SAN",
			chain: direct(p.root, leafSpec{uris: []string{evidenceSAN}, eku: serviceEKU})},
		{name: "two URI SANs", adapter: "receiver-sender", errHas: "URI SAN",
			chain: direct(p.root, leafSpec{uris: []string{receiverSAN, evidenceSAN}, eku: serviceEKU})},
		{name: "no SAN", adapter: "receiver-sender", errHas: "URI SAN",
			chain: direct(p.root, leafSpec{eku: serviceEKU})},
		{name: "DNS only", adapter: "receiver-sender", errHas: "DNS, IP or email",
			chain: direct(p.root, leafSpec{dns: []string{"receiver-sender.agent-adapters.svc"}, eku: serviceEKU})},
		{name: "URI and DNS", adapter: "receiver-sender", errHas: "DNS, IP or email",
			chain: direct(p.root, leafSpec{uris: []string{receiverSAN}, dns: []string{"localhost"}, eku: serviceEKU})},
		{name: "URI and IP", adapter: "receiver-sender", errHas: "DNS, IP or email",
			chain: direct(p.root, leafSpec{uris: []string{receiverSAN}, ips: loop, eku: serviceEKU})},
		{name: "URI and email", adapter: "receiver-sender", errHas: "DNS, IP or email",
			chain: direct(p.root, leafSpec{uris: []string{receiverSAN}, emails: []string{"a@b.example"}, eku: serviceEKU})},
		{name: "expired", adapter: "receiver-sender", errHas: "verify server chain",
			chain: direct(p.root, leafSpec{uris: []string{receiverSAN}, eku: serviceEKU,
				notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)})},
		{name: "not yet valid", adapter: "receiver-sender", errHas: "verify server chain",
			chain: direct(p.root, leafSpec{uris: []string{receiverSAN}, eku: serviceEKU,
				notBefore: time.Now().Add(time.Hour), notAfter: time.Now().Add(48 * time.Hour)})},
		{name: "clientAuth only", adapter: "receiver-sender", errHas: "verify server chain",
			chain: direct(p.root, leafSpec{uris: []string{receiverSAN}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})},
		{name: "no EKU extension", adapter: "receiver-sender", errHas: "serverAuth",
			chain: direct(p.root, leafSpec{uris: []string{receiverSAN}})},
		{name: "untrusted CA", adapter: "receiver-sender", errHas: "verify server chain",
			chain: direct(other.root, leafSpec{uris: []string{receiverSAN}, eku: serviceEKU})},
		{name: "missing intermediate", adapter: "receiver-sender", errHas: "verify server chain",
			chain: func() ([]*x509.Certificate, *ecdsa.PrivateKey) {
				c, k := p.inter.issue(t, leafSpec{uris: []string{receiverSAN}, eku: serviceEKU})
				return []*x509.Certificate{c}, k
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			chain, key := c.chain()
			srv, hits, peer := p.serve(t, chain, key)
			if !strings.HasPrefix(srv.URL, "https://127.0.0.1:") {
				t.Fatalf("server URL %s", srv.URL)
			}
			client, err := NewAdapterClient(c.adapter, p.roots, p.clientCert)
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/internal/adapter/"+c.adapter+"/execute", strings.NewReader("{}"))
			resp, err := client.Do(req)
			if c.ok {
				if err != nil {
					t.Fatalf("call failed: %v", err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusAccepted || hits.Load() != 1 || peer.Load() != gatewayTestSAN {
					t.Fatalf("status %d hits %d client SAN %v", resp.StatusCode, hits.Load(), peer.Load())
				}
				if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 || resp.ProtoMajor != 1 {
					t.Fatalf("TLS %+v proto %s", resp.TLS, resp.Proto)
				}
				return
			}
			if err == nil {
				resp.Body.Close()
				t.Fatalf("call succeeded with status %d", resp.StatusCode)
			}
			if !strings.Contains(err.Error(), c.errHas) {
				t.Fatalf("error %q does not mention %q", err, c.errHas)
			}
			if hits.Load() != 0 {
				t.Fatalf("request reached the server (%d)", hits.Load())
			}
		})
	}
}

// The default Go client, given only RootCAs, refuses the URI-only
// certificate on 127.0.0.1; this is the failure the custom verification
// replaces.
func TestDefaultHostnameCheckRefusesURIOnly(t *testing.T) {
	p := newPKI(t)
	c, k := p.root.issue(t, leafSpec{uris: []string{receiverSAN}, eku: serviceEKU})
	srv, _, _ := p.serve(t, []*x509.Certificate{c}, k)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: p.roots, GetClientCertificate: p.clientCert,
	}}}
	resp, err := client.Post(srv.URL, "application/json", strings.NewReader("{}"))
	if err == nil {
		resp.Body.Close()
		t.Fatal("default verification accepted a URI-only certificate")
	}
	if !strings.Contains(err.Error(), "IP SANs") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestAdapterClientNoRedirect(t *testing.T) {
	p := newPKI(t)
	c, k := p.root.issue(t, leafSpec{uris: []string{receiverSAN}, eku: serviceEKU})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{c.Raw}, PrivateKey: k, Leaf: c}}}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewAdapterClient("receiver-sender", p.roots, p.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post(srv.URL+"/x", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status %d, want the redirect itself", resp.StatusCode)
	}
}

// An environment proxy must not see execute delivery: the client has no
// Proxy func, so HTTPS_PROXY (pointing at a closed port) is ignored and the
// call still reaches the adapter directly.
func TestAdapterClientIgnoresProxyEnv(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	p := newPKI(t)
	c, k := p.root.issue(t, leafSpec{uris: []string{receiverSAN}, eku: serviceEKU})
	srv, hits, peer := p.serve(t, []*x509.Certificate{c}, k)
	client, err := NewAdapterClient("receiver-sender", p.roots, p.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatalf("transport %T has a Proxy func", client.Transport)
	}
	// Go never proxies loopback hosts, so the request names a non-loopback
	// host and only the dial is pointed at the test server. Server
	// verification does not use the host name (ServiceClientTLS).
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	client.Timeout = 5 * time.Second
	resp, err := client.Post("https://receiver-sender.agent-adapters.svc:8443/internal/adapter/receiver-sender/execute", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("delivery with HTTPS_PROXY set: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted || hits.Load() != 1 || peer.Load() != gatewayTestSAN {
		t.Fatalf("status %d hits %d client SAN %v", resp.StatusCode, hits.Load(), peer.Load())
	}
}

// callAdapter, the worker's delivery path, POSTs to
// <base>/internal/adapter/<id>/execute through the adapter client. The
// adapter handler runs only when the server certificate is the adapter's.
func TestCallAdapterThroughAdapterClient(t *testing.T) {
	p := newPKI(t)
	const decisionID, actionID = "0b8f8a9e-6f1c-4d55-9a57-3c1e2d7f0a11", "5a0c3e2b-1d4f-4b6a-8c9d-2e7f1a3b4c5d"
	for _, tc := range []struct {
		name, san string
		ok        bool
	}{
		{"adapter SAN", evidenceSAN, true},
		{"another adapter's SAN", receiverSAN, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf, key := p.root.issue(t, leafSpec{uris: []string{tc.san}, eku: serviceEKU})
			var hits atomic.Int32
			var clientSAN atomic.Value
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0][0].URIs) == 1 {
					clientSAN.Store(r.TLS.VerifiedChains[0][0].URIs[0].String())
				}
				var req ExecuteRequest
				b, _ := io.ReadAll(r.Body)
				if r.Method != http.MethodPost || r.URL.Path != "/internal/adapter/evidence-reader/execute" ||
					strictInto(b, &req) != nil || req.DecisionID != decisionID || req.ActionID != actionID {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(executeAck{DecisionID: decisionID, ActionID: actionID, State: "received"})
			}))
			srv.TLS = &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    p.roots,
			}
			srv.StartTLS()
			defer srv.Close()
			client, err := NewAdapterClient("evidence-reader", p.roots, p.clientCert)
			if err != nil {
				t.Fatal(err)
			}
			s := &Service{Adapter: func(id string) (AdapterEndpoint, bool) {
				return AdapterEndpoint{BaseURL: srv.URL, Client: client}, id == "evidence-reader"
			}}
			err = s.callAdapter(context.Background(), &claimed{
				decisionID: decisionID, actionID: actionID, adapterID: "evidence-reader",
				attempts: 1, expiresAt: time.Now().Add(time.Minute),
			})
			if tc.ok {
				if err != nil || hits.Load() != 1 || clientSAN.Load() != gatewayTestSAN {
					t.Fatalf("err %v hits %d client SAN %v", err, hits.Load(), clientSAN.Load())
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "URI SAN") || hits.Load() != 0 {
				t.Fatalf("err %v hits %d", err, hits.Load())
			}
		})
	}
}
