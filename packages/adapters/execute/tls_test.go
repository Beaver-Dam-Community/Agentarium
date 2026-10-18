package execute_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/testpki"
)

const (
	peerSAN  = "spiffe://agentarium.internal/ns/agent-control/sa/dispatch-coordinator"
	adapterS = "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender"
)

// leafSpec describes one certificate variant for the TLS tests.
type leafSpec struct {
	noEKU  bool
	ekus   []x509.ExtKeyUsage
	isCA   bool
	uris   []string
	dns    []string
	ips    []net.IP
	emails []string
}

func issueSpec(t *testing.T, ca *testpki.CA, s leafSpec) testpki.Leaf {
	t.Helper()
	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		DNSNames:       s.dns,
		IPAddresses:    s.ips,
		EmailAddresses: s.emails,
	}
	if !s.noEKU {
		tmpl.ExtKeyUsage = s.ekus
		if tmpl.ExtKeyUsage == nil {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		}
	}
	if s.isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	for _, u := range s.uris {
		p, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, p)
	}
	return ca.IssueTemplate(t, tmpl)
}

type badLeaf struct {
	spec   leafSpec
	reason string // substring of the verifier's error
}

// badLeaves are the variants both directions must refuse, keyed by name.
// want is the URI SAN the verifier expects.
func badLeaves(want string) map[string]badLeaf {
	const sans = "DNS, IP or email SAN"
	return map[string]badLeaf{
		"no EKU extension": {leafSpec{noEKU: true, uris: []string{want}}, "does not list extended key usage"},
		"CA leaf":          {leafSpec{isCA: true, uris: []string{want}}, "is a CA certificate"},
		"URI and DNS SAN":  {leafSpec{uris: []string{want}, dns: []string{"svc.agent-control.svc"}}, sans},
		"URI and IP SAN":   {leafSpec{uris: []string{want}, ips: []net.IP{net.IPv4(127, 0, 0, 1)}}, sans},
		"URI and email":    {leafSpec{uris: []string{want}, emails: []string{"svc@agentarium.internal"}}, sans},
		"two URI SANs":     {leafSpec{uris: []string{want, "spiffe://agentarium.internal/ns/x/sa/y"}}, "2 URI SANs"},
		"no URI SAN":       {leafSpec{}, "0 URI SANs"},
	}
}

// logBuffer collects http.Server error logs (the server side's handshake
// errors) for the reason checks.
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// waitFor waits until the log contains s; the server logs the handshake
// error shortly after the client sees the alert.
func (l *logBuffer) waitFor(s string) bool {
	for range 100 {
		l.mu.Lock()
		ok := strings.Contains(l.b.String(), s)
		l.mu.Unlock()
		if ok {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func (l *logBuffer) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.Reset()
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
}

func get(c *http.Client, u string) error {
	resp, err := c.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// TestClientTLSConfigServerCert dials a real TLS server with ClientTLSConfig
// and checks which server certificates the adapter accepts.
func TestClientTLSConfigServerCert(t *testing.T) {
	ca := testpki.NewCA(t, "agentarium-trust")
	caFile := ca.WritePEM(t)
	adapter := issueSpec(t, ca, leafSpec{uris: []string{adapterS}})
	files := execute.TLSFiles{CertFile: adapter.CertFile, KeyFile: adapter.KeyFile, CAFile: caFile}

	dial := func(t *testing.T, server testpki.Leaf) error {
		t.Helper()
		srv := httptest.NewUnstartedServer(okHandler())
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{server.TLS}, MinVersion: tls.VersionTLS13}
		srv.StartTLS()
		defer srv.Close()
		cfg, err := execute.ClientTLSConfig(files, peerSAN)
		if err != nil {
			t.Fatal(err)
		}
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
		return get(c, srv.URL)
	}

	if err := dial(t, issueSpec(t, ca, leafSpec{uris: []string{peerSAN}})); err != nil {
		t.Fatalf("URI-only service certificate refused: %v", err)
	}
	if err := dial(t, issueSpec(t, ca, leafSpec{ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, uris: []string{peerSAN}})); err != nil {
		t.Fatalf("serverAuth-only service certificate refused: %v", err)
	}
	for name, b := range badLeaves(peerSAN) {
		t.Run(name, func(t *testing.T) {
			err := dial(t, issueSpec(t, ca, b.spec))
			if err == nil || !strings.Contains(err.Error(), "execute: server certificate: ") || !strings.Contains(err.Error(), b.reason) {
				t.Fatalf("want refusal %q, got %v", b.reason, err)
			}
		})
	}
	t.Run("clientAuth only", func(t *testing.T) {
		if err := dial(t, issueSpec(t, ca, leafSpec{ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, uris: []string{peerSAN}})); err == nil {
			t.Fatal("handshake succeeded")
		}
	})
	t.Run("other URI SAN", func(t *testing.T) {
		if err := dial(t, issueSpec(t, ca, leafSpec{uris: []string{adapterS}})); err == nil {
			t.Fatal("handshake succeeded")
		}
	})
	t.Run("other CA", func(t *testing.T) {
		if err := dial(t, issueSpec(t, testpki.NewCA(t, "other"), leafSpec{uris: []string{peerSAN}})); err == nil {
			t.Fatal("handshake succeeded")
		}
	})
}

// TestServerTLSConfigClientCert serves over ServerTLSConfig and checks which
// client certificates complete the handshake.
func TestServerTLSConfigClientCert(t *testing.T) {
	ca := testpki.NewCA(t, "agentarium-trust")
	caFile := ca.WritePEM(t)
	server := issueSpec(t, ca, leafSpec{uris: []string{adapterS}})
	cfg, err := execute.ServerTLSConfig(execute.TLSFiles{CertFile: server.CertFile, KeyFile: server.KeyFile, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	// StartTLS would add its own certificate (cfg has GetCertificate only),
	// so the listener is wrapped with cfg unchanged.
	srv := httptest.NewUnstartedServer(okHandler())
	logs := &logBuffer{}
	srv.Config.ErrorLog = log.New(logs, "", 0)
	srv.Listener = tls.NewListener(srv.Listener, cfg)
	srv.Start()
	defer srv.Close()
	base := "https://" + srv.Listener.Addr().String()

	dial := func(client testpki.Leaf) error {
		// The server certificate has no DNS or IP SAN, so the test client
		// checks only the server chain; the subject here is the server side.
		roots := ca.Pool
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{client.TLS}, InsecureSkipVerify: true,
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				leaf, err := x509.ParseCertificate(raw[0])
				if err != nil {
					return err
				}
				_, err = leaf.Verify(x509.VerifyOptions{Roots: roots})
				return err
			},
		}}}
		return get(c, base)
	}

	if err := dial(issueSpec(t, ca, leafSpec{uris: []string{execute.GatewaySAN}})); err != nil {
		t.Fatalf("URI-only service client certificate refused: %v", err)
	}
	if err := dial(issueSpec(t, ca, leafSpec{ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, uris: []string{execute.GatewaySAN}})); err != nil {
		t.Fatalf("clientAuth-only client certificate refused: %v", err)
	}
	for name, b := range badLeaves(execute.GatewaySAN) {
		t.Run(name, func(t *testing.T) {
			logs.reset()
			if err := dial(issueSpec(t, ca, b.spec)); err == nil {
				t.Fatal("handshake succeeded")
			}
			if !logs.waitFor("execute: client certificate: ") || !logs.waitFor(b.reason) {
				t.Fatalf("server did not log refusal %q", b.reason)
			}
		})
	}
	t.Run("serverAuth only", func(t *testing.T) {
		if err := dial(issueSpec(t, ca, leafSpec{ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, uris: []string{execute.GatewaySAN}})); err == nil {
			t.Fatal("handshake succeeded")
		}
	})
}
