package transport_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/testpki"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

const receiverSAN = "spiffe://agentarium.internal/ns/agent-targets/sa/receiver"

// svcCert describes one server certificate variant for the agentarium-trust
// tests.
type svcCert struct {
	uris      []string
	dns       []string
	ekus      []x509.ExtKeyUsage
	noEKU     bool
	isCA      bool
	notBefore time.Time
	notAfter  time.Time
}

func issueSvc(t *testing.T, ca *testpki.CA, c svcCert) testpki.Leaf {
	t.Helper()
	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "svc"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: c.dns,
	}
	if !c.notBefore.IsZero() {
		tmpl.NotBefore = c.notBefore
	}
	if !c.notAfter.IsZero() {
		tmpl.NotAfter = c.notAfter
	}
	if !c.noEKU {
		tmpl.ExtKeyUsage = c.ekus
		if tmpl.ExtKeyUsage == nil {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
	}
	if c.isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	for _, u := range c.uris {
		p, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, p)
	}
	return ca.IssueTemplate(t, tmpl)
}

// svcTarget is a TLS server presenting cert (plus extra chain certificates)
// and recording the SNI name the client sent.
type svcTarget struct {
	srv   *httptest.Server
	port  string
	count atomic.Int32
	sni   atomic.Value
}

func newSvcTarget(t *testing.T, cert tls.Certificate) *svcTarget {
	t.Helper()
	st := &svcTarget{}
	st.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		st.count.Add(1)
		w.WriteHeader(201)
	}))
	st.srv.TLS = &tls.Config{GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		st.sni.Store(hi.ServerName)
		return &cert, nil
	}}
	st.srv.StartTLS()
	t.Cleanup(st.srv.Close)
	_, st.port, _ = net.SplitHostPort(st.srv.Listener.Addr().String())
	return st
}

func trustRequest(port string, pool *x509.CertPool, san string) transport.Request {
	tg := &target{port: port, ca: &testpki.CA{}}
	req := tg.request("{}")
	req.CARef = "agentarium-trust"
	req.RootCAs = pool
	req.Plan.ExpectedURISAN = san
	return req
}

func doTrust(t *testing.T, ca *testpki.CA, leaf tls.Certificate, san string, cfg transport.Config) (transport.Result, *svcTarget) {
	t.Helper()
	st := newSvcTarget(t, leaf)
	cfg.Resolver = loopback()
	return transport.Do(context.Background(), cfg, trustRequest(st.port, ca.Pool, san)), st
}

func wantTLSFailure(t *testing.T, r transport.Result, st *svcTarget, reason string) {
	t.Helper()
	if !r.Failed() || r.Stage != transport.StageTLS || len(r.ReasonCodes) != 1 || r.ReasonCodes[0] != "TLS_VERIFY_FAILED" {
		t.Fatalf("want failed/tls/TLS_VERIFY_FAILED, got stage %q codes %v err %v", r.Stage, r.ReasonCodes, r.Err)
	}
	if reason != "" && (r.Err == nil || !strings.Contains(r.Err.Error(), reason)) {
		t.Fatalf("error %v does not mention %q", r.Err, reason)
	}
	if st != nil && st.count.Load() != 0 {
		t.Fatal("target received a request")
	}
}

func TestTrustURISANAccepted(t *testing.T) {
	ca := testpki.NewCA(t, "agentarium-trust")
	leaf := issueSvc(t, ca, svcCert{uris: []string{receiverSAN}})
	r, st := doTrust(t, ca, leaf.TLS, receiverSAN, transport.Config{})
	if !r.Responded || r.StatusCode != 201 || st.count.Load() != 1 {
		t.Fatalf("result %+v err %v", r, r.Err)
	}
	// expected_tls_name is still sent as SNI although no hostname is checked.
	if got, _ := st.sni.Load().(string); got != host {
		t.Fatalf("SNI %q, want %q", got, host)
	}
}

func TestTrustIntermediateChainAccepted(t *testing.T) {
	root := testpki.NewCA(t, "agentarium-trust")
	inter := root.Intermediate(t, "agentarium-issuing")
	leaf := issueSvc(t, inter, svcCert{uris: []string{receiverSAN}})
	chained := leaf.TLS
	chained.Certificate = append(append([][]byte(nil), leaf.TLS.Certificate...), inter.Cert.Raw)
	r, st := doTrust(t, root, chained, receiverSAN, transport.Config{})
	if !r.Responded || st.count.Load() != 1 {
		t.Fatalf("intermediate chain refused: %+v err %v", r, r.Err)
	}
	// Without the intermediate in the handshake the chain does not build.
	r, st = doTrust(t, root, leaf.TLS, receiverSAN, transport.Config{})
	wantTLSFailure(t, r, st, "unknown authority")
}

func TestTrustCertificateRefusals(t *testing.T) {
	ca := testpki.NewCA(t, "agentarium-trust")
	other := "spiffe://agentarium.internal/ns/agent-targets/sa/receiver-probe"
	cases := map[string]struct {
		cert   svcCert
		reason string
	}{
		"wrong URI SAN":         {svcCert{uris: []string{other}}, "is not"},
		"extra URI SAN":         {svcCert{uris: []string{receiverSAN, other}}, "2 URI SANs"},
		"missing URI SAN":       {svcCert{}, "0 URI SANs"},
		"DNS SAN only":          {svcCert{dns: []string{host}}, "DNS, IP or email SAN"},
		"URI and DNS SAN":       {svcCert{uris: []string{receiverSAN}, dns: []string{host}}, "DNS, IP or email SAN"},
		"clientAuth EKU only":   {svcCert{uris: []string{receiverSAN}, ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, "incompatible key usage"},
		"no EKU extension":      {svcCert{uris: []string{receiverSAN}, noEKU: true}, "serverAuth"},
		"CA leaf":               {svcCert{uris: []string{receiverSAN}, isCA: true}, "CA certificate"},
		"expired":               {svcCert{uris: []string{receiverSAN}, notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)}, "expired"},
		"not yet valid":         {svcCert{uris: []string{receiverSAN}, notBefore: time.Now().Add(time.Hour), notAfter: time.Now().Add(48 * time.Hour)}, "not yet valid"},
		"URI SAN with fragment": {svcCert{uris: []string{receiverSAN + "#x"}}, "is not"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			leaf := issueSvc(t, ca, c.cert)
			r, st := doTrust(t, ca, leaf.TLS, receiverSAN, transport.Config{})
			wantTLSFailure(t, r, st, c.reason)
			var verr *transport.VerifyError
			if !errors.As(r.Err, &verr) {
				t.Fatalf("error %v is not a VerifyError", r.Err)
			}
		})
	}
	t.Run("untrusted root", func(t *testing.T) {
		stranger := testpki.NewCA(t, "agentarium-trust")
		leaf := issueSvc(t, stranger, svcCert{uris: []string{receiverSAN}})
		r, st := doTrust(t, ca, leaf.TLS, receiverSAN, transport.Config{})
		wantTLSFailure(t, r, st, "unknown authority")
	})
	t.Run("CurrentTime is the transport clock", func(t *testing.T) {
		leaf := issueSvc(t, ca, svcCert{uris: []string{receiverSAN}})
		late := func() time.Time { return time.Now().Add(72 * time.Hour) }
		r, st := doTrust(t, ca, leaf.TLS, receiverSAN, transport.Config{Now: late})
		wantTLSFailure(t, r, st, "expired")
	})
}

// The agentarium-trust path (InsecureSkipVerify + VerifyConnection) cannot
// be configured without a well-formed expected URI SAN and a trust pool.
func TestTrustConfigurationRequired(t *testing.T) {
	ca := testpki.NewCA(t, "agentarium-trust")
	leaf := issueSvc(t, ca, svcCert{uris: []string{receiverSAN}})
	st := newSvcTarget(t, leaf.TLS)
	cases := map[string]func(*transport.Request){
		"empty expected_uri_san":     func(r *transport.Request) { r.Plan.ExpectedURISAN = "" },
		"malformed expected_uri_san": func(r *transport.Request) { r.Plan.ExpectedURISAN = "spiffe://agentarium.internal/ns/*/sa/receiver" },
		"no trust pool":              func(r *transport.Request) { r.RootCAs = nil },
		"URI SAN on cluster target":  func(r *transport.Request) { r.CARef = "cluster" },
		"URI SAN on system target":   func(r *transport.Request) { r.CARef = "system" },
		"unknown ca_ref":             func(r *transport.Request) { r.CARef = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := trustRequest(st.port, ca.Pool, receiverSAN)
			mutate(&req)
			if _, err := transport.TLSConfig(req, nil); err == nil {
				t.Fatal("TLSConfig accepted the request")
			}
			if name != "no trust pool" {
				if err := transport.Validate(req); err == nil {
					t.Fatal("Validate accepted the plan")
				}
			}
			r := transport.Do(context.Background(), transport.Config{Resolver: loopback()}, req)
			wantTLSFailure(t, r, st, "")
			if r.Observation.LocalAddr != nil || r.Observation.ConnectStartedAt != nil {
				t.Fatal("a connection was made")
			}
		})
	}
	req := trustRequest(st.port, ca.Pool, receiverSAN)
	cfg, err := transport.TLSConfig(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil || cfg.ServerName != host {
		t.Fatalf("trust config: skip %v verify %v server name %q", cfg.InsecureSkipVerify, cfg.VerifyConnection != nil, cfg.ServerName)
	}
	for _, ref := range []string{"cluster", "system"} {
		r := req
		r.CARef, r.Plan.ExpectedURISAN = ref, ""
		cfg, err := transport.TLSConfig(r, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.InsecureSkipVerify {
			t.Fatalf("ca_ref %s skips the standard verification", ref)
		}
	}
}

// system and cluster keep Go's hostname verification: a certificate that
// chains to the pool but names another host, or only a URI SAN, is refused.
func TestStandardHostnameStillChecked(t *testing.T) {
	ca := testpki.NewCA(t, "pool")
	for _, ref := range []string{"system", "cluster"} {
		for name, cert := range map[string]svcCert{
			"other DNS name": {dns: []string{"other.agent-targets.svc"}},
			"URI SAN only":   {uris: []string{receiverSAN}},
		} {
			t.Run(ref+"/"+name, func(t *testing.T) {
				st := newSvcTarget(t, issueSvc(t, ca, cert).TLS)
				req := trustRequest(st.port, ca.Pool, "")
				req.CARef = ref
				r := transport.Do(context.Background(), transport.Config{Resolver: loopback()}, req)
				wantTLSFailure(t, r, st, "")
				var herr x509.HostnameError
				if !errors.As(r.Err, &herr) {
					t.Fatalf("error %v is not a hostname error", r.Err)
				}
			})
		}
		t.Run(ref+"/matching DNS name", func(t *testing.T) {
			st := newSvcTarget(t, issueSvc(t, ca, svcCert{dns: []string{host}}).TLS)
			req := trustRequest(st.port, ca.Pool, "")
			req.CARef = ref
			if r := transport.Do(context.Background(), transport.Config{Resolver: loopback()}, req); !r.Responded {
				t.Fatalf("matching hostname refused: %v", r.Err)
			}
		})
	}
}
