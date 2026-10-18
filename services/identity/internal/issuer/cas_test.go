package issuer

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/security/privateca/apiv1/privatecapb"
)

type fakeCAS struct {
	got   *privatecapb.CreateCertificateRequest
	leaf  string
	chain []string
	certs []*privatecapb.FetchCaCertsResponse_CertChain
	err   error
	calls int
}

func (f *fakeCAS) CreateCertificate(_ context.Context, r *privatecapb.CreateCertificateRequest) (*privatecapb.Certificate, error) {
	f.got = r
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &privatecapb.Certificate{PemCertificate: f.leaf, PemCertificateChain: f.chain}, nil
}

func (f *fakeCAS) FetchCaCerts(context.Context, *privatecapb.FetchCaCertsRequest) (*privatecapb.FetchCaCertsResponse, error) {
	return &privatecapb.FetchCaCertsResponse{CaCerts: f.certs}, nil
}

func TestCASIssueRequestShape(t *testing.T) {
	now := time.Date(2026, 10, 14, 15, 0, 0, 0, time.UTC)
	key := mustKey(t)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	const san = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"
	leaf := issue(t, leafSpec{uris: []string{san}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		notBefore: now.Add(-time.Minute), notAfter: now.Add(23 * time.Hour), key: key})
	f := &fakeCAS{leaf: leaf, chain: []string{"ISSUER"}}
	c := testCAS(f)
	c.Now = func() time.Time { return now }
	id := "0123456789abcdef0123456789abcdef"
	out, err := c.Issue(context.Background(), Request{RequestID: id, PublicKeyDER: pub, SAN: san, Lifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.ChainPEM) != 1 || out.ChainPEM[0] != "ISSUER" {
		t.Fatalf("chain = %v", out.ChainPEM)
	}
	r := f.got
	if r.Parent != c.Pool || r.CertificateId != id || r.RequestId != "01234567-89ab-cdef-0123-456789abcdef" {
		t.Fatalf("ids: %s %s %s", r.Parent, r.CertificateId, r.RequestId)
	}
	cfg := r.Certificate.GetConfig()
	if cfg == nil || r.Certificate.GetPemCsr() != "" {
		t.Fatal("not a config-based request")
	}
	if uris := cfg.SubjectConfig.SubjectAltName.Uris; len(uris) != 1 || uris[0] != san {
		t.Fatalf("SAN = %v", uris)
	}
	if r.Certificate.CertificateTemplate != c.ServiceTemplate || cfg.X509Config.KeyUsage != nil {
		t.Fatal("service key usage must come from the service template")
	}
	if cfg.X509Config.CaOptions.GetIsCa() {
		t.Fatal("is_ca requested")
	}
	block, _ := pem.Decode(cfg.PublicKey.Key)
	if block == nil || string(block.Bytes) != string(pub) || cfg.PublicKey.Format != privatecapb.PublicKey_PEM {
		t.Fatal("public key not passed through")
	}
	if r.Certificate.Lifetime.AsDuration() != 24*time.Hour {
		t.Fatalf("lifetime = %v", r.Certificate.Lifetime.AsDuration())
	}

	// Client-only template selected; a CA that adds serverAuth is still rejected.
	_, err = c.Issue(context.Background(), Request{RequestID: id, PublicKeyDER: pub, SAN: san, ClientOnly: true, Lifetime: 24 * time.Hour})
	if f.got.Certificate.CertificateTemplate != c.ClientTemplate || f.got.Certificate.GetConfig().X509Config.KeyUsage != nil {
		t.Fatal("client-only key usage must come from the client template")
	}
	if err == nil {
		t.Fatal("leaf with serverAuth accepted for client-only request")
	}

	if _, err := c.Issue(context.Background(), Request{RequestID: "bad id!", PublicKeyDER: pub, SAN: san}); err == nil {
		t.Fatal("invalid certificate id accepted")
	}
}

func testCAS(f *fakeCAS) CAS {
	return CAS{Client: f, Pool: "projects/p/locations/l/caPools/pool",
		ServiceTemplate: "projects/p/locations/l/certificateTemplates/service",
		ClientTemplate:  "projects/p/locations/l/certificateTemplates/client"}
}

func TestCASRejectsInvalidTemplateConfigBeforeIssuance(t *testing.T) {
	for name, mutate := range map[string]func(*CAS){
		"missing pool":     func(c *CAS) { c.Pool = "" },
		"malformed pool":   func(c *CAS) { c.Pool = "projects/p/locations/l/caPools/" },
		"missing service":  func(c *CAS) { c.ServiceTemplate = "" },
		"missing client":   func(c *CAS) { c.ClientTemplate = "" },
		"same template":    func(c *CAS) { c.ClientTemplate = c.ServiceTemplate },
		"short name":       func(c *CAS) { c.ServiceTemplate = "service" },
		"wrong collection": func(c *CAS) { c.ClientTemplate = c.Pool },
		"empty project":    func(c *CAS) { c.ClientTemplate = "projects//locations/l/certificateTemplates/client" },
		"empty location":   func(c *CAS) { c.ClientTemplate = "projects/p/locations//certificateTemplates/client" },
		"empty template":   func(c *CAS) { c.ClientTemplate = "projects/p/locations/l/certificateTemplates/" },
		"URL":              func(c *CAS) { c.ServiceTemplate = "https://privateca.googleapis.com/v1/" + c.ServiceTemplate },
		"whitespace":       func(c *CAS) { c.ServiceTemplate += " " },
		"trailing slash":   func(c *CAS) { c.ServiceTemplate += "/" },
		"traversal":        func(c *CAS) { c.ServiceTemplate = "projects/p/locations/l/certificateTemplates/.." },
		"query":            func(c *CAS) { c.ServiceTemplate += "?alt=json" },
		"service project":  func(c *CAS) { c.ServiceTemplate = "projects/other/locations/l/certificateTemplates/service" },
		"client project":   func(c *CAS) { c.ClientTemplate = "projects/other/locations/l/certificateTemplates/client" },
		"service location": func(c *CAS) { c.ServiceTemplate = "projects/p/locations/other/certificateTemplates/service" },
		"client location":  func(c *CAS) { c.ClientTemplate = "projects/p/locations/other/certificateTemplates/client" },
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeCAS{}
			c := testCAS(f)
			mutate(&c)
			for _, clientOnly := range []bool{false, true} {
				if _, err := c.Issue(context.Background(), Request{RequestID: "test", ClientOnly: clientOnly}); err == nil {
					t.Fatal("invalid installation configuration accepted")
				}
			}
			if f.calls != 0 {
				t.Fatal("invalid installation configuration reached CAS")
			}
		})
	}
}

func TestCASTemplateProfiles(t *testing.T) {
	// These are issuer-level verified-request fixtures, not bootstrap role grants.
	// Node bridge bootstrap remains disabled by the existing profile validator.
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, san  string
		clientOnly bool
	}{
		{"service", "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway", false},
		{"identity server", "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity", false},
		{"adapter", "spiffe://agentarium.internal/ns/agent-adapters/sa/notify-adapter", false},
		{"runtime", "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/11111111-2222-3333-4444-555555555555", true},
		{"probe", "spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner/pod/11111111-2222-3333-4444-555555555555", true},
		{"fixture", "spiffe://agentarium.internal/ns/agent-exec/sa/start-fixture/pod/11111111-2222-3333-4444-555555555555", true},
		{"node bridge", "spiffe://agentarium.internal/node-bridge/11111111-2222-3333-4444-555555555555/boot-id", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := mustKey(t)
			pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
			eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			if !tc.clientOnly {
				eku = append(eku, x509.ExtKeyUsageServerAuth)
			}
			f := &fakeCAS{leaf: issue(t, leafSpec{uris: []string{tc.san}, eku: eku, key: key, notBefore: now.Add(-time.Minute), notAfter: now.Add(23 * time.Hour)})}
			c := testCAS(f)
			c.Now = func() time.Time { return now }
			req := Request{RequestID: "test", PublicKeyDER: pub, SAN: tc.san, ClientOnly: tc.clientOnly, Lifetime: 24 * time.Hour}
			if _, err := c.Issue(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			want := c.ServiceTemplate
			if tc.clientOnly {
				want = c.ClientTemplate
			}
			if f.got.Certificate.CertificateTemplate != want || f.calls != 1 {
				t.Fatal("incorrect profile template selected")
			}
			f.err = errors.New("template denied")
			if _, err := c.Issue(context.Background(), req); !errors.Is(err, f.err) || f.calls != 2 || f.got.Certificate.CertificateTemplate != want {
				t.Fatal("CAS failure was hidden or attempted a fallback")
			}
		})
	}
}

func TestTrustBundle(t *testing.T) {
	now := time.Now()
	a := issue(t, leafSpec{key: mustKey(t), notBefore: now, notAfter: now.Add(time.Hour)})
	b := issue(t, leafSpec{key: mustKey(t), notBefore: now, notAfter: now.Add(time.Hour)})
	f := &fakeCAS{certs: []*privatecapb.FetchCaCertsResponse_CertChain{
		{Certificates: []string{b, a}}, {Certificates: []string{a}},
	}}
	out, err := CAS{Client: f, Pool: "p"}.TrustBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("bundle not de-duplicated:\n%s", out)
	}
	f.certs[0].Certificates = []string{a, b}
	again, _ := CAS{Client: f, Pool: "p"}.TrustBundle(context.Background())
	if again != out {
		t.Fatal("bundle depends on input order")
	}
	f.certs = nil
	if _, err := (CAS{Client: f, Pool: "p"}).TrustBundle(context.Background()); err == nil {
		t.Fatal("empty bundle accepted")
	}
}
