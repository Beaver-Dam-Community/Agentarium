package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert/workloadcerttest"
	"github.com/Beaver-Dam-Community/Agentarium/services/gateway/internal/gateway"
)

func full() config {
	return config{listen: ":8443", dbURL: "postgres://gateway@127.0.0.1:5432/agentarium", environment: "prod",
		gatewaySAN:  "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway",
		trustBundle: "/ca.pem", certFile: "/tls.crt", keyFile: "/tls.key",
		keyID: "prod-v1", bundleKeyFile: "/keys/prod-v1.pem", modelProfiles: "/profiles.json",
		auditSourceID: "gateway", auditSourceVersion: "v1", epochDir: "/var/lib/agentarium/epoch",
		healthURL: "https://control-health.agent-observe.svc:8443", healthSourceID: "gateway/pod-1",
		identityURL: "https://workload-identity.agent-control.svc:8443", identitySAN: gateway.IdentitySAN,
		auditURL: "https://audit-writer.agent-observe.svc:8443", auditWriterSAN: gateway.AuditWriterSAN}
}

func TestValidateFailsClosed(t *testing.T) {
	if err := full().validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*config){
		"database-url":         func(c *config) { c.dbURL = "" },
		"environment":          func(c *config) { c.environment = "" },
		"gateway-san":          func(c *config) { c.gatewaySAN = "" },
		"trust-bundle":         func(c *config) { c.trustBundle = "" },
		"tls-cert":             func(c *config) { c.certFile = "" },
		"tls-key":              func(c *config) { c.keyFile = "" },
		"bundle-key-file":      func(c *config) { c.bundleKeyFile = "" },
		"audit-source-id":      func(c *config) { c.auditSourceID = "" },
		"audit-source-version": func(c *config) { c.auditSourceVersion = "" },
		"epoch-dir":            func(c *config) { c.epochDir = "" },
		"health-url":           func(c *config) { c.healthURL = "" },
		"health-source-id":     func(c *config) { c.healthSourceID = "" },
		"identity-url":         func(c *config) { c.identityURL = "" },
		"identity-san":         func(c *config) { c.identitySAN = "" },
		"audit-url":            func(c *config) { c.auditURL = "" },
		"audit-writer-san":     func(c *config) { c.auditWriterSAN = "" },
	} {
		c := full()
		mut(&c)
		if err := c.validate(); err == nil || !strings.Contains(err.Error(), "--"+name) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, u := range []string{"http://control-health:8443", "https://control-health:8443/internal", "control-health:8443"} {
		c := full()
		c.healthURL = u
		if err := c.validate(); err == nil {
			t.Errorf("health URL %q accepted", u)
		}
	}
	for _, u := range []string{"http://workload-identity:8443", "https://workload-identity:8443/v1"} {
		c := full()
		c.identityURL = u
		if err := c.validate(); err == nil {
			t.Errorf("identity URL %q accepted", u)
		}
	}
	for _, u := range []string{"http://audit-writer:8443", "https://audit-writer:8443/internal"} {
		c := full()
		c.auditURL = u
		if err := c.validate(); err == nil {
			t.Errorf("audit URL %q accepted", u)
		}
	}
	// run refuses before opening anything.
	c := full()
	c.epochDir = ""
	if err := run(slog.New(slog.NewTextHandler(io.Discard, nil)), c); err == nil || !strings.Contains(err.Error(), "--epoch-dir") {
		t.Fatalf("run without epoch dir: %v", err)
	}
}

type noBundle struct{}

func (noBundle) Current() *policyloader.Snapshot { return nil }
func (noBundle) Status() policyloader.Status     { return policyloader.Status{} }

// newService leaves no decision-path dependency to the Unwired default, and
// the lease is the component = gateway, global/* lease of this replica.
func TestNewServiceWiresEveryDependency(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), full().dbURL) // lazy: no connection is made
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	hc := &http.Client{}
	svc, err := newService(pool, noBundle{}, slog.Default(), full(), "4", hc)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := svc.Policy.(gateway.PGPolicy); !ok || p.Environment != "prod" {
		t.Errorf("policy %#v", svc.Policy)
	}
	if _, ok := svc.Health.(gateway.PGHealth); !ok {
		t.Errorf("health %#v", svc.Health)
	}
	if r, ok := svc.Readiness.(gateway.HTTPReadiness); !ok || r.BaseURL != full().healthURL || r.Client != hc {
		t.Errorf("readiness %#v", svc.Readiness)
	}
	if _, ok := svc.Adapters.(gateway.PGAdapters); !ok {
		t.Errorf("adapters %#v", svc.Adapters)
	}
	if _, ok := svc.Audit.(*gateway.PGAuditor); !ok {
		t.Errorf("audit %#v", svc.Audit)
	}
	if _, ok := svc.Probes.(gateway.PGProbes); !ok {
		t.Errorf("probes %#v", svc.Probes)
	}
	if svc.Environment != "prod" || svc.GatewayIdentity != full().gatewaySAN {
		t.Errorf("service %q %q", svc.Environment, svc.GatewayIdentity)
	}
	for name, c := range map[string]config{
		"no audit source":  func() config { c := full(); c.auditSourceID = ""; return c }(),
		"no environment":   func() config { c := full(); c.environment = ""; return c }(),
		"http control URL": func() config { c := full(); c.healthURL = "http://control-health:8443"; return c }(),
	} {
		if _, err := newService(pool, noBundle{}, slog.Default(), c, "4", hc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := newService(pool, noBundle{}, slog.Default(), full(), "", hc); err == nil {
		t.Error("empty producer epoch accepted")
	}
	if _, err := newService(pool, noBundle{}, slog.Default(), full(), "4", nil); err == nil {
		t.Error("no control-health client accepted")
	}

	l, err := newLease(pool, noBundle{}, full(), hc)
	if err != nil {
		t.Fatal(err)
	}
	if l.Component != "gateway" || l.Scope != "global" || l.ScopeID != "*" || l.SourceID != "gateway/pod-1" || l.URL != full().healthURL {
		t.Errorf("lease %#v", l)
	}
	c := full()
	c.healthSourceID = ""
	if _, err := newLease(pool, noBundle{}, c, hc); err == nil {
		t.Error("lease without source_id accepted")
	}
}

func TestParseAdapterURLs(t *testing.T) {
	got, err := parseAdapterURLs("model=https://model-adapter.agent-adapters.svc:8443, evidence-reader=https://evidence-reader:8443/,receiver-sender=https://10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"model":           "https://model-adapter.agent-adapters.svc:8443",
		"evidence-reader": "https://evidence-reader:8443",
		"receiver-sender": "https://10.0.0.7",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for id, u := range want {
		if got[id] != u {
			t.Errorf("%s = %q, want %q", id, got[id], u)
		}
	}
	if got, err := parseAdapterURLs(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}

func TestParseAdapterURLsRejects(t *testing.T) {
	for _, s := range []string{
		"unknown=https://adapter",
		"model-adapter=https://adapter",
		"=https://adapter",
		"model",
		"model=",
		"model=http://adapter",
		"model=adapter:8443",
		"model=//adapter",
		"model=https://",
		"model=https://:8443",
		"model=https:adapter",
		"model=https://user@adapter",
		"model=https://user:pw@adapter",
		"model=https://adapter/path",
		"model=https://adapter//",
		"model=https://adapter/%2F",
		"model=https://adapter?query",
		"model=https://adapter?",
		"model=https://adapter/?q=1",
		"model=https://adapter#fragment",
		"model=https://adapter#",
		"model=https://adapter:port",
		"model=https://adapter,model=https://other",
	} {
		if got, err := parseAdapterURLs(s); err == nil {
			t.Errorf("parseAdapterURLs(%q) = %v, want error", s, got)
		}
	}
}

func TestLoadModelProfiles(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	m, err := loadModelProfiles(log, "../../../../packages/canonical/testdata/model-profiles.json")
	if err != nil || len(m) != 4 {
		t.Fatalf("valid file: %v %v", m, err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"agent":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"unset":   "",
		"missing": filepath.Join(t.TempDir(), "absent.json"),
		"invalid": bad,
	} {
		if m, err := loadModelProfiles(log, path); err == nil {
			t.Errorf("%s: loaded %v, want error", name, m)
		}
	}
}

// The bootstrap relay is required, so run stops before opening anything when
// its identity origin is missing or malformed.
func TestRunNeedsIdentityOrigin(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	base := full()
	base.identitySAN = gateway.IdentitySAN
	for _, u := range []string{"", "http://workload-identity:8443", "https://workload-identity:8443/internal", "https://workload-identity:8443?x", "https://user@workload-identity:8443", "https://workload-identity:8443#f", "https://"} {
		c := base
		c.identityURL = u
		if err := run(log, c); err == nil || !strings.Contains(err.Error(), "--identity-url") {
			t.Errorf("identity-url %q: %v", u, err)
		}
	}
	c := base
	c.identityURL, c.identitySAN = "https://workload-identity.agent-control.svc:8443", ""
	if err := run(log, c); err == nil || !strings.Contains(err.Error(), "--identity-san") {
		t.Errorf("empty identity-san: %v", err)
	}
}

func TestCertSource(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := workloadcerttest.Start(t, selfSAN)
	fileSAN := "spiffe://agentarium.internal/ns/agent-control/sa/from-file"
	certFile, keyFile := id.IssueFiles(t, fileSAN)
	absent := filepath.Join(t.TempDir(), "absent")
	identity := config{identityURL: id.URL, identitySAN: gateway.IdentitySAN, bootstrapToken: id.TokenFile, trustBundle: id.CAFile, gatewaySAN: selfSAN}

	for name, tc := range map[string]struct {
		c       config
		wantSAN string
	}{
		"file mode":               {config{identityURL: id.URL, identitySAN: gateway.IdentitySAN, trustBundle: id.CAFile, certFile: certFile, keyFile: keyFile, gatewaySAN: fileSAN}, fileSAN},
		"identity mode":           {identity, selfSAN},
		"identity trailing slash": {func() config { c := identity; c.identityURL += "/"; return c }(), selfSAN},
		// A bootstrap token selects in-memory mode even when valid files exist.
		"identity mode ignores files": {func() config { c := identity; c.certFile, c.keyFile = certFile, keyFile; return c }(), selfSAN},
	} {
		get, err := certSource(ctx, log, tc.c)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c, err := get()
		if err != nil || c.Leaf == nil {
			t.Fatalf("%s: certificate %v, %v", name, c, err)
		}
		if c.Leaf.URIs[0].String() != tc.wantSAN {
			t.Errorf("%s: SAN %s, want %s", name, c.Leaf.URIs[0], tc.wantSAN)
		}
	}

	for name, mutate := range map[string]func(*config){
		"file mode, missing files":          func(c *config) { *c = config{trustBundle: id.CAFile, certFile: absent, keyFile: absent} },
		"identity mode, no identity URL":    func(c *config) { c.identityURL = "" },
		"identity mode, other identity SAN": func(c *config) { c.identitySAN = "spiffe://agentarium.internal/ns/agent-control/sa/other" },
		"identity mode, missing token":      func(c *config) { c.bootstrapToken = absent },
		"identity mode, untrusted roots":    func(c *config) { c.trustBundle = absent },
		"identity mode, other gateway-san": func(c *config) {
			c.gatewaySAN = "spiffe://agentarium.internal/ns/agent-control/sa/other"
		},
	} {
		c := identity
		mutate(&c)
		if _, err := certSource(ctx, log, c); err == nil {
			t.Errorf("%s: started, want error", name)
		}
	}
	id.Wrong.Store(true)
	if _, err := certSource(ctx, log, identity); err == nil {
		t.Error("identity mode accepted a certificate for another SAN")
	}
}
