package main

import (
	"context"
	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert/workloadcerttest"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/healthlease"
	"github.com/Beaver-Dam-Community/Agentarium/services/coordinator/internal/dispatch"
)

func full() config {
	return config{listen: ":8443", dbURL: "postgres://coordinator@127.0.0.1:5432/agentarium", trustBundle: "/ca.pem",
		certFile: "/tls.crt", keyFile: "/tls.key", environment: "prod", auditSourceID: "coordinator",
		auditSourceVersion: "v1", epochDir: "/var/lib/agentarium/epoch",
		healthURL: "https://control-health.agent-observe.svc:8443", healthSourceID: "coordinator/pod-1"}
}

func TestValidateFailsClosed(t *testing.T) {
	if err := full().validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*config){
		"database-url":         func(c *config) { c.dbURL = "" },
		"environment":          func(c *config) { c.environment = "" },
		"audit-source-id":      func(c *config) { c.auditSourceID = "" },
		"audit-source-version": func(c *config) { c.auditSourceVersion = "" },
		"epoch-dir":            func(c *config) { c.epochDir = "" },
		"health-url":           func(c *config) { c.healthURL = "" },
		"health-source-id":     func(c *config) { c.healthSourceID = "" },
		"trust-bundle":         func(c *config) { c.trustBundle = "" },
		"tls-cert":             func(c *config) { c.certFile = "" },
	} {
		c := full()
		mut(&c)
		err := c.validate()
		if err == nil || !strings.Contains(err.Error(), "--"+name) {
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
	// run refuses before opening anything.
	c := full()
	c.environment = ""
	if err := run(slog.New(slog.NewTextHandler(io.Discard, nil)), c); err == nil || !strings.Contains(err.Error(), "--environment") {
		t.Fatalf("run without environment: %v", err)
	}
}

// newService leaves no dependency to the Unwired default.
func TestNewServiceWiresEveryDependency(t *testing.T) {
	pool, err := pgxpool.New(t.Context(), full().dbURL) // lazy: no connection is made
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	svc, err := newService(pool, slog.Default(), full(), "4", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := svc.Policy.(dispatch.PGPolicy); !ok || p.Environment != "prod" {
		t.Errorf("policy %#v", svc.Policy)
	}
	if _, ok := svc.Decisions.(dispatch.PGDecisions); !ok {
		t.Errorf("decisions %#v", svc.Decisions)
	}
	if _, ok := svc.Health.(dispatch.PGHealth); !ok {
		t.Errorf("health %#v", svc.Health)
	}
	if _, ok := svc.Audit.(*dispatch.PGAuditor); !ok {
		t.Errorf("audit %#v", svc.Audit)
	}
	l, ok := svc.Leases.(healthlease.Reporter)
	if !ok || l.Component != "coordinator" || l.Scope != "global" || l.ScopeID != "*" || l.SourceID != "coordinator/pod-1" ||
		l.URL != full().healthURL {
		t.Errorf("lease %#v", svc.Leases)
	}

	for name, c := range map[string]config{
		"no audit epoch source": func() config { c := full(); c.auditSourceID = ""; return c }(),
		"no environment":        func() config { c := full(); c.environment = ""; return c }(),
	} {
		if _, err := newService(pool, slog.Default(), c, "4", &http.Client{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := newService(pool, slog.Default(), full(), "", &http.Client{}); err == nil {
		t.Error("empty producer epoch accepted")
	}
	if _, err := newService(pool, slog.Default(), full(), "4", nil); err == nil {
		t.Error("no control-health client accepted")
	}
}

func TestCertSource(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := workloadcerttest.Start(t, selfSAN)
	certFile, keyFile := id.IssueFiles(t, "spiffe://agentarium.internal/ns/agent-control/sa/from-file")
	absent := filepath.Join(t.TempDir(), "absent")

	for name, tc := range map[string]struct {
		cf      certFlags
		wantSAN string
	}{
		"file mode":     {certFlags{trustBundle: id.CAFile, certFile: certFile, keyFile: keyFile}, "spiffe://agentarium.internal/ns/agent-control/sa/from-file"},
		"identity mode": {certFlags{identityURL: id.URL, tokenFile: id.TokenFile, trustBundle: id.CAFile, certFile: absent, keyFile: absent}, selfSAN},
		// --identity-url wins over valid files: no silent fallback.
		"identity mode ignores files": {certFlags{identityURL: id.URL, tokenFile: id.TokenFile, trustBundle: id.CAFile, certFile: certFile, keyFile: keyFile}, selfSAN},
	} {
		get, err := certSource(ctx, log, tc.cf)
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

	for name, cf := range map[string]certFlags{
		"file mode, missing files":       {trustBundle: id.CAFile, certFile: absent, keyFile: absent},
		"identity mode, no token flag":   {identityURL: id.URL, trustBundle: id.CAFile, certFile: certFile, keyFile: keyFile},
		"identity mode, missing token":   {identityURL: id.URL, tokenFile: absent, trustBundle: id.CAFile, certFile: certFile, keyFile: keyFile},
		"identity mode, untrusted roots": {identityURL: id.URL, tokenFile: id.TokenFile, trustBundle: absent},
	} {
		if _, err := certSource(ctx, log, cf); err == nil {
			t.Errorf("%s: started, want error", name)
		}
	}
	id.Wrong.Store(true)
	if _, err := certSource(ctx, log, certFlags{identityURL: id.URL, tokenFile: id.TokenFile, trustBundle: id.CAFile}); err == nil {
		t.Error("identity mode accepted a certificate for another SAN")
	}
}
