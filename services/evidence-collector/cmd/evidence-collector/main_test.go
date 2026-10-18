package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert/workloadcerttest"
)

func full() config {
	return config{databaseURL: "postgres://x", tenant: "hackathon", receiverURL: "https://receiver.agent-targets.svc:8443", targetID: "receiver-primary",
		trustBundle: "ca.pem", certFile: "c.pem", keyFile: "k.pem", healthURL: "https://control-health.agent-observe.svc:8443",
		healthSourceID: "evidence-collector/0", version: "v1", auditSourceID: "evidence-collector", auditSourceVersion: "v1",
		epochDir: "/var/lib/epoch", probeActionKey: "5a2b8a0e-6c0b-4b8e-9d0e-7b0c1f2a3b4c", settle: 5 * time.Second, lateWindow: time.Minute}
}

func TestEveryFlagRequired(t *testing.T) {
	if err := full().validate(); err != nil {
		t.Fatal(err)
	}
	clear := map[string]func(*config){
		"--database-url": func(c *config) { c.databaseURL = "" }, "--tenant": func(c *config) { c.tenant = "" },
		"--receiver-url": func(c *config) { c.receiverURL = "" }, "--target-id": func(c *config) { c.targetID = "" },
		"--tls-ca": func(c *config) { c.trustBundle = "" }, "--tls-cert": func(c *config) { c.certFile = "" },
		"--tls-key": func(c *config) { c.keyFile = "" }, "--health-url": func(c *config) { c.healthURL = "" },
		"--health-source-id": func(c *config) { c.healthSourceID = "" }, "--version": func(c *config) { c.version = "" },
		"--audit-source-id": func(c *config) { c.auditSourceID = "" }, "--audit-source-version": func(c *config) { c.auditSourceVersion = "" },
		"--epoch-dir": func(c *config) { c.epochDir = "" }, "--probe-action-key": func(c *config) { c.probeActionKey = "" },
	}
	for name, f := range clear {
		c := full()
		f(&c)
		if err := c.validate(); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, f := range map[string]func(*config){
		"http health":   func(c *config) { c.healthURL = "http://control-health:8443" },
		"upper uuid":    func(c *config) { c.probeActionKey = strings.ToUpper(c.probeActionKey) },
		"bad uuid":      func(c *config) { c.probeActionKey = "probe" },
		"negative wait": func(c *config) { c.settle = -time.Second },
	} {
		c := full()
		f(&c)
		if err := c.validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestObservedState(t *testing.T) {
	now := time.Now()
	if observedState(false, now.Add(-time.Second), now.Add(-time.Hour), now) != "healthy" {
		t.Fatal("fresh pass not healthy")
	}
	if observedState(true, now, now, now) != "unhealthy" {
		t.Fatal("probe failures not unhealthy")
	}
	if observedState(false, now.Add(-16*time.Second), now.Add(-time.Hour), now) != "unhealthy" {
		t.Fatal("stale loop healthy")
	}
	if observedState(false, time.Time{}, now.Add(-time.Second), now) != "healthy" {
		t.Fatal("start grace missing")
	}
	if observedState(false, time.Time{}, now.Add(-time.Minute), now) != "unhealthy" {
		t.Fatal("never-passing loop healthy")
	}
}

func TestIdentityModeFlags(t *testing.T) {
	c := full()
	c.identityURL, c.tokenFile, c.certFile, c.keyFile = "https://workload-identity.agent-control.svc:8443", "/var/run/agentarium-bootstrap/token", "", ""
	if err := c.validate(); err != nil {
		t.Fatalf("identity mode without cert files: %v", err)
	}
	c.tokenFile = ""
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "--bootstrap-token") {
		t.Fatalf("identity mode without token: %v", err)
	}
}

func TestCertSource(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := workloadcerttest.Start(t, selfSAN)
	certFile, keyFile := id.IssueFiles(t, "spiffe://agentarium.internal/ns/agent-observe/sa/from-file")
	absent := filepath.Join(t.TempDir(), "absent")

	for name, tc := range map[string]struct {
		cf      certFlags
		wantSAN string
	}{
		"file mode":     {certFlags{trustBundle: id.CAFile, certFile: certFile, keyFile: keyFile}, "spiffe://agentarium.internal/ns/agent-observe/sa/from-file"},
		"identity mode": {certFlags{identityURL: id.URL, tokenFile: id.TokenFile, trustBundle: id.CAFile, certFile: absent, keyFile: absent}, selfSAN},
		// --identity-url wins over valid files: no silent fallback.
		"identity mode ignores files": {certFlags{identityURL: id.URL, tokenFile: id.TokenFile, trustBundle: id.CAFile, certFile: certFile, keyFile: keyFile}, selfSAN},
	} {
		get, health, err := certSource(ctx, log, tc.cf)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if health == nil {
			t.Fatalf("%s: no control-health client", name)
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
		if _, _, err := certSource(ctx, log, cf); err == nil {
			t.Errorf("%s: started, want error", name)
		}
	}
	id.Wrong.Store(true)
	if _, _, err := certSource(ctx, log, certFlags{identityURL: id.URL, tokenFile: id.TokenFile, trustBundle: id.CAFile}); err == nil {
		t.Error("identity mode accepted a certificate for another SAN")
	}
}
