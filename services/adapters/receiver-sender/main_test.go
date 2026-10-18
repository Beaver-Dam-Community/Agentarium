package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/bundle"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/bundle/bundletest"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/healthlease"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert/workloadcerttest"
)

func TestPodUIDRequired(t *testing.T) {
	for v, ok := range map[string]bool{
		"6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f":  true,
		"":                                      false,
		"6F1C2D3E-4B5A-4C6D-8E7F-0A1B2C3D4E5F":  false,
		"6f1c2d3e4b5a4c6d8e7f0a1b2c3d4e5f":      false,
		" 6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f": false,
		"receiver-sender-7d9f-abcde":            false,
	} {
		got, err := podUID(func(k string) string {
			if k != "POD_UID" {
				t.Fatalf("read %s", k)
			}
			return v
		})
		if (err == nil) != ok || (ok && got != v) {
			t.Errorf("POD_UID %q: got %q err %v", v, got, err)
		}
	}
}

// full is a configuration with every required flag.
func full() config {
	return parseFlags(flag.NewFlagSet("t", flag.ContinueOnError), []string{
		"--tls-cert-file=c", "--tls-key-file=k", "--tls-ca-file=ca",
		"--coordinator-url=https://coordinator.agent-control.svc:8443", "--broker-url=https://credential-broker.agent-control.svc:8443",
		"--environment=prod", "--audit-source-id=receiver-sender", "--audit-source-version=v1", "--epoch-dir=/var/lib/agentarium/epoch",
		"--health-url=https://control-health.agent-observe.svc:8443", "--health-source-id=receiver-sender/receiver-sender-7d9f-abcde",
	})
}

func TestConfigRequiresEveryInput(t *testing.T) {
	c := full()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.storedInputs != "postgres" || c.bundleKeyID != "prod-v1" || c.bundleKeyFile != "/etc/agentarium-bundle-keys/prod-v1.pem" {
		t.Fatalf("defaults %+v", c)
	}
	for name, mut := range map[string]func(*config){
		"cert":                func(c *config) { c.certFile = "" },
		"coordinator":         func(c *config) { c.coordinatorURL = "" },
		"broker":              func(c *config) { c.brokerURL = "" },
		"environment":         func(c *config) { c.environment = "" },
		"bundle key id":       func(c *config) { c.bundleKeyID = "" },
		"bundle key file":     func(c *config) { c.bundleKeyFile = "" },
		"audit source":        func(c *config) { c.auditSourceID = "" },
		"audit version":       func(c *config) { c.auditSourceVersion = "" },
		"epoch dir":           func(c *config) { c.epochDir = "" },
		"health url":          func(c *config) { c.healthURL = "" },
		"health url http":     func(c *config) { c.healthURL = "http://control-health:8443" },
		"health url path":     func(c *config) { c.healthURL = "https://control-health:8443/x" },
		"health source":       func(c *config) { c.healthSourceID = "" },
		"source of other":     func(c *config) { c.healthSourceID = "model/receiver-sender-0" },
		"source without pod":  func(c *config) { c.healthSourceID = "receiver-sender/" },
		"source nested":       func(c *config) { c.healthSourceID = "receiver-sender/a/b" },
		"stored inputs":       func(c *config) { c.storedInputs = "unwired" },
		"stored inputs empty": func(c *config) { c.storedInputs = "" },
		"timeout":             func(c *config) { c.callTimeout = 0 },
	} {
		c := full()
		mut(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEngineNeedsEveryDependency(t *testing.T) {
	if _, err := newEngine(context.Background(), deps{}); err == nil {
		t.Fatal("engine without a pool")
	}
	// The engine's own check (used by newEngine after the database checks).
	cfg := execute.Config{Inputs: execute.Unwired{}, Bundles: &bundle.Source{}, Coordinator: &execute.HTTPCoordinator{},
		Credentials: &execute.HTTPBroker{BaseURL: "https://b", Client: &http.Client{}}, TLS: execute.Unwired{}}
	err := cfg.Wired()
	for _, want := range []string{"Auditor", "Coordinator client", "execute.Unwired"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Wired() = %v, want %s", err, want)
		}
	}
}

type fakeStatus struct{ st policyloader.Status }

func (f fakeStatus) Status() policyloader.Status { return f.st }

type fakePing struct{ err error }

func (f fakePing) Ping(context.Context) error { return f.err }

// leaseServer records the leases it acknowledges.
type leaseServer struct {
	mu     sync.Mutex
	leases []healthlease.Lease
}

func (s *leaseServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var l healthlease.Lease
	if r.URL.Path != "/internal/control-health/leases" || json.Unmarshal(b, &l) != nil {
		w.WriteHeader(400)
		return
	}
	s.mu.Lock()
	s.leases = append(s.leases, l)
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"lease_until": l.LeaseUntil, "scope_state": "healthy"})
}

func (s *leaseServer) last() healthlease.Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leases[len(s.leases)-1]
}

func TestLeaseReportsTheLoadedArtifact(t *testing.T) {
	cat, err := canonical.LoadCatalogDir("../../../packages/canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	signed := bundletest.Build(t, "bundle-1", cat, map[string]any{
		"receiver": map[string]any{"allowed_disclosure_fields": []string{"summary"}}, "adapter_constraints": map[string]any{}})
	f := &bundletest.Fetcher{}
	f.Put(signed)
	loader, err := policyloader.New(policyloader.Config{Source: bundletest.StaticSource{Row: signed.Desired()}, Fetcher: f,
		Keys: map[string]string{bundletest.KeyID: signed.PublicKeyPEM}, KeyID: bundletest.KeyID})
	if err != nil {
		t.Fatal(err)
	}
	ls := &leaseServer{}
	srv := httptest.NewTLSServer(ls)
	defer srv.Close()
	c := full()
	c.healthURL = srv.URL
	src := &bundle.Source{Loader: loader}
	status := &fakeStatus{}
	ping := &fakePing{}
	r, err := newLease(c, srv.Client(), src, status, ping)
	if err != nil {
		t.Fatal(err)
	}
	report := func() healthlease.Lease {
		t.Helper()
		if err := r.Report(context.Background()); err != nil {
			t.Fatal(err)
		}
		return ls.last()
	}
	// Before the first load: unhealthy, no version.
	l := report()
	if l.Component != "adapter" || l.Scope != "workload" || l.ScopeID != "agent-adapters/receiver-sender" ||
		l.SourceID != "receiver-sender/receiver-sender-7d9f-abcde" || l.ObservedState != "unhealthy" || l.ActiveVersion != nil ||
		l.CanonicalVersion == nil || *l.CanonicalVersion != "v1" {
		t.Fatalf("lease before load %+v", l)
	}
	if err := loader.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	l = report()
	if l.ObservedState != "healthy" || l.ActiveVersion == nil || *l.ActiveVersion != signed.ArtifactDigest ||
		l.LoadedArtifactDigest == nil || *l.LoadedArtifactDigest != signed.ArtifactDigest {
		t.Fatalf("lease after load %+v", l)
	}
	status.st.LastError = "newer bundle failed"
	if l = report(); l.ObservedState != "degraded" || *l.ActiveVersion != signed.ArtifactDigest {
		t.Fatalf("lease after a failed newer load %+v", l)
	}
	ping.err = errors.New("db down")
	if l = report(); l.ObservedState != "unhealthy" {
		t.Fatalf("lease with the database down %+v", l)
	}
}

func TestCertSource(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	id := workloadcerttest.Start(t, selfSAN)
	fileSAN := "spiffe://agentarium.internal/ns/agent-adapters/sa/from-file"
	certFile, keyFile := id.IssueFiles(t, fileSAN)
	absent := filepath.Join(t.TempDir(), "absent")
	identity := config{identityURL: id.URL, bootstrapToken: id.TokenFile, trustFile: id.CAFile}

	for name, tc := range map[string]struct {
		c       config
		wantSAN string
	}{
		"file mode":     {config{certFile: certFile, keyFile: keyFile, trustFile: id.CAFile}, fileSAN},
		"identity mode": {identity, selfSAN},
		// --identity-url wins over valid files: no silent fallback.
		"identity mode ignores files": {config{identityURL: id.URL, bootstrapToken: id.TokenFile, certFile: certFile, keyFile: keyFile, trustFile: id.CAFile}, selfSAN},
	} {
		cert, hc, err := certSource(t.Context(), logger, tc.c)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if hc == nil {
			t.Fatalf("%s: no control-health client", name)
		}
		c, err := cert()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil || leaf.URIs[0].String() != tc.wantSAN {
			t.Errorf("%s: SAN %v (%v), want %s", name, leaf, err, tc.wantSAN)
		}
		// Server and outbound clients use the same source.
		if _, err := execute.ServerTLSConfigFrom(id.CAFile, cert); err != nil {
			t.Errorf("%s: server TLS: %v", name, err)
		}
		if _, err := execute.ClientTLSConfigFrom(id.CAFile, cert, coordinatorSAN); err != nil {
			t.Errorf("%s: client TLS: %v", name, err)
		}
	}

	for name, c := range map[string]config{
		"file mode, no cert flags":       {trustFile: id.CAFile},
		"no trust bundle":                {identityURL: id.URL, bootstrapToken: id.TokenFile},
		"identity mode, no token flag":   {identityURL: id.URL, certFile: certFile, keyFile: keyFile, trustFile: id.CAFile},
		"identity mode, missing token":   {identityURL: id.URL, bootstrapToken: absent, trustFile: id.CAFile},
		"identity mode, untrusted roots": {identityURL: id.URL, bootstrapToken: id.TokenFile, trustFile: absent},
	} {
		if _, _, err := certSource(t.Context(), logger, c); err == nil {
			t.Errorf("%s: started, want error", name)
		}
	}
	id.Wrong.Store(true)
	if _, _, err := certSource(t.Context(), logger, identity); err == nil {
		t.Error("identity mode accepted a certificate for another SAN")
	}
}
