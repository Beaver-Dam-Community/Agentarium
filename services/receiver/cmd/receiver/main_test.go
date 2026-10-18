package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert/workloadcerttest"
)

func TestCertSource(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := workloadcerttest.Start(t, selfSAN)
	certFile, keyFile := id.IssueFiles(t, "spiffe://agentarium.internal/ns/agent-targets/sa/from-file")
	absent := filepath.Join(t.TempDir(), "absent")

	for name, tc := range map[string]struct {
		cf      certFlags
		wantSAN string
	}{
		"file mode":     {certFlags{trustBundle: id.CAFile, certFile: certFile, keyFile: keyFile}, "spiffe://agentarium.internal/ns/agent-targets/sa/from-file"},
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
