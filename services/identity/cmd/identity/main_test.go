package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsMissingTemplatesBeforeExternalSetup(t *testing.T) {
	const template = "projects/p/locations/l/certificateTemplates/service"
	for _, tc := range []struct{ service, client string }{{"", ""}, {template, ""}, {"", template}} {
		// The nonexistent claim key distinguishes configuration rejection from
		// later file reads, credentials, DB, Kubernetes and CAS setup.
		err := run(nil, ":8443", "projects/p/locations/l/caPools/pool", tc.service, tc.client,
			"postgres://unused", "", "agent-control", "workload-identity",
			filepath.Join(t.TempDir(), "missing-claim-key"), "", "test", nil, apiFlags{})
		if err == nil || !strings.Contains(err.Error(), "certificate template resource names") {
			t.Fatalf("missing template configuration reached external setup: %v", err)
		}
	}
}

// --session-apis fails closed at startup when an OIDC, bundle key or audit
// input is missing, before any external client is created.
func TestRunRejectsIncompleteSessionAPIs(t *testing.T) {
	dir := t.TempDir()
	roleMap := filepath.Join(dir, "role-map.yaml")
	key := filepath.Join(dir, "prod-v1.pem")
	if err := os.WriteFile(roleMap, []byte("tenant: hackathon\nusers:\n  - email: a@example.org\n    roles: [approver]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("unused"), 0o600); err != nil {
		t.Fatal(err)
	}
	full := func() apiFlags {
		return apiFlags{enabled: true, audiences: listFlag{"32555940559.apps.googleusercontent.com"}, domains: listFlag{"example.org"},
			roleMap: roleMap, bundleKeyID: "prod-v1", bundleKeyFile: key, auditSourceID: "identity", auditSourceVersion: "v1", epochDir: dir}
	}
	for want, mod := range map[string]func(*apiFlags){
		"--oidc-audience":        func(f *apiFlags) { f.audiences = nil },
		"--oidc-allowed-hd":      func(f *apiFlags) { f.domains = nil },
		"--oidc-role-map: open":  func(f *apiFlags) { f.roleMap = filepath.Join(dir, "missing.yaml") },
		"--bundle-key-file":      func(f *apiFlags) { f.bundleKeyFile = filepath.Join(dir, "missing.pem") },
		"--bundle-key-id":        func(f *apiFlags) { f.bundleKeyID = "" },
		"--audit-source-id":      func(f *apiFlags) { f.auditSourceID = "" },
		"--audit-source-version": func(f *apiFlags) { f.auditSourceVersion = "" },
		"--epoch-dir":            func(f *apiFlags) { f.epochDir = "" },
	} {
		api := full()
		mod(&api)
		err := run(nil, ":8443", "projects/p/locations/l/caPools/pool", "", "", "postgres://unused", "", "agent-control", "workload-identity",
			filepath.Join(dir, "missing-claim-key"), "", "test", nil, api)
		if err == nil || !strings.Contains(err.Error(), strings.TrimSuffix(want, ": open")) {
			t.Errorf("%s: %v", want, err)
		}
	}
	// Complete API inputs pass on to the existing configuration checks.
	err := run(nil, ":8443", "projects/p/locations/l/caPools/pool", "", "", "postgres://unused", "", "agent-control", "workload-identity",
		filepath.Join(dir, "missing-claim-key"), "", "test", nil, full())
	if err == nil || !strings.Contains(err.Error(), "certificate template resource names") {
		t.Fatalf("complete inputs: %v", err)
	}
}

func TestListFlag(t *testing.T) {
	var l listFlag
	_ = l.Set("a, b,,")
	_ = l.Set("c")
	if l.String() != "a,b,c" {
		t.Fatal(l)
	}
}
