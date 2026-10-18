package gateway

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

func testModelProfiles(t *testing.T) map[string]canonical.ModelProfileConfig {
	t.Helper()
	m, err := canonical.LoadModelProfiles(filepath.Join(repoRoot, "packages/canonical/testdata/model-profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func modelBody(session, key, profile string) string {
	phase := ""
	if profile == "policy_proposal" {
		phase = `,"phase":"final"`
	}
	return `{"session_id":"` + session + `","operation_id":"model.generate","requested_target":{"target_id":"agent-platform-gemini","profile":"` + profile + `"},` +
		`"arguments":{"conversation_id":"` + uuid.NewString() + `","messages":[{"kind":"text","role":"user","source":"user","text":"요약해 줘","ref":null,"function_name":null}],` +
		`"tool_declarations":[]` + phase + `},"client_request_key":"` + key + `"}`
}

// TestServiceCatalogModelProfiles: the catalog from the real
// policyloader Snapshot.Catalog() has no ModelProfiles (json:"-"), so
// model.generate was always 403 ENDPOINT_NOT_REGISTERED. Service.catalog
// attaches the installed profiles.
func TestServiceCatalogModelProfiles(t *testing.T) {
	p := loadTestPolicy(t, "")
	snap := p.loader.Current()
	c := serviceCaller()
	trusted := canonical.TrustedContext{ActionID: uuid.NewString(), RequestID: uuid.NewString(), AuthenticatedActor: c.AuthenticatedActor,
		SessionKind: c.Kind, SessionID: c.SessionID, Tenant: c.Tenant, Environment: "test", WorkloadDataState: synthetic}
	body := []byte(modelBody(c.SessionID, "key-model-1", "policy_proposal"))

	bare, err := (&Service{}).catalog(snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ne := canonical.NormalizeRaw(body, trusted, bare); ne == nil || ne.ReasonCodes[0] != "ENDPOINT_NOT_REGISTERED" {
		t.Fatalf("without profiles: %v, want ENDPOINT_NOT_REGISTERED", ne)
	}

	s := &Service{ModelProfiles: testModelProfiles(t)}
	cat, err := s.catalog(snap)
	if err != nil {
		t.Fatal(err)
	}
	env, _, ne := canonical.NormalizeRaw(body, trusted, cat)
	if ne != nil {
		t.Fatalf("with profiles: %v", ne)
	}
	if env.Limits["max_output_tokens"] != 8192 || env.Limits["max_request_bytes"] != 65536 || env.CatalogDigest != p.catalog.CatalogDigest {
		t.Fatalf("envelope limits %v catalog_digest %s", env.Limits, env.CatalogDigest)
	}

	// The per-request catalog does not share storage with the install config.
	delete(cat.ModelProfiles, "policy_proposal")
	again, _ := s.catalog(snap)
	if _, ok := again.ModelProfiles["policy_proposal"]; !ok || len(s.ModelProfiles) != 4 {
		t.Fatal("catalog() shares the installed profile map")
	}
}
