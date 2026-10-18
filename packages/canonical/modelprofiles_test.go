package canonical

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const profilesBase = `{` +
	`"agent":{"max_output_tokens":8192,"max_request_bytes":65536,"generation_config":{"temperature":0.2,"maxOutputTokens":8192},"response_schema":null},` +
	`"policy_proposal":{"max_output_tokens":8192,"max_request_bytes":65536,"generation_config":{"temperature":0},"response_schema":{"type":"object"}},` +
	`"intent_check":{"max_output_tokens":1024,"max_request_bytes":16384,"generation_config":{"temperature":0},"response_schema":{"type":"object"}},` +
	`"discovery":{"max_output_tokens":8192,"max_request_bytes":65536,"generation_config":{"temperature":0},"response_schema":{"type":"array"}}}`

func TestParseModelProfiles(t *testing.T) {
	m, err := ParseModelProfiles([]byte(profilesBase))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 4 {
		t.Fatalf("got %d profiles", len(m))
	}
	if m["agent"].ResponseSchema != nil {
		t.Errorf("null response_schema should decode as nil")
	}
	if ic := m["intent_check"]; ic.MaxOutputTokens != 1024 || ic.MaxRequestBytes != 16384 || string(ic.ResponseSchema) != `{"type":"object"}` {
		t.Errorf("intent_check = %+v", ic)
	}
	d1, err := ModelProfilesDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	// Whitespace and key order do not change the digest.
	f, err := LoadModelProfiles(filepath.Join("testdata", "model-profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	f["intent_check"] = m["intent_check"] // the fixture's output schemas differ
	f["discovery"] = m["discovery"]
	d2, _ := ModelProfilesDigest(f)
	if d1 != d2 || len(d1) != 64 {
		t.Errorf("digest %q vs %q", d1, d2)
	}
}

func TestParseModelProfilesRejects(t *testing.T) {
	agent := `"agent":{"max_output_tokens":8192,"max_request_bytes":65536,"generation_config":{"temperature":0.2,"maxOutputTokens":8192},"response_schema":null}`
	ic := `"intent_check":{"max_output_tokens":1024,"max_request_bytes":16384,"generation_config":{"temperature":0},"response_schema":{"type":"object"}}`
	cases := map[string]string{
		"missing profile":             strings.Replace(profilesBase, agent+",", "", 1),
		"extra profile":               strings.Replace(profilesBase, "{"+agent, `{"activation_probe":{"max_output_tokens":1,"max_request_bytes":1,"generation_config":{},"response_schema":null},`+agent, 1),
		"profile case":                strings.Replace(profilesBase, `"agent":`, `"Agent":`, 1),
		"duplicate profile":           strings.Replace(profilesBase, "{"+agent, "{"+agent+","+agent, 1),
		"profile not object":          strings.Replace(profilesBase, agent, `"agent":null`, 1),
		"unknown profile field":       strings.Replace(profilesBase, `"max_request_bytes":65536,"generation_config":{"temperature":0.2`, `"max_request_bytes":65536,"model":"x","generation_config":{"temperature":0.2`, 1),
		"missing profile field":       strings.Replace(profilesBase, `,"response_schema":null}`, `}`, 1),
		"duplicate profile field":     strings.Replace(profilesBase, `"max_output_tokens":8192,`, `"max_output_tokens":8192,"max_output_tokens":8192,`, 1),
		"zero max_output_tokens":      strings.Replace(profilesBase, `"max_output_tokens":1024`, `"max_output_tokens":0`, 1),
		"negative max_request_bytes":  strings.Replace(profilesBase, `"max_request_bytes":16384`, `"max_request_bytes":-1`, 1),
		"fractional limit":            strings.Replace(profilesBase, `"max_request_bytes":16384`, `"max_request_bytes":16384.5`, 1),
		"integral fraction limit":     strings.Replace(profilesBase, `"max_request_bytes":16384`, `"max_request_bytes":16384.0`, 1),
		"exponent limit":              strings.Replace(profilesBase, `"max_request_bytes":16384`, `"max_request_bytes":1e4`, 1),
		"string limit":                strings.Replace(profilesBase, `"max_request_bytes":16384`, `"max_request_bytes":"16384"`, 1),
		"limit beyond 2^53":           strings.Replace(profilesBase, `"max_request_bytes":16384`, `"max_request_bytes":9007199254740993`, 1),
		"generation_config null":      strings.Replace(profilesBase, `"generation_config":{"temperature":0},"response_schema":{"type":"object"}}`, `"generation_config":null,"response_schema":{"type":"object"}}`, 1),
		"generation_config array":     strings.Replace(profilesBase, `"generation_config":{"temperature":0},"response_schema":{"type":"object"}}`, `"generation_config":[],"response_schema":{"type":"object"}}`, 1),
		"intent_check schema null":    strings.Replace(profilesBase, ic, strings.Replace(ic, `"response_schema":{"type":"object"}`, `"response_schema":null`, 1), 1),
		"policy_proposal schema null": strings.Replace(profilesBase, `"generation_config":{"temperature":0},"response_schema":{"type":"object"}},"intent_check"`, `"generation_config":{"temperature":0},"response_schema":null},"intent_check"`, 1),
		"discovery schema null":       strings.Replace(profilesBase, `"response_schema":{"type":"array"}}}`, `"response_schema":null}}`, 1),
		"intent_check schema array":   strings.Replace(profilesBase, ic, strings.Replace(ic, `"response_schema":{"type":"object"}`, `"response_schema":[]`, 1), 1),
		"agent schema string":         strings.Replace(profilesBase, `"maxOutputTokens":8192},"response_schema":null`, `"maxOutputTokens":8192},"response_schema":"x"`, 1),
		"maxOutputTokens mismatch":    strings.Replace(profilesBase, `"maxOutputTokens":8192`, `"maxOutputTokens":4096`, 1),
		"maxOutputTokens string":      strings.Replace(profilesBase, `"maxOutputTokens":8192`, `"maxOutputTokens":"8192"`, 1),
		"duplicate in gen config":     strings.Replace(profilesBase, `"temperature":0.2,`, `"temperature":0.2,"temperature":0.3,`, 1),
		"trailing data":               profilesBase + `{}`,
		"trailing garbage":            profilesBase + ` x`,
		"top-level array":             `[` + profilesBase + `]`,
		"empty":                       ``,
		"invalid utf-8":               strings.Replace(profilesBase, `"temperature":0.2`, "\"temp\xff\":0.2", 1),
	}
	for name, in := range cases {
		if in == profilesBase {
			t.Fatalf("%s: mutation did not apply", name)
		}
		m, err := ParseModelProfiles([]byte(in))
		if err == nil {
			t.Errorf("%s: accepted %v", name, m)
			continue
		}
		t.Logf("%s: %v", name, err)
	}
}

func TestLoadModelProfilesMissingFile(t *testing.T) {
	if _, err := LoadModelProfiles(filepath.Join(t.TempDir(), "absent.json")); !os.IsNotExist(err) {
		t.Fatalf("err = %v, want not-exist", err)
	}
}

// TestModelProfilesFixNormalize reproduces the gateway bug: the bundle
// catalog round-trips through JSON (policyloader Snapshot.Catalog) and loses
// ModelProfiles, so model.generate is 403 ENDPOINT_NOT_REGISTERED until the
// loaded profiles are attached.
func TestModelProfilesFixNormalize(t *testing.T) {
	src := testCatalog(t)
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	var cat Catalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	body := `{"session_id":"` + testSession + `","operation_id":"model.generate","requested_target":{"target_id":"agent-platform-gemini","profile":"agent"},` +
		`"arguments":{"conversation_id":"` + conv + `","messages":[` + msgUser + `],"tool_declarations":[]},"client_request_key":"key-model-1"}`
	if _, _, ne := NormalizeRaw([]byte(body), testTrusted(), cat); ne == nil || len(ne.ReasonCodes) != 1 || ne.ReasonCodes[0] != "ENDPOINT_NOT_REGISTERED" {
		t.Fatalf("without profiles: %v, want ENDPOINT_NOT_REGISTERED", ne)
	}
	m, err := LoadModelProfiles(filepath.Join("testdata", "model-profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	cat.ModelProfiles = CloneModelProfiles(m)
	env, _, ne := NormalizeRaw([]byte(body), testTrusted(), cat)
	if ne != nil {
		t.Fatalf("with profiles: %v", ne)
	}
	if env.Limits["max_output_tokens"] != 8192 || env.Limits["max_request_bytes"] != 65536 {
		t.Errorf("limits = %v", env.Limits)
	}
}

func TestCloneModelProfiles(t *testing.T) {
	m, err := ParseModelProfiles([]byte(profilesBase))
	if err != nil {
		t.Fatal(err)
	}
	c := CloneModelProfiles(m)
	c["intent_check"].GenerationConfig[0] = 'X'
	delete(c, "agent")
	if m["intent_check"].GenerationConfig[0] != '{' || len(m) != 4 {
		t.Fatal("clone shares storage with the original")
	}
	if CloneModelProfiles(nil) != nil {
		t.Fatal("clone of nil should be nil")
	}
}
