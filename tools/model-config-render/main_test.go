package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

func fixture(t *testing.T) (map[string]any, canonical.Catalog) {
	t.Helper()
	cat, err := canonical.LoadCatalogDir("../../packages/canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../packages/canonical/testdata/model-profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	var profiles any
	if err := json.Unmarshal(raw, &profiles); err != nil {
		t.Fatal(err)
	}
	tools := map[string]any{}
	for profile, list := range names {
		declarations := []any{}
		for _, name := range list {
			declarations = append(declarations, map[string]any{"name": name, "description": "Synthetic test declaration", "parameters": map[string]any{"type": "object"}})
		}
		tools[profile] = declarations
	}
	return map[string]any{"project": map[string]any{"id": "agentarium-test"}, "model": map[string]any{
		"model_id": "gemini-test-model", "model_region": "us-central1", "api_version": "v1", "profiles": profiles, "tools": tools,
	}}, cat
}
func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestIdenticalNamespaceCopiesAndImageDigest(t *testing.T) {
	lock, cat := fixture(t)
	tools := encode(t, lock["model"].(map[string]any)["tools"])
	files, err := artifacts(encode(t, lock), cat, tools)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatal("unexpected outputs")
	}
	var list struct {
		Items []struct {
			Immutable bool `json:"immutable"`
			Metadata  struct {
				Namespace   string            `json:"namespace"`
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}
	if err := json.Unmarshal(files["configmaps.json"], &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 3 {
		t.Fatal("missing namespace copies")
	}
	for i, item := range list.Items {
		if !item.Immutable || item.Metadata.Namespace != []string{"agent-control", "agent-adapters", "agent-observe"}[i] || item.Metadata.Name != list.Items[0].Metadata.Name {
			t.Fatal("namespace/name/immutable differs")
		}
		for _, name := range []string{"model-profiles.json", "model-tools.json"} {
			if item.Data[name] != string(files[name]) {
				t.Fatal("config copy differs")
			}
			digest, e := canonical.CanonicalDigestJSON(files[name])
			if e != nil {
				t.Fatal(e)
			}
			key := "agentarium.io/" + strings.TrimSuffix(name, ".json") + "-digest"
			if item.Metadata.Annotations[key] != digest {
				t.Fatal("digest differs")
			}
		}
	}
	padded := append([]byte("\n"), tools...)
	if _, err := artifacts(encode(t, lock), cat, padded); err != nil {
		t.Fatal("whitespace should preserve JCS digest", err)
	}
	wrong := bytes.Replace(tools, []byte("Synthetic test declaration"), []byte("Different description"), 1)
	if _, err := artifacts(encode(t, lock), cat, wrong); err == nil {
		t.Fatal("accepted stale image")
	}
}

func TestRejectMismatchesBeforeOutput(t *testing.T) {
	cases := map[string]func(map[string]any, *canonical.Catalog){
		"missing model":   func(l map[string]any, c *canonical.Catalog) { delete(l, "model") },
		"extra model key": func(l map[string]any, c *canonical.Catalog) { l["model"].(map[string]any)["override"] = true },
		"project":         func(l map[string]any, c *canonical.Catalog) { l["project"].(map[string]any)["id"] = "other-project" },
		"model":           func(l map[string]any, c *canonical.Catalog) { l["model"].(map[string]any)["model_id"] = "other-model" },
		"location":        func(l map[string]any, c *canonical.Catalog) { l["model"].(map[string]any)["model_region"] = "global" },
		"API":             func(l map[string]any, c *canonical.Catalog) { l["model"].(map[string]any)["api_version"] = "v1beta1" },
		"tools null": func(l map[string]any, c *canonical.Catalog) {
			l["model"].(map[string]any)["tools"].(map[string]any)["intent_check"] = nil
		},
		"wrong order": func(l map[string]any, c *canonical.Catalog) {
			a := l["model"].(map[string]any)["tools"].(map[string]any)["agent"].([]any)
			a[0], a[1] = a[1], a[0]
		},
		"request limit": func(l map[string]any, c *canonical.Catalog) {
			l["model"].(map[string]any)["profiles"].(map[string]any)["intent_check"].(map[string]any)["max_request_bytes"] = 65536
		},
		"token limit": func(l map[string]any, c *canonical.Catalog) {
			l["model"].(map[string]any)["profiles"].(map[string]any)["intent_check"].(map[string]any)["max_output_tokens"] = 1025
		},
		"missing schema": func(l map[string]any, c *canonical.Catalog) {
			l["model"].(map[string]any)["profiles"].(map[string]any)["policy_proposal"].(map[string]any)["response_schema"] = nil
		},
		"no model target": func(l map[string]any, c *canonical.Catalog) { delete(c.Targets, "agent-platform-gemini") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			lock, cat := fixture(t)
			change(lock, &cat)
			if _, err := artifacts(encode(t, lock), cat, nil); err == nil {
				t.Fatal("accepted invalid installation")
			}
		})
	}
	lock, cat := fixture(t)
	dup := bytes.Replace(encode(t, lock), []byte(`"api_version":"v1"`), []byte(`"api_version":"v1","api_version":"v1"`), 1)
	if _, err := artifacts(dup, cat, nil); err == nil {
		t.Fatal("accepted duplicate key")
	}
}

func TestOutputDoesNotOverwriteAndFailureLeavesNothing(t *testing.T) {
	root := t.TempDir()
	lock, _ := fixture(t)
	path := filepath.Join(root, "lock.json")
	out := filepath.Join(root, "out")
	if err := os.WriteFile(path, encode(t, lock), 0600); err != nil {
		t.Fatal(err)
	}
	cat := "../../packages/canonical/testdata/catalog"
	if err := run(path, cat, out, ""); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(out, "model-tools.json"))
	if err := run(path, cat, out, ""); err == nil {
		t.Fatal("overwrote existing output")
	}
	after, _ := os.ReadFile(filepath.Join(out, "model-tools.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("changed previous output")
	}
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	failed := filepath.Join(root, "failed")
	if err := run(path, cat, failed, ""); err == nil {
		t.Fatal("accepted absent model")
	}
	if _, err := os.Stat(failed); !os.IsNotExist(err) {
		t.Fatal("created invalid output")
	}
}
