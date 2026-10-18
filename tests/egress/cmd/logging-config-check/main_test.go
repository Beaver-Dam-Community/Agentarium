package main

import (
	"encoding/json"
	"os"
	"testing"

	"sigs.k8s.io/yaml"
)

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// live returns kubectl-shaped JSON built from the reviewed files, as if the
// installer applied them unchanged. mutate edits the decoded objects first.
func live(t *testing.T, mutateLogging func(map[string]any), mutatePolicies func([]any) []any) ([]byte, []byte, []byte, []byte) {
	t.Helper()
	manifest := read(t, "../../../../deploy/gcp/base/network/network-logging.yaml")
	rendered := read(t, "../../../../deploy/gcp/base/network/rendered/policies.yaml")
	j, err := yaml.YAMLToJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var nl map[string]any
	if err := json.Unmarshal(j, &nl); err != nil {
		t.Fatal(err)
	}
	nl["status"] = map[string]any{}
	nl["metadata"].(map[string]any)["uid"] = "00000000-0000-4000-8000-000000000000"
	if mutateLogging != nil {
		mutateLogging(nl)
	}
	var list map[string]any
	if err := json.Unmarshal(rendered, &list); err != nil {
		t.Fatal(err)
	}
	items := list["items"].([]any)
	for _, item := range items {
		meta := item.(map[string]any)["metadata"].(map[string]any)
		annotations, _ := meta["annotations"].(map[string]any)
		if annotations == nil {
			annotations = map[string]any{}
		}
		annotations["kubectl.kubernetes.io/last-applied-configuration"] = "{}"
		meta["annotations"] = annotations
	}
	if mutatePolicies != nil {
		items = mutatePolicies(items)
	}
	list["items"] = items
	a, _ := json.Marshal(nl)
	b, _ := json.Marshal(list)
	return manifest, rendered, a, b
}

func find(items []any, namespace, name string) map[string]any {
	for _, item := range items {
		meta := item.(map[string]any)["metadata"].(map[string]any)
		if meta["namespace"] == namespace && meta["name"] == name {
			return meta
		}
	}
	return nil
}

func failed(r report) map[string]bool {
	out := map[string]bool{}
	for _, c := range r.Checks {
		if !c.Passed {
			out[c.Name] = true
		}
	}
	return out
}

func TestInstalledAsReviewedPasses(t *testing.T) {
	r, err := evaluate(live(t, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Passed || len(r.Checks) != 4 {
		t.Fatalf("%+v", r)
	}
	var on []string
	for _, c := range r.Checks {
		if c.Name == "allow_logging_annotated_policies" {
			on = c.Expected.([]string)
		}
	}
	if len(on) != 8 {
		t.Fatalf("expected the 8 agent-exec/agent-adapters allow policies, got %v", on)
	}
}

func TestDriftFails(t *testing.T) {
	cluster := func(nl map[string]any) map[string]any {
		return nl["spec"].(map[string]any)["cluster"].(map[string]any)
	}
	cases := map[string]struct {
		logging  func(map[string]any)
		policies func([]any) []any
		check    string
	}{
		"deny logging off": {logging: func(nl map[string]any) {
			cluster(nl)["deny"].(map[string]any)["log"] = false
		}, check: "network_logging_spec"},
		"deny delegated": {logging: func(nl map[string]any) {
			cluster(nl)["deny"].(map[string]any)["delegate"] = true
		}, check: "network_logging_spec"},
		"allow everything": {logging: func(nl map[string]any) {
			cluster(nl)["allow"].(map[string]any)["delegate"] = false
		}, check: "network_logging_spec"},
		"extra spec field": {logging: func(nl map[string]any) {
			nl["spec"].(map[string]any)["node"] = map[string]any{}
		}, check: "network_logging_spec"},
		"missing spec": {logging: func(nl map[string]any) { delete(nl, "spec") }, check: "network_logging_spec"},
		"wrong name": {logging: func(nl map[string]any) {
			nl["metadata"].(map[string]any)["name"] = "other"
		}, check: "network_logging_identity"},
		"annotation removed": {policies: func(items []any) []any {
			delete(find(items, "agent-exec", "agent-runtime-allow")["annotations"].(map[string]any), annotation)
			return items
		}, check: "allow_logging_annotated_policies"},
		"annotation false": {policies: func(items []any) []any {
			find(items, "agent-adapters", "receiver-sender-allow")["annotations"].(map[string]any)[annotation] = "false"
			return items
		}, check: "allow_logging_annotated_policies"},
		"annotation outside scope": {policies: func(items []any) []any {
			find(items, "agent-control", "policy-gateway-allow")["annotations"].(map[string]any)[annotation] = "true"
			return items
		}, check: "allow_logging_annotated_policies"},
		"default deny annotated": {policies: func(items []any) []any {
			find(items, "agent-exec", "default-deny")["annotations"].(map[string]any)[annotation] = "true"
			return items
		}, check: "allow_logging_annotated_policies"},
		"extra annotated live policy": {policies: func(items []any) []any {
			return append(items, map[string]any{"metadata": map[string]any{
				"namespace": "agent-exec", "name": "temporary-allow",
				"annotations": map[string]any{annotation: "true"}}})
		}, check: "allow_logging_annotated_policies"},
		"unannotated policy missing": {policies: func(items []any) []any {
			out := items[:0:0]
			for _, item := range items {
				meta := item.(map[string]any)["metadata"].(map[string]any)
				if meta["namespace"] != "agent-control" || meta["name"] != "default-deny" {
					out = append(out, item)
				}
			}
			return out
		}, check: "rendered_policies_missing_live"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := evaluate(live(t, c.logging, c.policies))
			if err != nil {
				t.Fatal(err)
			}
			if r.Passed || !failed(r)[c.check] {
				t.Fatalf("expected %s to fail: %+v", c.check, r)
			}
		})
	}
}

func TestMalformedInputIsAnError(t *testing.T) {
	m, rendered, l, p := live(t, nil, nil)
	for name, in := range map[string][4][]byte{
		"live logging":          {m, rendered, []byte("{"), p},
		"live policies":         {m, rendered, l, []byte("[")},
		"empty rendered":        {m, []byte(`{"items":[]}`), l, p},
		"manifest without spec": {[]byte("kind: NetworkLogging\n"), rendered, l, p},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := evaluate(in[0], in[1], in[2], in[3]); err == nil {
				t.Fatal("expected an input error, not a report")
			}
		})
	}
}
