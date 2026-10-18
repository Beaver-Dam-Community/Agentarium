package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"sigs.k8s.io/yaml"
)

// pruneSchema keeps the default-bearing part of a structural schema node.
func pruneSchema(n map[string]any) *schemaNode {
	out := &schemaNode{}
	if d, ok := n["default"]; ok {
		out.Default, _ = json.Marshal(d)
	}
	if props, ok := n["properties"].(map[string]any); ok {
		for k, c := range props {
			if p := pruneSchema(c.(map[string]any)); p != nil {
				if out.Properties == nil {
					out.Properties = map[string]*schemaNode{}
				}
				out.Properties[k] = p
			}
		}
	}
	if items, ok := n["items"].(map[string]any); ok {
		out.Items = pruneSchema(items)
	}
	if ap, ok := n["additionalProperties"].(map[string]any); ok {
		out.AdditionalProperties = pruneSchema(ap)
	}
	if out.Default == nil && out.Properties == nil && out.Items == nil && out.AdditionalProperties == nil {
		return nil
	}
	return out
}

// TestCRDDefaultsMatchPinnedCRD regenerates crd_defaults.json from the pinned
// Tetragon 1.7.1 CRDs when TETRAGON_CRD_DIR points at
// install/kubernetes/tetragon/crds-yaml of that release. With
// UPDATE_CRD_DEFAULTS=1 it rewrites the file.
func TestCRDDefaultsMatchPinnedCRD(t *testing.T) {
	dir := os.Getenv("TETRAGON_CRD_DIR")
	if dir == "" {
		t.Skip("TETRAGON_CRD_DIR not set; crd_defaults.json not regenerated")
	}
	gen := crdDefaults{Source: map[string]string{"release": "cilium/tetragon v1.7.1"}, Specs: map[string]*schemaNode{}}
	for kind, file := range map[string]string{"TracingPolicy": "cilium.io_tracingpolicies.yaml", "TracingPolicyNamespaced": "cilium.io_tracingpoliciesnamespaced.yaml"} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		gen.Source[file] = "sha256:" + hex.EncodeToString(sum[:])
		var crd struct {
			Spec struct {
				Names    struct{ Kind string }
				Versions []struct {
					Name   string
					Schema struct {
						OpenAPIV3Schema map[string]any `json:"openAPIV3Schema"`
					}
				}
			}
		}
		if err := yaml.Unmarshal(raw, &crd); err != nil {
			t.Fatal(err)
		}
		if crd.Spec.Names.Kind != kind || len(crd.Spec.Versions) != 1 || crd.Spec.Versions[0].Name != "v1alpha1" {
			t.Fatalf("%s: unexpected CRD shape", file)
		}
		spec := crd.Spec.Versions[0].Schema.OpenAPIV3Schema["properties"].(map[string]any)["spec"].(map[string]any)
		gen.Specs[kind] = pruneSchema(spec)
	}
	want, err := json.MarshalIndent(gen, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if os.Getenv("UPDATE_CRD_DEFAULTS") == "1" {
		if err := os.WriteFile("crd_defaults.json", want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(want, crdDefaultsJSON) {
		t.Fatal("crd_defaults.json differs from the pinned CRDs; rerun with UPDATE_CRD_DEFAULTS=1")
	}
}

// The committed policies rely on CRD defaults, so hashing the raw YAML and the
// stored object differ unless both sides default. Defaulting is idempotent.
func TestCRDDefaultsFillTheStoredFields(t *testing.T) {
	for _, p := range repoPolicies(t) {
		raw := p.Object["spec"]
		def, err := ApplyCRDDefaults(p.GetKind(), raw)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ApplyCRDDefaults(p.GetKind(), def)
		if err != nil || !reflect.DeepEqual(def, again) {
			t.Fatalf("%s: defaulting is not idempotent: %v", p.GetName(), err)
		}
		if reflect.DeepEqual(raw, def) {
			t.Fatalf("%s: no CRD default applied; the raw-vs-stored mismatch would go untested", p.GetName())
		}
		spec := def.(map[string]any)
		for _, kp := range spec["kprobes"].([]any) {
			k := kp.(map[string]any)
			if _, ok := k["return"]; !ok {
				t.Fatalf("%s: kprobe without return default", p.GetName())
			}
			if _, ok := k["syscall"]; !ok {
				t.Fatalf("%s: kprobe without syscall default", p.GetName())
			}
			for _, a := range asList(k["args"]) {
				for _, f := range []string{"maxData", "resolve", "returnCopy"} {
					if _, ok := a.(map[string]any)[f]; !ok {
						t.Fatalf("%s: arg without %s default", p.GetName(), f)
					}
				}
			}
			for _, sel := range asList(k["selectors"]) {
				for _, mb := range asList(sel.(map[string]any)["matchBinaries"]) {
					if _, ok := mb.(map[string]any)["followChildren"]; !ok {
						t.Fatalf("%s: matchBinaries without followChildren default", p.GetName())
					}
				}
			}
		}
	}
	if _, err := ApplyCRDDefaults("Pod", map[string]any{}); err == nil {
		t.Fatal("unknown kind accepted")
	}
	// An explicit value is kept, not replaced by the default.
	got, _ := ApplyCRDDefaults("TracingPolicy", map[string]any{"kprobes": []any{map[string]any{"call": "x", "syscall": false}}})
	if got.(map[string]any)["kprobes"].([]any)[0].(map[string]any)["syscall"] != false {
		t.Fatal("explicit syscall:false overwritten")
	}
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}
