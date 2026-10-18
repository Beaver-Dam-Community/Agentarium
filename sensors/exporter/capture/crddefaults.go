package capture

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
)

// crd_defaults.json is the default-bearing part of the pinned Tetragon 1.7.1
// TracingPolicy and TracingPolicyNamespaced CRD schemas (spec subtree only):
// every schema node that has a `default` or leads to one, keeping only
// `properties`, `items`, `additionalProperties` and `default`. It is
// generated from install/kubernetes/tetragon/crds-yaml of the pinned release
// (see TestCRDDefaultsMatchPinnedCRD) and is the single source that
// deploy/gcp/sensors/render.py also reads, so both rule_hash sides apply the
// same defaults.
//
//go:embed crd_defaults.json
var crdDefaultsJSON []byte

type schemaNode struct {
	Properties           map[string]*schemaNode `json:"properties,omitempty"`
	Items                *schemaNode            `json:"items,omitempty"`
	AdditionalProperties *schemaNode            `json:"additionalProperties,omitempty"`
	Default              json.RawMessage        `json:"default,omitempty"`
}

type crdDefaults struct {
	Source map[string]string      `json:"source"`
	Specs  map[string]*schemaNode `json:"specs"`
}

var defaults = func() crdDefaults {
	var d crdDefaults
	if err := json.Unmarshal(crdDefaultsJSON, &d); err != nil {
		panic("capture: invalid crd_defaults.json: " + err.Error())
	}
	return d
}()

// ApplyCRDDefaults returns a copy of a TracingPolicy(Namespaced) spec with the
// pinned CRD's structural defaults applied the way the API server does when
// it stores the object: a missing property that has a default gets it, then
// defaulting continues inside every present value (arrays through `items`,
// maps through `additionalProperties`). Applying it to an object read back
// from the API server changes nothing, so the renderer (raw YAML) and the
// verifier (stored object) hash the same spec.
func ApplyCRDDefaults(kind string, spec any) (any, error) {
	root, ok := defaults.Specs[kind]
	if !ok {
		return nil, fmt.Errorf("no CRD defaults for kind %q", kind)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if err := applyDefaults(out, root); err != nil {
		return nil, err
	}
	return out, nil
}

func applyDefaults(v any, n *schemaNode) error {
	if n == nil {
		return nil
	}
	switch x := v.(type) {
	case map[string]any:
		for k, child := range n.Properties {
			if _, present := x[k]; !present && len(child.Default) > 0 {
				var d any
				if err := json.Unmarshal(child.Default, &d); err != nil {
					return err
				}
				x[k] = d
			}
			if val, present := x[k]; present {
				if err := applyDefaults(val, child); err != nil {
					return err
				}
			}
		}
		if n.AdditionalProperties != nil {
			for k, val := range x {
				if _, named := n.Properties[k]; !named {
					if err := applyDefaults(val, n.AdditionalProperties); err != nil {
						return err
					}
				}
			}
		}
	case []any:
		for _, el := range x {
			if err := applyDefaults(el, n.Items); err != nil {
				return err
			}
		}
	case nil:
	default:
		if n.Properties != nil || n.Items != nil {
			return errors.New("spec value does not match the CRD schema shape")
		}
	}
	return nil
}
