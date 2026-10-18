package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
)

// Model profile constants are not part of bundle data.catalog (Catalog keeps
// ModelProfiles out of JSON and catalog_digest), so a service that normalizes
// model.generate loads them as an install input and attaches them to every
// catalog it hands to Normalize. The gateway reads the file once at startup
// (--model-profiles); the model adapter can reuse the same loader.
//
// File format: one JSON object whose keys are exactly the COMMON
// model_profile enum (agent, policy_proposal, intent_check, discovery) and
// whose values have exactly the ModelProfileConfig keys:
//
//	{"agent": {"max_output_tokens": 8192, "max_request_bytes": 65536,
//	           "generation_config": {...}, "response_schema": null}, ...}
//
// SPEC-QUESTION: TASK-02 3.3 says the constants come from the environment
// lock via TASK-05, but the lock has no per-profile values and no spec names
// this file, its owner or how it reaches the gateway and the model adapter.

// modelProfileKeys are the json tags of ModelProfileConfig, all required.
var modelProfileKeys = []string{"max_output_tokens", "max_request_bytes", "generation_config", "response_schema"}

// LoadModelProfiles reads and validates a model profile file (ParseModelProfiles).
func LoadModelProfiles(path string) (map[string]ModelProfileConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, err := ParseModelProfiles(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// ParseModelProfiles strictly decodes and validates the model profile file.
// It rejects invalid UTF-8, duplicate keys, trailing data, unknown or missing
// keys at the top and profile levels, and values outside the rules below. A
// null response_schema is returned as a nil ResponseSchema.
func ParseModelProfiles(raw []byte) (map[string]ModelProfileConfig, error) {
	// contractJCSScan: every value here is digested with JCS, so the file gets
	// the same grammar, duplicate-key and number-range contract. Fractions are
	// allowed because generation_config carries values such as temperature.
	root, err := scanJSON(raw, contractJCSScan)
	if err != nil {
		return nil, err
	}
	if root.kind != kindObject {
		return nil, errors.New("$: expected object")
	}
	if err := exactKeys(root, sortedProfileNames(), "$"); err != nil {
		return nil, err
	}
	for i, name := range root.keys {
		if err := checkModelProfile(name, root.vals[i]); err != nil {
			return nil, err
		}
	}
	var m map[string]ModelProfileConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	for name, pc := range m {
		if string(pc.ResponseSchema) == "null" {
			pc.ResponseSchema = nil
			m[name] = pc
		}
	}
	return m, nil
}

func checkModelProfile(name string, n *jnode) error {
	path := "$." + name
	if n.kind != kindObject {
		return fmt.Errorf("%s: expected object", path)
	}
	if err := exactKeys(n, modelProfileKeys, path); err != nil {
		return err
	}
	var maxOut int64
	for i, k := range n.keys {
		v := n.vals[i]
		p := path + "." + k
		switch k {
		case "max_output_tokens", "max_request_bytes":
			x, err := positiveInt(v, p)
			if err != nil {
				return err
			}
			if k == "max_output_tokens" {
				maxOut = x
			}
		case "generation_config":
			if v.kind != kindObject {
				return fmt.Errorf("%s: expected object", p)
			}
		case "response_schema":
			switch name {
			case "agent":
				// agent has no structured output; null means
				// response_schema_digest = null. An object is also accepted.
				if v.kind != kindObject && v.kind != kindNull {
					return fmt.Errorf("%s: expected object or null", p)
				}
			default:
				// intent_check (IntentCheckResult), policy_proposal (final
				// step responseSchema) and discovery (candidate output schema)
				// have a server-fixed output schema (TASK-05 model profile).
				// policy_proposal applies this schema only when its canonical
				// phase is final; exploration binds a null schema digest.
				if v.kind != kindObject {
					return fmt.Errorf("%s: expected object", p)
				}
			}
		}
	}
	// SPEC-QUESTION: the output token limit can appear both as
	// max_output_tokens and as generation_config.maxOutputTokens. The spec
	// should name one canonical source; until then both must agree.
	gen := n.vals[indexOf(n.keys, "generation_config")]
	if j := indexOf(gen.keys, "maxOutputTokens"); j >= 0 {
		p := path + ".generation_config.maxOutputTokens"
		x, err := positiveInt(gen.vals[j], p)
		if err != nil {
			return err
		}
		if x != maxOut {
			return fmt.Errorf("%s = %d differs from max_output_tokens = %d", p, x, maxOut)
		}
	}
	return nil
}

// exactKeys requires n's keys to equal want exactly (case-sensitive, no
// missing, no extra). Duplicates were already rejected by the scan.
func exactKeys(n *jnode, want []string, path string) error {
	for _, k := range n.keys {
		if indexOf(want, k) < 0 {
			return fmt.Errorf("%s: unknown key %q", path, k)
		}
	}
	for _, k := range want {
		if indexOf(n.keys, k) < 0 {
			return fmt.Errorf("%s: missing key %q", path, k)
		}
	}
	return nil
}

func positiveInt(n *jnode, path string) (int64, error) {
	if n.kind != kindNumber {
		return 0, fmt.Errorf("%s: expected integer", path)
	}
	x, err := strconv.ParseInt(n.num, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: expected integer, got %s", path, n.num)
	}
	if x <= 0 || x > MaxSafeInteger {
		return 0, fmt.Errorf("%s: %d is not a positive integer within 2^53-1", path, x)
	}
	return x, nil
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return -1
}

func sortedProfileNames() []string {
	out := make([]string, 0, len(modelProfiles))
	for p := range modelProfiles {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ModelProfilesDigest is the canonical digest (SHA-256 of JCS) of the
// validated profile map, with a nil ResponseSchema as null. Operators compare
// it between the gateway and the model adapter; it is not an API field.
func ModelProfilesDigest(m map[string]ModelProfileConfig) (string, error) {
	return CanonicalDigest(m)
}

// CloneModelProfiles deep-copies m so a per-request Catalog never shares
// mutable storage with the install config.
func CloneModelProfiles(m map[string]ModelProfileConfig) map[string]ModelProfileConfig {
	if m == nil {
		return nil
	}
	out := make(map[string]ModelProfileConfig, len(m))
	for k, v := range m {
		v.GenerationConfig = bytes.Clone(v.GenerationConfig)
		v.ResponseSchema = bytes.Clone(v.ResponseSchema)
		out[k] = v
	}
	return out
}
