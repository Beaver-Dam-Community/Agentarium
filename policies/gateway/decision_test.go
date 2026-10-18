// Package gateway holds the gateway Rego policy. This test evaluates
// decision.rego with the OPA module pinned in go.mod, the same version the
// gateway embeds (TASK-04 3.1–3.2), so CI does not need an opa binary.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

const artifactDigest = "abababababababababababababababababababababababababababababababab"

type want struct {
	Verdict        string   `json:"verdict"`
	ReasonCodes    []string `json:"reason_codes"`
	MatchedRuleIDs []string `json:"matched_rule_ids"`
	Evaluated      string   `json:"evaluated"`
	DecisionBasis  *string  `json:"decision_basis"`
}

type testCase struct {
	Name   string                     `json:"name"`
	Base   string                     `json:"base"`
	Set    map[string]json.RawMessage `json:"set"`
	Remove []string                   `json:"remove"`
	Want   want                       `json:"want"`
}

type caseFile struct {
	EvaluatedSets map[string][]string `json:"evaluated_sets"`
	Cases         []testCase          `json:"cases"`
}

type result struct {
	Verdict          string   `json:"verdict"`
	ReasonCodes      []string `json:"reason_codes"`
	MatchedRuleIDs   []string `json:"matched_rule_ids"`
	EvaluatedRuleIDs []string `json:"evaluated_rule_ids"`
	DecisionBasis    *string  `json:"decision_basis"`
}

func TestDecision(t *testing.T) {
	ctx := context.Background()
	cat, err := canonical.LoadCatalogDir("../../packages/canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	pq := prepare(t, ctx, cat)

	var cf caseFile
	readJSON(t, "testdata/cases.json", &cf)
	if len(cf.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range cf.Cases {
		t.Run(c.Name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata/base", c.Base+".json"))
			if err != nil {
				t.Fatal(err)
			}
			raw = bytes.ReplaceAll(raw, []byte("@CATALOG_DIGEST@"), []byte(cat.CatalogDigest))
			raw = bytes.ReplaceAll(raw, []byte("@ARTIFACT_DIGEST@"), []byte(artifactDigest))
			var input any
			if err := json.Unmarshal(raw, &input); err != nil {
				t.Fatal(err)
			}
			for p, v := range c.Set {
				var val any
				if err := json.Unmarshal(v, &val); err != nil {
					t.Fatal(err)
				}
				input = edit(t, input, p, val, false)
			}
			for _, p := range c.Remove {
				input = edit(t, input, p, nil, true)
			}

			got := eval(t, ctx, pq, input)
			evaluated, ok := cf.EvaluatedSets[c.Want.Evaluated]
			if !ok {
				t.Fatalf("unknown evaluated set %q", c.Want.Evaluated)
			}
			exp := result{
				Verdict: c.Want.Verdict, ReasonCodes: c.Want.ReasonCodes, MatchedRuleIDs: c.Want.MatchedRuleIDs,
				EvaluatedRuleIDs: evaluated, DecisionBasis: c.Want.DecisionBasis,
			}
			// Order matters: the gateway stores these arrays as they come.
			if !reflect.DeepEqual(got, exp) {
				g, _ := json.Marshal(got)
				e, _ := json.Marshal(exp)
				t.Fatalf("\n got  %s\n want %s", g, e)
			}

			// Decision meaning (TASK-04 3.2): matched and evaluated are never
			// empty, a service session never gets approval_required, and
			// decision_basis is set exactly when the verdict is allow.
			if len(got.MatchedRuleIDs) == 0 || len(got.EvaluatedRuleIDs) == 0 {
				t.Fatal("empty matched_rule_ids or evaluated_rule_ids")
			}
			if sessionKind(input) == "service" && got.Verdict == "approval_required" {
				t.Fatal("service session got approval_required")
			}
			if (got.Verdict == "allow") != (got.DecisionBasis != nil) {
				t.Fatalf("verdict %s with decision_basis %v", got.Verdict, got.DecisionBasis)
			}
		})
	}
}

func prepare(t *testing.T, ctx context.Context, cat canonical.Catalog) rego.PreparedEvalQuery {
	t.Helper()
	src, err := os.ReadFile("decision.rego")
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	readJSON(t, "testdata/policy-data.json", &data)
	for k := range data {
		if strings.HasPrefix(k, "_") {
			delete(data, k)
		}
	}
	catJSON, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	var catData any
	if err := json.Unmarshal(catJSON, &catData); err != nil {
		t.Fatal(err)
	}
	data["catalog"] = catData
	data["data_class_rank"] = map[string]any{"none": 0, "synthetic": 1, "internal": 2, "confidential": 3}

	pq, err := rego.New(
		rego.Query("data.agentarium.gateway.result"),
		rego.Module("decision.rego", string(src)),
		rego.Store(inmem.NewFromObject(data)),
	).PrepareForEval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return pq
}

// eval requires exactly one defined result.
func eval(t *testing.T, ctx context.Context, pq rego.PreparedEvalQuery, input any) result {
	t.Helper()
	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		t.Fatalf("result undefined or not unique: %v", rs)
	}
	b, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	var r result
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("result shape: %v: %s", err, b)
	}
	if r.ReasonCodes == nil || r.MatchedRuleIDs == nil || r.EvaluatedRuleIDs == nil || !bytes.Contains(b, []byte(`"decision_basis"`)) {
		t.Fatalf("result has missing fields: %s", b)
	}
	return r
}

// edit sets or removes the value at a JSON Pointer (RFC 6901, no escapes).
func edit(t *testing.T, doc any, pointer string, val any, remove bool) any {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	var walk func(node any, i int) any
	walk = func(node any, i int) any {
		key := parts[i]
		last := i == len(parts)-1
		switch n := node.(type) {
		case map[string]any:
			if last {
				if remove {
					if _, ok := n[key]; !ok {
						t.Fatalf("%s: no such key", pointer)
					}
					delete(n, key)
				} else {
					n[key] = val
				}
				return n
			}
			child, ok := n[key]
			if !ok {
				t.Fatalf("%s: no such key %q", pointer, key)
			}
			n[key] = walk(child, i+1)
			return n
		case []any:
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx >= len(n) {
				t.Fatalf("%s: bad index %q", pointer, key)
			}
			if last {
				if remove {
					return append(n[:idx], n[idx+1:]...)
				}
				n[idx] = val
				return n
			}
			n[idx] = walk(n[idx], i+1)
			return n
		default:
			t.Fatalf("%s: cannot descend into %T", pointer, node)
			return nil
		}
	}
	return walk(doc, 0)
}

func sessionKind(input any) string {
	m, _ := input.(map[string]any)
	s, _ := m["verified_session"].(map[string]any)
	k, _ := s["kind"].(string)
	return k
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// TestSpecMatchesPolicy keeps the TASK-04 3.2 code block identical to
// decision.rego, so the spec cannot drift from what the gateway evaluates.
func TestSpecMatchesPolicy(t *testing.T) {
	spec, err := os.ReadFile("../../docs/tech-specs/TASK-04-policy-gateway.md")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("decision.rego")
	if err != nil {
		t.Fatal(err)
	}
	body := src[bytes.Index(src, []byte("package agentarium.gateway")):]
	if !bytes.Contains(spec, append(append([]byte("```rego\n"), body...), "```\n"...)) {
		t.Fatal("TASK-04 3.2 Rego block differs from policies/gateway/decision.rego")
	}
}
