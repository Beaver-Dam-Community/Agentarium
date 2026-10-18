package checks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var prodEnv = Env{ProjectID: "example-prod", ProjectNumber: "111111111111"}

func load(t *testing.T, name string) *Policy {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePolicy(data)
	if err != nil {
		t.Fatalf("ParsePolicy(%s): %v", name, err)
	}
	return p
}

func rules(vs []Violation) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.Rule)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestCheckFixtures(t *testing.T) {
	tests := []struct {
		file string
		env  Env
		want []string
	}{
		{"clean.json", prodEnv, nil},
		{"exec_principal.json", prodEnv, []string{RuleExecGrant}},
		{"exec_principal_set.json", prodEnv, []string{RuleExecGrant}},
		{"exec_legacy.json", prodEnv, []string{RuleExecGrant}},
		{"exec_deleted.json", prodEnv, []string{RuleExecGrant}},
		{"whole_pool.json", prodEnv, []string{RuleWholePoolGrant}},
		{"cluster_wide.json", prodEnv, []string{RuleWholePoolGrant}},
		{"ksa_uid.json", prodEnv, []string{RuleUnresolvedSelector}},
		{"cross_env_principal.json", prodEnv, []string{RuleCrossEnvPool}},
		{"cross_env_legacy.json", prodEnv, []string{RuleCrossEnvPool}},
		{"cross_env_condition.json", prodEnv, []string{RuleCrossEnvPool}},
		{"project_number_mismatch.json", prodEnv, []string{RuleCrossEnvPool}},
		// Without a project number only pool strings are compared.
		{"project_number_mismatch.json", Env{ProjectID: "example-prod"}, nil},
		// The prod-clean policy seen from the regression environment is cross-env.
		{"clean.json", Env{ProjectID: "example-regression"}, []string{RuleCrossEnvPool}},
	}
	for _, tt := range tests {
		t.Run(tt.file+"/"+tt.env.ProjectID+"/"+tt.env.ProjectNumber, func(t *testing.T) {
			vs, err := Check(load(t, tt.file), tt.env)
			if err != nil {
				t.Fatal(err)
			}
			if got := rules(vs); !slices.Equal(got, tt.want) {
				t.Fatalf("rules = %v, want %v (violations: %v)", got, tt.want, vs)
			}
			for _, v := range vs {
				if v.Role == "" || v.Member == "" {
					t.Errorf("violation without role/member: %+v", v)
				}
			}
		})
	}
}

func TestCheckRequiresProjectID(t *testing.T) {
	if _, err := Check(&Policy{}, Env{}); err == nil {
		t.Fatal("expected error for empty project ID")
	}
}

func TestParsePolicyRejects(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"duplicate key fixture", "", "duplicate key"},
		{"unknown field fixture", "", "unexpected key"},
		{"trailing data", `{"bindings":[]} {}`, "trailing data"},
		{"not an object", `[]`, "decode policy"},
		{"deep nesting", `{"auditConfigs":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`, "nesting too deep"},
		{"top-level duplicate", `{"version":1,"version":3}`, "duplicate key"},
		{"case-only duplicate fixture", "", "differ only by case"},
		{"wrong-case key fixture", "", "unexpected key"},
		{"wrong-case top-level key", `{"Bindings":[]}`, "unexpected key"},
		{"wrong-case role", `{"bindings":[{"ROLE":"roles/viewer","members":[]}]}`, "unexpected key"},
		{"wrong-case condition key", `{"bindings":[{"role":"r","members":[],"condition":{"Expression":"true"}}]}`, "unexpected key"},
		{"case collision inside auditConfigs", `{"auditConfigs":[{"service":"a","Service":"b"}]}`, "differ only by case"},
	}
	files := map[string]string{
		"duplicate key fixture":       "duplicate_key.json",
		"unknown field fixture":       "unknown_field.json",
		"case-only duplicate fixture": "case_duplicate_members.json",
		"wrong-case key fixture":      "wrong_case_members.json",
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.data)
			if f, ok := files[tt.name]; ok {
				var err error
				if data, err = os.ReadFile(filepath.Join("testdata", f)); err != nil {
					t.Fatal(err)
				}
			}
			_, err := ParsePolicy(data)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestParsePolicyAcceptsNestedValues(t *testing.T) {
	data := `{"auditConfigs":[{"service":"allServices","auditLogConfigs":[{"logType":"DATA_READ"}]}],` +
		`"bindings":[{"role":"roles/viewer","members":["group:g@example.com"]}],"etag":"x","version":1}`
	p, err := ParsePolicy([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Bindings) != 1 || p.Bindings[0].Role != "roles/viewer" {
		t.Fatalf("unexpected policy: %+v", p)
	}
}
