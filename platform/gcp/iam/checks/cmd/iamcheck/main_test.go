package main

import (
	"bytes"
	"strings"
	"testing"
)

const td = "../../testdata/"

// allow prefixes args with the allowlist inputs and role definition.
func allow(args ...string) []string {
	return append([]string{"-project-number", "111111111111", "-cross-env-config", td + "cross_env_inputs.json", "-role-definition", td + "role_definition.json"}, args...)
}

func TestRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
		out  string
	}{
		{"clean", []string{"-project-id", "example-prod", td + "clean.json"}, 0, ""},
		{"violation", []string{"-project-id", "example-prod", td + "clean.json", td + "exec_principal.json"}, 1, "EXEC_PRINCIPAL_GRANT"},
		{"parse error", []string{"-project-id", "example-prod", td + "duplicate_key.json"}, 2, ""},
		{"missing file", []string{"-project-id", "example-prod", td + "absent.json"}, 2, ""},
		{"no project", []string{td + "clean.json"}, 2, ""},
		{"no files", []string{"-project-id", "example-prod"}, 2, ""},
		// Cross-environment grants (TASK-06 3.3, #97) pass only from an asset export.
		{"allowed four from asset export", append([]string{"-project-id", "example-prod", "-project-number", "111111111111"},
			allow("-assets", td+"assets_allowed.ndjson")...), 0, ""},
		{"realistic gcloud asset export", append([]string{"-project-id", "example-prod", "-project-number", "111111111111"},
			allow("-assets", td+"asset_export_realistic.ndjson")...), 0, ""},
		{"asset export without allowlist", []string{"-project-id", "example-prod", "-assets", td + "assets_allowed.ndjson"}, 1, "CROSS_ENV_POOL"},
		{"allowlist without project number", []string{"-project-id", "example-prod", "-cross-env-config", td + "cross_env_inputs.json",
			"-role-definition", td + "role_definition.json", "-assets", td + "asset_export_realistic.ndjson"}, 2, ""},
		{"viewer exported for the reports bucket", append([]string{"-project-id", "example-prod"},
			allow("-assets", td+"assets_reports_viewer.ndjson")...), 1, "CROSS_ENV_POOL"},
		// A plain policy file never gets the exemption, and a resource label is not accepted.
		{"plain policy file", append([]string{"-project-id", "example-prod"}, allow(td+"cross_env_principal.json")...), 1, "CROSS_ENV_POOL"},
		{"label syntax is not a resource", append([]string{"-project-id", "example-prod"},
			allow("//storage.googleapis.com/projects/_/buckets/example-regression-requests="+td+"cross_env_principal.json")...), 2, ""},
		{"duplicate resource in one export", append([]string{"-project-id", "example-prod"}, allow("-assets", td+"assets_duplicate.ndjson")...), 2, ""},
		{"duplicate resource across exports", append([]string{"-project-id", "example-prod"},
			allow("-assets", td+"assets_allowed.ndjson", "-assets", td+"assets_reports_viewer.ndjson")...), 2, ""},
		{"allowlist without role definition", []string{"-project-id", "example-prod", "-cross-env-config", td + "cross_env_inputs.json", "-assets", td + "assets_allowed.ndjson"}, 2, ""},
		{"role definition that is not one", []string{"-project-id", "example-prod", "-cross-env-config", td + "cross_env_inputs.json",
			"-role-definition", td + "clean.json", "-assets", td + "assets_allowed.ndjson"}, 2, ""},
		{"allowlist checked from another project", append([]string{"-project-id", "attacker-project"}, allow("-assets", td+"assets_allowed.ndjson")...), 2, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.want {
				t.Fatalf("exit = %d, want %d (stdout %q, stderr %q)", got, tt.want, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.out) {
				t.Fatalf("stdout %q does not contain %q", stdout.String(), tt.out)
			}
		})
	}
}
