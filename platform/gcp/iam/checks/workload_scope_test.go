package checks

import (
	"fmt"
	"slices"
	"testing"
)

// Issue #97 has not authorized exceptions for these resource-specific grants.
// Even objectCreator for regression reports remains a foreign-pool violation.
func TestWorkloadEnvironmentBoundary(t *testing.T) {
	cases := []struct{ name, role, ksa string }{
		{"decision-input-read", "roles/storage.objectViewer", "decision-replay"},
		{"manifest-public-key", "projects/example-prod/roles/agentariumManifestPublicKey", "decision-replay"},
		{"regression-request-read", "roles/storage.objectViewer", "regression-runner"},
		{"regression-report-create", "roles/storage.objectCreator", "regression-runner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, foreign := range []bool{false, true} {
				project, number := prodEnv.ProjectID, prodEnv.ProjectNumber
				if foreign {
					project, number = "example-regression", "222222222222"
				}
				member := fmt.Sprintf("principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s.svc.id.goog/subject/ns/agent-release/sa/%s", number, project, tc.ksa)
				vs, err := Check(&Policy{Bindings: []Binding{{Role: tc.role, Members: []string{member}}}}, prodEnv)
				if err != nil {
					t.Fatal(err)
				}
				if foreign && !slices.Contains(rules(vs), RuleCrossEnvPool) {
					t.Fatalf("foreign pool allowed: %v", vs)
				}
				if !foreign && len(vs) != 0 {
					t.Fatalf("same-environment principal rejected: %v", vs)
				}
			}
		})
	}
}
