package egress

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// TestNetworkLoggingManifestMatchesSpec keeps the applied manifest equal to the
// TASK-06 3.4 block. It does not show that GKE accepted or enforces it.
func TestNetworkLoggingManifestMatchesSpec(t *testing.T) {
	doc, err := os.ReadFile("../../docs/tech-specs/TASK-06-egress-credentials.md")
	if err != nil {
		t.Fatal(err)
	}
	const start = "```yaml\n# deploy/gcp/base/network/network-logging.yaml\n"
	i := strings.Index(string(doc), start)
	if i < 0 {
		t.Fatal("TASK-06 3.4 network-logging block not found")
	}
	block := string(doc)[i+len("```yaml\n"):]
	block = block[:strings.Index(block, "```")]
	raw, err := os.ReadFile("../../deploy/gcp/base/network/network-logging.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var want, got map[string]any
	if err := yaml.Unmarshal([]byte(block), &want); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("manifest differs from TASK-06 3.4:\nspec %v\nfile %v", want, got)
	}
	cluster := got["spec"].(map[string]any)["cluster"].(map[string]any)
	expected := map[string]any{
		"allow": map[string]any{"log": true, "delegate": true},
		"deny":  map[string]any{"log": true, "delegate": false},
	}
	if got["kind"] != "NetworkLogging" || got["apiVersion"] != "networking.gke.io/v1alpha1" ||
		got["metadata"].(map[string]any)["name"] != "default" || !reflect.DeepEqual(cluster, expected) {
		t.Fatalf("unexpected NetworkLogging: %v", got)
	}
}
