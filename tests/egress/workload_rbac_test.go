package egress_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// workloadRBAC is the exact permission ceiling of each TASK-06 workload RBAC
// file: "<namespace or *>|<group>|<resource>|<verb>|<resourceName or *>".
// It is a manifest check only; live additive bindings need the live check.
var workloadRBAC = map[string]struct {
	subject     string
	permissions []string
}{
	"node-readiness": {"agent-control/node-readiness", []string{
		"*||nodes|get|*", "*||nodes|list|*", "*||nodes|patch|*", "*||nodes|watch|*"}},
	"correlation": {"agent-observe/correlation", []string{
		"*||nodes|get|*", "*||nodes|list|*", "*||nodes|watch|*"}},
	"control-health": {"agent-observe/control-health", []string{
		"agent-adapters|apps|deployments|get|*", "agent-adapters|apps|deployments|list|*", "agent-adapters|apps|deployments|watch|*",
		"agent-control|apps|deployments|get|*", "agent-control|apps|deployments|list|*", "agent-control|apps|deployments|watch|*"}},
	"pod-watcher": {"agent-observe/pod-watcher", []string{
		"agent-exec||pods|list|*", "agent-exec||pods|watch|*"}},
	"discovery": {"agent-observe/discovery", []string{
		"agent-observe|batch|jobs|create|*", "agent-observe|batch|jobs|get|*", "agent-observe||pods|list|*"}},
	"releaser": {"agent-release/releaser", []string{
		"agent-exec|cilium.io|tracingpoliciesnamespaced|get|agentarium-protected-file",
		"agent-exec|cilium.io|tracingpoliciesnamespaced|get|agentarium-tcp-connect",
		"agent-exec|cilium.io|tracingpoliciesnamespaced|patch|agentarium-protected-file",
		"agent-exec|cilium.io|tracingpoliciesnamespaced|patch|agentarium-tcp-connect",
		"agent-exec|cilium.io|tracingpoliciesnamespaced|update|agentarium-protected-file",
		"agent-exec|cilium.io|tracingpoliciesnamespaced|update|agentarium-tcp-connect"}},
}

func decodeAll(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	var out []map[string]any
	for {
		var obj map[string]any
		if err := d.Decode(&obj); errors.Is(err, io.EOF) {
			return out
		} else if err != nil {
			t.Fatal(err)
		}
		if obj != nil {
			out = append(out, obj)
		}
	}
}

func convert(t *testing.T, in map[string]any, out any) {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

func expand(t *testing.T, scope string, rules []rbacv1.PolicyRule) []string {
	t.Helper()
	var out []string
	for _, r := range rules {
		if len(r.NonResourceURLs) != 0 {
			t.Fatalf("non-resource rule %+v", r)
		}
		names := r.ResourceNames
		if len(names) == 0 {
			names = []string{"*"}
		}
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					for _, n := range names {
						if g == "*" || res == "*" || v == "*" || n == "" {
							t.Fatalf("wildcard rule %+v", r)
						}
						out = append(out, strings.Join([]string{scope, g, res, v, n}, "|"))
					}
				}
			}
		}
	}
	return out
}

func TestWorkloadRBACCeilings(t *testing.T) {
	for file, want := range workloadRBAC {
		t.Run(file, func(t *testing.T) {
			objects := decodeAll(t, "../../deploy/gcp/base/rbac/"+file+".yaml")
			roles := map[string][]string{}
			bindings := map[string]bool{}
			var got []string
			for _, obj := range objects {
				switch obj["kind"] {
				case "Role":
					var r rbacv1.Role
					convert(t, obj, &r)
					if r.Name != "agentarium-"+file || r.Namespace == "" {
						t.Fatalf("unexpected Role %s/%s", r.Namespace, r.Name)
					}
					roles["Role/"+r.Namespace] = nil
					got = append(got, expand(t, r.Namespace, r.Rules)...)
				case "ClusterRole":
					var r rbacv1.ClusterRole
					convert(t, obj, &r)
					if r.Name != "agentarium-"+file || r.AggregationRule != nil {
						t.Fatalf("unexpected ClusterRole %s", r.Name)
					}
					roles["ClusterRole/"] = nil
					got = append(got, expand(t, "*", r.Rules)...)
				case "RoleBinding", "ClusterRoleBinding":
					var b rbacv1.RoleBinding
					convert(t, obj, &b)
					kind := strings.TrimSuffix(obj["kind"].(string), "Binding")
					ns, sa, _ := strings.Cut(want.subject, "/")
					if b.Name != "agentarium-"+file || b.RoleRef != (rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: kind, Name: b.Name}) ||
						!reflect.DeepEqual(b.Subjects, []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: ns}}) {
						t.Fatalf("binding must grant only %s its own role: %+v", want.subject, b)
					}
					bindings[kind+"/"+b.Namespace] = true
				default:
					t.Fatalf("unexpected kind %v", obj["kind"])
				}
			}
			if len(roles) != len(bindings) {
				t.Fatalf("roles %v and bindings %v differ", roles, bindings)
			}
			for key := range roles {
				if !bindings[key] {
					t.Fatalf("role %s has no binding", key)
				}
			}
			sort.Strings(got)
			expected := append([]string(nil), want.permissions...)
			sort.Strings(expected)
			if !reflect.DeepEqual(got, expected) {
				t.Fatalf("permission ceiling\n got %v\nwant %v", got, expected)
			}
		})
	}
}

// TestLiveCheckMatchesManifests keeps the live check's allowed cases equal to
// the manifest ceilings above, so the live report cannot drift from them.
func TestLiveCheckMatchesManifests(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	out, err := exec.Command(python, "check_workload_rbac.py", "--print-allowed").Output()
	if err != nil {
		t.Fatal(err)
	}
	var allowed map[string][][4]string
	if err := json.Unmarshal(out, &allowed); err != nil {
		t.Fatal(err)
	}
	if len(allowed) != len(workloadRBAC) {
		t.Fatalf("live check subjects %v", allowed)
	}
	for _, want := range workloadRBAC {
		var got []string
		for _, c := range allowed[want.subject] {
			namespace, verb, resource, name := c[0], c[1], c[2], c[3]
			plural, group, _ := strings.Cut(resource, ".")
			if namespace == "" {
				namespace = "*"
			}
			if name == "" {
				name = "*"
			}
			got = append(got, strings.Join([]string{namespace, group, plural, verb, name}, "|"))
		}
		sort.Strings(got)
		expected := append([]string(nil), want.permissions...)
		sort.Strings(expected)
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("%s live allowed cases\n got %v\nwant %v", want.subject, got, expected)
		}
	}
}
