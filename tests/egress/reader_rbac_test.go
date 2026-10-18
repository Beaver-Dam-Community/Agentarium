package egress_test

import (
	"bytes"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestReaderRBACCeiling(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/gcp/base/rbac/kubernetes-reader.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	var objects []map[string]any
	for {
		var obj map[string]any
		err = decoder.Decode(&obj)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		objects = append(objects, obj)
	}
	if len(objects) != 3 {
		t.Fatal("reader manifest must contain one SA and one namespaced role/binding")
	}
	// Exact permission expansion detects wildcard, subresource, API group and
	// write escalation independently of YAML rule grouping or ordering.
	decode := func(index int, out any) {
		t.Helper()
		data, err := os.ReadFile("../../deploy/gcp/base/rbac/kubernetes-reader.yaml")
		if err != nil {
			t.Fatal(err)
		}
		d := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for i := 0; i < index; i++ {
			var skip any
			if err = d.Decode(&skip); err != nil {
				t.Fatal(err)
			}
		}
		if err = d.Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	var sa corev1.ServiceAccount
	decode(0, &sa)
	if sa.Kind != "ServiceAccount" || sa.Name != "kubernetes-reader" || sa.Namespace != "agent-adapters" || sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		t.Fatal("unexpected identity or automatic token mount")
	}
	if len(sa.Secrets) > 0 || len(sa.Annotations) > 0 {
		t.Fatal("reader must not acquire static tokens or GSA annotations here")
	}
	var role rbacv1.Role
	decode(1, &role)
	if role.Kind != "Role" || role.Name != "agentarium-kubernetes-reader" || role.Namespace != "agent-targets" {
		t.Fatal("reader role escaped target namespace")
	}
	var permissions []string
	for _, rule := range role.Rules {
		if len(rule.NonResourceURLs) != 0 || len(rule.ResourceNames) != 0 {
			t.Fatal("unexpected non-resource or named grant")
		}
		for _, group := range rule.APIGroups {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					permissions = append(permissions, strings.Join([]string{group, resource, verb}, "/"))
				}
			}
		}
	}
	sort.Strings(permissions)
	want := []string{"/events/get", "/events/list", "/pods/get", "/pods/list", "/pods/log/get"}
	if !reflect.DeepEqual(permissions, want) {
		t.Fatalf("permission ceiling: %v", permissions)
	}
	var binding rbacv1.RoleBinding
	decode(2, &binding)
	if binding.Kind != "RoleBinding" || binding.Namespace != role.Namespace || binding.Name != role.Name || binding.RoleRef != (rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: role.Name}) {
		t.Fatal("unexpected cluster-wide or redirected binding")
	}
	wantSubjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa.Name, Namespace: sa.Namespace}}
	if !reflect.DeepEqual(binding.Subjects, wantSubjects) {
		t.Fatalf("unexpected subjects: %+v", binding.Subjects)
	}
}
