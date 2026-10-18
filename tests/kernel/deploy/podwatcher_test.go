package deploy

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const podWatcherImage = reg + "/pod-watcher@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// The pod-watcher Deployment (TASK-09 3.6) renders, is a single leader-elected
// replica with a persistent spool, and is admitted by the deploy/gcp/base
// agent-role-contract VAP and PSA restricted in agent-observe.
func TestPodWatcherDeploymentIsAdmitted(t *testing.T) {
	raw := string(read(t, filepath.Join(repo, "deploy/gcp/sensors/pod-watcher.yaml")))
	var lines []string
	for _, l := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			l = strings.ReplaceAll(l, "${POD_WATCHER_IMAGE}", podWatcherImage)
			l = strings.ReplaceAll(l, "${CLUSTER_UID}", "00000000-0000-4000-8000-000000000001")
			if strings.Contains(l, "${") {
				t.Fatalf("unknown placeholder: %s", l)
			}
		}
		lines = append(lines, l)
	}
	typed, generic := decode(t, []byte(strings.Join(lines, "\n")))
	if len(generic) != 0 {
		t.Fatalf("unexpected objects: %v", generic)
	}
	var dep *appsv1.Deployment
	var cm *corev1.ConfigMap
	var role *rbacv1.Role
	for _, o := range typed {
		switch o := o.(type) {
		case *appsv1.Deployment:
			dep = o
		case *corev1.ConfigMap:
			cm = o
		case *rbacv1.Role:
			role = o
		}
	}
	if dep == nil || cm == nil || role == nil {
		t.Fatal("missing Deployment, ConfigMap or Role")
	}
	if *dep.Spec.Replicas != 1 || dep.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Fatal("pod-watcher must be one replica with Recreate")
	}
	spec := dep.Spec.Template.Spec
	if spec.SecurityContext.FSGroupChangePolicy == nil || *spec.SecurityContext.FSGroupChangePolicy != corev1.FSGroupChangeOnRootMismatch {
		t.Fatal("fsGroup must not recursively widen private spool permissions on remount")
	}
	var config struct {
		Directory string `json:"directory"`
	}
	if err := json.Unmarshal([]byte(cm.Data["config.json"]), &config); err != nil {
		t.Fatal(err)
	}
	if config.Directory != "/var/lib/agentarium/pod-watcher/spool" {
		t.Fatal("spool must be a private child of the fsGroup mount root")
	}

	var spool bool
	for _, v := range spec.Volumes {
		spool = spool || (v.Name == "spool" && v.PersistentVolumeClaim != nil)
		if v.HostPath != nil {
			t.Fatal("pod-watcher must not use hostPath")
		}
	}
	if !spool {
		t.Fatal("spool must be a PersistentVolumeClaim")
	}
	if env := spec.Containers[0].Env; len(env) != 1 || env[0].Name != "POD_NAME" || env[0].ValueFrom.FieldRef.FieldPath != "metadata.name" {
		t.Fatalf("leader identity env: %+v", env)
	}
	// Lease RBAC is limited to create and the named lease.
	for _, r := range role.Rules {
		if strings.Join(r.APIGroups, ",") != "coordination.k8s.io" || strings.Join(r.Resources, ",") != "leases" {
			t.Fatalf("unexpected rule %+v", r)
		}
		if len(r.ResourceNames) == 0 && strings.Join(r.Verbs, ",") != "create" {
			t.Fatalf("unnamed lease rule must be create only: %+v", r)
		}
	}
	// Config keys match the pod-watcher command's strict configuration.
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cm.Data["config.json"]), &cfg); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "ca_file,capacity_bytes,cluster_uid,collector_origin,directory,health_origin,identity_origin,lease_name,lease_namespace,namespace,page_size,token_file"
	if strings.Join(keys, ",") != want {
		t.Fatalf("config keys %v", keys)
	}
	values := baseValues("", "")
	values["AGENT_OBSERVE_IMAGES"] = podWatcherImage
	c := newClusterValues(t, values)
	pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "pod-watcher-x", Namespace: "agent-observe", Labels: dep.Spec.Template.Labels}, Spec: spec}
	if res := c.admit(t, pod); len(res) != 0 {
		t.Fatalf("pod-watcher Pod denied: %v", res)
	}
	values["AGENT_OBSERVE_IMAGES"] = reg + "/other@sha256:" + strings.Repeat("d", 64)
	if res := newClusterValues(t, values).admit(t, pod); len(res) == 0 {
		t.Fatal("pod-watcher image outside AGENT_OBSERVE_IMAGES admitted")
	}
}
