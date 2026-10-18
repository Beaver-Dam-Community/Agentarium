package deploy

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const netpolImage = reg + "/sensors-netpol-collector@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

// The netpol-collector DaemonSet (M2-9) renders and is admitted in
// agent-sensors with the read-only /var/log/network and spool hostPaths only.
func TestNetpolCollectorDaemonSetIsAdmitted(t *testing.T) {
	raw := string(read(t, filepath.Join(repo, "deploy/gcp/sensors/netpol-collector.yaml")))
	repl := strings.NewReplacer("${NETPOL_COLLECTOR_IMAGE}", netpolImage, "${CLUSTER_UID}", "00000000-0000-4000-8000-000000000001", "${NETPOL_NORMALIZATION_VERSION}", "netpol-v1", "${NETPOL_VERSION}", "sample")
	var lines []string
	for _, l := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			l = repl.Replace(l)
			if strings.Contains(l, "${") {
				t.Fatalf("unknown placeholder: %s", l)
			}
		}
		lines = append(lines, l)
	}
	typed, generic := decode(t, []byte(strings.Join(lines, "\n")))
	var ds *appsv1.DaemonSet
	var cm *corev1.ConfigMap
	var sa *corev1.ServiceAccount
	for _, o := range typed {
		switch o := o.(type) {
		case *appsv1.DaemonSet:
			ds = o
		case *corev1.ConfigMap:
			cm = o
		case *corev1.ServiceAccount:
			sa = o
		}
	}
	var kinds []string
	for _, g := range generic {
		kinds = append(kinds, g["kind"].(string))
	}
	sort.Strings(kinds)
	if ds == nil || cm == nil || sa == nil || strings.Join(kinds, ",") != "ClusterRole,ClusterRoleBinding" {
		t.Fatalf("objects: ds=%v cm=%v other=%v", ds != nil, cm != nil, kinds)
	}
	for _, g := range generic {
		if g["kind"] == "ClusterRole" {
			rules, _ := json.Marshal(g["rules"])
			if string(rules) != `[{"apiGroups":[""],"resources":["nodes"],"verbs":["get"]}]` {
				t.Fatalf("ClusterRole must be nodes get only: %s", rules)
			}
		}
	}
	spec := ds.Spec.Template.Spec
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cm.Data["config.json"]), &cfg); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "boot_id_path,ca_file,cluster_uid,final_flush_seconds,health_origin,identity_origin,identity_peer_san,live_file,max_line_bytes,normalization_version,receiver_origin,spool_capacity_bytes,spool_dir,token_file,version" {
		t.Fatalf("config keys %v", keys)
	}
	if grace := spec.TerminationGracePeriodSeconds; grace == nil || float64(*grace) <= cfg["final_flush_seconds"].(float64) {
		t.Fatal("termination grace must exceed final_flush_seconds")
	}
	if !spec.HostNetwork || spec.DNSPolicy != corev1.DNSClusterFirstWithHostNet || spec.ServiceAccountName != "netpol-collector" {
		t.Fatal("hostNetwork DaemonSet with cluster DNS and its own KSA")
	}
	for _, m := range spec.Containers[0].VolumeMounts {
		if m.Name == "policy-log" && !m.ReadOnly {
			t.Fatal("/var/log/network must be read-only")
		}
	}
	pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "netpol-collector-x", Namespace: "agent-sensors", Labels: ds.Spec.Template.Labels}, Spec: spec}
	c := newCluster(t, "", netpolImage)
	if res := c.admit(t, pod); len(res) != 0 {
		t.Fatalf("netpol-collector Pod denied: %v", res)
	}
	spec.Containers[0].VolumeMounts[0].ReadOnly = false
	if res := c.admit(t, pod); len(res) == 0 {
		t.Fatal("writable /var/log/network admitted")
	}
}
