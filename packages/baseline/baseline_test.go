package baseline

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

var update = flag.Bool("update", false, "rewrite testdata/golden.json")

const fixtureDir = "testdata/observation"

func loadObservation(t *testing.T) Observation {
	t.Helper()
	obs := Observation{Objects: map[string][]map[string]any{}}
	for _, s := range Sources() {
		b, err := os.ReadFile(filepath.Join(fixtureDir, s.ID+".json"))
		if err != nil {
			t.Fatal(err)
		}
		items, err := ParseItems(b)
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		obs.Objects[s.ID] = items
	}
	b, err := os.ReadFile(filepath.Join(fixtureDir, "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := DecodeJSON(b, &obs.Cluster); err != nil {
		t.Fatal(err)
	}
	return obs
}

func mustCompute(t *testing.T, obs Observation) Digests {
	t.Helper()
	d, err := Compute(obs)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func find(t *testing.T, obs Observation, id, ns, name string) map[string]any {
	t.Helper()
	for _, o := range obs.Objects[id] {
		if gotNS, gotName := nsName(o); gotNS == ns && gotName == name {
			return o
		}
	}
	t.Fatalf("%s %s/%s not in fixture", id, ns, name)
	return nil
}

func TestGoldenDigests(t *testing.T) {
	got := mustCompute(t, loadObservation(t))
	b, _ := json.MarshalIndent(got, "", "  ")
	b = append(b, '\n')
	path := "testdata/golden.json"
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(b) {
		t.Fatalf("golden mismatch (run with -update after review)\nwant %s\ngot  %s", want, b)
	}
	for k, v := range map[string]string{"admission": got.Admission, "exec_rbac": got.ExecRBAC, "network_policy": got.NetworkPolicy,
		"node_pool_config": got.NodePoolConfig, "sensor_policy": got.SensorPolicy, "sensor_release_policies": got.SensorReleasePolicies} {
		if !isHex64(v) {
			t.Errorf("%s = %q", k, v)
		}
	}
}

func TestEmptyListDigest(t *testing.T) {
	got, err := DigestObjects(nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := canonical.SHA256Hex([]byte("[]")); got != want {
		t.Fatalf("empty digest %s, want %s", got, want)
	}
}

func TestNormalizeDropsExactlyListedFields(t *testing.T) {
	in := map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{
			"name": "x", "namespace": "agent-control",
			"resourceVersion": "1", "uid": "u", "creationTimestamp": "t", "generation": json.Number("2"),
			"managedFields":   []any{map[string]any{"manager": "m"}},
			"labels":          map[string]any{"a": "b"},
			"annotations":     map[string]any{LastAppliedAnnotation: "{}", "keep.me/x": "1"},
			"finalizers":      []any{"f"},
			"ownerReferences": []any{map[string]any{"name": "o"}},
		},
		"data":   map[string]any{"k": "v"},
		"status": map[string]any{"phase": "x"},
	}
	want := map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{
			"name": "x", "namespace": "agent-control",
			"labels":          map[string]any{"a": "b"},
			"annotations":     map[string]any{"keep.me/x": "1"},
			"finalizers":      []any{"f"},
			"ownerReferences": []any{map[string]any{"name": "o"}},
		},
		"data": map[string]any{"k": "v"},
	}
	orig, _ := json.Marshal(in)
	got := Normalize(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize:\n got %#v\nwant %#v", got, want)
	}
	if after, _ := json.Marshal(in); string(after) != string(orig) {
		t.Fatal("Normalize mutated its input")
	}

	cases := []struct {
		name string
		ann  map[string]any
		want any // nil = annotations key removed
	}{
		{"only last-applied", map[string]any{LastAppliedAnnotation: "{}"}, nil},
		{"logging annotation kept", map[string]any{"policy.network.gke.io/enable-logging": "true", LastAppliedAnnotation: "{}"}, map[string]any{"policy.network.gke.io/enable-logging": "true"}},
		{"no last-applied", map[string]any{"a": "1"}, map[string]any{"a": "1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Normalize(map[string]any{"metadata": map[string]any{"name": "n", "annotations": c.ann}})
			got, ok := o["metadata"].(map[string]any)["annotations"]
			if c.want == nil {
				if ok {
					t.Fatalf("annotations kept: %v", got)
				}
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("annotations %v, want %v", got, c.want)
			}
		})
	}
}

func TestOrderIndependence(t *testing.T) {
	obs := loadObservation(t)
	want := mustCompute(t, obs)
	for id, items := range obs.Objects {
		rev := make([]map[string]any, len(items))
		for i := range items {
			rev[len(items)-1-i] = items[i]
		}
		obs.Objects[id] = rev
	}
	pools := obs.Cluster["nodePools"].([]any)
	sort.Slice(pools, func(i, j int) bool {
		return pools[i].(map[string]any)["name"].(string) > pools[j].(map[string]any)["name"].(string)
	})
	if got := mustCompute(t, obs); got != want {
		t.Fatalf("order changed digests:\n got %+v\nwant %+v", got, want)
	}
}

// Every change below must leave exactly the listed digests changed.
func TestChangeSensitivity(t *testing.T) {
	type mut func(t *testing.T, o Observation)
	md := func(o map[string]any) map[string]any { return o["metadata"].(map[string]any) }
	ann := func(o map[string]any) map[string]any {
		m := md(o)
		if m["annotations"] == nil {
			m["annotations"] = map[string]any{}
		}
		return m["annotations"].(map[string]any)
	}
	cases := []struct {
		name    string
		mut     mut
		changed []string
	}{
		{"volatile metadata and status only", func(t *testing.T, o Observation) {
			for _, items := range o.Objects {
				for _, it := range items {
					m := md(it)
					m["resourceVersion"], m["uid"], m["generation"] = "777", "other", json.Number("99")
					m["creationTimestamp"] = "2030-01-01T00:00:00Z"
					m["managedFields"] = []any{}
					ann(it)[LastAppliedAnnotation] = "changed"
					it["status"] = map[string]any{"x": "y"}
				}
			}
		}, nil},
		{"logging annotation removed", func(t *testing.T, o Observation) {
			delete(ann(find(t, o, "networkpolicies", "agent-exec", "default-deny")), "policy.network.gke.io/enable-logging")
		}, []string{KindNetworkPolicy}},
		{"other annotation on VAP", func(t *testing.T, o Observation) {
			ann(find(t, o, "validatingadmissionpolicies", "", "agent-role-pod-constraints"))["x"] = "y"
		}, []string{KindAdmission}},
		{"NetworkPolicy outside role namespaces", func(t *testing.T, o Observation) {
			find(t, o, "networkpolicies", "default", "other-team")["spec"] = map[string]any{}
		}, nil},
		{"unrelated RoleBinding", func(t *testing.T, o Observation) {
			find(t, o, "rolebindings", "agent-control", "unrelated")["roleRef"] = map[string]any{}
		}, nil},
		{"unreferenced ClusterRole", func(t *testing.T, o Observation) {
			find(t, o, "clusterroles", "", "cluster-admin")["rules"] = []any{}
		}, nil},
		{"Role referenced from another namespace", func(t *testing.T, o Observation) {
			find(t, o, "roles", "agent-targets", "probe-reader")["rules"] = []any{}
		}, []string{KindExecRBAC}},
		{"ClusterRole bound to system:authenticated", func(t *testing.T, o Observation) {
			find(t, o, "clusterroles", "", "system:basic-user")["rules"] = []any{}
		}, []string{KindExecRBAC}},
		{"release policy", func(t *testing.T, o Observation) {
			find(t, o, "tracingpoliciesnamespaced", "agent-exec", "agentarium-tcp-connect")["spec"] = map[string]any{}
		}, []string{KeySensorReleasePolicies}},
		{"other TracingPolicyNamespaced in agent-exec", func(t *testing.T, o Observation) {
			find(t, o, "tracingpoliciesnamespaced", "agent-exec", "agentarium-extra")["spec"] = map[string]any{"x": "y"}
		}, []string{KindSensorPolicy}},
		{"DaemonSet outside projection", func(t *testing.T, o Observation) {
			ds := find(t, o, "tetragon-daemonset", "agent-sensors", "tetragon")
			ds["spec"].(map[string]any)["updateStrategy"] = map[string]any{"type": "OnDelete"}
			md(ds)["labels"] = map[string]any{"x": "y"}
			ann(ds)["z"] = "w"
		}, nil},
		{"DaemonSet pod template", func(t *testing.T, o Observation) {
			tpl := find(t, o, "tetragon-daemonset", "agent-sensors", "tetragon")["spec"].(map[string]any)["template"].(map[string]any)
			tpl["spec"].(map[string]any)["tolerations"] = []any{}
		}, []string{KindSensorPolicy}},
		{"tetragon-config", func(t *testing.T, o Observation) {
			find(t, o, "tetragon-config", "agent-sensors", "tetragon-config")["data"] = map[string]any{}
		}, []string{KindSensorPolicy}},
		{"node pool taint removed", func(t *testing.T, o Observation) {
			p := o.Cluster["nodePools"].([]any)[1].(map[string]any) // exec-pool
			cfg := p["config"].(map[string]any)
			cfg["taints"] = cfg["taints"].([]any)[:1]
		}, []string{KindNodePoolConfig}},
		{"node pool field outside projection", func(t *testing.T, o Observation) {
			p := o.Cluster["nodePools"].([]any)[1].(map[string]any)
			p["config"].(map[string]any)["machineType"] = "e2-standard-8"
			p["status"] = "RECONCILING"
			o.Cluster["currentMasterVersion"] = "1.34.0"
			o.Cluster["maintenancePolicy"].(map[string]any)["resourceVersion"] = "zzz"
		}, nil},
		{"cluster maintenance exclusion", func(t *testing.T, o Observation) {
			o.Cluster["maintenancePolicy"].(map[string]any)["window"].(map[string]any)["maintenanceExclusions"] = map[string]any{}
		}, []string{KindNodePoolConfig}},
	}
	base := mustCompute(t, loadObservation(t))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs := loadObservation(t)
			c.mut(t, obs)
			got := mustCompute(t, obs)
			var changed []string
			for k, pair := range map[string][2]string{
				KindAdmission: {base.Admission, got.Admission}, KindExecRBAC: {base.ExecRBAC, got.ExecRBAC},
				KindNetworkPolicy: {base.NetworkPolicy, got.NetworkPolicy}, KindNodePoolConfig: {base.NodePoolConfig, got.NodePoolConfig},
				KindSensorPolicy: {base.SensorPolicy, got.SensorPolicy}, KeySensorReleasePolicies: {base.SensorReleasePolicies, got.SensorReleasePolicies},
			} {
				if pair[0] != pair[1] {
					changed = append(changed, k)
				}
			}
			sort.Strings(changed)
			want := append([]string(nil), c.changed...)
			sort.Strings(want)
			if !reflect.DeepEqual(changed, want) && !(len(changed) == 0 && len(want) == 0) {
				t.Fatalf("changed %v, want %v", changed, want)
			}
		})
	}
}

func keys(objs []map[string]any) []string {
	var out []string
	for _, o := range objs {
		k := sortKey(o)
		out = append(out, k[1]+" "+k[2]+"/"+k[3])
	}
	sort.Strings(out)
	return out
}

func TestExecRBACSelection(t *testing.T) {
	obs := loadObservation(t)
	got := keys(SelectExecRBAC(obs.Objects["roles"], obs.Objects["rolebindings"], obs.Objects["clusterroles"], obs.Objects["clusterrolebindings"]))
	want := []string{
		"ClusterRole /system:basic-user",
		"ClusterRole /tetragon",
		"ClusterRoleBinding /system:basic-user",
		"ClusterRoleBinding /tetragon",
		"Role agent-exec/runtime",
		"Role agent-sensors/tetragon",
		"Role agent-targets/probe-reader",
		"RoleBinding agent-exec/runtime",
		"RoleBinding agent-observe/dangling",
		"RoleBinding agent-sensors/tetragon",
		"RoleBinding agent-targets/exec-reads-targets",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selection\n got %v\nwant %v", got, want)
	}
}

func TestExecSubject(t *testing.T) {
	cases := []struct {
		kind, name, ns, bindingNS string
		want                      bool
	}{
		{"ServiceAccount", "a", "agent-exec", "", true},
		{"ServiceAccount", "a", "", "agent-sensors", true},
		{"ServiceAccount", "a", "", "agent-control", false},
		{"ServiceAccount", "a", "agent-control", "agent-exec", false},
		{"User", "system:serviceaccount:agent-exec:x", "", "", true},
		{"User", "system:serviceaccount:agent-exec:", "", "", false},
		{"User", "system:serviceaccount:agent-control:x", "", "", false},
		{"User", "alice@example.com", "", "", false},
		{"Group", "system:serviceaccounts", "", "", true},
		{"Group", "system:serviceaccounts:agent-sensors", "", "", true},
		{"Group", "system:serviceaccounts:agent-control", "", "", false},
		{"Group", "system:authenticated", "", "", true},
		{"Group", "system:unauthenticated", "", "", true},
		{"Group", "system:masters", "", "", false},
	}
	for _, c := range cases {
		s := map[string]any{"kind": c.kind, "name": c.name}
		if c.ns != "" {
			s["namespace"] = c.ns
		}
		if got := execSubject(s, c.bindingNS); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}

func TestSensorSplit(t *testing.T) {
	obs := loadObservation(t)
	src, _ := sourceByID("tracingpoliciesnamespaced")
	install, release := SplitSensor(Select(src, obs.Objects["tracingpoliciesnamespaced"]))
	if got := keys(release); !reflect.DeepEqual(got, []string{"TracingPolicyNamespaced agent-exec/agentarium-protected-file", "TracingPolicyNamespaced agent-exec/agentarium-tcp-connect"}) {
		t.Fatalf("release %v", got)
	}
	if got := keys(install); !reflect.DeepEqual(got, []string{"TracingPolicyNamespaced agent-exec/agentarium-extra"}) {
		t.Fatalf("install %v", got)
	}
	// Same names in another Namespace stay in the install part.
	other := deepCopy(release[0]).(map[string]any)
	other["metadata"].(map[string]any)["namespace"] = "agent-targets"
	if _, r := SplitSensor([]map[string]any{other}); len(r) != 0 {
		t.Fatal("release policy name outside agent-exec treated as release")
	}

	d := mustCompute(t, obs)
	wantRelease, err := DigestObjects(release)
	if err != nil {
		t.Fatal(err)
	}
	if d.SensorReleasePolicies != wantRelease {
		t.Fatal("sensor_release_policies is not the digest of the two release policies")
	}
	drift, err := SensorDriftDigest(d.SensorPolicy, d.SensorReleasePolicies)
	if err != nil {
		t.Fatal(err)
	}
	jcs := `{"install":"` + d.SensorPolicy + `","release":"` + d.SensorReleasePolicies + `"}`
	if want := canonical.SHA256Hex([]byte(jcs)); drift != want {
		t.Fatalf("drift digest %s, want %s", drift, want)
	}
	if _, err := SensorDriftDigest("abc", d.SensorReleasePolicies); err == nil {
		t.Fatal("non-hex digest accepted")
	}
}

func TestProjectDaemonSet(t *testing.T) {
	obs := loadObservation(t)
	got := ProjectDaemonSet(find(t, obs, "tetragon-daemonset", "agent-sensors", "tetragon"))
	var topKeys []string
	for k := range got {
		topKeys = append(topKeys, k)
	}
	sort.Strings(topKeys)
	if !reflect.DeepEqual(topKeys, []string{"apiVersion", "kind", "metadata", "spec"}) {
		t.Fatalf("keys %v", topKeys)
	}
	if !reflect.DeepEqual(got["metadata"], map[string]any{"name": "tetragon", "namespace": "agent-sensors"}) {
		t.Fatalf("metadata %v", got["metadata"])
	}
	spec := got["spec"].(map[string]any)
	if len(spec) != 1 || spec["template"] == nil {
		t.Fatalf("spec %v", spec)
	}
}

func TestNodePoolConfigDefaults(t *testing.T) {
	implicit := map[string]any{"nodePools": []any{map[string]any{"name": "p", "config": map[string]any{}}}}
	explicit := map[string]any{
		"nodePools": []any{map[string]any{"name": "p", "config": map[string]any{"taints": []any{}, "labels": map[string]any{}},
			"management": map[string]any{"autoUpgrade": false, "autoRepair": false}}},
		"maintenancePolicy": map[string]any{"window": map[string]any{}},
	}
	a, err := NodePoolConfig(implicit)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NodePoolConfig(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("defaults differ\n%v\n%v", a, b)
	}
	for _, bad := range []map[string]any{{}, {"nodePools": []any{map[string]any{}}},
		{"nodePools": []any{map[string]any{"name": "p"}, map[string]any{"name": "p"}}}} {
		if _, err := NodePoolConfig(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestSelectFillsTypeMeta(t *testing.T) {
	src, _ := sourceByID("roles")
	got := Select(src, []map[string]any{{"metadata": map[string]any{"name": "r", "namespace": "agent-exec"}}})
	if len(got) != 1 || got[0]["apiVersion"] != "rbac.authorization.k8s.io/v1" || got[0]["kind"] != "Role" {
		t.Fatalf("got %v", got)
	}
	if got := Select(src, []map[string]any{{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "r"}}}); len(got) != 0 {
		t.Fatalf("foreign kind kept: %v", got)
	}
}

func TestMissing(t *testing.T) {
	obs := loadObservation(t)
	for _, s := range Sources() {
		if m := Missing(s, obs.Objects[s.ID]); len(m) != 0 {
			t.Errorf("%s: fixture missing %v", s.ID, m)
		}
	}
	src, _ := sourceByID("constraints-configmaps")
	if got := Missing(src, obs.Objects[src.ID][:1]); !reflect.DeepEqual(got, []string{"agent-control/agent-exec-constraints"}) {
		t.Fatalf("missing %v", got)
	}
	nl, _ := sourceByID("networkloggings")
	if got := Missing(nl, nil); !reflect.DeepEqual(got, []string{"default"}) {
		t.Fatalf("missing %v", got)
	}
	if got := MissingReleasePolicies(obs.Objects["tracingpoliciesnamespaced"]); len(got) != 0 {
		t.Fatalf("release missing %v", got)
	}
	if got := MissingReleasePolicies(nil); len(got) != 2 {
		t.Fatalf("release missing %v", got)
	}
}

func TestDuplicateObjectRejected(t *testing.T) {
	o := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "a", "namespace": "n"}}
	if _, err := DigestObjects([]map[string]any{o, deepCopy(o).(map[string]any)}); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestReleasePoliciesDigest(t *testing.T) {
	obs := loadObservation(t)
	src, _ := sourceByID("tracingpoliciesnamespaced")
	_, release := SplitSensor(Select(src, obs.Objects["tracingpoliciesnamespaced"]))
	got, err := ReleasePoliciesDigest(release)
	if err != nil {
		t.Fatal(err)
	}
	if d := mustCompute(t, obs); got != d.SensorReleasePolicies {
		t.Fatalf("digest %s, want sensor_release_policies %s", got, d.SensorReleasePolicies)
	}
	with := func(edit func(o map[string]any)) []map[string]any {
		objs := []map[string]any{deepCopy(release[0]).(map[string]any), deepCopy(release[1]).(map[string]any)}
		edit(objs[0])
		return objs
	}
	extra := deepCopy(release[0]).(map[string]any)
	extra["metadata"].(map[string]any)["name"] = "agentarium-extra"
	for name, objs := range map[string][]map[string]any{
		"empty":            nil,
		"missing one":      release[:1],
		"duplicate":        {release[0], release[0], release[1]},
		"extra object":     append([]map[string]any{extra}, release...),
		"wrong namespace":  with(func(o map[string]any) { o["metadata"].(map[string]any)["namespace"] = "agent-targets" }),
		"wrong name":       with(func(o map[string]any) { o["metadata"].(map[string]any)["name"] = "agentarium-protected-files" }),
		"wrong kind":       with(func(o map[string]any) { o["kind"] = "TracingPolicy" }),
		"wrong apiVersion": with(func(o map[string]any) { o["apiVersion"] = "cilium.io/v1beta1" }),
	} {
		if d, err := ReleasePoliciesDigest(objs); err == nil {
			t.Errorf("%s: accepted, digest %s", name, d)
		}
	}
}
