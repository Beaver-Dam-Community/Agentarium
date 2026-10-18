// Package admission holds offline checks for the TASK-01 Kubernetes base
// manifests (deploy/gcp/base/{namespaces,admission}, rbac/drift-probe.yaml).
// Nothing here talks to a cluster.
package admission

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	admv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/validation"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
	psapi "k8s.io/pod-security-admission/api"
	"sigs.k8s.io/yaml"
)

var repoRoot = filepath.Join("..", "..", "..")

// manifestFiles are the files owned by TASK-01 in this change.
var manifestFiles = []string{
	"deploy/gcp/base/namespaces/namespaces.yaml",
	"deploy/gcp/base/namespaces/agent-exec-resources.yaml",
	"deploy/gcp/base/admission/priority-classes.yaml",
	"deploy/gcp/base/admission/constraints.yaml",
	"deploy/gcp/base/admission/agent-exec.yaml",
	"deploy/gcp/base/admission/agent-roles.yaml",
	"deploy/gcp/base/admission/agent-sensors.yaml",
	"deploy/gcp/base/admission/node-readiness-scope.yaml",
	"deploy/gcp/base/admission/discovery-snapshot.yaml",
	"deploy/gcp/base/rbac/drift-probe.yaml",
}

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	digestD = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	reg     = "us-docker.pkg.dev/test-project/agentarium/"

	runtimeImage     = reg + "runtime@" + digestA
	probeImage       = reg + "probe-runner@" + digestB
	fixtureImage     = reg + "start-fixture@" + digestC
	probeEntrypoint  = "/app/bin/probe-runner"
	fixtureEntry     = "/app/bin/start-fixture"
	gatewayImage     = reg + "gateway@" + digestD
	adapterImage     = reg + "kubernetes-reader@" + digestA
	sqlProxyImage    = reg + "cloud-sql-proxy@" + digestB
	tetragonImage    = reg + "tetragon@" + digestA
	exporterImage    = reg + "sensors-exporter@" + digestB
	recorderImage    = reg + "lifecycle-recorder@" + digestC
	guardImage       = reg + "runtime-guard@" + digestD
	netpolImage      = reg + "sensors-netpol-collector@" + digestA
	snapshotImage    = reg + "discovery-snapshot@" + digestC
	auditImage       = reg + "audit@" + digestD
	discoveryBucket  = "agentarium-test-discovery"
	correlationImage = reg + "correlation@" + digestC
	nriAnnotationKey = "io.containerd.nri.tolerate-missing-plugins"
)

// TASK-01 3.2.1 / deploy/gcp/sensors/sensor-permissions.json host_paths.
// /sys/fs/cgroup is appended last (#231) so the index-based cases keep their paths.
var tetragonHostPaths = []string{"/proc", "/sys/fs/bpf", "/var/lib/agentarium/sensor-spool", "/var/run/cilium", "/var/run/cilium/tetragon", "/var/run/tetragon", "/sys/fs/cgroup"}

// sampleRender stands in for values the renderer takes from
// deploy/gcp/environment.lock.json and CI outputs.
func sampleRender() map[string]string {
	return map[string]string{
		"PSS_VERSION":               "v1.33",
		"RUNTIME_IMAGE":             runtimeImage,
		"PROBE_IMAGES":              probeImage,
		"FIXTURE_IMAGES":            fixtureImage,
		"PROBE_ENTRYPOINTS":         probeImage + "=" + probeEntrypoint + "," + fixtureImage + "=" + fixtureEntry,
		"GUARDED_RUNTIME_ENABLED":   "false",
		"FORBIDDEN_ANNOTATION_KEYS": nriAnnotationKey,
		"AGENT_CONTROL_IMAGES":      gatewayImage + "," + sqlProxyImage,
		"AGENT_ADAPTERS_IMAGES":     adapterImage + "," + probeImage + "," + sqlProxyImage,
		"AGENT_OBSERVE_IMAGES":      strings.Join([]string{sqlProxyImage, snapshotImage, auditImage, correlationImage}, ","),
		"DISCOVERY_SNAPSHOT_IMAGE":  snapshotImage,
		"DISCOVERY_BUCKET":          discoveryBucket,
		"AGENT_RELEASE_IMAGES":      sqlProxyImage,
		"AGENT_TARGETS_IMAGES":      sqlProxyImage,
		"AGENT_SENSORS_IMAGES":      strings.Join([]string{tetragonImage, exporterImage, recorderImage, guardImage, netpolImage}, ","),
		"TETRAGON_HOST_PATHS":       strings.Join(tetragonHostPaths, ","),
		"TETRAGON_IMAGE":            tetragonImage,
	}
}

var placeholderRE = regexp.MustCompile(`\$\{([A-Za-z0-9_]*)\}`)

func render(t *testing.T, raw string, values map[string]string) string {
	t.Helper()
	var missing []string
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue // render notes in comments name the placeholders
		}
		lines[i] = placeholderRE.ReplaceAllStringFunc(line, func(m string) string {
			name := placeholderRE.FindStringSubmatch(m)[1]
			v, ok := values[name]
			if !ok {
				missing = append(missing, name)
				return m
			}
			return v
		})
	}
	if len(missing) > 0 {
		t.Fatalf("unknown or unrendered placeholders: %v", missing)
	}
	return strings.Join(lines, "\n")
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, admv1.AddToScheme, rbacv1.AddToScheme, schedulingv1.AddToScheme,
	} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

type decoded struct {
	file string
	obj  runtime.Object
}

// decodeStrict splits a multi-document YAML stream and decodes every
// non-empty document into its typed Go struct, rejecting unknown and
// duplicate fields.
func decodeStrict(t *testing.T, s *runtime.Scheme, file, data string) []decoded {
	t.Helper()
	ser := kjson.NewSerializerWithOptions(kjson.DefaultMetaFactory, s, s, kjson.SerializerOptions{Yaml: true, Strict: true})
	r := kyaml.NewYAMLReader(bufio.NewReader(strings.NewReader(data)))
	var out []decoded
	for {
		doc, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("%s: split: %v", file, err)
		}
		var probe map[string]any
		if err := yaml.Unmarshal(doc, &probe); err != nil {
			t.Fatalf("%s: yaml: %v", file, err)
		}
		if len(probe) == 0 {
			continue
		}
		obj, _, err := ser.Decode(doc, nil, nil)
		if err != nil {
			t.Fatalf("%s: strict decode: %v\n%s", file, err, doc)
		}
		out = append(out, decoded{file: file, obj: obj})
	}
	return out
}

func readFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func loadAll(t *testing.T, values map[string]string) []decoded {
	t.Helper()
	s := newScheme(t)
	var all []decoded
	for _, f := range manifestFiles {
		all = append(all, decodeStrict(t, s, f, render(t, readFile(t, f), values))...)
	}
	return all
}

func TestManifestsParseStrictly(t *testing.T) {
	all := loadAll(t, sampleRender())
	counts := map[string]int{}
	for _, d := range all {
		counts[d.obj.GetObjectKind().GroupVersionKind().Kind]++
	}
	want := map[string]int{
		"Namespace":                        7,
		"ResourceQuota":                    2,
		"LimitRange":                       1,
		"PriorityClass":                    1,
		"ConfigMap":                        3,
		"ValidatingAdmissionPolicy":        9,
		"ValidatingAdmissionPolicyBinding": 9,
		"ClusterRole":                      1,
		"ClusterRoleBinding":               1,
		"Role":                             2,
		"RoleBinding":                      2,
	}
	if !equality.Semantic.DeepEqual(counts, want) {
		t.Fatalf("object kinds = %v, want %v", counts, want)
	}
}

// Every placeholder in the raw manifests must be a known render input, and
// every placeholder must be quoted so a rendered "true" or "" stays a string.
func TestPlaceholdersKnownAndQuoted(t *testing.T) {
	known := sampleRender()
	quoted := regexp.MustCompile(`"\$\{[A-Z0-9_]+\}"`)
	for _, f := range manifestFiles {
		raw := readFile(t, f)
		for _, line := range strings.Split(raw, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range placeholderRE.FindAllStringSubmatch(line, -1) {
				if _, ok := known[m[1]]; !ok {
					t.Errorf("%s: unknown placeholder %s", f, m[0])
				}
			}
			if placeholderRE.MatchString(line) && len(quoted.FindAllString(line, -1)) != len(placeholderRE.FindAllString(line, -1)) {
				t.Errorf("%s: placeholder not quoted: %s", f, strings.TrimSpace(line))
			}
		}
		if strings.Contains(raw, ":latest") {
			t.Errorf("%s: contains a :latest reference", f)
		}
	}
}

func TestNamespacesPSS(t *testing.T) {
	all := loadAll(t, sampleRender())
	want := []string{"agent-adapters", "agent-control", "agent-exec", "agent-observe", "agent-release", "agent-sensors", "agent-targets"}
	var got []string
	for _, d := range all {
		ns, ok := d.obj.(*corev1.Namespace)
		if !ok {
			continue
		}
		got = append(got, ns.Name)
		enforce := "restricted"
		if ns.Name == "agent-sensors" {
			enforce = "privileged"
		}
		expect := map[string]string{
			psapi.EnforceLevelLabel: enforce, psapi.AuditLevelLabel: "restricted", psapi.WarnLevelLabel: "restricted",
		}
		for k, v := range expect {
			if ns.Labels[k] != v {
				t.Errorf("%s: %s = %q, want %q", ns.Name, k, ns.Labels[k], v)
			}
		}
		for _, k := range []string{psapi.EnforceVersionLabel, psapi.AuditVersionLabel, psapi.WarnVersionLabel} {
			v := ns.Labels[k]
			if v != "v1.33" {
				t.Errorf("%s: %s = %q, want rendered lock minor", ns.Name, k, v)
			}
			if _, err := psapi.ParseVersion(v); err != nil || v == "latest" {
				t.Errorf("%s: %s = %q is not a pinned PSS version: %v", ns.Name, k, v, err)
			}
		}
		for k, v := range ns.Labels {
			if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
				t.Errorf("%s: label %s=%q: %v", ns.Name, k, v, errs)
			}
		}
	}
	sort.Strings(got)
	if !equality.Semantic.DeepEqual(got, want) {
		t.Fatalf("namespaces = %v, want %v", got, want)
	}
}

func TestExecQuotasAndPriorityClass(t *testing.T) {
	for _, d := range loadAll(t, sampleRender()) {
		switch o := d.obj.(type) {
		case *schedulingv1.PriorityClass:
			if o.Name != "agentarium-runtime" || o.Value != 1000 || o.PreemptionPolicy == nil ||
				*o.PreemptionPolicy != corev1.PreemptNever || o.GlobalDefault {
				t.Errorf("PriorityClass %s does not match spec 3.3: %+v", o.Name, o)
			}
		case *corev1.ResourceQuota:
			if o.Namespace != "agent-exec" || o.Spec.ScopeSelector == nil || len(o.Spec.ScopeSelector.MatchExpressions) != 1 {
				t.Fatalf("quota %s: bad scope", o.Name)
			}
			e := o.Spec.ScopeSelector.MatchExpressions[0]
			if e.ScopeName != corev1.ResourceQuotaScopePriorityClass || !equality.Semantic.DeepEqual(e.Values, []string{"agentarium-runtime"}) {
				t.Errorf("quota %s: scope %+v", o.Name, e)
			}
			hard := map[string]string{}
			for k, v := range o.Spec.Hard {
				hard[string(k)] = v.String()
			}
			var want map[string]string
			switch o.Name {
			case "agent-runtime-quota":
				if e.Operator != corev1.ScopeSelectorOpIn {
					t.Errorf("runtime quota operator %s", e.Operator)
				}
				want = map[string]string{
					"pods": "5", "requests.cpu": "2500m", "requests.memory": "2560Mi",
					"limits.cpu": "10", "limits.memory": "10Gi",
				}
			case "agent-probe-quota":
				if e.Operator != corev1.ScopeSelectorOpNotIn {
					t.Errorf("probe quota operator %s", e.Operator)
				}
				want = map[string]string{"pods": "22"}
			default:
				t.Fatalf("unexpected quota %s", o.Name)
			}
			if !equality.Semantic.DeepEqual(hard, want) {
				t.Errorf("quota %s hard = %v, want %v", o.Name, hard, want)
			}
		case *corev1.LimitRange:
			if len(o.Spec.Limits) != 1 || o.Spec.Limits[0].Type != corev1.LimitTypeContainer {
				t.Fatalf("LimitRange %s: %+v", o.Name, o.Spec)
			}
			m := o.Spec.Limits[0].Max
			if m.Cpu().String() != "2" || m.Memory().String() != "2Gi" || m.StorageEphemeral().String() != "2Gi" {
				t.Errorf("LimitRange max = %v", m)
			}
		}
	}
}

func TestDriftProbeReadOnly(t *testing.T) {
	var cr *rbacv1.ClusterRole
	roles := map[string]*rbacv1.Role{}
	bindings := map[string]bool{}
	for _, d := range loadAll(t, sampleRender()) {
		switch o := d.obj.(type) {
		case *rbacv1.ClusterRole:
			cr = o
		case *rbacv1.Role:
			if roles[o.Namespace] != nil {
				t.Fatalf("duplicate Role namespace %s", o.Namespace)
			}
			roles[o.Namespace] = o
		case *rbacv1.ClusterRoleBinding:
			checkDriftSubject(t, o.Name, o.Subjects, o.RoleRef, "ClusterRole")
		case *rbacv1.RoleBinding:
			if o.Namespace != "agent-control" && o.Namespace != "agent-sensors" {
				t.Errorf("RoleBinding namespace %s", o.Namespace)
			}
			if bindings[o.Namespace] {
				t.Fatalf("duplicate RoleBinding namespace %s", o.Namespace)
			}
			bindings[o.Namespace] = true
			checkDriftSubject(t, o.Name, o.Subjects, o.RoleRef, "Role")
		}
	}
	if cr == nil || len(roles) != 2 || len(bindings) != 2 || roles["agent-control"] == nil || roles["agent-sensors"] == nil || !bindings["agent-control"] || !bindings["agent-sensors"] {
		t.Fatal("drift-probe ClusterRole/Role missing")
	}
	want := map[string][]string{
		"admissionregistration.k8s.io": {"validatingadmissionpolicies", "validatingadmissionpolicybindings"},
		"rbac.authorization.k8s.io":    {"clusterrolebindings", "clusterroles", "rolebindings", "roles"},
		"networking.k8s.io":            {"networkpolicies"},
		"networking.gke.io":            {"networkloggings"},
		"cilium.io":                    {"tracingpolicies", "tracingpoliciesnamespaced"},
		"":                             {"namespaces", "nodes"},
	}
	got := map[string][]string{}
	for _, r := range cr.Rules {
		if !equality.Semantic.DeepEqual(r.Verbs, []string{"get", "list"}) || len(r.ResourceNames) > 0 || len(r.NonResourceURLs) > 0 {
			t.Errorf("ClusterRole rule not get/list only: %+v", r)
		}
		for _, g := range r.APIGroups {
			got[g] = append(got[g], r.Resources...)
		}
	}
	for g := range got {
		sort.Strings(got[g])
	}
	if !equality.Semantic.DeepEqual(got, want) {
		t.Errorf("ClusterRole resources = %v, want %v", got, want)
	}
	wantRoles := map[string][]rbacv1.PolicyRule{
		"agent-control": {{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"agent-exec-constraints", "agent-role-constraints"}, Verbs: []string{"get"}}},
		"agent-sensors": {
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"tetragon-config"}, Verbs: []string{"get"}},
			{APIGroups: []string{"apps"}, Resources: []string{"daemonsets"}, ResourceNames: []string{"tetragon"}, Verbs: []string{"get"}},
		},
	}
	for namespace, rules := range wantRoles {
		role := roles[namespace]
		if role.Name != "drift-probe" || !equality.Semantic.DeepEqual(role.Rules, rules) {
			t.Errorf("Role %s permission ceiling: %+v", namespace, role)
		}
	}
	// Match only the rendered resource rules checked above. This is an offline
	// permission check, not a claim about a cluster's additive RBAC bindings.
	allows := func(namespace, group, resource, name, verb string) bool {
		rules := append([]rbacv1.PolicyRule{}, cr.Rules...)
		if role := roles[namespace]; role != nil {
			rules = append(rules, role.Rules...)
		}
		for _, rule := range rules {
			if slices.Contains(rule.APIGroups, group) && slices.Contains(rule.Resources, resource) && slices.Contains(rule.Verbs, verb) && (len(rule.ResourceNames) == 0 || slices.Contains(rule.ResourceNames, name)) {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		namespace, group, resource, name, verb string
		want                                   bool
	}{
		{"", "cilium.io", "tracingpolicies", "sensor", "get", true},
		{"", "cilium.io", "tracingpolicies", "", "list", true},
		{"agent-sensors", "cilium.io", "tracingpoliciesnamespaced", "sensor", "get", true},
		{"agent-sensors", "cilium.io", "tracingpoliciesnamespaced", "", "list", true},
		{"agent-sensors", "", "configmaps", "tetragon-config", "get", true},
		{"agent-sensors", "apps", "daemonsets", "tetragon", "get", true},
		{"agent-control", "", "configmaps", "agent-exec-constraints", "get", true},
		{"agent-control", "", "configmaps", "agent-role-constraints", "get", true},
		{"agent-control", "", "configmaps", "tetragon-config", "get", false},
		{"agent-control", "apps", "daemonsets", "tetragon", "get", false},
		{"agent-sensors", "", "configmaps", "another-config", "get", false},
		{"agent-sensors", "apps", "daemonsets", "another-daemonset", "get", false},
		{"agent-sensors", "", "configmaps", "", "list", false},
		{"agent-sensors", "apps", "daemonsets", "", "list", false},
		{"agent-sensors", "", "secrets", "tetragon-config", "get", false},
		{"agent-sensors", "apps", "daemonsets/status", "tetragon", "get", false},
		{"agent-sensors", "", "configmaps", "tetragon-config", "update", false},
		{"agent-sensors", "apps", "daemonsets", "tetragon", "patch", false},
		{"", "cilium.io", "tracingpolicies", "sensor", "delete", false},
		{"agent-sensors", "cilium.io", "tracingpoliciesnamespaced", "sensor", "create", false},
		{"agent-sensors", "cilium.io", "tracingpoliciesnamespaced", "", "watch", false},
	} {
		t.Run(strings.Join([]string{tc.namespace, tc.group, tc.resource, tc.name, tc.verb}, "/"), func(t *testing.T) {
			if got := allows(tc.namespace, tc.group, tc.resource, tc.name, tc.verb); got != tc.want {
				t.Errorf("rendered permission = %v, want %v", got, tc.want)
			}
		})
	}
}

func checkDriftSubject(t *testing.T, name string, subjects []rbacv1.Subject, ref rbacv1.RoleRef, kind string) {
	t.Helper()
	want := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "drift-probe", Namespace: "agent-observe"}}
	if !equality.Semantic.DeepEqual(subjects, want) || name != "drift-probe" || ref.APIGroup != rbacv1.GroupName || ref.Kind != kind || ref.Name != "drift-probe" {
		t.Errorf("binding %s: subjects %+v ref %+v", name, subjects, ref)
	}
}

// Every YAML file in the two Kustomize directories is listed in its
// kustomization.yaml and every listed resource exists.
func TestKustomizationsComplete(t *testing.T) {
	for _, dir := range []string{"deploy/gcp/base/namespaces", "deploy/gcp/base/admission"} {
		var k struct {
			Resources []string `json:"resources"`
		}
		if err := yaml.Unmarshal([]byte(readFile(t, dir+"/kustomization.yaml")), &k); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(filepath.Join(repoRoot, dir))
		if err != nil {
			t.Fatal(err)
		}
		var files []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".yaml") && e.Name() != "kustomization.yaml" {
				files = append(files, e.Name())
			}
		}
		res := append([]string(nil), k.Resources...)
		sort.Strings(res)
		sort.Strings(files)
		if !equality.Semantic.DeepEqual(res, files) {
			t.Errorf("%s: kustomization resources %v, files %v", dir, res, files)
		}
	}
}

// specDelta is a documented departure of a manifest policy from its spec
// literal (see the SPEC-DELTA header comment of the manifest). The manifest
// must equal the spec literal with these additions appended and nothing else
// changed; the added expressions are covered by policies_test.go.
type specDelta struct {
	addResources   []string // appended to resourceRules[0].resources
	addVariables   []string // appended variable names
	addValidations []string // appended validation messages
}

var specDeltas = map[string]specDelta{
	"ValidatingAdmissionPolicy/node-readiness-scope": {
		addResources:   []string{"nodes/status"},
		addVariables:   []string{"newStartTaints", "oldStartTaints"},
		addValidations: []string{"NODE_READINESS_SCOPE_INVALID", "NODE_READINESS_SCOPE_INVALID"},
	},
}

// applyDelta returns the spec literal with the delta's additions, taking the
// added expressions from the manifest after checking their names/messages.
func applyDelta(t *testing.T, key string, spec, got *admv1.ValidatingAdmissionPolicy, d specDelta) *admv1.ValidatingAdmissionPolicy {
	t.Helper()
	want := spec.DeepCopy()
	rules := want.Spec.MatchConstraints.ResourceRules
	rules[0].Resources = append(rules[0].Resources, d.addResources...)
	nv, nval := len(spec.Spec.Variables), len(spec.Spec.Validations)
	if len(got.Spec.Variables) != nv+len(d.addVariables) || len(got.Spec.Validations) != nval+len(d.addValidations) {
		t.Errorf("%s: manifest adds %d variables and %d validations, delta documents %d and %d", key,
			len(got.Spec.Variables)-nv, len(got.Spec.Validations)-nval, len(d.addVariables), len(d.addValidations))
		return want
	}
	for i, name := range d.addVariables {
		v := got.Spec.Variables[nv+i]
		if v.Name != name {
			t.Errorf("%s: added variable %d is %q, want %q", key, i, v.Name, name)
		}
		want.Spec.Variables = append(want.Spec.Variables, v)
	}
	for i, msg := range d.addValidations {
		v := got.Spec.Validations[nval+i]
		if v.Message != msg {
			t.Errorf("%s: added validation %d has message %q, want %q", key, i, v.Message, msg)
		}
		want.Spec.Validations = append(want.Spec.Validations, v)
	}
	return want
}

// The spec (TASK-01 3.2, 3.2.1) gives literal YAML for several policies and
// bindings; the manifests must contain exactly those objects, except for the
// additions listed in specDeltas.
func TestSpecLiteralPoliciesUnchanged(t *testing.T) {
	s := newScheme(t)
	spec := readFile(t, "docs/tech-specs/TASK-01-gke-platform.md")
	blockRE := regexp.MustCompile("(?s)```yaml\n(.*?)```")
	specObjs := map[string]runtime.Object{}
	for _, m := range blockRE.FindAllStringSubmatch(spec, -1) {
		if !strings.Contains(m[1], "kind: ValidatingAdmissionPolicy") {
			continue
		}
		for _, d := range decodeStrict(t, s, "TASK-01 spec", m[1]) {
			specObjs[objKey(d.obj)] = d.obj
		}
	}
	if len(specObjs) < 7 {
		t.Fatalf("found only %d literal objects in the spec", len(specObjs))
	}
	got := map[string]runtime.Object{}
	for _, d := range loadAll(t, sampleRender()) {
		got[objKey(d.obj)] = d.obj
	}
	for k := range specDeltas {
		if _, ok := specObjs[k]; !ok {
			t.Errorf("spec delta %s has no spec literal", k)
		}
	}
	for k, want := range specObjs {
		if d, ok := specDeltas[k]; ok {
			g, ok := got[k].(*admv1.ValidatingAdmissionPolicy)
			if !ok {
				t.Errorf("%s missing from the manifests", k)
				continue
			}
			want = applyDelta(t, k, want.(*admv1.ValidatingAdmissionPolicy), g, d)
		}
		if !equality.Semantic.DeepEqual(got[k], want) {
			t.Errorf("%s differs from the spec literal", k)
		}
	}
}

func objKey(o runtime.Object) string {
	var buf bytes.Buffer
	buf.WriteString(o.GetObjectKind().GroupVersionKind().Kind)
	switch v := o.(type) {
	case *admv1.ValidatingAdmissionPolicy:
		buf.WriteString("/" + v.Name)
	case *admv1.ValidatingAdmissionPolicyBinding:
		buf.WriteString("/" + v.Name)
	}
	return buf.String()
}
