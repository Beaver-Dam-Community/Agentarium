// Package deploy checks the rendered TASK-09 sensor installation offline:
// deploy/gcp/sensors/render.py output, the post-rendered exporter sidecar, the
// rendered TracingPolicies, sensor-permissions.json, and admission of the
// DaemonSet Pod by the deploy/gcp/base agent-sensors policies (VAP + PSA).
// Nothing here talks to a cluster.
//
// The pinned chart archive is read from TETRAGON_CHART, or pulled with
// `helm pull tetragon --repo https://helm.cilium.io --version 1.7.1`.
package deploy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/capture"
	admv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/version"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/environment"
	psapi "k8s.io/pod-security-admission/api"
	pspolicy "k8s.io/pod-security-admission/policy"
	"sigs.k8s.io/yaml"
)

var repo = filepath.Join("..", "..", "..")

const (
	reg           = "us-docker.pkg.dev/test-project/agentarium"
	exporterImage = reg + "/sensors-exporter@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tetragonImage = reg + "/tetragon@sha256:255f3d403e615f6a6f557cf4f197a5db3959ace9ad7003309f5e0d4b4300c815"
)

var sampleValues = map[string]string{
	"IMAGE_REPOSITORY": reg, "EXPORTER_IMAGE": exporterImage,
	"IDENTITY_ORIGIN": "https://policy-gateway.agent-control.svc:8443", "COLLECTOR_ORIGIN": "https://audit-writer.agent-observe.svc:8443", "HEALTH_ORIGIN": "https://control-health.agent-observe.svc:8443",
	"EXPORTER_VERSION": "sample", "SENSOR_GENERATION": "1", "NORMALIZATION_VERSION": "sample-normalization",
	"SPOOL_CAPACITY_BYTES": "268435456",
}

func chart(t *testing.T) string {
	if p := os.Getenv("TETRAGON_CHART"); p != "" {
		return p
	}
	dir := t.TempDir()
	if out, err := exec.Command("helm", "pull", "tetragon", "--repo", "https://helm.cilium.io", "--version", "1.7.1", "-d", dir).CombinedOutput(); err != nil {
		t.Skipf("pinned Tetragon chart unavailable (set TETRAGON_CHART): %s", out)
	}
	return filepath.Join(dir, "tetragon-1.7.1.tgz")
}

func renderSensors(t *testing.T, values map[string]string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	raw, _ := json.Marshal(values)
	vf := filepath.Join(dir, "values.json")
	if err := os.WriteFile(vf, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	cmd := exec.Command("python3", filepath.Join(repo, "deploy/gcp/sensors/render.py"), "--values", vf, "--chart", chart(t), "--out", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", errors.New(string(b))
	}
	return out, nil
}

func scheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, admv1.AddToScheme, schedulingv1.AddToScheme, rbacv1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// decode strictly decodes the kinds this package checks and returns the rest
// as generic maps.
func decode(t *testing.T, data []byte) ([]runtime.Object, []map[string]any) {
	t.Helper()
	s := scheme(t)
	ser := kjson.NewSerializerWithOptions(kjson.DefaultMetaFactory, s, s, kjson.SerializerOptions{Yaml: true, Strict: true})
	r := kyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	var typed []runtime.Object
	var generic []map[string]any
	for {
		doc, err := r.Read()
		if errors.Is(err, io.EOF) {
			return typed, generic
		}
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := yaml.Unmarshal(doc, &m); err != nil {
			t.Fatal(err)
		}
		if len(m) == 0 {
			continue
		}
		switch m["kind"] {
		case "DaemonSet", "Deployment", "ConfigMap", "Namespace", "ServiceAccount", "PersistentVolumeClaim", "Role", "RoleBinding", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
			obj, _, err := ser.Decode(doc, nil, nil)
			if err != nil {
				t.Fatalf("strict decode %v: %v", m["kind"], err)
			}
			typed = append(typed, obj)
		default:
			generic = append(generic, m)
		}
	}
}

func read(t *testing.T, path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type permissions struct {
	ServiceAccount string   `json:"service_account"`
	HostNetwork    bool     `json:"host_network"`
	HostPID        bool     `json:"host_pid"`
	HostIPC        bool     `json:"host_ipc"`
	HostPaths      []string `json:"host_paths"`
}

func TestRenderedSensorInstallation(t *testing.T) {
	out, err := renderSensors(t, sampleValues)
	if err != nil {
		t.Fatal(err)
	}
	typed, _ := decode(t, read(t, filepath.Join(out, "tetragon.yaml")))
	var ds *appsv1.DaemonSet
	for _, o := range typed {
		if d, ok := o.(*appsv1.DaemonSet); ok {
			ds = d
		}
	}
	if ds == nil {
		t.Fatal("no DaemonSet")
	}
	spec := ds.Spec.Template.Spec
	if spec.ServiceAccountName != "tetragon" || ds.Spec.Template.Labels["app.kubernetes.io/name"] != "tetragon" || !spec.HostNetwork || spec.DNSPolicy != corev1.DNSClusterFirstWithHostNet {
		t.Fatalf("identity/network: sa=%s labels=%v hostNetwork=%v dns=%s", spec.ServiceAccountName, ds.Spec.Template.Labels, spec.HostNetwork, spec.DNSPolicy)
	}
	for _, tol := range spec.Tolerations {
		if tol.Key == "" || tol.Operator != corev1.TolerationOpEqual {
			t.Fatalf("tolerations must be an explicit list: %+v", tol)
		}
	}
	volumes := map[string]corev1.Volume{}
	for _, v := range spec.Volumes {
		volumes[v.Name] = v
	}
	var exporter *corev1.Container
	for i := range spec.Containers {
		c := &spec.Containers[i]
		if !strings.Contains(c.Image, "@sha256:") || !strings.HasPrefix(c.Image, reg+"/") {
			t.Fatalf("container %s image %q is not a pinned registry digest", c.Name, c.Image)
		}
		if c.Name == "exporter" {
			exporter = c
		}
	}
	if exporter == nil || exporter.Image != exporterImage || strings.Join(exporter.Command, " ") != "/app" || strings.Join(exporter.Args, " ") != "--config /etc/agentarium/exporter/config.json" {
		t.Fatalf("exporter sidecar: %+v", exporter)
	}
	sc := exporter.SecurityContext
	if sc == nil || (sc.Privileged != nil && *sc.Privileged) || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem || sc.Capabilities == nil || len(sc.Capabilities.Add) != 0 || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Fatalf("exporter security context: %+v", sc)
	}
	// The exporter runs as UID 0 with host /proc mounted. containerd-proxy's
	// non-dumpable protection (#264) holds only while this container cannot
	// ptrace: drop ALL and never add SYS_PTRACE.
	for _, c := range sc.Capabilities.Add {
		if strings.TrimPrefix(strings.ToUpper(string(c)), "CAP_") == "SYS_PTRACE" {
			t.Fatalf("exporter must not add SYS_PTRACE: %+v", sc.Capabilities)
		}
	}
	mounts := map[string]corev1.VolumeMount{}
	for _, m := range exporter.VolumeMounts {
		host := ""
		if hp := volumes[m.Name].HostPath; hp != nil {
			host = hp.Path
		}
		mounts[host+"|"+m.Name] = m
	}
	export, ok := mounts["/var/run/cilium/tetragon|export-logs"]
	if !ok || !export.ReadOnly {
		t.Fatalf("export file hostPath must be read-only for the exporter: %+v", exporter.VolumeMounts)
	}
	if cfgMount, ok := mounts["|tetragon-config"]; !ok || !cfgMount.ReadOnly {
		t.Fatalf("tetragon-config must be mounted read-only: %+v", exporter.VolumeMounts)
	}
	if _, ok := mounts["/var/run/tetragon|tetragon-run"]; ok {
		t.Fatal("exporter must not get the Tetragon gRPC socket directory")
	}
	spool, ok := mounts["/var/lib/agentarium/sensor-spool|sensor-spool"]
	if !ok || spool.ReadOnly {
		t.Fatalf("spool must be a read-write hostPath: %+v", exporter.VolumeMounts)
	}
	if env := exporter.Env; len(env) != 1 || env[0].Name != "NODE_NAME" || env[0].ValueFrom.FieldRef.FieldPath != "spec.nodeName" {
		t.Fatalf("NODE_NAME downward API: %+v", env)
	}
	if v := volumes["identity-token"]; v.Projected == nil || v.Projected.Sources[0].ServiceAccountToken.Audience != "agentarium-identity" {
		t.Fatalf("identity token volume: %+v", v)
	}

	// Policies: connect and file per observed Namespace, one cluster tcp-state.
	_, policies := decode(t, read(t, filepath.Join(out, "policies.yaml")))
	got := []string{}
	for _, p := range policies {
		md := p["metadata"].(map[string]any)
		ns, _ := md["namespace"].(string)
		got = append(got, p["kind"].(string)+"/"+ns+"/"+md["name"].(string))
	}
	sort.Strings(got)
	want := []string{"TracingPolicy//agentarium-tcp-state", "TracingPolicyNamespaced/agent-adapters/agentarium-protected-file", "TracingPolicyNamespaced/agent-adapters/agentarium-tcp-connect", "TracingPolicyNamespaced/agent-exec/agentarium-protected-file", "TracingPolicyNamespaced/agent-exec/agentarium-tcp-connect"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("policies %v", got)
	}

	// Exporter config binds the rule hash of exactly the rendered policies.
	cfgTyped, _ := decode(t, read(t, filepath.Join(out, "exporter-config.yaml")))
	cm := cfgTyped[0].(*corev1.ConfigMap)
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cm.Data["config.json"]), &cfg); err != nil {
		t.Fatal(err)
	}
	// rule_hash (TASK-09 4, PR #185): JCS SHA-256 of {kind, namespace, name,
	// spec} sorted, with the pinned CRD defaults applied to each spec. The
	// exporter's own capture.ApplyCRDDefaults and capture.RuleHash recompute
	// it here, independently of the Python renderer.
	var elems, raw []capture.Policy
	for _, p := range policies {
		md := p["metadata"].(map[string]any)
		ns, _ := md["namespace"].(string)
		spec, err := capture.ApplyCRDDefaults(p["kind"].(string), p["spec"])
		if err != nil {
			t.Fatal(err)
		}
		elems = append(elems, capture.Policy{Kind: p["kind"].(string), Namespace: ns, Name: md["name"].(string), Spec: spec})
		raw = append(raw, capture.Policy{Kind: p["kind"].(string), Namespace: ns, Name: md["name"].(string), Spec: p["spec"]})
	}
	wantHash, err := capture.RuleHash(elems)
	if err != nil {
		t.Fatal(err)
	}
	undefaulted, _ := capture.RuleHash(raw)
	if cfg["rule_hash"] != wantHash || wantHash == undefaulted || cfg["collector_origin"] != sampleValues["COLLECTOR_ORIGIN"] || cm.Namespace != "agent-sensors" || cm.Name != "agentarium-exporter" {
		t.Fatalf("exporter config: rule_hash=%v want %s (undefaulted %s)", cfg["rule_hash"], wantHash, undefaulted)
	}
	if cfg["identity_peer_san"] != "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway" || cfg["tetragon_config_dir"] != "/etc/tetragon-config" {
		t.Fatalf("identity relay/config dir: %v", cfg)
	}
	// Exact export/filter settings come from the rendered tetragon-config.
	var tetragonConfig *corev1.ConfigMap
	for _, o := range typed {
		if c, ok := o.(*corev1.ConfigMap); ok && c.Name == "tetragon-config" {
			tetragonConfig = c
		}
	}
	settings, _ := cfg["tetragon_settings"].(map[string]any)
	for k, v := range tetragonConfig.Data {
		_, want := settings[k]
		if strings.HasPrefix(k, "export-") || strings.Contains(k, "filter") {
			if !want || settings[k] != strings.TrimSpace(v) {
				t.Fatalf("tetragon_settings missing or different %s", k)
			}
		}
	}
	if tetragonConfig.Data["metrics-server"] != "127.0.0.1:2112" || settings["metrics-server"] != "127.0.0.1:2112" {
		t.Fatalf("metrics must be loopback-only: %q", tetragonConfig.Data["metrics-server"])
	}
	// The DaemonSet restarts when the exporter config changes.
	digest := sha256.Sum256([]byte(cm.Data["config.json"]))
	if ds.Spec.Template.Annotations["checksum/exporter-config"] != hex.EncodeToString(digest[:]) {
		t.Fatal("missing or stale checksum/exporter-config annotation")
	}

	// The committed permission record is regenerated, not hand-written.
	rendered, committed := read(t, filepath.Join(out, "sensor-permissions.json")), read(t, filepath.Join(repo, "deploy/gcp/sensors/sensor-permissions.json"))
	if !bytes.Equal(rendered, committed) {
		t.Fatalf("deploy/gcp/sensors/sensor-permissions.json is stale; re-render:\n%s", rendered)
	}
	var perms permissions
	if err := json.Unmarshal(rendered, &perms); err != nil {
		t.Fatal(err)
	}

	// Admission: the rendered DaemonSet Pod is admitted in agent-sensors when
	// the agent-sensors.tetragon.hostPaths parameter equals the recorded list.
	pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tetragon-x", Namespace: "agent-sensors", Labels: ds.Spec.Template.Labels}, Spec: spec}
	images := tetragonImage + "," + exporterImage
	c := newCluster(t, strings.Join(perms.HostPaths, ","), images)
	if res := c.admit(t, pod); len(res) != 0 {
		t.Fatalf("rendered sensor Pod denied: %v", res)
	}
	// The previously assumed list omits the chart's run directories.
	old := newCluster(t, "/sys/kernel/btf,/sys/fs/bpf,/proc,/var/run/cilium/tetragon,/var/lib/agentarium/sensor-spool", images)
	if res := old.admit(t, pod); !contains(res, "agent-sensors-contract:SENSORS_HOSTPATH_NOT_ALLOWED") {
		t.Fatalf("expected hostPath denial with the incomplete list, got %v", res)
	}
	// An image outside agent-sensors.images is denied.
	other := newCluster(t, strings.Join(perms.HostPaths, ","), tetragonImage)
	if res := other.admit(t, pod); !contains(res, "agent-sensors-contract:SENSORS_IMAGE_NOT_ALLOWED") {
		t.Fatalf("expected image denial, got %v", res)
	}
}

func TestRenderRejectsIncompleteOrUnpinnedValues(t *testing.T) {
	for name, mutate := range map[string]func(map[string]string){
		"missing value":   func(v map[string]string) { delete(v, "NORMALIZATION_VERSION") },
		"tag image":       func(v map[string]string) { v["EXPORTER_IMAGE"] = reg + "/sensors-exporter:latest" },
		"plain http":      func(v map[string]string) { v["COLLECTOR_ORIGIN"] = "http://audit-writer.agent-observe.svc:8443" },
		"unknown key":     func(v map[string]string) { v["EXTRA"] = "x" },
		"zero generation": func(v map[string]string) { v["SENSOR_GENERATION"] = "0" },
		"identity origin not the gateway": func(v map[string]string) {
			v["IDENTITY_ORIGIN"] = "https://workload-identity.agent-control.svc:8443"
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := map[string]string{}
			for k, x := range sampleValues {
				v[k] = x
			}
			mutate(v)
			if _, err := renderSensors(t, v); err == nil {
				t.Fatal("render accepted invalid values")
			}
		})
	}
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// ---- offline admission chain (same construction as tests/platform/admission) ----

var minCompat = version.MajorMinor(1, 33)

type cluster struct {
	namespaces map[string]*corev1.Namespace
	policies   map[string]*admv1.ValidatingAdmissionPolicy
	validators map[string]validating.Validator
	bindings   []*admv1.ValidatingAdmissionPolicyBinding
	configMaps map[string]*corev1.ConfigMap
	psa        pspolicy.Evaluator
}

var placeholder = regexp.MustCompile(`\$\{([A-Za-z0-9_]*)\}`)

// baseValues fill the TASK-01 placeholders that do not concern sensors with
// syntactically valid samples; the sensor inputs are the values under test.
func baseValues(hostPaths, images string) map[string]string {
	img := reg + "/sample@sha256:" + strings.Repeat("a", 64)
	return map[string]string{
		"PSS_VERSION": "v1.33", "RUNTIME_IMAGE": img, "PROBE_IMAGES": img, "FIXTURE_IMAGES": img,
		"PROBE_ENTRYPOINTS": img + "=/app/bin/probe-runner", "GUARDED_RUNTIME_ENABLED": "false",
		"FORBIDDEN_ANNOTATION_KEYS": "io.containerd.nri.tolerate-missing-plugins",
		"AGENT_CONTROL_IMAGES":      img, "AGENT_ADAPTERS_IMAGES": img, "AGENT_OBSERVE_IMAGES": img, "AGENT_RELEASE_IMAGES": img, "AGENT_TARGETS_IMAGES": img,
		"DISCOVERY_SNAPSHOT_IMAGE": img, "DISCOVERY_BUCKET": "agentarium-test-discovery",
		"AGENT_SENSORS_IMAGES": images, "TETRAGON_HOST_PATHS": hostPaths, "TETRAGON_IMAGE": tetragonOf(images),
	}
}

// tetragonOf is the Tetragon digest in the sensor image list (#183
// TETRAGON_IMAGE), or empty, which admits no tetragon Pod.
func tetragonOf(images string) string {
	for _, img := range strings.Split(images, ",") {
		if strings.Contains(img, "/tetragon@") {
			return img
		}
	}
	return ""
}

func newCluster(t *testing.T, hostPaths, images string) *cluster {
	t.Helper()
	return newClusterValues(t, baseValues(hostPaths, images))
}

func newClusterValues(t *testing.T, values map[string]string) *cluster {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(repo, "deploy/gcp/base/admission/*.yaml"))
	files = append(files, filepath.Join(repo, "deploy/gcp/base/namespaces/namespaces.yaml"))
	c := &cluster{namespaces: map[string]*corev1.Namespace{}, policies: map[string]*admv1.ValidatingAdmissionPolicy{}, validators: map[string]validating.Validator{}, configMaps: map[string]*corev1.ConfigMap{}}
	for _, f := range files {
		if filepath.Base(f) == "kustomization.yaml" {
			continue
		}
		lines := strings.Split(string(read(t, f)), "\n")
		for i, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			lines[i] = placeholder.ReplaceAllStringFunc(l, func(m string) string {
				v, ok := values[placeholder.FindStringSubmatch(m)[1]]
				if !ok {
					t.Fatalf("%s: unknown placeholder %s", f, m)
				}
				return v
			})
		}
		typed, _ := decode(t, []byte(strings.Join(lines, "\n")))
		for _, o := range typed {
			switch o := o.(type) {
			case *corev1.Namespace:
				if o.Labels == nil {
					o.Labels = map[string]string{}
				}
				o.Labels[corev1.LabelMetadataName] = o.Name
				c.namespaces[o.Name] = o
			case *admv1.ValidatingAdmissionPolicy:
				c.policies[o.Name] = o
				v := compile(o)
				if err := v.CompileError(); err != nil {
					t.Fatalf("policy %s: %v", o.Name, err)
				}
				c.validators[o.Name] = v
			case *admv1.ValidatingAdmissionPolicyBinding:
				c.bindings = append(c.bindings, o)
			case *corev1.ConfigMap:
				c.configMaps[o.Namespace+"/"+o.Name] = o
			}
		}
	}
	if c.namespaces["agent-sensors"] == nil || len(c.bindings) == 0 {
		t.Fatal("base admission manifests not loaded")
	}
	e, err := pspolicy.NewEvaluator(pspolicy.DefaultChecks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.psa = e
	return c
}

func compile(p *admv1.ValidatingAdmissionPolicy) validating.Validator {
	envSet := environment.MustBaseEnvSet(minCompat)
	hasParam := p.Spec.ParamKind != nil
	optionalVars := plugincel.OptionalVariableDeclarations{HasParams: hasParam, HasAuthorizer: true}
	exprVars := plugincel.OptionalVariableDeclarations{HasParams: hasParam, HasAuthorizer: false}
	compiler, err := plugincel.NewCompositedCompiler(envSet)
	if err != nil {
		return validating.NewValidator(nil, nil, nil, nil, p.Spec.FailurePolicy, err)
	}
	vars := make([]plugincel.NamedExpressionAccessor, len(p.Spec.Variables))
	for i, v := range p.Spec.Variables {
		vars[i] = &validating.Variable{Name: v.Name, Expression: v.Expression}
	}
	compiler.CompileAndStoreVariables(vars, optionalVars, environment.StoredExpressions)
	validations := make([]plugincel.ExpressionAccessor, len(p.Spec.Validations))
	messages := make([]plugincel.ExpressionAccessor, len(p.Spec.Validations))
	for i, v := range p.Spec.Validations {
		validations[i] = &validating.ValidationCondition{Expression: v.Expression, Message: v.Message, Reason: v.Reason}
		if v.MessageExpression != "" {
			messages[i] = &validating.MessageExpressionCondition{MessageExpression: v.MessageExpression}
		}
	}
	var matcher matchconditions.Matcher
	if len(p.Spec.MatchConditions) > 0 {
		acc := make([]plugincel.ExpressionAccessor, len(p.Spec.MatchConditions))
		for i := range p.Spec.MatchConditions {
			acc[i] = (*matchconditions.MatchCondition)(&p.Spec.MatchConditions[i])
		}
		matcher = matchconditions.NewMatcher(compiler.CompileCondition(acc, optionalVars, environment.StoredExpressions), p.Spec.FailurePolicy, "policy", "validate", p.Name)
	}
	return validating.NewValidator(compiler.CompileCondition(validations, optionalVars, environment.StoredExpressions), matcher,
		compiler.CompileCondition(nil, optionalVars, environment.StoredExpressions),
		compiler.CompileCondition(messages, exprVars, environment.StoredExpressions), p.Spec.FailurePolicy, nil)
}

func (c *cluster) admit(t *testing.T, pod *corev1.Pod) []string {
	t.Helper()
	var out []string
	ns := c.namespaces[pod.Namespace]
	lvl, _ := psapi.ParseLevel(ns.Labels[psapi.EnforceLevelLabel])
	ver, _ := psapi.ParseVersion(ns.Labels[psapi.EnforceVersionLabel])
	for _, r := range c.psa.EvaluatePod(psapi.LevelVersion{Level: lvl, Version: ver}, &pod.ObjectMeta, &pod.Spec) {
		if !r.Allowed {
			out = append(out, "PSA:"+r.ForbiddenReason)
		}
	}
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	gvk := schema.GroupVersionKind{Version: "v1", Kind: "Pod"}
	attrs := admission.NewAttributesRecord(pod, nil, gvk, pod.Namespace, pod.Name, gvr, "", admission.Create, nil, false, &user.DefaultInfo{Name: "system:serviceaccount:kube-system:daemon-set-controller"})
	va := &admission.VersionedAttributes{Attributes: attrs, VersionedKind: gvk, VersionedObject: admission.NewLazyObject(pod), VersionedOldObject: admission.NewLazyObject(nil)}
	for _, b := range c.bindings {
		p := c.policies[b.Spec.PolicyName]
		if !matchesPods(p.Spec.MatchConstraints) {
			continue
		}
		if sel := b.Spec.MatchResources; sel != nil && sel.NamespaceSelector != nil {
			s, err := metav1.LabelSelectorAsSelector(sel.NamespaceSelector)
			if err != nil {
				t.Fatal(err)
			}
			if !s.Matches(labels.Set(ns.Labels)) {
				continue
			}
		}
		var params runtime.Object
		if b.Spec.ParamRef != nil {
			cm, ok := c.configMaps[b.Spec.ParamRef.Namespace+"/"+b.Spec.ParamRef.Name]
			if !ok {
				out = append(out, p.Name+":PARAM_NOT_FOUND")
				continue
			}
			params = cm
		}
		res := c.validators[p.Name].Validate(context.Background(), gvr, va, params, ns, celconfig.RuntimeCELCostBudget, nil)
		for _, d := range res.Decisions {
			switch {
			case d.Evaluation == validating.EvalError:
				out = append(out, p.Name+":ERROR:"+d.Message)
			case d.Action == validating.ActionDeny:
				out = append(out, p.Name+":"+d.Message)
			}
		}
	}
	sort.Strings(out)
	return out
}

func matchesPods(m *admv1.MatchResources) bool {
	for _, rule := range m.ResourceRules {
		op, res := false, false
		for _, o := range rule.Operations {
			op = op || o == admv1.Create || o == admv1.OperationAll
		}
		for _, r := range rule.Resources {
			res = res || r == "pods"
		}
		if op && res {
			return true
		}
	}
	return false
}
