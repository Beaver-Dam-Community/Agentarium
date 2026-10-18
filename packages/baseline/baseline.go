// Package baseline implements the TASK-01 section 4 baseline digests that the
// installer (tools/baseline-digests/) writes to the environment lock and the
// TASK-10 drift probe recomputes. Both sides must use these functions; the
// package only selects, projects, normalizes and digests objects that the
// caller already fetched, so it performs no I/O.
//
// Rules (TASK-01 4 "baseline input location and shared normalization"): from every object drop
// metadata.resourceVersion, metadata.uid, metadata.creationTimestamp,
// metadata.managedFields, metadata.generation, the annotation
// kubectl.kubernetes.io/last-applied-configuration and status; keep every
// other annotation; sort by (apiVersion, kind, metadata.namespace,
// metadata.name); digest is SHA-256(JCS(array)) via packages/canonical.
package baseline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Baseline kinds and the extra lock key, in lock order.
const (
	KindAdmission             = "admission"
	KindExecRBAC              = "exec_rbac"
	KindNetworkPolicy         = "network_policy"
	KindNodePoolConfig        = "node_pool_config"
	KindSensorPolicy          = "sensor_policy"
	KeySensorReleasePolicies  = "sensor_release_policies"
	LastAppliedAnnotation     = "kubectl.kubernetes.io/last-applied-configuration"
	releasePolicyNamespace    = "agent-exec"
	sensorsNamespace          = "agent-sensors"
	controlNamespace          = "agent-control"
	tracingPolicyNamespacedKd = "TracingPolicyNamespaced"
)

// ReleasePolicyNames are the TASK-14 releaser-managed TracingPolicyNamespaced
// objects in agent-exec (TASK-14 3.4). They form the release part of
// sensor_policy; everything else collected for sensor_policy is the install part.
var ReleasePolicyNames = []string{"agentarium-protected-file", "agentarium-tcp-connect"}

// ExecNamespaces are the execution Namespaces whose RBAC is in exec_rbac.
var ExecNamespaces = []string{"agent-exec", "agent-sensors"}

// RoleNamespaces are the seven role Namespaces whose NetworkPolicies are in
// network_policy.
var RoleNamespaces = []string{"agent-adapters", "agent-control", "agent-exec", "agent-observe", "agent-release", "agent-sensors", "agent-targets"}

// Source is one read the collector performs. Reads are get/list only.
// Namespaces nil means cluster-scoped (Namespaced false) or all Namespaces
// (Namespaced true). Names nil means LIST; otherwise each name is a GET and an
// absent name is an absent observation.
type Source struct {
	ID           string // stable identifier; tools/baseline-digests --from-dir reads <ID>.json
	BaselineKind string
	APIVersion   string // group/version, e.g. "rbac.authorization.k8s.io/v1" or "v1"
	Kind         string
	Resource     string // plural resource name for the API path
	Namespaced   bool
	Namespaces   []string
	Names        []string
}

// Group returns the API group ("" for core).
func (s Source) Group() string {
	g, _, ok := strings.Cut(s.APIVersion, "/")
	if !ok {
		return ""
	}
	return g
}

// Version returns the API version.
func (s Source) Version() string {
	i := strings.LastIndex(s.APIVersion, "/")
	return s.APIVersion[i+1:]
}

// IsGet reports whether the source is read by name.
func (s Source) IsGet() bool { return len(s.Names) > 0 }

// Sources returns the TASK-01 4 read table, in a fixed order. The node pool
// configuration is not a Kubernetes read; see NodePoolConfig.
func Sources() []Source {
	return []Source{
		{ID: "validatingadmissionpolicies", BaselineKind: KindAdmission, APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy", Resource: "validatingadmissionpolicies"},
		{ID: "validatingadmissionpolicybindings", BaselineKind: KindAdmission, APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding", Resource: "validatingadmissionpolicybindings"},
		{ID: "constraints-configmaps", BaselineKind: KindAdmission, APIVersion: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespaced: true, Namespaces: []string{controlNamespace}, Names: []string{"agent-exec-constraints", "agent-role-constraints"}},
		{ID: "roles", BaselineKind: KindExecRBAC, APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Resource: "roles", Namespaced: true},
		{ID: "rolebindings", BaselineKind: KindExecRBAC, APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Resource: "rolebindings", Namespaced: true},
		{ID: "clusterroles", BaselineKind: KindExecRBAC, APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Resource: "clusterroles"},
		{ID: "clusterrolebindings", BaselineKind: KindExecRBAC, APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Resource: "clusterrolebindings"},
		{ID: "networkpolicies", BaselineKind: KindNetworkPolicy, APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Resource: "networkpolicies", Namespaced: true, Namespaces: RoleNamespaces},
		{ID: "networkloggings", BaselineKind: KindNetworkPolicy, APIVersion: "networking.gke.io/v1alpha1", Kind: "NetworkLogging", Resource: "networkloggings", Names: []string{"default"}},
		{ID: "tracingpolicies", BaselineKind: KindSensorPolicy, APIVersion: "cilium.io/v1alpha1", Kind: "TracingPolicy", Resource: "tracingpolicies"},
		{ID: "tracingpoliciesnamespaced", BaselineKind: KindSensorPolicy, APIVersion: "cilium.io/v1alpha1", Kind: tracingPolicyNamespacedKd, Resource: "tracingpoliciesnamespaced", Namespaced: true},
		{ID: "tetragon-config", BaselineKind: KindSensorPolicy, APIVersion: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespaced: true, Namespaces: []string{sensorsNamespace}, Names: []string{"tetragon-config"}},
		{ID: "tetragon-daemonset", BaselineKind: KindSensorPolicy, APIVersion: "apps/v1", Kind: "DaemonSet", Resource: "daemonsets", Namespaced: true, Namespaces: []string{sensorsNamespace}, Names: []string{"tetragon"}},
	}
}

// Observation is everything the collector read: Objects[Source.ID] holds the
// items of that source (any extra items outside the source's Namespaces/Names
// are ignored), and Cluster is the GKE clusters.get response as JSON.
type Observation struct {
	Objects map[string][]map[string]any
	Cluster map[string]any
}

// Digests is the lock baseline_digests object. Field order is the lock order.
type Digests struct {
	Admission             string `json:"admission"`
	ExecRBAC              string `json:"exec_rbac"`
	NetworkPolicy         string `json:"network_policy"`
	NodePoolConfig        string `json:"node_pool_config"`
	SensorPolicy          string `json:"sensor_policy"`
	SensorReleasePolicies string `json:"sensor_release_policies"`
}

// Compute returns the six lock digests for an observation. It does not decide
// whether an absent object is an error; callers that must fail on absence
// (the installer) check with Missing first.
func Compute(obs Observation) (Digests, error) {
	var d Digests
	sel := func(id string) ([]map[string]any, error) {
		src, ok := sourceByID(id)
		if !ok {
			return nil, fmt.Errorf("unknown source %q", id)
		}
		return Select(src, obs.Objects[id]), nil
	}
	collect := func(ids ...string) ([]map[string]any, error) {
		var out []map[string]any
		for _, id := range ids {
			s, err := sel(id)
			if err != nil {
				return nil, err
			}
			out = append(out, s...)
		}
		return out, nil
	}
	var err error

	adm, err := collect("validatingadmissionpolicies", "validatingadmissionpolicybindings", "constraints-configmaps")
	if err != nil {
		return d, err
	}
	if d.Admission, err = DigestObjects(adm); err != nil {
		return d, fmt.Errorf("%s: %w", KindAdmission, err)
	}

	var rb [4][]map[string]any
	for i, id := range []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"} {
		if rb[i], err = sel(id); err != nil {
			return d, err
		}
	}
	if d.ExecRBAC, err = DigestObjects(SelectExecRBAC(rb[0], rb[1], rb[2], rb[3])); err != nil {
		return d, fmt.Errorf("%s: %w", KindExecRBAC, err)
	}

	np, err := collect("networkpolicies", "networkloggings")
	if err != nil {
		return d, err
	}
	if d.NetworkPolicy, err = DigestObjects(np); err != nil {
		return d, fmt.Errorf("%s: %w", KindNetworkPolicy, err)
	}

	if obs.Cluster == nil {
		return d, fmt.Errorf("%s: no GKE cluster observation", KindNodePoolConfig)
	}
	npc, err := NodePoolConfig(obs.Cluster)
	if err != nil {
		return d, fmt.Errorf("%s: %w", KindNodePoolConfig, err)
	}
	if d.NodePoolConfig, err = canonical.CanonicalDigest(npc); err != nil {
		return d, fmt.Errorf("%s: %w", KindNodePoolConfig, err)
	}

	sensor, err := collect("tracingpolicies", "tracingpoliciesnamespaced", "tetragon-config")
	if err != nil {
		return d, err
	}
	ds, err := sel("tetragon-daemonset")
	if err != nil {
		return d, err
	}
	for _, o := range ds {
		sensor = append(sensor, ProjectDaemonSet(o))
	}
	install, release := SplitSensor(sensor)
	if d.SensorPolicy, err = DigestObjects(install); err != nil {
		return d, fmt.Errorf("%s: %w", KindSensorPolicy, err)
	}
	if d.SensorReleasePolicies, err = DigestObjects(release); err != nil {
		return d, fmt.Errorf("%s: %w", KeySensorReleasePolicies, err)
	}
	return d, nil
}

func sourceByID(id string) (Source, bool) {
	for _, s := range Sources() {
		if s.ID == id {
			return s, true
		}
	}
	return Source{}, false
}

// Select keeps the items that belong to src (Namespace and name filters),
// filling apiVersion/kind from src when a LIST item lacks them. Items are
// deep-copied.
func Select(src Source, items []map[string]any) []map[string]any {
	var out []map[string]any
	for _, it := range items {
		o := deepCopy(it).(map[string]any)
		if _, ok := o["apiVersion"]; !ok {
			o["apiVersion"] = src.APIVersion
		}
		if _, ok := o["kind"]; !ok {
			o["kind"] = src.Kind
		}
		if o["apiVersion"] != src.APIVersion || o["kind"] != src.Kind {
			continue
		}
		ns, name := nsName(o)
		if src.Namespaced && len(src.Namespaces) > 0 && !contains(src.Namespaces, ns) {
			continue
		}
		if src.IsGet() && !contains(src.Names, name) {
			continue
		}
		out = append(out, o)
	}
	return out
}

// Missing lists "namespace/name" (or "name") of named sources that are absent
// from items. The installer treats any missing name as a failure (TASK-01 4);
// the drift probe treats it as an absent observation.
func Missing(src Source, items []map[string]any) []string {
	if !src.IsGet() {
		return nil
	}
	have := map[string]bool{}
	for _, o := range Select(src, items) {
		ns, name := nsName(o)
		have[ns+"/"+name] = true
	}
	nss := src.Namespaces
	if !src.Namespaced {
		nss = []string{""}
	}
	var miss []string
	for _, ns := range nss {
		for _, n := range src.Names {
			if !have[ns+"/"+n] {
				if ns == "" {
					miss = append(miss, n)
				} else {
					miss = append(miss, ns+"/"+n)
				}
			}
		}
	}
	return miss
}

// MissingReleasePolicies lists the release-managed TracingPolicyNamespaced
// names absent from the selected tracingpoliciesnamespaced items.
// SPEC-QUESTION: TASK-01 4 makes absence fatal only for objects fixed by name
// (GET). The two release policies come from a LIST, but sensor_release_policies
// is meaningless without them and TASK-14 3.4 says the installer creates them,
// so the installer also fails when either is missing.
func MissingReleasePolicies(items []map[string]any) []string {
	src, _ := sourceByID("tracingpoliciesnamespaced")
	have := map[string]bool{}
	for _, o := range Select(src, items) {
		if isRelease(o) {
			_, name := nsName(o)
			have[name] = true
		}
	}
	var miss []string
	for _, n := range ReleasePolicyNames {
		if !have[n] {
			miss = append(miss, releasePolicyNamespace+"/"+n)
		}
	}
	return miss
}

// ReleasePoliciesDigest is the sensor_release_policies digest of the objects
// the TASK-14 releaser rendered (TASK-14 3.4). Unlike DigestObjects it
// requires exactly the agent-exec TracingPolicyNamespaced objects in
// ReleasePolicyNames, so a wrong Namespace, a wrong name, an extra object or a
// missing policy is an error instead of a valid but different digest.
func ReleasePoliciesDigest(objs []map[string]any) (string, error) {
	for _, o := range objs {
		if !isRelease(o) {
			k := sortKey(o)
			return "", fmt.Errorf("%s: not a release policy: %s %s %s/%s", KeySensorReleasePolicies, k[0], k[1], k[2], k[3])
		}
	}
	d, err := DigestObjects(objs)
	if err != nil {
		return "", fmt.Errorf("%s: %w", KeySensorReleasePolicies, err)
	}
	if miss := MissingReleasePolicies(objs); len(miss) > 0 {
		return "", fmt.Errorf("%s: missing %s", KeySensorReleasePolicies, strings.Join(miss, ", "))
	}
	return d, nil
}

// Normalize returns a deep copy of obj without the volatile fields. Other
// annotations are kept.
// SPEC-QUESTION: when removing last-applied-configuration leaves the
// annotations map empty, the empty map is dropped too, so an object applied
// with client-side apply and the same object applied server-side digest the
// same. The spec does not say this explicitly.
// SPEC-QUESTION (TASK-14 3.4 Q0): only that case is normalized. An empty
// annotations or labels map that is present in a rendered manifest is kept,
// while the live object read back from the API server may omit it, so the
// rendered and live digests of the same policy can differ. TASK-14 leaves
// this shape difference, like CRD defaulting, to the regression project Q0.
func Normalize(obj map[string]any) map[string]any {
	o := deepCopy(obj).(map[string]any)
	delete(o, "status")
	md, ok := o["metadata"].(map[string]any)
	if !ok {
		return o
	}
	for _, k := range []string{"resourceVersion", "uid", "creationTimestamp", "managedFields", "generation"} {
		delete(md, k)
	}
	if ann, ok := md["annotations"].(map[string]any); ok {
		if _, had := ann[LastAppliedAnnotation]; had {
			delete(ann, LastAppliedAnnotation)
			if len(ann) == 0 {
				delete(md, "annotations")
			}
		}
	}
	return o
}

// DigestObjects normalizes and sorts objs and returns SHA-256(JCS(array)).
// An empty list is a valid observation (digest of "[]"). Two objects with the
// same (apiVersion, kind, namespace, name) are rejected.
func DigestObjects(objs []map[string]any) (string, error) {
	norm := make([]map[string]any, 0, len(objs))
	for _, o := range objs {
		norm = append(norm, Normalize(o))
	}
	SortObjects(norm)
	arr := make([]any, len(norm))
	for i, o := range norm {
		if i > 0 && sortKey(norm[i-1]) == sortKey(o) {
			k := sortKey(o)
			return "", fmt.Errorf("duplicate object %s %s %s/%s", k[0], k[1], k[2], k[3])
		}
		arr[i] = o
	}
	return canonical.CanonicalDigest(arr)
}

// SortObjects sorts in place by (apiVersion, kind, metadata.namespace, metadata.name).
func SortObjects(objs []map[string]any) {
	sort.SliceStable(objs, func(i, j int) bool {
		a, b := sortKey(objs[i]), sortKey(objs[j])
		for k := range a {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
}

func sortKey(o map[string]any) [4]string {
	av, _ := o["apiVersion"].(string)
	k, _ := o["kind"].(string)
	ns, name := nsName(o)
	return [4]string{av, k, ns, name}
}

// ProjectDaemonSet reduces a DaemonSet to {apiVersion, kind,
// metadata.namespace, metadata.name, spec.template} (TASK-01 4).
func ProjectDaemonSet(obj map[string]any) map[string]any {
	ns, name := nsName(obj)
	md := map[string]any{"name": name}
	if ns != "" {
		md["namespace"] = ns
	}
	out := map[string]any{"apiVersion": obj["apiVersion"], "kind": obj["kind"], "metadata": md}
	spec := map[string]any{}
	if s, ok := obj["spec"].(map[string]any); ok {
		if t, ok := s["template"]; ok {
			spec["template"] = deepCopy(t)
		}
	}
	out["spec"] = spec
	return out
}

// SplitSensor separates the sensor_policy collection into the install part
// and the release part (the TASK-14 releaser-managed policies).
func SplitSensor(objs []map[string]any) (install, release []map[string]any) {
	for _, o := range objs {
		if isRelease(o) {
			release = append(release, o)
		} else {
			install = append(install, o)
		}
	}
	return install, release
}

func isRelease(o map[string]any) bool {
	if o["kind"] != tracingPolicyNamespacedKd || o["apiVersion"] != "cilium.io/v1alpha1" {
		return false
	}
	ns, name := nsName(o)
	return ns == releasePolicyNamespace && contains(ReleasePolicyNames, name)
}

// SensorDriftDigest is the sensor_policy drift comparison value
// SHA-256(JCS({"install": <install digest>, "release": <release digest>}))
// (TASK-10 3.2). Only record_drift uses it; the lock stores the two parts.
func SensorDriftDigest(install, release string) (string, error) {
	for _, h := range []string{install, release} {
		if !isHex64(h) {
			return "", fmt.Errorf("digest %q is not 64 lowercase hex", h)
		}
	}
	return canonical.CanonicalDigest(map[string]string{"install": install, "release": release})
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func nsName(o map[string]any) (string, string) {
	md, _ := o["metadata"].(map[string]any)
	ns, _ := md["namespace"].(string)
	name, _ := md["name"].(string)
	return ns, name
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = deepCopy(x)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, x := range t {
			s[i] = deepCopy(x)
		}
		return s
	default:
		return v
	}
}

// DecodeJSON decodes JSON keeping numbers exact (json.Number), the form every
// caller should hand to this package so the JCS integer range check sees the
// original literal.
func DecodeJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after JSON value")
	}
	return nil
}

// ParseItems decodes a Kubernetes JSON list (`{"items": [...]}`, e.g.
// `kubectl get -o json`) or a single object into items, numbers kept exact.
func ParseItems(b []byte) ([]map[string]any, error) {
	var v map[string]any
	if err := DecodeJSON(b, &v); err != nil {
		return nil, err
	}
	raw, isList := v["items"]
	if !isList {
		return []map[string]any{v}, nil
	}
	arr, ok := raw.([]any)
	if !ok && raw != nil {
		return nil, fmt.Errorf("items is not an array")
	}
	out := make([]map[string]any, 0, len(arr))
	for i, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("items[%d] is not an object", i)
		}
		out = append(out, m)
	}
	return out, nil
}
