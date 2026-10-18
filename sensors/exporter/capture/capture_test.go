package capture

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"sigs.k8s.io/yaml"
)

const exportFile = "/var/run/cilium/tetragon/tetragon.log"

// repoPolicies renders the committed policy sources the way
// deploy/gcp/sensors/render.py does: namespaced ones per observed Namespace.
func repoPolicies(t *testing.T) []*unstructured.Unstructured {
	t.Helper()
	var out []*unstructured.Unstructured
	for _, f := range []string{"network.yaml", "file-access.yaml", "tcp-state.yaml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "tetragon", "policies", f))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := yaml.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m["kind"] == "TracingPolicy" {
			out = append(out, &unstructured.Unstructured{Object: m})
			continue
		}
		for _, ns := range []string{"agent-exec", "agent-adapters"} {
			c := (&unstructured.Unstructured{Object: m}).DeepCopy()
			c.SetNamespace(ns)
			out = append(out, c)
		}
	}
	return out
}

// metrics serves the pinned 1.7.1 policymetrics exposition shape.
type metrics struct {
	mu          sync.Mutex
	rows        []string // `policy="..",policy_namespace=".."`
	states      map[string]int
	extraStates []string
	down        bool
}

func (m *metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down || r.URL.Path != "/metrics" {
		w.WriteHeader(503)
		return
	}
	fmt.Fprintln(w, "# HELP tetragon_tracingpolicy_kernel_memory_bytes The amount of kernel memory in bytes used by policy's sensors non-shared BPF maps (memlock).")
	fmt.Fprintln(w, "# TYPE tetragon_tracingpolicy_kernel_memory_bytes gauge")
	for _, r := range m.rows {
		fmt.Fprintf(w, "tetragon_tracingpolicy_kernel_memory_bytes{%s} 4096\n", r)
	}
	fmt.Fprintln(w, "# HELP tetragon_tracingpolicy_loaded The number of loaded tracing policy by state.")
	fmt.Fprintln(w, "# TYPE tetragon_tracingpolicy_loaded gauge")
	for _, s := range []string{"disabled", "enabled", "error", "load_error"} {
		fmt.Fprintf(w, "tetragon_tracingpolicy_loaded{state=%q} %d\n", s, m.states[s])
	}
	for _, s := range m.extraStates {
		fmt.Fprintln(w, s)
	}
}

func settings() map[string]string {
	s := map[string]string{
		"export-allowlist":        `{"event_set":["PROCESS_EXEC", "PROCESS_EXIT", "PROCESS_KPROBE", "PROCESS_UPROBE", "PROCESS_TRACEPOINT", "PROCESS_LSM"]}`,
		"export-filename":         exportFile,
		"export-file-max-size-mb": "10",
		"export-file-max-backups": "5",
	}
	for k, v := range Invariants {
		s[k] = v
	}
	return s
}

// stored returns the policy as the API server stores it: the pinned CRD
// defaults filled in (the fake dynamic client does not default).
func stored(t *testing.T, p *unstructured.Unstructured) *unstructured.Unstructured {
	t.Helper()
	c := p.DeepCopy()
	spec, err := ApplyCRDDefaults(c.GetKind(), c.Object["spec"])
	if err != nil {
		t.Fatal(err)
	}
	c.Object["spec"] = spec
	return c
}

func setup(t *testing.T) (*Verifier, *metrics, string) {
	t.Helper()
	return setupWith(t, true)
}

// setupWith stores CRD-defaulted objects (as a real API server does) or the
// raw YAML; the expected rule_hash is always computed from the raw YAML with
// ApplyCRDDefaults, the way deploy/gcp/sensors/render.py computes it.
func setupWith(t *testing.T, defaulted bool) (*Verifier, *metrics, string) {
	t.Helper()
	policies := repoPolicies(t)
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{ClusterPolicies: "TracingPolicyList", NamespacedPolicies: "TracingPolicyNamespacedList"})
	m := &metrics{states: map[string]int{"enabled": len(policies)}}
	var elems []Policy
	for _, p := range policies {
		var err error
		obj := p
		if defaulted {
			obj = stored(t, p)
		}
		if p.GetNamespace() == "" {
			_, err = client.Resource(ClusterPolicies).Create(context.Background(), obj, metav1.CreateOptions{})
		} else {
			_, err = client.Resource(NamespacedPolicies).Namespace(p.GetNamespace()).Create(context.Background(), obj, metav1.CreateOptions{})
		}
		if err != nil {
			t.Fatal(err)
		}
		spec, err := ApplyCRDDefaults(p.GetKind(), p.Object["spec"])
		if err != nil {
			t.Fatal(err)
		}
		elems = append(elems, Policy{Kind: p.GetKind(), Namespace: p.GetNamespace(), Name: p.GetName(), Spec: spec})
		m.rows = append(m.rows, fmt.Sprintf("policy=%q,policy_namespace=%q", p.GetName(), p.GetNamespace()))
	}
	// A non-agentarium policy loaded elsewhere is ignored by the set check.
	m.rows = append(m.rows, `policy="other",policy_namespace="kube-system"`)
	m.states["enabled"]++
	hash, err := RuleHash(elems)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: m}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	dir := t.TempDir()
	write := func(k, v string) {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range settings() {
		write(k, v)
	}
	write("debug", "false") // unrelated keys are not compared
	write("gops-address", "localhost:8118")
	if err := os.Mkdir(filepath.Join(dir, "..data"), 0o755); err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(client, hash, settings(), dir, exportFile, "http://"+ln.Addr().String()+"/metrics")
	if err != nil {
		t.Fatal(err)
	}
	return v, m, dir
}

func TestVerifierPassesOnlyWhenLoadedRulesMatch(t *testing.T) {
	ctx := context.Background()
	check := func(v *Verifier, want bool, wantErr bool, what string) {
		t.Helper()
		ok, err := v.VerifyCapture(ctx)
		if ok != want || (err != nil) != wantErr {
			t.Fatalf("%s: ok=%v err=%v", what, ok, err)
		}
	}
	v, m, dir := setup(t)
	check(v, true, false, "matching installation")

	m.mu.Lock()
	m.states["disabled"] = 1
	m.mu.Unlock()
	check(v, false, true, "disabled policy")
	m.mu.Lock()
	m.states["disabled"] = 0
	saved := m.rows
	m.rows = m.rows[1:]
	m.mu.Unlock()
	check(v, false, false, "expected policy not loaded")
	m.mu.Lock()
	m.rows = append(append([]string{}, saved...), `policy="agentarium-extra",policy_namespace=""`)
	m.mu.Unlock()
	check(v, false, false, "unexpected agentarium policy loaded")
	m.mu.Lock()
	m.rows = saved
	m.down = true
	m.mu.Unlock()
	check(v, false, true, "metrics unavailable")
	m.mu.Lock()
	m.down = false
	m.mu.Unlock()
	check(v, true, false, "restored")

	// Unknown non-zero state, duplicate state rows, too few enabled.
	for _, c := range []struct {
		extra   []string
		enabled int
		wantErr bool
		what    string
	}{
		{[]string{`tetragon_tracingpolicy_loaded{state="pending"} 1`}, -1, true, "unknown non-zero state"},
		{[]string{`tetragon_tracingpolicy_loaded{state="enabled"} 99`}, -1, true, "duplicate enabled row"},
		{nil, 2, false, "enabled count below declared policies"},
		{[]string{`tetragon_tracingpolicy_loaded{state="pending"} 0`}, -1, false, "unknown zero state is allowed"},
	} {
		m.mu.Lock()
		before := m.states["enabled"]
		m.extraStates = c.extra
		if c.enabled >= 0 {
			m.states["enabled"] = c.enabled
		}
		m.mu.Unlock()
		want := c.what == "unknown zero state is allowed"
		check(v, want, c.wantErr, c.what)
		m.mu.Lock()
		m.extraStates, m.states["enabled"] = nil, before
		m.mu.Unlock()
	}

	good := v.RuleHash
	v.RuleHash = strings.Repeat("0", 64)
	check(v, false, false, "rule hash mismatch")
	v.RuleHash = good

	for _, c := range []struct{ key, value, what string }{
		{"export-aggregation", "true", "unexpected export key"},
		{"process-filter", "x", "unexpected filter key"},
		{"export-file-max-backups", "1", "changed expected export value"},
		{"export-rate-limit", "100", "rate limit"},
		{"export-filename", "/tmp/other.log", "export file moved"},
	} {
		path := filepath.Join(dir, c.key)
		old, existed := os.ReadFile(path)
		os.WriteFile(path, []byte(c.value), 0o644)
		check(v, false, false, c.what)
		if existed == nil {
			os.WriteFile(path, old, 0o644)
		} else {
			os.Remove(path)
		}
	}
	os.Remove(filepath.Join(dir, "export-denylist"))
	check(v, false, false, "missing pinned key")
}

func TestNewVerifierRejectsUnsafeInputs(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	hash := strings.Repeat("a", 64)
	if _, err := NewVerifier(client, hash, settings(), "/x", exportFile, "http://10.0.0.1:2112/metrics"); err == nil {
		t.Fatal("non-loopback metrics accepted")
	}
	bad := settings()
	bad["export-rate-limit"] = "100"
	if _, err := NewVerifier(client, hash, bad, "/x", exportFile, "http://127.0.0.1:2112/metrics"); err == nil {
		t.Fatal("expectation without the invariant accepted")
	}
	if _, err := NewVerifier(client, hash, settings(), "/x", "/other", "http://127.0.0.1:2112/metrics"); err == nil {
		t.Fatal("export-filename different from the tailed file accepted")
	}
}

func TestRuleHashIsOrderIndependentAndBindsSpec(t *testing.T) {
	a := []Policy{{Kind: "TracingPolicyNamespaced", Namespace: "agent-exec", Name: "x", Spec: map[string]any{"a": 1}}, {Kind: "TracingPolicy", Name: "y", Spec: map[string]any{}}}
	b := []Policy{a[1], a[0]}
	h1, _ := RuleHash(a)
	h2, _ := RuleHash(b)
	a[0].Spec = map[string]any{"a": 2}
	h3, _ := RuleHash(a)
	if h1 != h2 || h1 == h3 {
		t.Fatal("rule hash must be order independent and bind the spec")
	}
}

// The render side hashes raw YAML with CRD defaults applied; the verifier
// reads API-server objects that already carry them. Both match, and a hash of
// the undefaulted YAML (the earlier render behaviour) does not.
func TestRuleHashMatchesCRDDefaultedObjects(t *testing.T) {
	for _, defaulted := range []bool{true, false} {
		v, _, _ := setupWith(t, defaulted)
		if ok, err := v.VerifyCapture(context.Background()); !ok || err != nil {
			t.Fatalf("defaulted=%v: %v %v", defaulted, ok, err)
		}
	}
	var raw []Policy
	for _, p := range repoPolicies(t) {
		raw = append(raw, Policy{Kind: p.GetKind(), Namespace: p.GetNamespace(), Name: p.GetName(), Spec: p.Object["spec"]})
	}
	undefaulted, err := RuleHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, _, _ := setupWith(t, true)
	v.RuleHash = undefaulted
	if ok, _ := v.VerifyCapture(context.Background()); ok {
		t.Fatal("a rule_hash of the undefaulted YAML matched the stored objects")
	}
}
