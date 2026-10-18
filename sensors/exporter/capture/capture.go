// Package capture is the exporter's CaptureVerifier (TASK-09 3.5 "capture
// verification", PR #185). A healthy lease needs, on every check:
//
//  1. Tetragon's loopback policy metrics show exactly the expected
//     agentarium policies loaded and no policy in load_error/error/disabled;
//  2. rule_hash recomputed from the Kubernetes policy objects equals the
//     installed value;
//  3. the export/filter keys of the mounted tetragon-config equal the
//     rendered values as an exact set.
//
// The exporter is never given Tetragon's gRPC socket: that socket also
// serves policy add/delete/disable (TASK-01 3.2.1).
package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const Prefix = "agentarium-"

var (
	ClusterPolicies    = schema.GroupVersionResource{Group: "cilium.io", Version: "v1alpha1", Resource: "tracingpolicies"}
	NamespacedPolicies = schema.GroupVersionResource{Group: "cilium.io", Version: "v1alpha1", Resource: "tracingpoliciesnamespaced"}
)

// Policy is the rule_hash element: {kind, namespace, name, spec}; cluster
// policies use an empty namespace. kind is the Kubernetes object kind.
type Policy struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Spec      any    `json:"spec"`
}

// RuleHash is the JCS SHA-256 of the policies sorted by (kind, namespace, name).
// Each spec must already have the pinned CRD defaults applied
// (ApplyCRDDefaults), as the API server stores it.
func RuleHash(policies []Policy) (string, error) {
	sorted := append([]Policy(nil), policies...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	raw, err := canonical.CanonicalJSON(sorted)
	if err != nil {
		return "", err
	}
	return canonical.SHA256Hex(raw), nil
}

// Invariants are TASK-09 3.1 values the verifier enforces even if the
// installed expectation were edited.
var Invariants = map[string]string{
	"enable-process-ns":    "true",
	"export-rate-limit":    "-1",
	"export-denylist":      `{"health_check":true}`,
	"export-file-compress": "false",
	"export-file-perm":     "600",
	"field-filters":        "",
	"redaction-filters":    "",
	"metrics-server":       "127.0.0.1:2112",
}

// ExportKey reports whether a tetragon-config key affects export or filtering;
// every such key must be in the expected set.
func ExportKey(k string) bool {
	return strings.HasPrefix(k, "export-") || strings.Contains(k, "filter")
}

type Verifier struct {
	Policies dynamic.Interface
	RuleHash string
	// Settings are the rendered tetragon-config values of every ExportKey
	// plus the Invariants keys.
	Settings   map[string]string
	ConfigDir  string // read-only mount of the tetragon-config ConfigMap
	ExportFile string // the file the exporter tails; must equal export-filename
	metricsURL string
	client     *http.Client
}

func NewVerifier(policies dynamic.Interface, ruleHash string, settings map[string]string, configDir, exportFile, metricsEndpoint string) (*Verifier, error) {
	u, err := url.Parse(metricsEndpoint)
	if err != nil || u.Scheme != "http" || u.Path != "/metrics" || u.User != nil || u.RawQuery != "" {
		return nil, errors.New("invalid metrics endpoint")
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() || u.Port() == "" {
		return nil, errors.New("metrics must use an explicit loopback IP and port")
	}
	if policies == nil || len(ruleHash) != 64 || configDir == "" || exportFile == "" {
		return nil, errors.New("incomplete capture verifier")
	}
	for k, v := range Invariants {
		if settings[k] != v {
			return nil, fmt.Errorf("expected setting %s must be the TASK-09 value", k)
		}
	}
	if settings["export-filename"] != exportFile {
		return nil, errors.New("export-filename must be the tailed export file")
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: time.Second}
	return &Verifier{Policies: policies, RuleHash: ruleHash, Settings: settings, ConfigDir: configDir, ExportFile: exportFile, metricsURL: metricsEndpoint,
		client: &http.Client{Transport: tr, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// settings compares the mounted ConfigMap with the expected exact set.
func (v *Verifier) settings() (bool, error) {
	entries, err := os.ReadDir(v.ConfigDir)
	if err != nil {
		return false, err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		k := e.Name()
		if strings.HasPrefix(k, "..") { // ConfigMap projection internals
			continue
		}
		want, expected := v.Settings[k]
		_, pinned := Invariants[k]
		if !expected && !pinned && !ExportKey(k) {
			continue // unrelated Tetragon setting
		}
		if !expected {
			return false, nil // unexpected export/filter key
		}
		b, err := os.ReadFile(filepath.Join(v.ConfigDir, k))
		if err != nil {
			return false, err
		}
		if string(bytes.TrimSpace(b)) != want {
			return false, nil
		}
		seen[k] = true
	}
	for k := range v.Settings {
		if !seen[k] {
			return false, nil
		}
	}
	return true, nil
}

func (v *Verifier) declared(ctx context.Context) ([]Policy, error) {
	var out []Policy
	for _, r := range []struct {
		gvr  schema.GroupVersionResource
		kind string
	}{{ClusterPolicies, "TracingPolicy"}, {NamespacedPolicies, "TracingPolicyNamespaced"}} {
		list, err := v.Policies.Resource(r.gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, item := range list.Items {
			if !strings.HasPrefix(item.GetName(), Prefix) {
				continue
			}
			if item.GetKind() != "" && item.GetKind() != r.kind {
				return nil, fmt.Errorf("unexpected kind %s", item.GetKind())
			}
			spec, ok := item.Object["spec"]
			if !ok {
				return nil, fmt.Errorf("policy %s has no spec", item.GetName())
			}
			// The stored spec already carries the CRD defaults; applying them
			// again is a no-op and keeps the hash independent of whether a
			// field was written explicitly or filled by the API server.
			if spec, err = ApplyCRDDefaults(r.kind, spec); err != nil {
				return nil, fmt.Errorf("policy %s: %w", item.GetName(), err)
			}
			out = append(out, Policy{Kind: r.kind, Namespace: item.GetNamespace(), Name: item.GetName(), Spec: spec})
		}
	}
	return out, nil
}

// loaded reads Tetragon's policy metrics: the agentarium (namespace/name)
// set and the per-state counts.
func (v *Verifier) loaded(ctx context.Context) (map[string]bool, map[string]float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.metricsURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "text/plain; version=0.0.4")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, nil, errors.New("metrics request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, errors.New("metrics endpoint did not return success")
	}
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, errors.New("invalid metrics exposition")
	}
	label := func(m *dto.Metric, name string) (string, bool) {
		for _, l := range m.GetLabel() {
			if l.GetName() == name {
				return l.GetValue(), true
			}
		}
		return "", false
	}
	memory, states := families["tetragon_tracingpolicy_kernel_memory_bytes"], families["tetragon_tracingpolicy_loaded"]
	if memory == nil || states == nil {
		return nil, nil, errors.New("policy metrics unavailable")
	}
	set := map[string]bool{}
	for _, m := range memory.GetMetric() {
		name, ok1 := label(m, "policy")
		ns, ok2 := label(m, "policy_namespace")
		if !ok1 || !ok2 {
			return nil, nil, errors.New("policy metric without policy labels")
		}
		if strings.HasPrefix(name, Prefix) {
			key := ns + "/" + name
			if set[key] {
				return nil, nil, errors.New("duplicate policy metric")
			}
			set[key] = true
		}
	}
	counts := map[string]float64{}
	for _, m := range states.GetMetric() {
		s, ok := label(m, "state")
		if !ok || m.GetGauge() == nil {
			return nil, nil, errors.New("invalid policy state metric")
		}
		if _, dup := counts[s]; dup {
			return nil, nil, fmt.Errorf("duplicate policy state row %q", s)
		}
		counts[s] = m.GetGauge().GetValue()
	}
	if _, ok := counts["enabled"]; !ok {
		return nil, nil, errors.New("policy state metric has no enabled row")
	}
	return set, counts, nil
}

// VerifyCapture implements healthreport.CaptureVerifier. false with a nil
// error is a definite mismatch; an error means the check could not run.
// Both keep the lease unhealthy.
func (v *Verifier) VerifyCapture(ctx context.Context) (bool, error) {
	if v == nil || v.client == nil {
		return false, errors.New("incomplete capture verifier")
	}
	if ok, err := v.settings(); !ok || err != nil {
		return false, err
	}
	declared, err := v.declared(ctx)
	if err != nil {
		return false, err
	}
	hash, err := RuleHash(declared)
	if err != nil {
		return false, err
	}
	if hash != v.RuleHash || len(declared) == 0 {
		return false, nil
	}
	set, counts, err := v.loaded(ctx)
	if err != nil {
		return false, err
	}
	// Every state other than enabled, including states this code does not
	// know, must be zero; enabled must cover every declared policy.
	for state, n := range counts {
		if state != "enabled" && n != 0 {
			return false, fmt.Errorf("tracing policy state %q has %v policies", state, n)
		}
	}
	if counts["enabled"] < float64(len(declared)) || len(set) != len(declared) {
		return false, nil
	}
	for _, p := range declared {
		if !set[p.Namespace+"/"+p.Name] {
			return false, nil
		}
	}
	return true, nil
}
