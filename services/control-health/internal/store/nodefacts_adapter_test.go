package store

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

// nodeAPI is a local HTTPS Kubernetes API that serves only GET/LIST on nodes,
// the TASK-06 control-health grant, and returns 403 for anything else.
type nodeAPI struct {
	*httptest.Server
	mu       sync.Mutex
	nodes    []corev1.Node
	getUID   map[string]types.UID // name -> UID returned by GET (replacement race)
	requests []string
	denied   []string
}

func newNodeAPI(t *testing.T, nodes ...corev1.Node) (*nodeAPI, kubernetes.Interface) {
	t.Helper()
	a := &nodeAPI{nodes: nodes, getUID: map[string]types.UID{}}
	a.Server = httptest.NewTLSServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Certificate().Raw})
	client, err := kubernetes.NewForConfig(&rest.Config{Host: a.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}, QPS: -1})
	if err != nil {
		t.Fatal(err)
	}
	return a, client
}

func (a *nodeAPI) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	line := r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
	a.requests = append(a.requests, line)
	w.Header().Set("Content-Type", "application/json")
	name, isNode := strings.CutPrefix(r.URL.Path, "/api/v1/nodes")
	watch := r.URL.Query().Get("watch") != ""
	if r.Method != http.MethodGet || !isNode || watch || strings.Contains(name, "/status") {
		a.denied = append(a.denied, line)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`))
		return
	}
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		start, _ := strconv.Atoi(r.URL.Query().Get("continue"))
		items := a.nodes[min(start, len(a.nodes)):]
		list := corev1.NodeList{TypeMeta: metav1.TypeMeta{Kind: "NodeList", APIVersion: "v1"}}
		if limit, _ := strconv.Atoi(r.URL.Query().Get("limit")); limit > 0 && limit < len(items) {
			items = items[:limit]
			list.Continue = strconv.Itoa(start + limit)
		}
		list.Items = items
		_ = json.NewEncoder(w).Encode(list)
		return
	}
	for _, n := range a.nodes {
		if n.Name == name {
			if uid, ok := a.getUID[name]; ok {
				n.UID = uid
			}
			n.TypeMeta = metav1.TypeMeta{Kind: "Node", APIVersion: "v1"}
			_ = json.NewEncoder(w).Encode(n)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`))
}

var q0Runtime = NodeRuntime{OSImage: "Container-Optimized OS from Google", KernelVersion: "6.6.87+", ContainerRuntimeVersion: "containerd://2.0.4", KubeletVersion: "v1.33.5-gke.1"}

func node(name, uid, pool, boot string, rt NodeRuntime) corev1.Node {
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid), Labels: map[string]string{NodePoolLabel: pool}},
		Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{BootID: boot, OSImage: rt.OSImage, KernelVersion: rt.KernelVersion,
			ContainerRuntimeVersion: rt.ContainerRuntimeVersion, KubeletVersion: rt.KubeletVersion}}}
}

func lockRows(t *testing.T) map[string]StartupCaptureRow {
	t.Helper()
	raw := `[{"node_pool":"exec-pool","runtime_profile_digest":"` + strings.Repeat("a", 64) + `","value":"guarded","measurement":"measured","q0_run_id":"20261017-q0",
	  "node_runtime":{"os_image":"Container-Optimized OS from Google","kernel_version":"6.6.87+","container_runtime_version":"containerd://2.0.4","kubelet_version":"v1.33.5-gke.1"}},
	 {"node_pool":"control-pool","runtime_profile_digest":null,"value":"unsupported","measurement":"not_measured","q0_run_id":null,"node_runtime":null}]`
	rows, err := ParseStartupCapture([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

const (
	execUID    = "6f1f0a0e-0000-4000-8000-000000000001"
	controlUID = "6f1f0a0e-0000-4000-8000-000000000002"
)

func TestKubeNodeFactsMeasuredAndNotMeasured(t *testing.T) {
	stale := q0Runtime
	stale.KubeletVersion = "v1.34.0-gke.9" // not compared for not_measured rows
	api, client := newNodeAPI(t, node("exec-a", execUID, "exec-pool", "boot-a", q0Runtime), node("ctl-a", controlUID, "control-pool", "boot-c", stale))
	src := KubeNodeFacts{Client: client, Rows: lockRows(t)}
	got, err := src.Current(context.Background(), execUID)
	if err != nil || got != (NodeFacts{execUID, "boot-a", "guarded", Measured}) {
		t.Fatalf("measured: %+v %v", got, err)
	}
	got, err = src.Current(context.Background(), controlUID)
	if err != nil || got != (NodeFacts{controlUID, "boot-c", "unsupported", NotMeasured}) {
		t.Fatalf("not_measured: %+v %v", got, err)
	}
	if len(api.denied) != 0 {
		t.Fatalf("requests outside nodes get/list: %v", api.denied)
	}
	for _, r := range api.requests {
		if strings.Contains(r, "watch") || strings.Contains(r, "fieldSelector") {
			t.Fatalf("unexpected request %q", r)
		}
	}
}

func TestKubeNodeFactsRejects(t *testing.T) {
	upgraded := q0Runtime
	upgraded.KubeletVersion = "v1.33.6-gke.2"
	newKernel := q0Runtime
	newKernel.KernelVersion = "6.6.99+"
	cases := map[string]struct {
		nodes  []corev1.Node
		mutate func(*nodeAPI)
		want   error
	}{
		"uid swap on same name": {[]corev1.Node{node("exec-a", execUID, "exec-pool", "boot-a", q0Runtime)},
			func(a *nodeAPI) { a.getUID["exec-a"] = "6f1f0a0e-0000-4000-8000-0000000000ff" }, ErrNodeReplaced},
		"uid not present":    {[]corev1.Node{node("exec-a", controlUID, "exec-pool", "boot-a", q0Runtime)}, nil, ErrNodeNotFound},
		"uid twice":          {[]corev1.Node{node("exec-a", execUID, "exec-pool", "b", q0Runtime), node("exec-b", execUID, "exec-pool", "b", q0Runtime)}, nil, ErrNodeAmbiguous},
		"kubelet upgraded":   {[]corev1.Node{node("exec-a", execUID, "exec-pool", "boot-a", upgraded)}, nil, ErrProfileStale},
		"kernel replaced":    {[]corev1.Node{node("exec-a", execUID, "exec-pool", "boot-a", newKernel)}, nil, ErrProfileStale},
		"pool without row":   {[]corev1.Node{node("exec-a", execUID, "system-pool", "boot-a", q0Runtime)}, nil, ErrNodePoolUnknown},
		"pool label missing": {[]corev1.Node{node("exec-a", execUID, "", "boot-a", q0Runtime)}, nil, ErrNodePoolUnknown},
		"no boot id":         {[]corev1.Node{node("exec-a", execUID, "exec-pool", "", q0Runtime)}, nil, ErrNodeNoBoot},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			api, client := newNodeAPI(t, c.nodes...)
			if c.mutate != nil {
				c.mutate(api)
			}
			if _, err := (KubeNodeFacts{Client: client, Rows: lockRows(t)}).Current(context.Background(), execUID); !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

func TestKubeNodeFactsListsAllPages(t *testing.T) {
	var nodes []corev1.Node
	for i := range 1100 {
		nodes = append(nodes, node("n-"+strconv.Itoa(i), "6f1f0a0e-0000-4000-9000-"+strings.Repeat("0", 8)+strconv.Itoa(1000+i), "exec-pool", "b", q0Runtime))
	}
	nodes = append(nodes, node("exec-a", execUID, "exec-pool", "boot-a", q0Runtime))
	api, client := newNodeAPI(t, nodes...)
	if _, err := (KubeNodeFacts{Client: client, Rows: lockRows(t)}).Current(context.Background(), execUID); err != nil {
		t.Fatal(err)
	}
	lists := 0
	for _, r := range api.requests {
		if strings.HasPrefix(r, "GET /api/v1/nodes?") {
			lists++
		}
	}
	if lists != 3 {
		t.Fatalf("LIST pages=%d", lists)
	}
}

func TestParseStartupCaptureRejects(t *testing.T) {
	digest := `"` + strings.Repeat("a", 64) + `"`
	rt := `{"os_image":"o","kernel_version":"k","container_runtime_version":"c","kubelet_version":"v"}`
	measured := `{"node_pool":"exec-pool","runtime_profile_digest":` + digest + `,"value":"guarded","measurement":"measured","q0_run_id":"r","node_runtime":` + rt + `}`
	notMeasured := `{"node_pool":"exec-pool","runtime_profile_digest":null,"value":"unsupported","measurement":"not_measured","q0_run_id":null,"node_runtime":null}`
	for _, ok := range []string{"[" + measured + "]", "[" + notMeasured + "]", "[]"} {
		if _, err := ParseStartupCapture([]byte(ok)); err != nil {
			t.Fatalf("valid %s rejected: %v", ok, err)
		}
	}
	for name, raw := range map[string]string{
		"duplicate pool":            "[" + measured + "," + notMeasured + "]",
		"guarded not measured":      "[" + strings.Replace(notMeasured, `"unsupported"`, `"guarded"`, 1) + "]",
		"measured without run":      "[" + strings.Replace(measured, `"q0_run_id":"r"`, `"q0_run_id":null`, 1) + "]",
		"measured without runtime":  "[" + strings.Replace(measured, rt, "null", 1) + "]",
		"measured without digest":   "[" + strings.Replace(measured, digest, "null", 1) + "]",
		"not measured with runtime": "[" + strings.Replace(notMeasured, `"node_runtime":null`, `"node_runtime":`+rt, 1) + "]",
		"runtime field missing":     "[" + strings.Replace(measured, `,"kubelet_version":"v"`, "", 1) + "]",
		"empty runtime value":       "[" + strings.Replace(measured, `"kubelet_version":"v"`, `"kubelet_version":""`, 1) + "]",
		"bad digest":                "[" + strings.Replace(measured, digest, `"ABC"`, 1) + "]",
		"unknown measurement":       "[" + strings.Replace(measured, `"measured"`, `"incomplete"`, 1) + "]",
		"unknown key":               "[" + strings.Replace(measured, `"value"`, `"extra":1,"value"`, 1) + "]",
		"missing key":               "[" + strings.Replace(notMeasured, `,"q0_run_id":null`, "", 1) + "]",
		"not array":                 measured,
		"trailing data":             "[]{}",
	} {
		if _, err := ParseStartupCapture([]byte(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// The fixture enforces exactly the reviewed control-health Node grant.
func TestControlHealthNodeRBACManifest(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../deploy/gcp/base/rbac/control-health-nodes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	docs := strings.Split(string(raw), "\n---")
	var role rbacv1.ClusterRole
	var binding rbacv1.ClusterRoleBinding
	if len(docs) != 2 || yaml.Unmarshal([]byte(docs[0]), &role) != nil || yaml.Unmarshal([]byte(docs[1]), &binding) != nil {
		t.Fatal("expected one ClusterRole and one ClusterRoleBinding")
	}
	if role.Kind != "ClusterRole" || len(role.Rules) != 1 {
		t.Fatalf("role %+v", role)
	}
	r := role.Rules[0]
	if !slices.Equal(r.APIGroups, []string{""}) || !slices.Equal(r.Resources, []string{"nodes"}) || !slices.Equal(r.Verbs, []string{"get", "list"}) || len(r.ResourceNames) != 0 || len(r.NonResourceURLs) != 0 {
		t.Fatalf("rule %+v", r)
	}
	if binding.Kind != "ClusterRoleBinding" || binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != role.Name ||
		len(binding.Subjects) != 1 || binding.Subjects[0] != (rbacv1.Subject{Kind: "ServiceAccount", Name: "control-health", Namespace: "agent-observe"}) {
		t.Fatalf("binding %+v", binding)
	}
}
