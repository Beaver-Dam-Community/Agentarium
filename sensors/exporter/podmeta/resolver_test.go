package podmeta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/normalize"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const node = "gke-exec-node-a"

var statuses = struct{ Resolved, Unresolved, Socket string }{normalize.MetadataResolved, normalize.MetadataUnresolved, normalize.MetadataTupleScoped}

func cid(c byte) string { return strings.Repeat(string(c), 64) }

func testPod(ns, name, uid, ip string, container string) *corev1.Pod {
	p := &corev1.Pod{TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid), ResourceVersion: "1"}, Spec: corev1.PodSpec{NodeName: node}}
	if ip != "" {
		p.Status.PodIPs = []corev1.PodIP{{IP: ip}}
	}
	if container != "" {
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "main", ContainerID: "containerd://" + container}}
	}
	return p
}

// apiServer is a minimal Kubernetes API that enforces the node field selector
// the resolver must use and streams WATCH events pushed by the test.
type apiServer struct {
	*httptest.Server
	mu       sync.Mutex
	list     []corev1.Pod
	events   chan string
	selector []string
}

func newAPIServer(t *testing.T, pods ...*corev1.Pod) *apiServer {
	a := &apiServer{events: make(chan string, 16)}
	for _, p := range pods {
		a.list = append(a.list, *p)
	}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pods" || r.Method != http.MethodGet {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		sel := r.URL.Query().Get("fieldSelector")
		a.mu.Lock()
		a.selector = append(a.selector, sel)
		a.mu.Unlock()
		if sel != "spec.nodeName="+node {
			http.Error(w, "node field selector required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") != "true" {
			a.mu.Lock()
			body, _ := json.Marshal(corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}, ListMeta: metav1.ListMeta{ResourceVersion: "10"}, Items: a.list})
			a.mu.Unlock()
			_, _ = w.Write(body)
			return
		}
		flusher := w.(http.Flusher)
		if r.URL.Query().Get("sendInitialEvents") == "true" {
			// WatchList contract: initial state as ADDED events, then a bookmark
			// annotated k8s.io/initial-events-end.
			a.mu.Lock()
			for i := range a.list {
				b, _ := json.Marshal(map[string]any{"type": "ADDED", "object": &a.list[i]})
				_, _ = fmt.Fprintln(w, string(b))
			}
			a.mu.Unlock()
			b, _ := json.Marshal(map[string]any{"type": "BOOKMARK", "object": map[string]any{"kind": "Pod", "apiVersion": "v1", "metadata": map[string]any{"resourceVersion": "10", "annotations": map[string]string{"k8s.io/initial-events-end": "true"}}}})
			_, _ = fmt.Fprintln(w, string(b))
		}
		flusher.Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case line := <-a.events:
				_, _ = fmt.Fprintln(w, line)
				flusher.Flush()
			}
		}
	}))
	t.Cleanup(a.Close)
	return a
}

func (a *apiServer) push(t *testing.T, kind string, p *corev1.Pod) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": kind, "object": p})
	if err != nil {
		t.Fatal(err)
	}
	a.events <- string(b)
}

func start(t *testing.T, a *apiServer, now func() time.Time, grace time.Duration) *Resolver {
	t.Helper()
	r, err := New(Config{NodeName: node, Observed: []string{"agent-exec", "agent-adapters"}, Grace: grace, Retain: time.Hour, Now: now, PodCIDRs: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(&rest.Config{Host: a.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, client) }()
	t.Cleanup(func() { cancel(); <-done })
	return r
}

func resolve(t *testing.T, r *Resolver, q normalize.Query) normalize.Resolution {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := r.Resolve(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestResolveThroughNodeScopedInformer(t *testing.T) {
	exec := testPod("agent-exec", "probe", "11111111-1111-4111-8111-111111111111", "10.8.0.5", cid('a'))
	system := testPod("kube-system", "dns", "22222222-2222-4222-8222-222222222222", "10.8.0.9", cid('b'))
	a := newAPIServer(t, exec, system)
	r := start(t, a, time.Now, time.Minute)
	now := time.Now()

	got := resolve(t, r, normalize.Query{EventType: "process_exec", SourceTime: now, DockerPrefix: cid('a')[:15]})
	if got.Scope != normalize.Include || got.ContainerID != cid('a') || got.PodUID != string(exec.UID) || got.MetadataStatus != statuses.Resolved {
		t.Fatalf("observed container: %+v", got)
	}
	if got := resolve(t, r, normalize.Query{EventType: "tcp_connect", SourceTime: now, DockerPrefix: cid('b')[:15]}); got.Scope != normalize.Exclude {
		t.Fatalf("kube-system container must be excluded: %+v", got)
	}
	if got := resolve(t, r, normalize.Query{EventType: "process_exec", SourceTime: now}); got.Scope != normalize.Exclude {
		t.Fatalf("host process must be excluded: %+v", got)
	}
	in := resolve(t, r, normalize.Query{EventType: "tcp_state", SourceTime: now, Socket: &normalize.Tuple{SAddr: "10.8.0.5", SPort: 40000, DAddr: "10.9.0.1", DPort: 443}})
	if in.Scope != normalize.Include || in.MetadataStatus != statuses.Socket || in.PodUID != "" || in.ContainerID != "" {
		t.Fatalf("observed Pod socket: %+v", in)
	}
	if got := resolve(t, r, normalize.Query{EventType: "tcp_state", SourceTime: now, Socket: &normalize.Tuple{SAddr: "10.8.0.9", SPort: 53, DAddr: "10.9.5.77", DPort: 4000}}); got.Scope != normalize.Exclude {
		t.Fatalf("non-observed socket must be excluded: %+v", got)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.selector {
		if s != "spec.nodeName="+node {
			t.Fatalf("request without node selector: %q", s)
		}
	}
}

func TestPendingContainerWaitsForWatchAndExpiresToUnresolved(t *testing.T) {
	a := newAPIServer(t)
	r := start(t, a, time.Now, 3*time.Second)
	late := testPod("agent-adapters", "adapter", "33333333-3333-4333-8333-333333333333", "10.8.0.6", cid('c'))
	go func() {
		time.Sleep(300 * time.Millisecond)
		a.push(t, "ADDED", late)
	}()
	start := time.Now()
	got := resolve(t, r, normalize.Query{EventType: "process_exec", SourceTime: start, DockerPrefix: cid('c')[:15]})
	if got.Scope != normalize.Include || got.PodUID != string(late.UID) || time.Since(start) < 250*time.Millisecond {
		t.Fatalf("pending container must wait for WATCH: %+v after %s", got, time.Since(start))
	}
	// A sandbox container never appears in Pod status: kept as unresolved.
	got = resolve(t, r, normalize.Query{EventType: "process_exec", SourceTime: time.Now().Add(-4 * time.Second), DockerPrefix: cid('d')[:15]})
	if got.Scope != normalize.Include || got.MetadataStatus != statuses.Unresolved || got.PodUID != "" {
		t.Fatalf("expired pending container: %+v", got)
	}
}

func TestDeletedPodKeepsUIDUntilRetentionAndSocketAfterDelete(t *testing.T) {
	p := testPod("agent-exec", "short", "44444444-4444-4444-8444-444444444444", "10.8.0.7", cid('e'))
	a := newAPIServer(t, p)
	var mu sync.Mutex
	clock := time.Now()
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	r := start(t, a, now, time.Second)
	_ = resolve(t, r, normalize.Query{EventType: "process_exec", SourceTime: now(), DockerPrefix: cid('e')[:15]})
	before := now().Add(-time.Second)
	a.push(t, "DELETED", p)
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		deleted := !r.pods[string(p.UID)].deleted.IsZero()
		r.mu.Unlock()
		if deleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("delete not observed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := resolve(t, r, normalize.Query{EventType: "process_exit", SourceTime: before, DockerPrefix: cid('e')[:15]}); got.PodUID != string(p.UID) {
		t.Fatalf("tombstone lost UID: %+v", got)
	}
	if got := resolve(t, r, normalize.Query{EventType: "tcp_state", SourceTime: before, Socket: &normalize.Tuple{SAddr: "10.8.0.7", DAddr: "10.9.0.1", DPort: 443}}); got.Scope != normalize.Include {
		t.Fatalf("socket before deletion: %+v", got)
	}
	after := now().Add(time.Second)
	mu.Lock()
	clock = clock.Add(5 * time.Second)
	mu.Unlock()
	// After deletion the IP is no longer attributed to the old Pod, but it is
	// still inside the node Pod CIDR, so it is kept as unresolved.
	if got := resolve(t, r, normalize.Query{EventType: "tcp_state", SourceTime: after, Socket: &normalize.Tuple{SAddr: "10.8.0.7", DAddr: "10.9.0.1", DPort: 443}}); got.Scope != normalize.Include || got.MetadataStatus != statuses.Unresolved {
		t.Fatalf("reused IP after deletion must not be attributed: %+v", got)
	}
	mu.Lock()
	clock = clock.Add(2 * time.Hour)
	mu.Unlock()
	a.push(t, "DELETED", testPod("kube-system", "other", "55555555-5555-4555-8555-555555555555", "", ""))
	time.Sleep(200 * time.Millisecond)
	if got := resolve(t, r, normalize.Query{EventType: "process_exit", SourceTime: now().Add(-2 * time.Second), DockerPrefix: cid('e')[:15]}); got.MetadataStatus != statuses.Unresolved {
		t.Fatalf("retention expiry must drop tombstone: %+v", got)
	}
}

func TestUnsyncedResolveHonorsCancellation(t *testing.T) {
	r, err := New(Config{NodeName: node, Observed: []string{"agent-exec"}, Grace: time.Second, Retain: time.Second, PodCIDRs: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := r.Resolve(ctx, normalize.Query{EventType: "process_exec", DockerPrefix: cid('a')[:15]}); err == nil {
		t.Fatal("unsynced cache must not decide")
	}
	for _, bad := range []Config{{}, {NodeName: node, Observed: []string{"agent-exec"}, Grace: time.Second, Retain: time.Second}, {NodeName: node, Observed: []string{"Bad_NS"}, Grace: time.Second, Retain: time.Second}} {
		if _, err := New(bad); err == nil {
			t.Fatalf("invalid config accepted: %+v", bad)
		}
	}
}

// Socket decisions must not exclude what the node cache cannot yet attribute.
func TestSocketScopeWaitsForLateIPAndKeepsUnattributable(t *testing.T) {
	a := newAPIServer(t)
	r := start(t, a, time.Now, 2*time.Second)
	// Late IP assignment: the Pod exists first without an IP.
	p := testPod("agent-exec", "late", "77777777-7777-4777-8777-777777777777", "", cid('f'))
	a.push(t, "ADDED", p)
	go func() {
		time.Sleep(300 * time.Millisecond)
		withIP := p.DeepCopy()
		withIP.Status.PodIPs = []corev1.PodIP{{IP: "10.8.0.40"}}
		a.push(t, "MODIFIED", withIP)
	}()
	got := resolve(t, r, normalize.Query{EventType: "tcp_state", SourceTime: time.Now(), Socket: &normalize.Tuple{SAddr: "10.8.0.40", SPort: 41000, DAddr: "10.9.5.1", DPort: 443}})
	if got.Scope != normalize.Include || got.MetadataStatus != statuses.Socket {
		t.Fatalf("late Pod IP must be waited for, got %+v", got)
	}
	// Observed hostNetwork Pod: its node IP cannot attribute the socket, but
	// the event must be kept.
	host := testPod("agent-adapters", "hostnet", "88888888-8888-4888-8888-888888888888", "192.168.0.2", cid('9'))
	host.Spec.HostNetwork = true
	a.push(t, "ADDED", host)
	deadline := time.Now().Add(5 * time.Second)
	for {
		got = resolve(t, r, normalize.Query{EventType: "tcp_state", SourceTime: time.Now().Add(-time.Minute), Socket: &normalize.Tuple{SAddr: "192.168.0.2", SPort: 41000, DAddr: "10.9.5.1", DPort: 443}})
		if got.Scope == normalize.Include || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got.Scope != normalize.Include || got.MetadataStatus != statuses.Unresolved {
		t.Fatalf("observed hostNetwork socket dropped: %+v", got)
	}
	// An address in this node's Pod CIDR that no cached Pod owns is kept as
	// unresolved after grace, never excluded.
	start := time.Now()
	got = resolve(t, r, normalize.Query{EventType: "tcp_state", SourceTime: start, Socket: &normalize.Tuple{SAddr: "10.8.0.99", SPort: 41000, DAddr: "10.9.5.1", DPort: 443}})
	if got.Scope != normalize.Include || got.MetadataStatus != statuses.Unresolved || time.Since(start) < 1500*time.Millisecond {
		t.Fatalf("CIDR-internal unknown endpoint: %+v after %s", got, time.Since(start))
	}
	// Positive exclusion: both endpoints are outside the node Pod CIDR.
	if got := resolve(t, r, normalize.Query{EventType: "tcp_state", SourceTime: time.Now(), Socket: &normalize.Tuple{SAddr: "10.9.5.2", SPort: 41000, DAddr: "10.9.5.1", DPort: 443}}); got.Scope != normalize.Exclude {
		t.Fatalf("outside-node socket: %+v", got)
	}
}
