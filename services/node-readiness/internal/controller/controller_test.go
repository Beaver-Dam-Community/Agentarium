package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/node-readiness/internal/controlhealth"
	"github.com/Beaver-Dam-Community/Agentarium/services/node-readiness/internal/readiness"
)

var t0 = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// processStart is far enough before t0 that probes judged near t0 are fresh.
var processStart = t0.Add(-10 * time.Minute)

type fakeHealth struct {
	mu   sync.Mutex
	resp func(uid string) (*controlhealth.NodeHealth, error)
}

func (f *fakeHealth) NodeHealth(_ context.Context, uid string) (*controlhealth.NodeHealth, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resp(uid)
}

func (f *fakeHealth) set(fn func(uid string) (*controlhealth.NodeHealth, error)) {
	f.mu.Lock()
	f.resp = fn
	f.mu.Unlock()
}

func healthy(judgedAt time.Time) func(string) (*controlhealth.NodeHealth, error) {
	return func(uid string) (*controlhealth.NodeHealth, error) {
		capture := "unsupported"
		h := &controlhealth.NodeHealth{
			Scope: "node", ScopeID: uid, EvaluatedAt: t0, State: "healthy",
			Leases: []controlhealth.LeaseStatus{
				{Component: "node-sensors", SourceID: "a", ObservedState: "healthy", LeaseUntil: t0.Add(15 * time.Second)},
				{Component: "lifecycle-recorder", SourceID: "b", ObservedState: "healthy", LeaseUntil: t0.Add(15 * time.Second)},
			},
			MissingComponents: []string{}, OpenHolds: []controlhealth.Hold{}, StartupCapture: &capture,
		}
		for _, k := range readiness.RequiredProbeKinds {
			j := judgedAt
			h.Probes = append(h.Probes, controlhealth.Probe{ProbeKind: k, LastJudgedAt: &j, LastResult: "pass", ConsecutivePasses: 2})
		}
		return h, nil
	}
}

func withNodeHold(uid string) (*controlhealth.NodeHealth, error) {
	h, _ := healthy(t0.Add(-time.Second))(uid)
	h.State = "unhealthy"
	h.OpenHolds = []controlhealth.Hold{{HoldID: "h1", Scope: "node", ScopeID: uid, Reason: "sensor_degraded"}}
	return h, nil
}

func unavailable(string) (*controlhealth.NodeHealth, error) {
	return nil, &controlhealth.APIError{StatusCode: 503, ReasonCodes: []string{"CONTROL_HEALTH_UNAVAILABLE"}}
}

var otherTaints = []corev1.Taint{
	{Key: "agentarium-role", Value: "exec", Effect: corev1.TaintEffectNoSchedule},
	{Key: "example.com/maintenance", Value: "x", Effect: corev1.TaintEffectPreferNoSchedule},
}

func testNode(name, boot string, withStart bool) *corev1.Node {
	taints := []corev1.Taint{otherTaints[0]}
	if withStart {
		taints = append(taints, startTaint)
	}
	taints = append(taints, otherTaints[1])
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, UID: types.UID(name + "-uid"), ResourceVersion: "1",
			Labels:      map[string]string{RoleLabel: "exec", "keep": "me"},
			Annotations: map[string]string{"a": "b"},
		},
		Spec:   corev1.NodeSpec{Taints: taints, Unschedulable: false},
		Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{BootID: boot}},
	}
}

type harness struct {
	t      *testing.T
	client *fake.Clientset
	ctrl   *Controller
	health *fakeHealth
	now    time.Time
}

func newHarness(t *testing.T, nodes ...*corev1.Node) *harness {
	t.Helper()
	h := &harness{t: t, health: &fakeHealth{resp: unavailable}, now: t0}
	h.client = fake.NewClientset()
	for _, n := range nodes {
		if _, err := h.client.CoreV1().Nodes().Create(context.Background(), n, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	ctrl, err := New(h.client, h.health, Config{
		Resync: 50 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return h.now }, StartedAt: processStart,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.ctrl = ctrl
	for _, n := range nodes {
		h.syncLister(n.Name)
	}
	// As Run does once the informer has synced.
	h.ctrl.recordInitialNodes()
	return h
}

// syncLister copies the tracker's node into the informer cache, as a watch event would.
func (h *harness) syncLister(name string) *corev1.Node {
	h.t.Helper()
	n, err := h.client.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		h.t.Fatal(err)
	}
	idx := h.ctrl.factory.Core().V1().Nodes().Informer().GetIndexer()
	if err := idx.Update(n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// bumpRV gives the stored node a new resourceVersion, as the API server does
// on every write; the fake tracker leaves object resourceVersions unchanged.
func (h *harness) bumpRV(name string) {
	h.t.Helper()
	gvr := corev1.SchemeGroupVersion.WithResource("nodes")
	obj, err := h.client.Tracker().Get(gvr, "", name)
	if err != nil {
		h.t.Fatal(err)
	}
	n := obj.(*corev1.Node).DeepCopy()
	rv, _ := strconv.Atoi(n.ResourceVersion)
	n.ResourceVersion = strconv.Itoa(rv + 1)
	if err := h.client.Tracker().Update(gvr, n, ""); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) reconcile(name string) *corev1.Node {
	h.t.Helper()
	before := h.syncLister(name)
	h.client.ClearActions()
	if _, err := h.ctrl.Reconcile(context.Background(), name); err != nil {
		h.t.Fatalf("reconcile: %v", err)
	}
	if patchCount(h.client.Actions()) > 0 {
		h.bumpRV(name)
	}
	after := h.syncLister(name)
	assertScopeValid(h.t, before, after)
	assertOnlyTaintPatches(h.t, h.client.Actions())
	return after
}

// assertScopeValid mirrors the node-readiness-scope VAP (TASK-01 3.2.1):
// taints other than the start taint, labels, annotations and unschedulable
// must be identical, with taint order preserved.
func assertScopeValid(t *testing.T, old, cur *corev1.Node) {
	t.Helper()
	filter := func(ts []corev1.Taint) []corev1.Taint {
		out := []corev1.Taint{}
		for _, x := range ts {
			if x.Key != StartTaintKey {
				out = append(out, x)
			}
		}
		return out
	}
	if !reflect.DeepEqual(filter(old.Spec.Taints), filter(cur.Spec.Taints)) {
		t.Fatalf("NODE_READINESS_SCOPE_INVALID: other taints changed\nold %v\nnew %v", old.Spec.Taints, cur.Spec.Taints)
	}
	if !reflect.DeepEqual(old.Labels, cur.Labels) || !reflect.DeepEqual(old.Annotations, cur.Annotations) ||
		old.Spec.Unschedulable != cur.Spec.Unschedulable {
		t.Fatal("NODE_READINESS_SCOPE_INVALID: labels/annotations/unschedulable changed")
	}
}

func assertOnlyTaintPatches(t *testing.T, actions []k8stesting.Action) {
	t.Helper()
	for _, a := range actions {
		switch act := a.(type) {
		case k8stesting.PatchAction:
			if act.GetPatchType() != types.JSONPatchType {
				t.Fatalf("patch type %s, want JSON patch", act.GetPatchType())
			}
			var ops []map[string]any
			if err := json.Unmarshal(act.GetPatch(), &ops); err != nil {
				t.Fatal(err)
			}
			for _, op := range ops {
				path := op["path"].(string)
				if op["op"] == "test" && (path == "/metadata/resourceVersion" || path == "/spec/taints") {
					continue
				}
				if !strings.HasPrefix(path, "/spec/taints") {
					t.Fatalf("patch touches %s", path)
				}
			}
		case k8stesting.UpdateAction:
			t.Fatalf("controller must not send full updates: %v", act)
		}
	}
}

func patchCount(actions []k8stesting.Action) int {
	n := 0
	for _, a := range actions {
		if _, ok := a.(k8stesting.PatchAction); ok {
			n++
		}
	}
	return n
}

func TestRemovesStartTaintWhenReady(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", true))
	h.health.set(healthy(t0.Add(-time.Second)))
	n := h.reconcile("n1")
	if hasStartTaint(n) {
		t.Fatal("start taint should be removed")
	}
	if !reflect.DeepEqual(n.Spec.Taints, otherTaints) {
		t.Fatalf("other taints must be kept in order: %v", n.Spec.Taints)
	}
}

func TestKeepsTaintWhenNotReady(t *testing.T) {
	for name, fn := range map[string]func(string) (*controlhealth.NodeHealth, error){
		"node hold": withNodeHold, "control-health unavailable": unavailable,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, testNode("n1", "boot-1", true))
			h.health.set(fn)
			n := h.reconcile("n1")
			if !hasStartTaint(n) {
				t.Fatal("start taint must stay")
			}
			if c := patchCount(h.client.Actions()); c != 0 {
				t.Fatalf("no patch expected, got %d", c)
			}
		})
	}
}

func TestReaddsTaintOnHoldAndRecovers(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", false))
	h.health.set(healthy(t0.Add(-time.Second)))
	if n := h.reconcile("n1"); hasStartTaint(n) {
		t.Fatal("healthy node must stay untainted")
	}
	h.health.set(withNodeHold)
	n := h.reconcile("n1")
	if !hasStartTaint(n) {
		t.Fatal("node hold must re-add start taint")
	}
	want := append(append([]corev1.Taint{}, otherTaints...), startTaint)
	if !reflect.DeepEqual(n.Spec.Taints, want) {
		t.Fatalf("start taint must be appended: %v", n.Spec.Taints)
	}
	h.health.set(healthy(t0.Add(-time.Second)))
	if n := h.reconcile("n1"); hasStartTaint(n) {
		t.Fatal("start taint should be removed again once healthy")
	}
}

func TestAddsTaintToNodeWithoutTaints(t *testing.T) {
	node := testNode("n1", "boot-1", false)
	node.Spec.Taints = nil
	h := newHarness(t, node)
	h.health.set(unavailable)
	n := h.reconcile("n1")
	if !reflect.DeepEqual(n.Spec.Taints, []corev1.Taint{startTaint}) {
		t.Fatalf("taints %v", n.Spec.Taints)
	}
}

func TestBootIDChangeReaddsTaint(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", true))
	h.health.set(healthy(t0.Add(-time.Second)))
	if n := h.reconcile("n1"); hasStartTaint(n) {
		t.Fatal("expected ready on boot-1")
	}

	// Reboot: new boot ID; control-health still reports the probes judged before it.
	n, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	n.Status.NodeInfo.BootID = "boot-2"
	if _, err := h.client.CoreV1().Nodes().UpdateStatus(context.Background(), n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.bumpRV("n1")
	h.now = t0.Add(30 * time.Second)
	if n := h.reconcile("n1"); !hasStartTaint(n) {
		t.Fatal("boot ID change must re-add the start taint")
	}
	// Still stale probes on the next pass: taint stays, no patch.
	if n := h.reconcile("n1"); !hasStartTaint(n) || patchCount(h.client.Actions()) != 0 {
		t.Fatal("stale probes must keep the taint without patching")
	}
	// Probes judged only 10s after the reboot may cover an old-boot stimulus.
	h.health.set(withFreshLeases(t0.Add(40*time.Second), t0.Add(55*time.Second)))
	h.now = t0.Add(45 * time.Second)
	if n := h.reconcile("n1"); !hasStartTaint(n) {
		t.Fatal("probes inside the freshness margin must keep the taint")
	}
	// Judged after reboot + margin: taint removed.
	h.health.set(withFreshLeases(t0.Add(30*time.Second+readiness.ProbeFreshnessMargin+time.Second), t0.Add(3*time.Minute)))
	h.now = t0.Add(2 * time.Minute)
	if n := h.reconcile("n1"); hasStartTaint(n) {
		t.Fatal("fresh probes after reboot should remove the taint")
	}
}

func withFreshLeases(judgedAt, leaseUntil time.Time) func(string) (*controlhealth.NodeHealth, error) {
	return func(uid string) (*controlhealth.NodeHealth, error) {
		r, _ := healthy(judgedAt)(uid)
		r.EvaluatedAt = judgedAt
		for i := range r.Leases {
			r.Leases[i].LeaseUntil = leaseUntil
		}
		return r, nil
	}
}

// newController builds a controller over an existing clientset, as after a restart.
func newController(t *testing.T, client *fake.Clientset, hf *fakeHealth, startedAt time.Time, now *time.Time) *Controller {
	t.Helper()
	ctrl, err := New(client, hf, Config{
		Resync: 50 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return *now }, StartedAt: startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ctrl
}

func loadNode(t *testing.T, client *fake.Clientset, ctrl *Controller, name string) *corev1.Node {
	t.Helper()
	n, err := client.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.factory.Core().V1().Nodes().Informer().GetIndexer().Update(n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A boot change while the controller is down is invisible to it. After the
// restart, probe passes judged before the restart (possibly the old boot's)
// must not remove the taint, and an untainted node must be re-tainted.
func TestRestartAfterUnobservedBootChangeIgnoresStaleProbes(t *testing.T) {
	for _, tainted := range []bool{true, false} {
		t.Run(fmt.Sprintf("tainted=%v", tainted), func(t *testing.T) {
			// boot-1 was ready before the outage; the node rebooted to boot-2
			// while the controller was down. Taints survive a reboot.
			client := fake.NewClientset(testNode("n1", "boot-2", tainted))
			now := t0.Add(time.Minute)
			restart := t0.Add(30 * time.Second)
			hf := &fakeHealth{resp: withFreshLeases(t0, now.Add(15*time.Second))} // judged before restart
			ctrl := newController(t, client, hf, restart, &now)

			loadNode(t, client, ctrl, "n1")
			ctrl.recordInitialNodes() // as Run does after the initial sync
			if _, err := ctrl.Reconcile(context.Background(), "n1"); err != nil {
				t.Fatal(err)
			}
			n := loadNode(t, client, ctrl, "n1")
			if !hasStartTaint(n) {
				t.Fatal("stale probes after restart must leave the node tainted")
			}
			if !reflect.DeepEqual(n.Spec.Taints[:1], otherTaints[:1]) {
				t.Fatalf("other taints changed: %v", n.Spec.Taints)
			}

			// Probes judged after restart + margin: taint removed.
			now = restart.Add(readiness.ProbeFreshnessMargin + 10*time.Second)
			hf.set(withFreshLeases(now.Add(-time.Second), now.Add(15*time.Second)))
			if _, err := ctrl.Reconcile(context.Background(), "n1"); err != nil {
				t.Fatal(err)
			}
			if n := loadNode(t, client, ctrl, "n1"); hasStartTaint(n) {
				t.Fatal("fresh probes after restart should remove the taint")
			}
		})
	}
}

func TestFirstSeenUntaintedNodeWithStaleProbesIsRetainted(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", false))
	h.ctrl.cfg.StartedAt = t0
	h.health.set(healthy(t0.Add(-time.Second)))
	n := h.reconcile("n1")
	if !hasStartTaint(n) {
		t.Fatal("first-seen node with probes judged before process start must be tainted")
	}
	want := append(append([]corev1.Taint{}, otherTaints...), startTaint)
	if !reflect.DeepEqual(n.Spec.Taints, want) {
		t.Fatalf("start taint must be appended only: %v", n.Spec.Taints)
	}
}

func TestNodeLeavingSelectorIsRetainted(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", true))
	h.health.set(healthy(t0.Add(-time.Second)))
	if n := h.reconcile("n1"); hasStartTaint(n) {
		t.Fatal("expected ready")
	}
	// Someone with nodes patch removes the pool label; the watch drops the node.
	n, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	delete(n.Labels, RoleLabel)
	if _, err := h.client.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := h.ctrl.factory.Core().V1().Nodes().Informer().GetIndexer().Delete(n); err != nil {
		t.Fatal(err)
	}
	before, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	h.client.ClearActions()
	requeue, err := h.ctrl.Reconcile(context.Background(), "n1")
	if err != nil || requeue {
		t.Fatalf("requeue=%v err=%v", requeue, err)
	}
	after, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	if !hasStartTaint(after) {
		t.Fatal("node leaving the selector must get the start taint back")
	}
	assertScopeValid(t, before, after)
	assertOnlyTaintPatches(t, h.client.Actions())
	if _, ok := h.ctrl.boots["n1"]; ok {
		t.Fatal("boot state must be dropped")
	}
}

func TestPatchFailureIsRetriedWithinCap(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", false))
	h.health.set(unavailable)
	calls := 0
	h.client.PrependReactor("patch", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls <= 3 {
			return true, nil, errors.New("apiserver unavailable")
		}
		return false, nil, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.ctrl.queue.Add("n1")
	go h.ctrl.runWorker(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{}); hasStartTaint(n) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("taint not applied after transient patch failures (%d patch calls)", calls)
}

func TestRecreatedNodeIsNotABootChange(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", true))
	if _, changed := h.ctrl.trackBoot("n1", "uid-a", "boot-1"); changed {
		t.Fatal("first sight is not a change")
	}
	if _, changed := h.ctrl.trackBoot("n1", "uid-b", "boot-9"); changed {
		t.Fatal("new UID is a new node")
	}
	if at, changed := h.ctrl.trackBoot("n1", "uid-b", "boot-10"); !changed || at.IsZero() {
		t.Fatal("boot change on same UID must be reported")
	}
}

func TestConflictingPatchFailsInsteadOfOverwriting(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", true))
	h.health.set(healthy(t0.Add(-time.Second)))
	stale := h.syncLister("n1")
	// Another actor adds a taint after the controller's cache was filled.
	cur := stale.DeepCopy()
	cur.Spec.Taints = append(cur.Spec.Taints, corev1.Taint{Key: "late", Effect: corev1.TaintEffectNoSchedule})
	cur.ResourceVersion = "2"
	if _, err := h.client.CoreV1().Nodes().Update(context.Background(), cur, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := h.ctrl.Reconcile(context.Background(), "n1")
	if err == nil || !strings.Contains(err.Error(), "test") {
		t.Fatalf("patch built from a stale node must fail its test op, got %v", err)
	}
	got, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	if !hasStartTaint(got) || len(got.Spec.Taints) != 4 {
		t.Fatalf("node must be unchanged: %v", got.Spec.Taints)
	}
}

func TestDeletedNodeIsForgotten(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", true))
	h.health.set(healthy(t0.Add(-time.Second)))
	h.reconcile("n1")
	n := h.syncLister("n1")
	if err := h.ctrl.factory.Core().V1().Nodes().Informer().GetIndexer().Delete(n); err != nil {
		t.Fatal(err)
	}
	requeue, err := h.ctrl.Reconcile(context.Background(), "n1")
	if err != nil || requeue {
		t.Fatalf("deleted node: requeue=%v err=%v", requeue, err)
	}
	if _, ok := h.ctrl.boots["n1"]; ok {
		t.Fatal("boot state must be dropped")
	}
}

func TestRunOnlyWatchesPoolNodes(t *testing.T) {
	pool := testNode("pool", "boot-1", true)
	foreign := testNode("foreign", "boot-1", false)
	delete(foreign.Labels, RoleLabel)
	client := fake.NewClientset(pool, foreign)
	hf := &fakeHealth{resp: healthy(t0.Add(-time.Second))}
	ctrl, err := New(client, hf, Config{
		Resync: 20 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return t0 }, StartedAt: processStart,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ctrl.Run(ctx, 1) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := client.CoreV1().Nodes().Get(context.Background(), "pool", metav1.GetOptions{})
		if !hasStartTaint(n) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n, _ := client.CoreV1().Nodes().Get(context.Background(), "pool", metav1.GetOptions{}); hasStartTaint(n) {
		t.Fatal("pool node taint was not removed")
	}
	if ctrl.ObservedState(15*time.Second) != "healthy" {
		t.Fatalf("observed state %s", ctrl.ObservedState(15*time.Second))
	}

	// Health turns bad: the periodic resync re-adds the taint without a Node event.
	hf.set(withNodeHold)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := client.CoreV1().Nodes().Get(context.Background(), "pool", metav1.GetOptions{})
		if hasStartTaint(n) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n, _ := client.CoreV1().Nodes().Get(context.Background(), "pool", metav1.GetOptions{}); !hasStartTaint(n) {
		t.Fatal("resync did not re-add the taint")
	}
	for _, a := range client.Actions() {
		if p, ok := a.(k8stesting.PatchAction); ok && p.GetName() == "foreign" {
			t.Fatal("non-pool node must not be patched")
		}
	}
}

func TestObservedState(t *testing.T) {
	h := newHarness(t)
	if s := h.ctrl.ObservedState(15 * time.Second); s != "unhealthy" {
		t.Fatalf("before sync: %s", s)
	}
	h.ctrl.cacheSynced.Store(true)
	if s := h.ctrl.ObservedState(15 * time.Second); s != "healthy" {
		t.Fatalf("synced: %s", s)
	}
	h.ctrl.lastErrUnix.Store(t0.Unix())
	if s := h.ctrl.ObservedState(15 * time.Second); s != "degraded" {
		t.Fatalf("recent error: %s", s)
	}
	h.now = t0.Add(16 * time.Second)
	if s := h.ctrl.ObservedState(15 * time.Second); s != "healthy" {
		t.Fatalf("old error: %s", s)
	}
}

type fakeReporter struct {
	mu     sync.Mutex
	leases []controlhealth.Lease
	err    error
}

func (f *fakeReporter) ReportLease(_ context.Context, l controlhealth.Lease) (*controlhealth.LeaseAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leases = append(f.leases, l)
	return &controlhealth.LeaseAck{LeaseUntil: l.LeaseUntil}, f.err
}

func TestLeaseReporter(t *testing.T) {
	r := &fakeReporter{err: errors.New("down")}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunLeaseReporter(ctx, r, LeaseConfig{
			SourceID: "node-readiness-0", Version: "v1", Interval: 10 * time.Millisecond, TTL: 15 * time.Second,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return t0 },
		}, func() string { return "healthy" })
		close(done)
	}()
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.leases) < 2 {
		t.Fatalf("want repeated reports despite errors, got %d", len(r.leases))
	}
	l := r.leases[0]
	if l.Component != "node-readiness" || l.Scope != "global" || l.ScopeID != "*" || l.SourceID != "node-readiness-0" ||
		l.ObservedState != "healthy" || !l.LeaseUntil.Equal(t0.Add(15*time.Second)) || !l.ReportedAt.Equal(t0) ||
		l.ActiveVersion == nil || *l.ActiveVersion != "v1" {
		t.Fatalf("lease %+v", l)
	}
}
