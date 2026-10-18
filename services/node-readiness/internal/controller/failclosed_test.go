package controller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// A node that leaves the pool selector is forgotten. If it reboots while
// outside the pool and comes back, its boot change was never observed, so
// probe passes judged before it re-entered must not remove the taint.
func TestNodeReenteringPoolIsBootUnknownFromReentry(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", true))
	h.health.set(healthy(t0.Add(-time.Second)))
	if n := h.reconcile("n1"); hasStartTaint(n) {
		t.Fatal("expected ready")
	}

	n, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	delete(n.Labels, RoleLabel)
	if _, err := h.client.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := h.ctrl.factory.Core().V1().Nodes().Informer().GetIndexer().Delete(n); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ctrl.Reconcile(context.Background(), "n1"); err != nil {
		t.Fatal(err)
	}

	// Rebooted while unwatched, then the pool label is restored.
	n, _ = h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	n.Labels[RoleLabel] = "exec"
	n.Status.NodeInfo.BootID = "boot-2"
	if _, err := h.client.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.now = t0.Add(time.Minute)
	h.health.set(withFreshLeases(t0, h.now.Add(15*time.Second))) // judged before re-entry
	if n := h.reconcile("n1"); !hasStartTaint(n) {
		t.Fatal("probes judged before the node re-entered the pool must not remove the taint")
	}
}

// A node first seen after the initial sync (new node, or label added later)
// may have rebooted after process start without the controller seeing it.
func TestNodeAddedAfterSyncIsBootUnknownFromFirstSight(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.CoreV1().Nodes().Create(context.Background(), testNode("n1", "boot-1", false), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.health.set(healthy(t0.Add(-time.Second))) // judged after StartedAt+margin, before first sight
	n := h.reconcile("n1")
	if !hasStartTaint(n) {
		t.Fatal("probes judged before the node was first seen must not keep it untainted")
	}
	want := append(append([]corev1.Taint{}, otherTaints...), startTaint)
	if !reflect.DeepEqual(n.Spec.Taints, want) {
		t.Fatalf("start taint must be appended only: %v", n.Spec.Taints)
	}
}

// Adding the taint is the fail-closed direction; a cache that lags the API
// server (here: an unrelated status update not yet delivered by the watch)
// must not keep a not-ready node untainted.
func TestStaleCacheDoesNotBlockReaddingTaint(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", false))
	h.health.set(withNodeHold)
	cur, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	cur.ResourceVersion = "2"
	cur.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
	if _, err := h.client.CoreV1().Nodes().UpdateStatus(context.Background(), cur, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	before, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	h.client.ClearActions()
	if _, err := h.ctrl.Reconcile(context.Background(), "n1"); err != nil {
		t.Fatalf("re-adding the taint must not fail on a stale cache: %v", err)
	}
	after, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	if !hasStartTaint(after) {
		t.Fatal("start taint must be re-added")
	}
	assertScopeValid(t, before, after)
	assertOnlyTaintPatches(t, h.client.Actions())
}

// The controller's own removal may not be in the cache yet. A not-ready
// decision taken from that cache must not trust its "already tainted" view.
func TestOwnRemovalNotYetInCacheIsReverted(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", true))
	h.health.set(healthy(t0.Add(-time.Second)))
	if _, err := h.ctrl.Reconcile(context.Background(), "n1"); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{}); hasStartTaint(n) {
		t.Fatal("expected removal")
	}
	// The watch has not delivered the removal; the cache still shows the taint.
	h.health.set(withNodeHold)
	h.client.ClearActions()
	if _, err := h.ctrl.Reconcile(context.Background(), "n1"); err != nil {
		t.Fatal(err)
	}
	n, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	if !hasStartTaint(n) {
		t.Fatal("node hold must re-add the taint even though the cache still shows it")
	}
	assertOnlyTaintPatches(t, h.client.Actions())
}

// A node whose taint cannot be enforced for longer than the lease TTL makes
// the controller unhealthy, even while errors keep it "degraded".
func TestObservedStateUnhealthyWhenNodeStaysUnreconciled(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", false))
	h.health.set(unavailable)
	h.ctrl.cacheSynced.Store(true)
	h.client.PrependReactor("patch", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	h.ctrl.queue.Add("n1")
	h.ctrl.processNext(context.Background())
	h.now = t0.Add(10 * time.Second)
	h.ctrl.processNext(context.Background())
	h.now = t0.Add(16 * time.Second)
	if s := h.ctrl.ObservedState(15 * time.Second); s != "unhealthy" {
		t.Fatalf("taint not enforceable for >TTL: state %s, want unhealthy", s)
	}
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// A worker stuck inside a reconcile must not leave the lease healthy.
func TestObservedStateUnhealthyWhileReconcileStuck(t *testing.T) {
	clk := &testClock{t: t0}
	client := fake.NewClientset(testNode("n1", "boot-1", false))
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	client.PrependReactor("patch", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return false, nil, nil
	})
	ctrl, err := New(client, &fakeHealth{resp: unavailable}, Config{
		Resync: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: clk.Now, StartedAt: processStart,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctrl.cacheSynced.Store(true)
	loadNode(t, client, ctrl, "n1")
	ctrl.queue.Add("n1")
	done := make(chan struct{})
	go func() { ctrl.processNext(context.Background()); close(done) }()
	<-entered
	if s := ctrl.ObservedState(15 * time.Second); s == "unhealthy" {
		t.Fatalf("in-flight reconcile within TTL: state %s", s)
	}
	clk.Add(16 * time.Second)
	if s := ctrl.ObservedState(15 * time.Second); s != "unhealthy" {
		t.Fatalf("reconcile stuck >TTL: state %s, want unhealthy", s)
	}
	close(release)
	<-done
	if s := ctrl.ObservedState(15 * time.Second); s != "healthy" {
		t.Fatalf("after the reconcile completed: state %s", s)
	}
}

// An unhealthy controller cannot vouch for taint state, so it lets its lease
// expire (TASK-10: node-readiness lease expiry places a global lease_expired hold).
func TestLeaseNotRenewedWhileUnhealthy(t *testing.T) {
	r := &fakeReporter{}
	var mu sync.Mutex
	state := "unhealthy"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunLeaseReporter(ctx, r, LeaseConfig{
			SourceID: "node-readiness-0", Interval: 5 * time.Millisecond, TTL: 15 * time.Second,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return t0 },
		}, func() string { mu.Lock(); defer mu.Unlock(); return state })
		close(done)
	}()
	time.Sleep(40 * time.Millisecond)
	r.mu.Lock()
	n := len(r.leases)
	r.mu.Unlock()
	if n != 0 {
		t.Fatalf("unhealthy controller renewed its lease %d times", n)
	}
	mu.Lock()
	state = "degraded"
	mu.Unlock()
	time.Sleep(40 * time.Millisecond)
	cancel()
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.leases) == 0 || r.leases[0].ObservedState != "degraded" {
		t.Fatalf("degraded controller must keep reporting: %+v", r.leases)
	}
}
