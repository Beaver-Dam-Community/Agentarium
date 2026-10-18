package controller

import (
	"context"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	k8stesting "k8s.io/client-go/testing"
)

const leaseTTL = 15 * time.Second

func forbidden() error {
	return apierrors.NewForbidden(schema.GroupResource{Resource: "nodes"}, "n1",
		errDenied("ValidatingAdmissionPolicy 'node-readiness-scope' denied request: NODE_READINESS_SCOPE_INVALID"))
}

func invalid() error {
	return apierrors.NewInvalid(schema.GroupKind{Kind: "Node"}, "n1",
		field.ErrorList{field.Invalid(field.NewPath(""), "", "NODE_READINESS_SCOPE_INVALID")})
}

type errDenied string

func (e errDenied) Error() string { return string(e) }

// denyPatches makes every node patch fail with err and counts the attempts.
func denyPatches(h *harness, err error) *int {
	calls := 0
	h.client.PrependReactor("patch", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		return true, nil, err
	})
	return &calls
}

// leavePool removes the protected role label in the API and drops the node
// from the informer cache, as the label-selected watch would.
func leavePool(t *testing.T, h *harness, name string) {
	t.Helper()
	n, err := h.client.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	delete(n.Labels, RoleLabel)
	if _, err := h.client.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := h.ctrl.factory.Core().V1().Nodes().Informer().GetIndexer().Delete(n); err != nil {
		t.Fatal(err)
	}
}

func processOnce(t *testing.T, h *harness, key string) {
	t.Helper()
	h.ctrl.queue.Add(key)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !h.ctrl.processNext(ctx) {
		t.Fatal("queue shut down")
	}
}

// A node that left the pool selector cannot get the start taint back through
// node-readiness-scope; the denial is recorded and the key settles, so the
// controller keeps renewing its lease (PR #13 review).
func TestDeniedReaddForNodeOutsidePoolSettles(t *testing.T) {
	for name, err := range map[string]error{"forbidden": forbidden(), "invalid": invalid()} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, testNode("n1", "boot-1", false))
			h.ctrl.cacheSynced.Store(true)
			leavePool(t, h, "n1")
			calls := denyPatches(h, err)

			processOnce(t, h, "n1")

			if *calls != 1 {
				t.Fatalf("patch attempts = %d, want 1", *calls)
			}
			if h.ctrl.queue.NumRequeues("n1") != 0 || h.ctrl.queue.Len() != 0 {
				t.Fatalf("key must not be requeued (requeues %d, len %d)", h.ctrl.queue.NumRequeues("n1"), h.ctrl.queue.Len())
			}
			if h.ctrl.unsettledLongerThan(0) {
				t.Fatal("key must be settled")
			}
			if s := h.ctrl.ObservedState(leaseTTL); s != "degraded" {
				t.Fatalf("state right after the denial = %s, want degraded", s)
			}
			h.now = h.now.Add(2 * leaseTTL)
			if s := h.ctrl.ObservedState(leaseTTL); s != "healthy" {
				t.Fatalf("state after the lease TTL = %s, want healthy (lease keeps renewing)", s)
			}
		})
	}
}

// The same denial for a node still in the pool (the cache only lags) is a
// real failure: it is retried and keeps the key unsettled, as before.
func TestDeniedReaddForNodeInPoolIsRetried(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", false))
	h.ctrl.cacheSynced.Store(true)
	// Gone from the cache, but the API object still carries the pool label.
	n, _ := h.client.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	if err := h.ctrl.factory.Core().V1().Nodes().Informer().GetIndexer().Delete(n); err != nil {
		t.Fatal(err)
	}
	calls := denyPatches(h, forbidden())

	processOnce(t, h, "n1")

	if *calls != 1 || h.ctrl.queue.NumRequeues("n1") != 1 {
		t.Fatalf("in-pool denial must be retried (calls %d, requeues %d)", *calls, h.ctrl.queue.NumRequeues("n1"))
	}
	h.now = h.now.Add(2 * leaseTTL)
	if s := h.ctrl.ObservedState(leaseTTL); s != "unhealthy" {
		t.Fatalf("state = %s, want unhealthy while an in-pool node stays unsettled", s)
	}
}

// A denial on the normal reconcile path (node in the cache) is unchanged.
func TestDeniedTaintOnPoolNodeIsRetried(t *testing.T) {
	h := newHarness(t, testNode("n1", "boot-1", false))
	h.ctrl.cacheSynced.Store(true)
	h.health.set(withNodeHold)
	calls := denyPatches(h, forbidden())

	processOnce(t, h, "n1")

	if *calls < 1 || h.ctrl.queue.NumRequeues("n1") != 1 || !h.ctrl.unsettledLongerThan(-time.Nanosecond) {
		t.Fatalf("pool node denial must stay unsettled and be retried (calls %d, requeues %d)", *calls, h.ctrl.queue.NumRequeues("n1"))
	}
}
