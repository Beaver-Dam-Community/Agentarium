package revoker

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type fakeStore struct {
	mu        sync.Mutex
	unrevoked []PodRef
	revoked   []string
	listed    chan struct{} // receives once per UnrevokedPods call, if set
}

func (f *fakeStore) RevokePod(_ context.Context, uid string, _ time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, uid)
	return 1, nil
}

func (f *fakeStore) UnrevokedPods(context.Context, time.Time) ([]PodRef, error) {
	if f.listed != nil {
		f.listed <- struct{}{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.unrevoked), nil
}

func (f *fakeStore) revokedUIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.revoked)
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestReconcileRevokesOnlyMissingPods(t *testing.T) {
	st := &fakeStore{unrevoked: []PodRef{{"agent-exec", "live-1"}, {"agent-exec", "gone-1"}, {"agent-adapters", "gone-2"}}}
	r := &Revoker{Store: st, Log: discard(), Namespaces: []string{"agent-exec", "agent-adapters"}}
	if err := r.Reconcile(context.Background(), map[string]bool{"live-1": true}); err != nil {
		t.Fatal(err)
	}
	if got := st.revokedUIDs(); !slices.Equal(got, []string{"gone-1", "gone-2"}) {
		t.Fatalf("revoked = %v", got)
	}
}

func TestReconcileSkipsUnwatchedNamespace(t *testing.T) {
	// "elsewhere-1" is not live as far as the informers know, but its
	// namespace is not watched, so it must not be revoked.
	st := &fakeStore{unrevoked: []PodRef{{"agent-exec", "gone-1"}, {"agent-other", "elsewhere-1"}}}
	r := &Revoker{Store: st, Log: discard(), Namespaces: []string{"agent-exec"}}
	if err := r.Reconcile(context.Background(), map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if got := st.revokedUIDs(); !slices.Equal(got, []string{"gone-1"}) {
		t.Fatalf("revoked = %v", got)
	}
}

func parseFlag(args ...string) ([]string, error) {
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var l NamespaceList
	fs.Var(&l, "pod-namespaces", "")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return l, ValidateNamespaces(l)
}

func TestNamespaceFlag(t *testing.T) {
	got, err := parseFlag("--pod-namespaces=agent-exec,agent-control", "--pod-namespaces", "agent-adapters")
	if err != nil || !slices.Equal(got, []string{"agent-exec", "agent-control", "agent-adapters"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for name, args := range map[string][]string{
		"none":             nil,
		"empty value":      {"--pod-namespaces="},
		"empty entry":      {"--pod-namespaces=agent-exec,,agent-control"},
		"trailing comma":   {"--pod-namespaces=agent-exec,"},
		"whitespace entry": {"--pod-namespaces=agent-exec, "},
		"padded entry":     {"--pod-namespaces=agent-exec, agent-control"},
		"duplicate":        {"--pod-namespaces=agent-exec,agent-exec"},
		"duplicate flag":   {"--pod-namespaces=agent-exec", "--pod-namespaces=agent-exec"},
		"not a name":       {"--pod-namespaces=Agent_Exec"},
	} {
		if _, err := parseFlag(args...); err == nil {
			t.Errorf("%s: accepted %v", name, args)
		}
	}
}

func TestRunRejectsNoNamespaces(t *testing.T) {
	r := &Revoker{Client: fake.NewClientset(), Store: &fakeStore{}, Log: discard()}
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("Run without namespaces succeeded")
	}
}

func pod(ns, name, uid string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid)}}
}

// rbacClient returns a fake clientset that, like the TASK-06 RBAC, allows
// pods list and watch only inside the given namespaces. A cluster-wide or
// other-namespace request is Forbidden, so an informer making one never syncs.
func rbacClient(t *testing.T, allowed []string, objs ...runtime.Object) *fake.Clientset {
	t.Helper()
	cs := fake.NewClientset(objs...)
	forbidden := func(a k8stesting.Action) error {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", nil)
	}
	cs.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if !slices.Contains(allowed, a.GetNamespace()) {
			return true, nil, forbidden(a)
		}
		return false, nil, nil
	})
	cs.PrependWatchReactor("pods", func(a k8stesting.Action) (bool, watch.Interface, error) {
		if !slices.Contains(allowed, a.GetNamespace()) {
			return true, nil, forbidden(a)
		}
		return false, nil, nil
	})
	return cs
}

func TestRunReconcilesOnlyAfterEveryNamespaceSynced(t *testing.T) {
	watched := []string{"agent-exec", "agent-adapters"}
	cs := rbacClient(t, watched,
		pod("agent-exec", "runtime", "live-exec"),
		pod("agent-adapters", "probe", "live-adapters"),
		pod("agent-other", "x", "live-other"),
	)
	// Hold the agent-adapters list until released.
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	cs.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() == "agent-adapters" {
			<-release
		}
		return false, nil, nil
	})
	st := &fakeStore{
		listed: make(chan struct{}, 16),
		unrevoked: []PodRef{
			{"agent-exec", "live-exec"},
			{"agent-exec", "gone-exec"},
			{"agent-adapters", "live-adapters"},
			{"agent-adapters", "gone-adapters"},
			{"agent-other", "live-other"},
			{"agent-other", "gone-other"},
		},
	}
	r := &Revoker{Client: cs, Store: st, Log: discard(), Namespaces: watched, Resync: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	select {
	case <-st.listed:
		t.Fatal("reconcile ran before the agent-adapters informer synced")
	case <-time.After(200 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	select {
	case <-st.listed:
	case <-time.After(5 * time.Second):
		t.Fatal("no reconcile after every informer synced")
	}
	// Reconcile revokes right after listing; wait for it to finish.
	deadline := time.Now().Add(5 * time.Second)
	for len(st.revokedUIDs()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	got := st.revokedUIDs()
	slices.Sort(got)
	if !slices.Equal(got, []string{"gone-adapters", "gone-exec"}) {
		t.Fatalf("revoked = %v", got)
	}
}

func TestRunRevokesOnDeleteInEveryNamespace(t *testing.T) {
	watched := []string{"agent-exec", "agent-adapters"}
	cs := rbacClient(t, watched,
		pod("agent-exec", "runtime", "uid-exec"),
		pod("agent-adapters", "probe", "uid-adapters"),
	)
	// Open the tracker watch here and only then report it, so the deletes
	// below cannot happen before the watch exists.
	watching := make(chan string, 16)
	cs.PrependWatchReactor("pods", func(a k8stesting.Action) (bool, watch.Interface, error) {
		wa, ok := a.(k8stesting.WatchActionImpl)
		if !ok || !slices.Contains(watched, a.GetNamespace()) {
			return false, nil, nil
		}
		w, err := cs.Tracker().Watch(a.GetResource(), a.GetNamespace(), wa.ListOptions)
		if err == nil {
			watching <- a.GetNamespace()
		}
		return true, w, err
	})
	st := &fakeStore{listed: make(chan struct{}, 16)}
	r := &Revoker{Client: cs, Store: st, Log: discard(), Namespaces: watched, Resync: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	// With Resync of an hour, only the delete handlers can revoke below.
	seen := map[string]bool{}
	for len(seen) < len(watched) {
		select {
		case ns := <-watching:
			seen[ns] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("watches started: %v", seen)
		}
	}
	select {
	case <-st.listed:
	case <-time.After(5 * time.Second):
		t.Fatal("no initial reconcile")
	}
	for _, p := range []struct{ ns, name string }{{"agent-exec", "runtime"}, {"agent-adapters", "probe"}} {
		if err := cs.CoreV1().Pods(p.ns).Delete(ctx, p.name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(st.revokedUIDs()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := st.revokedUIDs()
	slices.Sort(got)
	if !slices.Equal(got, []string{"uid-adapters", "uid-exec"}) {
		t.Fatalf("revoked = %v", got)
	}
}

func TestRunDoesNotReconcileWhenANamespaceCannotBeListed(t *testing.T) {
	// agent-adapters is configured but the RBAC does not cover it: its
	// informer never syncs, so nothing is revoked (fail safe).
	cs := rbacClient(t, []string{"agent-exec"}, pod("agent-exec", "runtime", "live-exec"))
	st := &fakeStore{listed: make(chan struct{}, 16), unrevoked: []PodRef{{"agent-exec", "gone-exec"}}}
	r := &Revoker{Client: cs, Store: st, Log: discard(), Namespaces: []string{"agent-exec", "agent-adapters"}, Resync: time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := r.Run(ctx); err == nil {
		t.Fatal("Run returned nil before its caches synced")
	}
	select {
	case <-st.listed:
		t.Fatal("reconcile ran without every informer synced")
	default:
	}
	if got := st.revokedUIDs(); len(got) != 0 {
		t.Fatalf("revoked = %v", got)
	}
}
