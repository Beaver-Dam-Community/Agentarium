// Package revoker records revoked_at for Pod-bound certificates when the Pod
// is deleted (TASK-03 3.3.1: DevOps tier CAS cannot revoke, so the gateway and
// coordinator check issued_certificates.revoked_at instead).
//
// SPEC-QUESTION: TASK-03 3.3.2 gives the identity KSA pods/nodes get and
// watch only. A client-go informer also needs list, and without an initial
// list a restart would miss Pods deleted while the service was down. This
// package therefore needs pods list+watch (PR description, TASK-06 RBAC).
//
// The Pod permissions are namespaced (one Role per namespace in the TASK-06
// RBAC), so the revoker runs one Pod informer per configured namespace and
// never lists or watches Pods cluster-wide. It reads no Nodes.
package revoker

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// PodRef is a Pod that still holds unexpired, unrevoked certificates.
type PodRef struct {
	Namespace string
	UID       string
}

// Store is the issued_certificates access the revoker needs.
type Store interface {
	RevokePod(ctx context.Context, podUID string, at time.Time) (int64, error)
	UnrevokedPods(ctx context.Context, now time.Time) ([]PodRef, error)
}

// Revoker watches Pods and revokes certificates of deleted ones.
type Revoker struct {
	Client kubernetes.Interface
	Store  Store
	Log    *slog.Logger
	Now    func() time.Time
	// Namespaces are the namespaces whose Pods are watched. The list must be
	// the complete set of namespaces in which Pod-bound certificates can be
	// issued (the namespaces of the pods Roles in the TASK-06 RBAC).
	// Reconcile compares the unrevoked Pod UIDs with the union of these
	// informer caches and treats a missing UID as a deleted Pod. Matching
	// on UID alone would revoke the live Pods of any namespace left out of
	// the list, so Reconcile instead skips (and logs) certificates whose
	// namespace is not listed. The cost of an incomplete list is therefore
	// that such certificates are not revoked when their Pod is deleted and
	// only expire. See ValidateNamespaces for the accepted values.
	Namespaces []string
	// Resync is how often a full reconciliation runs. It also retries any
	// revocation that failed on the delete event. Default 1 minute.
	Resync time.Duration
}

// NamespaceList is a flag.Value for the watched namespaces. The flag may be
// repeated and each value may hold a comma-separated list. Entries are kept
// as given; ValidateNamespaces checks them after parsing.
type NamespaceList []string

var _ flag.Value = (*NamespaceList)(nil)

func (l *NamespaceList) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, ",")
}

func (l *NamespaceList) Set(v string) error {
	*l = append(*l, strings.Split(v, ",")...)
	return nil
}

// ValidateNamespaces rejects an empty list, an empty or whitespace entry, an
// entry that is not a namespace name (DNS-1123 label) and a duplicate.
func ValidateNamespaces(ns []string) error {
	if len(ns) == 0 {
		return errors.New("no pod namespaces configured")
	}
	seen := make(map[string]bool, len(ns))
	for i, n := range ns {
		if strings.TrimSpace(n) == "" {
			return fmt.Errorf("pod namespace %d is empty", i)
		}
		if errs := validation.IsDNS1123Label(n); len(errs) > 0 {
			return fmt.Errorf("pod namespace %q: %s", n, strings.Join(errs, "; "))
		}
		if seen[n] {
			return fmt.Errorf("pod namespace %q is listed twice", n)
		}
		seen[n] = true
	}
	return nil
}

func (r *Revoker) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile revokes every unrevoked certificate whose Pod UID is not in live,
// for Pods in a watched namespace only. live must be the union of all
// namespace informer caches. It runs once all caches have synced, to cover
// deletions missed while the service was not watching, and then periodically.
func (r *Revoker) Reconcile(ctx context.Context, live map[string]bool) error {
	watched := make(map[string]bool, len(r.Namespaces))
	for _, ns := range r.Namespaces {
		watched[ns] = true
	}
	pods, err := r.Store.UnrevokedPods(ctx, r.now())
	if err != nil {
		return err
	}
	for _, p := range pods {
		if !watched[p.Namespace] {
			// Fail safe: without an informer for the namespace a live Pod
			// looks deleted. Issuance needs pods get in that namespace, so
			// this only happens if the list and the RBAC drift apart.
			r.Log.Warn("certificate of a pod in an unwatched namespace left unrevoked", "namespace", p.Namespace, "pod_uid", p.UID)
			continue
		}
		if live[p.UID] {
			continue
		}
		if _, err := r.Store.RevokePod(ctx, p.UID, r.now()); err != nil {
			return err
		}
		r.Log.Info("revoked certificates of a pod deleted while not watching", "namespace", p.Namespace, "pod_uid", p.UID)
	}
	return nil
}

func (r *Revoker) onDelete(ctx context.Context) func(obj any) {
	return func(obj any) {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			tomb, ok := obj.(cache.DeletedFinalStateUnknown)
			if !ok {
				return
			}
			if pod, ok = tomb.Obj.(*corev1.Pod); !ok {
				return
			}
		}
		// A failed revoke is not lost: the Pod is gone from the informer
		// cache, so the next periodic Reconcile revokes it again.
		if n, err := r.Store.RevokePod(ctx, string(pod.UID), r.now()); err != nil {
			r.Log.Error("revoke on pod delete failed; reconcile will retry", "namespace", pod.Namespace, "pod_uid", pod.UID, "err", err)
		} else if n > 0 {
			r.Log.Info("revoked certificates of deleted pod", "namespace", pod.Namespace, "pod_uid", pod.UID, "count", n)
		}
	}
}

// Run starts one Pod informer per namespace, reconciles once every cache is
// synced and then revokes on every delete event until ctx ends.
func (r *Revoker) Run(ctx context.Context) error {
	if err := ValidateNamespaces(r.Namespaces); err != nil {
		return err
	}
	infs := make([]cache.SharedIndexInformer, 0, len(r.Namespaces))
	synced := make([]cache.InformerSynced, 0, len(r.Namespaces))
	for _, ns := range r.Namespaces {
		factory := informers.NewSharedInformerFactoryWithOptions(r.Client, 0, informers.WithNamespace(ns))
		inf := factory.Core().V1().Pods().Informer()
		if _, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{DeleteFunc: r.onDelete(ctx)}); err != nil {
			return err
		}
		factory.Start(ctx.Done())
		infs = append(infs, inf)
		synced = append(synced, inf.HasSynced)
	}
	// Reconciling before every cache is synced would revoke live Pods of
	// the namespaces not yet listed.
	if !cache.WaitForCacheSync(ctx.Done(), synced...) {
		return ctx.Err()
	}
	resync := r.Resync
	if resync <= 0 {
		resync = time.Minute
	}
	for {
		live := map[string]bool{}
		for _, inf := range infs {
			for _, obj := range inf.GetStore().List() {
				if pod, ok := obj.(*corev1.Pod); ok {
					live[string(pod.UID)] = true
				}
			}
		}
		if err := r.Reconcile(ctx, live); err != nil {
			r.Log.Error("revocation reconcile failed; retrying", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(resync):
		}
	}
}
