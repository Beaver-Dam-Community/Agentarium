// Package controller removes and re-adds the start taint on exec/control
// pool nodes from TASK-10 control-health evidence (TASK-01 3.5).
package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/Beaver-Dam-Community/Agentarium/services/node-readiness/internal/controlhealth"
	"github.com/Beaver-Dam-Community/Agentarium/services/node-readiness/internal/readiness"
)

const (
	FieldManager = "node-readiness"
	// RoleLabel is the protected pool label; only exec and control pool nodes
	// carry the start taint (TASK-01 3.1, 4 lock table).
	RoleLabel    = "node-restriction.kubernetes.io/agentarium-role"
	NodeSelector = RoleLabel + " in (exec,control)"
)

// poolSelector is NodeSelector parsed; it is a constant expression.
var poolSelector = func() labels.Selector {
	s, err := labels.Parse(NodeSelector)
	if err != nil {
		panic(err)
	}
	return s
}()

func inPool(n *corev1.Node) bool { return poolSelector.Matches(labels.Set(n.Labels)) }

// HealthQuerier is the control-health node query.
type HealthQuerier interface {
	NodeHealth(ctx context.Context, nodeUID string) (*controlhealth.NodeHealth, error)
}

type Config struct {
	// Resync is how often each node is re-evaluated without a Node event, so
	// lease expiry and new holds re-add the taint. Defaults to the 5s heartbeat.
	Resync time.Duration
	// QueryTimeout bounds one control-health query.
	QueryTimeout time.Duration
	Logger       *slog.Logger
	Now          func() time.Time
	// StartedAt is the process start. Boot state is in memory only, so a boot
	// change while the controller was down cannot be seen; every node is
	// treated as boot-unknown from StartedAt. Defaults to Now() in New.
	StartedAt time.Time
	// MaxRetryDelay caps the per-node error backoff so a failing taint patch
	// is retried within the lease TTL window. Defaults to 10s.
	MaxRetryDelay time.Duration
	// ReconcileTimeout bounds one reconcile including API server calls, so a
	// hung request cannot hold a node key forever. Defaults to 3*QueryTimeout.
	ReconcileTimeout time.Duration
}

type bootState struct {
	uid       types.UID
	bootID    string
	changedAt time.Time
}

// rvRef identifies one cached version of a node object.
type rvRef struct {
	uid types.UID
	rv  string
}

type Controller struct {
	client  kubernetes.Interface
	factory informers.SharedInformerFactory
	lister  corelisters.NodeLister
	synced  cache.InformerSynced
	queue   workqueue.TypedRateLimitingInterface[string]
	health  HealthQuerier
	cfg     Config
	log     *slog.Logger

	mu    sync.Mutex
	boots map[string]bootState
	// initial holds the nodes listed at the initial cache sync; only those
	// are vouched for from StartedAt (see trackBoot).
	initial map[string]types.UID
	// removedFrom is the cached version a start taint removal was patched
	// from, until the cache shows a different version.
	removedFrom map[string]rvRef
	// unsettled is when a node key started going without a successful
	// reconcile (in flight or failing).
	unsettled map[string]time.Time

	cacheSynced atomic.Bool
	lastErrUnix atomic.Int64
}

func New(client kubernetes.Interface, health HealthQuerier, cfg Config) (*Controller, error) {
	if cfg.Resync <= 0 {
		cfg.Resync = 5 * time.Second
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.StartedAt.IsZero() {
		cfg.StartedAt = cfg.Now()
	}
	if cfg.MaxRetryDelay <= 0 {
		cfg.MaxRetryDelay = 10 * time.Second
	}
	if cfg.ReconcileTimeout <= 0 {
		cfg.ReconcileTimeout = 3 * cfg.QueryTimeout
	}
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = NodeSelector }))
	nodes := factory.Core().V1().Nodes()

	c := &Controller{
		client:  client,
		factory: factory,
		lister:  nodes.Lister(),
		synced:  nodes.Informer().HasSynced,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](100*time.Millisecond, cfg.MaxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "node-readiness"}),
		health:      health,
		cfg:         cfg,
		log:         cfg.Logger,
		boots:       map[string]bootState{},
		removedFrom: map[string]rvRef{},
		unsettled:   map[string]time.Time{},
	}
	_, err := nodes.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.enqueue,
		UpdateFunc: func(_, obj any) { c.enqueue(obj) },
		DeleteFunc: c.enqueue,
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Controller) enqueue(obj any) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.queue.Add(key)
}

// Run blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context, workers int) error {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	c.factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.synced) {
		return errors.New("node-readiness: node informer cache did not sync")
	}
	c.recordInitialNodes()
	c.cacheSynced.Store(true)
	c.log.Info("node informer synced", "selector", NodeSelector)

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}
	<-ctx.Done()
	return nil
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNext(ctx) {
	}
}

func (c *Controller) processNext(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	c.markUnsettled(key)
	rctx, cancel := context.WithTimeout(ctx, c.cfg.ReconcileTimeout)
	requeue, err := c.Reconcile(rctx, key)
	cancel()
	if err != nil {
		c.lastErrUnix.Store(c.cfg.Now().Unix())
		c.log.Error("reconcile failed", "node", key, "err", err)
		c.queue.AddRateLimited(key)
		return true
	}
	c.markSettled(key)
	c.queue.Forget(key)
	if requeue {
		c.queue.AddAfter(key, c.cfg.Resync)
	}
	return true
}

// Reconcile evaluates one node and adds or removes only the start taint.
// It returns whether the node should be re-evaluated after Resync.
func (c *Controller) Reconcile(ctx context.Context, name string) (bool, error) {
	node, err := c.lister.Get(name)
	if apierrors.IsNotFound(err) {
		return false, c.handleGone(ctx, name)
	}
	if err != nil {
		return false, err
	}

	cacheBehind := c.cacheBehindRemoval(node)
	bootID := node.Status.NodeInfo.BootID
	notBefore, changed := c.trackBoot(name, node.UID, bootID)
	if changed {
		c.log.Info("boot ID changed; re-adding start taint", "node", name, "boot_id", bootID)
		if err := c.ensureStartTaint(ctx, node, cacheBehind); err != nil {
			return false, err
		}
		// The current boot cannot be ready yet (notBefore is now); evaluate
		// on the next pass from a cache that includes the taint.
		return true, nil
	}

	var dec readiness.Decision
	qctx, cancel := context.WithTimeout(ctx, c.cfg.QueryTimeout)
	h, qerr := c.health.NodeHealth(qctx, string(node.UID))
	cancel()
	if qerr != nil {
		// SPEC-QUESTION: an unreachable control-health is treated as not ready
		// (TASK-10 chapter 5 "if the verification service fails, the default is hold").
		c.lastErrUnix.Store(c.cfg.Now().Unix())
		c.log.Warn("control-health query failed; node treated as not ready", "node", name, "err", qerr)
		dec = readiness.Decision{Reasons: []string{"control_health_unavailable"}}
	} else {
		dec = readiness.Evaluate(readiness.Input{
			NodeUID:         string(node.UID),
			BootID:          bootID,
			Health:          h,
			Now:             c.cfg.Now(),
			ProbesNotBefore: notBefore,
		})
	}

	had := hasStartTaint(node)
	if !dec.Ready {
		if err := c.ensureStartTaint(ctx, node, cacheBehind); err != nil {
			return false, err
		}
		if !had {
			c.log.Info("start taint re-added", "node", name, "node_uid", node.UID, "reasons", dec.Reasons)
		}
		return true, nil
	}
	if cacheBehind {
		// This controller already removed the taint from this version; the
		// cache has not caught up. Nothing to remove.
		return true, nil
	}
	if _, err := c.setStartTaint(ctx, node, false); err != nil {
		return false, err
	}
	if had {
		c.noteRemoval(node)
		c.log.Info("start taint removed", "node", name, "node_uid", node.UID, "boot_id", bootID)
	}
	return true, nil
}

// ensureStartTaint makes sure the node carries the start taint. Adding is the
// fail-closed direction, so it does not depend on the informer cache being
// current: when the cache may predate this controller's own removal
// (cacheBehind), or a patch built from the cache fails, the node is re-read
// from the API server and the patch is rebuilt from that copy.
func (c *Controller) ensureStartTaint(ctx context.Context, node *corev1.Node, cacheBehind bool) error {
	if hasStartTaint(node) && !cacheBehind {
		return nil
	}
	if !hasStartTaint(node) {
		_, err := c.setStartTaint(ctx, node, true)
		if err == nil {
			return nil
		}
		c.log.Warn("start taint patch from cache failed; retrying from the API server", "node", node.Name, "err", err)
	}
	live, err := c.client.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", node.Name, err)
	}
	_, err = c.setStartTaint(ctx, live, true)
	return err
}

// noteRemoval records the cached version a removal was patched from.
func (c *Controller) noteRemoval(node *corev1.Node) {
	c.mu.Lock()
	c.removedFrom[node.Name] = rvRef{uid: node.UID, rv: node.ResourceVersion}
	c.mu.Unlock()
}

// cacheBehindRemoval reports whether the cached node is still the version this
// controller removed the start taint from, i.e. the watch has not delivered
// the removal yet. A different cached version drops the record.
func (c *Controller) cacheBehindRemoval(node *corev1.Node) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ref, ok := c.removedFrom[node.Name]
	if !ok {
		return false
	}
	if ref.uid == node.UID && ref.rv == node.ResourceVersion {
		return true
	}
	delete(c.removedFrom, node.Name)
	return false
}

// recordInitialNodes snapshots the nodes in the cache right after the initial
// sync. Run calls it before starting workers.
func (c *Controller) recordInitialNodes() {
	nodes, err := c.lister.List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initial = make(map[string]types.UID, len(nodes))
	for _, n := range nodes {
		c.initial[n.Name] = n.UID
	}
}

func (c *Controller) markUnsettled(key string) {
	c.mu.Lock()
	if _, ok := c.unsettled[key]; !ok {
		c.unsettled[key] = c.cfg.Now()
	}
	c.mu.Unlock()
}

func (c *Controller) markSettled(key string) {
	c.mu.Lock()
	delete(c.unsettled, key)
	c.mu.Unlock()
}

// unsettledLongerThan reports whether any node key has gone without a
// successful reconcile for longer than d.
func (c *Controller) unsettledLongerThan(d time.Duration) bool {
	now := c.cfg.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, since := range c.unsettled {
		if now.Sub(since) > d {
			return true
		}
	}
	return false
}

// trackBoot records the node's boot ID and returns the earliest time the
// controller can vouch for the current boot: max(StartedAt, observed boot
// change). changed is true when a previously seen non-empty boot ID of the
// same Node object was replaced. A node listed at the initial sync is
// boot-unknown from StartedAt. Any other first sight (a node added later,
// labelled into the pool later, back after leaving it, or a new UID under
// the same name) is boot-unknown from now, because it may have rebooted
// unobserved after StartedAt.
func (c *Controller) trackBoot(name string, uid types.UID, bootID string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, seen := c.boots[name]
	if !seen || prev.uid != uid {
		at := c.cfg.StartedAt
		if c.initial[name] != uid {
			if now := c.cfg.Now(); now.After(at) {
				at = now
			}
		}
		delete(c.initial, name)
		c.boots[name] = bootState{uid: uid, bootID: bootID, changedAt: at}
		return at, false
	}
	if prev.bootID == bootID {
		return prev.changedAt, false
	}
	st := bootState{uid: uid, bootID: bootID, changedAt: c.cfg.Now()}
	if st.changedAt.Before(c.cfg.StartedAt) {
		st.changedAt = c.cfg.StartedAt
	}
	c.boots[name] = st
	return st.changedAt, prev.bootID != ""
}

// handleGone runs when a node is no longer in the informer cache. If it still
// exists it has left the pool label selector; the start taint is re-added so
// a node the controller may have untainted does not stay schedulable
// unmanaged. Only the start taint is patched.
func (c *Controller) handleGone(ctx context.Context, name string) error {
	defer c.forgetNode(name)
	node, err := c.client.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		c.log.Info("node removed", "node", name)
		return nil
	}
	if err != nil {
		return fmt.Errorf("get node %s that left the cache: %w", name, err)
	}
	if hasStartTaint(node) {
		return nil
	}
	c.log.Warn("node left the pool selector; re-adding start taint", "node", name, "labels", node.Labels)
	_, err = c.setStartTaint(ctx, node, true)
	if err != nil && !inPool(node) && (apierrors.IsInvalid(err) || apierrors.IsForbidden(err)) {
		// node-readiness-scope (TASK-01 3.2.1) admits only Nodes whose current
		// role label is exec or control, so this patch is always denied for a
		// Node that left the selector. Retrying would keep the key unsettled
		// past the lease TTL and stop lease renewal (global lease_expired hold,
		// TASK-10), so the denial is recorded as a recent error (degraded) and
		// the key is settled. A denial for a Node still in the pool (cache lag)
		// is returned and retried as before.
		c.lastErrUnix.Store(c.cfg.Now().Unix())
		c.log.Error("start taint re-add denied for a node outside the pool selector",
			"node", name, "labels", node.Labels, "err", err)
		return nil
	}
	return err
}

func (c *Controller) forgetNode(name string) {
	c.mu.Lock()
	delete(c.boots, name)
	delete(c.initial, name)
	delete(c.removedFrom, name)
	c.mu.Unlock()
}

func (c *Controller) setStartTaint(ctx context.Context, node *corev1.Node, want bool) (*corev1.Node, error) {
	patch, err := startTaintPatch(node, want)
	if err != nil || patch == nil {
		return node, err
	}
	updated, err := c.client.CoreV1().Nodes().Patch(ctx, node.Name, types.JSONPatchType, patch,
		metav1.PatchOptions{FieldManager: FieldManager})
	if err != nil {
		return nil, fmt.Errorf("patch start taint on %s: %w", node.Name, err)
	}
	return updated, nil
}

// ObservedState is the node-readiness lease state: unhealthy before the
// informer syncs or while any node has gone without a successful reconcile
// (stuck in flight or failing) for longer than the lease TTL, degraded if a
// reconcile or query failed within the lease TTL, healthy otherwise. An
// unhealthy controller does not renew its lease (RunLeaseReporter).
func (c *Controller) ObservedState(ttl time.Duration) string {
	if !c.cacheSynced.Load() || c.unsettledLongerThan(ttl) {
		return "unhealthy"
	}
	if last := c.lastErrUnix.Load(); last != 0 && c.cfg.Now().Sub(time.Unix(last, 0)) < ttl {
		return "degraded"
	}
	return "healthy"
}
