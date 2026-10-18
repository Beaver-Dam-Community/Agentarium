// Package podmeta resolves the exporter's include/exclude decision from the
// read-only Kubernetes Pod API of the exporter's own node (TASK-09 3.3:
// "node/Pod metadata is enriched from the read-only Kubernetes API"). It never trusts the
// Pod/container fields that Tetragon copied into the raw event.
package podmeta

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/normalize"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

type Config struct {
	NodeName string
	// Observed are the Namespaces whose events are kept (agent-exec,
	// agent-adapters). Events positively attributed elsewhere are excluded.
	Observed []string
	// Grace bounds how long an unmatched container prefix may wait for the
	// kubelet status update before it is recorded as unresolved.
	Grace time.Duration
	// Retain keeps deleted Pods resolvable for late-read events.
	Retain time.Duration
	// PodCIDRs are this node's Pod ranges (Node spec.podCIDRs). An endpoint in
	// them that no cached Pod owns may belong to a Pod whose IP the cache has
	// not seen yet, so it is never excluded.
	PodCIDRs []netip.Prefix
	Now      func() time.Time
}

type pod struct {
	uid, namespace string
	ips            []netip.Addr
	hostNetwork    bool
	deleted        time.Time
}

// Resolver implements normalize.Resolver. Feed it with Upsert/Delete from a
// node-scoped Pod informer and call MarkSynced after the initial LIST.
type Resolver struct {
	c          Config
	observed   map[string]bool
	mu         sync.Mutex
	changed    chan struct{}
	synced     bool
	pods       map[string]*pod   // Pod UID
	containers map[string]string // full containerd ID -> Pod UID
	statuses   map[string]status // full containerd ID -> kubelet status
}

type status struct {
	imageID string
	running bool
}

// Container is the kubelet-reported state of one container on this node, as
// read from the node-scoped Pod API. It is metadata, not kernel evidence.
type Container struct {
	PodUID, Namespace string
	// Observed is true when the Pod's Namespace is in the exporter filter.
	Observed bool
	Running  bool
	Deleted  bool
	// ImageID is ContainerStatus.imageID verbatim.
	ImageID string
}

func New(c Config) (*Resolver, error) {
	if c.NodeName == "" || len(c.Observed) == 0 || c.Grace <= 0 || c.Retain < c.Grace || len(c.PodCIDRs) == 0 {
		return nil, errors.New("pod metadata resolver requires node, observed namespaces, grace and retention")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	r := &Resolver{c: c, observed: map[string]bool{}, changed: make(chan struct{}), pods: map[string]*pod{}, containers: map[string]string{}, statuses: map[string]status{}}
	for _, ns := range c.Observed {
		if len(validation.IsDNS1123Label(ns)) != 0 {
			return nil, errors.New("invalid observed namespace")
		}
		r.observed[ns] = true
	}
	return r, nil
}

func (r *Resolver) notify() {
	close(r.changed)
	r.changed = make(chan struct{})
}

// containerID strips the CRI runtime scheme. Only containerd IDs are accepted
// because the pinned node image is COS_CONTAINERD.
func containerID(s string) (string, bool) {
	id, ok := strings.CutPrefix(s, "containerd://")
	if !ok || len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", false
	}
	return id, true
}

// Upsert records a Pod observed on this node. Pods on other nodes are ignored.
func (r *Resolver) Upsert(p *corev1.Pod) {
	if p == nil || p.Spec.NodeName != r.c.NodeName || p.UID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.pods[string(p.UID)]
	if entry == nil {
		entry = &pod{}
		r.pods[string(p.UID)] = entry
	}
	entry.uid, entry.namespace, entry.hostNetwork = string(p.UID), p.Namespace, p.Spec.HostNetwork
	// A hostNetwork Pod's IP is the node IP; it is kept so that sockets of an
	// observed hostNetwork Pod are never silently excluded.
	entry.ips = entry.ips[:0]
	for _, ip := range p.Status.PodIPs {
		if a, err := netip.ParseAddr(ip.IP); err == nil {
			entry.ips = append(entry.ips, a)
		}
	}
	for _, list := range [][]corev1.ContainerStatus{p.Status.InitContainerStatuses, p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses} {
		for _, s := range list {
			if id, ok := containerID(s.ContainerID); ok {
				r.containers[id] = entry.uid
				r.statuses[id] = status{imageID: s.ImageID, running: s.State.Running != nil}
			}
		}
	}
	r.notify()
}

// Delete keeps a tombstone for Retain so events read after Pod deletion still
// resolve to the original UID (TASK-09 3.2: "keep the original UID even after the Pod is deleted").
func (r *Resolver) Delete(p *corev1.Pod) {
	if p == nil {
		return
	}
	r.Upsert(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry := r.pods[string(p.UID)]; entry != nil && entry.deleted.IsZero() {
		entry.deleted = r.c.Now()
	}
	r.gc()
	r.notify()
}

func (r *Resolver) gc() {
	cutoff := r.c.Now().Add(-r.c.Retain)
	for uid, entry := range r.pods {
		if !entry.deleted.IsZero() && entry.deleted.Before(cutoff) {
			delete(r.pods, uid)
			for id, owner := range r.containers {
				if owner == uid {
					delete(r.containers, id)
					delete(r.statuses, id)
				}
			}
		}
	}
}

// Container returns the cached state of a full containerd ID. ok is false
// before the initial LIST or when the ID is not (yet) in any Pod status.
func (r *Resolver) Container(id string) (Container, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	uid, found := r.containers[id]
	if !r.synced || !found {
		return Container{}, false
	}
	entry, st := r.pods[uid], r.statuses[id]
	return Container{PodUID: uid, Namespace: entry.namespace, Observed: r.observed[entry.namespace], Running: st.running, Deleted: !entry.deleted.IsZero(), ImageID: st.imageID}, true
}

func (r *Resolver) MarkSynced() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.synced = true
	r.notify()
}

// Resolve blocks while the decision still depends on pending Pod API state.
// Returning Unknown would stop acquisition permanently, so waiting is bounded
// by Grace measured from the event's source time.
func (r *Resolver) Resolve(ctx context.Context, q normalize.Query) (normalize.Resolution, error) {
	for {
		res, final, wait := r.try(q)
		if final {
			return res, nil
		}
		select {
		case <-ctx.Done():
			return normalize.Resolution{}, ctx.Err()
		case <-wait:
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (r *Resolver) try(q normalize.Query) (normalize.Resolution, bool, <-chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.synced {
		return normalize.Resolution{}, false, r.changed
	}
	if q.EventType == "tcp_state" {
		return r.socket(q)
	}
	if q.DockerPrefix == "" {
		// Tetragon leaves docker empty only outside a container cgroup.
		return normalize.Resolution{Scope: normalize.Exclude}, true, nil
	}
	var match string
	matches := 0
	for id := range r.containers {
		if strings.HasPrefix(id, q.DockerPrefix) {
			match = id
			matches++
		}
	}
	if matches == 1 {
		entry := r.pods[r.containers[match]]
		if !r.observed[entry.namespace] {
			return normalize.Resolution{Scope: normalize.Exclude}, true, nil
		}
		return normalize.Resolution{Scope: normalize.Include, MetadataStatus: normalize.MetadataResolved, ContainerID: match, PodUID: entry.uid}, true, nil
	}
	if matches > 1 || !r.c.Now().Before(q.SourceTime.Add(r.c.Grace)) {
		// Sandbox (pause) containers and containers that exited before their
		// status was published never appear in Pod status. Keep the event.
		return normalize.Resolution{Scope: normalize.Include, MetadataStatus: normalize.MetadataUnresolved}, true, nil
	}
	return normalize.Resolution{}, false, r.changed
}

// socket decides a softirq tcp_state event from its tuple (r.mu held).
//   - an endpoint owned by an observed Pod: keep (socket status);
//   - an endpoint owned by an observed hostNetwork Pod (node IP): keep as
//     unresolved, because the node IP cannot attribute the socket;
//   - an endpoint inside this node's Pod CIDRs that no cached Pod owns: wait
//     up to Grace for the IP to appear, then keep as unresolved;
//   - otherwise every endpoint is positively owned by a non-observed Pod or is
//     outside this node's Pod ranges: exclude.
func (r *Resolver) socket(q normalize.Query) (normalize.Resolution, bool, <-chan struct{}) {
	if q.Socket == nil {
		return normalize.Resolution{Scope: normalize.Include, MetadataStatus: normalize.MetadataUnresolved}, true, nil
	}
	unknown, hostNetwork := false, false
	for _, text := range []string{q.Socket.SAddr, q.Socket.DAddr} {
		a, err := netip.ParseAddr(text)
		if err != nil {
			unknown = true
			continue
		}
		owned := false
		for _, entry := range r.pods {
			if !entry.deleted.IsZero() && entry.deleted.Before(q.SourceTime) {
				continue
			}
			for _, ip := range entry.ips {
				if ip != a {
					continue
				}
				owned = true
				if r.observed[entry.namespace] {
					if entry.hostNetwork {
						hostNetwork = true
						continue
					}
					return normalize.Resolution{Scope: normalize.Include, MetadataStatus: normalize.MetadataTupleScoped}, true, nil
				}
			}
		}
		if !owned {
			for _, prefix := range r.c.PodCIDRs {
				if prefix.Contains(a) {
					unknown = true
				}
			}
		}
	}
	if hostNetwork {
		return normalize.Resolution{Scope: normalize.Include, MetadataStatus: normalize.MetadataUnresolved}, true, nil
	}
	if !unknown {
		return normalize.Resolution{Scope: normalize.Exclude}, true, nil
	}
	if r.c.Now().Before(q.SourceTime.Add(r.c.Grace)) {
		return normalize.Resolution{}, false, r.changed
	}
	return normalize.Resolution{Scope: normalize.Include, MetadataStatus: normalize.MetadataUnresolved}, true, nil
}

var _ normalize.Resolver = (*Resolver)(nil)
