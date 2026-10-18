// Package watcher drives typed Kubernetes LIST/WATCH through durable lifecycle
// WAL and checkpoint delivery. It requires explicit normalization and gap sinks.
package watcher

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/delivery"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/watch"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	watchtools "k8s.io/client-go/tools/watch"
)

var errRelist = errors.New("watch history expired; relist before reporting the gap")

// Gap is an internal adapter input, not a newly invented HTTP wire object.
// GapSink must durably record this observation before returning nil. Unknown
// event loss is not converted into a fabricated sequence range or count.
type Gap struct {
	Scope, LastCommittedResourceVersion, Reason string
	// Epoch is this producer's watcher epoch.
	Epoch string
	// LastCommittedAt is a lower bound of the last committed checkpoint time
	// (TASK-07 committed_at, or the time the cursor request was sent), or the
	// producer start when nothing was committed. It never overstates coverage.
	LastCommittedAt time.Time
	DetectedAt      time.Time
}
type Config struct {
	Directory, Namespace, ClusterUID string
	Core                             coreclient.CoreV1Interface
	Collector                        *batch.Client
	Normalize                        func(context.Context, PodEvent) ([]Facts, error)
	GapSink                          func(context.Context, Gap) error
	PageSize                         int64
	Capacity                         int64
}
type Producer struct {
	config      Config
	identity    *epochLease
	journal     *wal.Journal
	pump        *delivery.Pump
	committed   string
	committedAt time.Time
	started     time.Time
	// expired is set by a watch 410; the gap is reported after the relist
	// completes and before its cursor is committed (TASK-10 3.6, #178).
	expired *Gap
}

func validUUID(s string) bool { id, err := uuid.Parse(s); return err == nil && id.String() == s }
func Open(c Config) (*Producer, error) {
	if c.Directory == "" || len(validation.IsDNS1123Label(c.Namespace)) != 0 || !validUUID(c.ClusterUID) || c.Core == nil || c.Collector == nil || c.Normalize == nil || c.GapSink == nil {
		return nil, errors.New("watcher requires namespace, trusted cluster UID, clients, normalizer and durable gap sink")
	}
	if c.PageSize == 0 {
		c.PageSize = 100
	}
	if c.PageSize < 1 || c.PageSize > 1000 {
		return nil, errors.New("invalid LIST page size")
	}
	scope := "namespace/" + c.Namespace
	identity, err := openEpoch(c.Directory, scope, c.ClusterUID)
	if err != nil {
		return nil, err
	}
	journal, err := wal.Open(filepath.Join(c.Directory, "wal"), identity.epoch, c.Capacity)
	if err != nil {
		identity.close()
		return nil, err
	}
	pump, err := delivery.New(delivery.Config{Journal: journal, Client: c.Collector, SourceID: batch.PodWatcherSource, Stream: batch.Lifecycle, WatchScope: scope, RecoveryReason: "wal_segment_corrupt"})
	if err != nil {
		journal.Close()
		identity.close()
		return nil, err
	}
	return &Producer{config: c, identity: identity, journal: journal, pump: pump, started: time.Now().UTC()}, nil
}
func (p *Producer) Close() error {
	e := p.journal.Close()
	other := p.identity.close()
	if e != nil {
		return e
	}
	return other
}
func retryable(err error) bool {
	var status *batch.HTTPError
	if errors.As(err, &status) {
		return status.Retryable()
	}
	var protocol *batch.ProtocolError
	if errors.As(err, &protocol) {
		return false
	}
	var network net.Error
	return errors.As(err, &network)
}
func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (p *Producer) drain(ctx context.Context) error {
	delay := time.Second
	for {
		result, err := p.pump.Flush(ctx)
		if err != nil {
			if !retryable(err) {
				return err
			}
			if err = wait(ctx, delay); err != nil {
				return err
			}
			delay = min(delay*2, 30*time.Second)
			continue
		}
		if result.Idle {
			return nil
		}
		if result.Acked == 0 && result.Quarantined == 0 {
			window, err := p.journal.Next(batch.MaxRecords, batch.MaxBytes)
			if err != nil {
				return err
			}
			if window.Epoch != "" {
				if err = wait(ctx, delay); err != nil {
					return err
				}
				delay = min(delay*2, 30*time.Second)
			}
		} else {
			delay = time.Second
		}
	}
}

// resumeCheckpoint retries only transport/server failures. Authentication and
// protocol errors retain their fail-closed behavior and never reach Kubernetes.
func (p *Producer) resumeCheckpoint(ctx context.Context) (*batch.CheckpointResult, error) {
	delay := time.Second
	for {
		checkpoint, err := p.pump.ResumeCheckpoint(ctx)
		if err == nil || !retryable(err) {
			return checkpoint, err
		}
		if err := wait(ctx, delay); err != nil {
			return nil, err
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func (p *Producer) commitCursor(ctx context.Context, rv string) error {
	if rv == "" || rv == "0" {
		return errors.New("empty/initial resourceVersion cannot be committed")
	}
	if err := p.drain(ctx); err != nil {
		return err
	}
	queuedAt := time.Now().UTC()
	if err := p.pump.QueueCursor(rv); err != nil {
		return err
	}
	if err := p.drain(ctx); err != nil {
		return err
	}
	p.committed, p.committedAt = rv, queuedAt
	return nil
}
func (p *Producer) observe(ctx context.Context, event PodEvent) error {
	if err := p.enqueue(ctx, event); err != nil {
		return err
	}
	return p.drain(ctx)
}

// enqueue persists facts without a per-Pod upload. LIST drains at page boundaries;
// WATCH still uses observe so its event cannot advance before delivery is durable.
func (p *Producer) enqueue(ctx context.Context, event PodEvent) error {
	pod := event.Pod
	if pod == nil || pod.Namespace != p.config.Namespace || !validUUID(string(pod.UID)) || pod.Name == "" || pod.ResourceVersion == "" {
		return errors.New("invalid Pod identity or scope")
	}
	facts, err := p.config.Normalize(ctx, PodEvent{Pod: pod.DeepCopy(), Type: event.Type, Snapshot: event.Snapshot})
	if err != nil {
		return err
	}
	if len(facts) == 0 || len(facts) > 100 {
		return errors.New("normalizer must produce a bounded nonempty set of facts")
	}
	for _, fact := range facts {
		build, err := prepareRecord(fact, p.config.ClusterUID, batch.PodWatcherSource, pod)
		if err != nil {
			return err
		}
		_, err = p.journal.Append(build, wal.Checkpoint{})
		if errors.Is(err, wal.ErrFull) {
			// Append refuses capacity before reserving a sequence. Drain once and
			// retry this exact fact only if ACK cleanup actually freed space.
			// An oversized fact or retained quarantine must not spin forever.
			before, _ := p.journal.Usage()
			if before == 0 {
				return err
			}
			if err := p.drain(ctx); err != nil {
				return err
			}
			after, _ := p.journal.Usage()
			if after >= before {
				return wal.ErrFull
			}
			_, err = p.journal.Append(build, wal.Checkpoint{})
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// list commits only the LIST snapshot RV after the final page and every record.
// Item RVs do not advance the snapshot cursor. A failed/inconsistent page leaves
// the current checkpoint unchanged; already durable records remain replayable.
func (p *Producer) list(ctx context.Context) (string, error) {
	options := metav1.ListOptions{Limit: p.config.PageSize}
	snapshot := ""
	seen := map[string]bool{}
	delay := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		page, err := p.config.Core.Pods(p.config.Namespace).List(ctx, options)
		if err != nil {
			expired := apierrors.IsGone(err) || apierrors.IsResourceExpired(err)
			transient := apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsTooManyRequests(err) || apierrors.IsServiceUnavailable(err) || apierrors.IsInternalError(err) || retryable(err)
			if !expired && !transient {
				return "", err
			}
			if expired {
				// Discard only the incomplete pagination state. Already durable
				// observations survive, while no partial snapshot cursor commits.
				options.Continue = ""
				snapshot = ""
				seen = map[string]bool{}
			}
			if err := wait(ctx, delay); err != nil {
				return "", err
			}
			delay = min(delay*2, 30*time.Second)
			continue
		}
		delay = time.Second
		if page.ResourceVersion == "" || page.ResourceVersion == "0" {
			return "", errors.New("LIST missing usable snapshot resourceVersion")
		}
		if snapshot == "" {
			snapshot = page.ResourceVersion
		} else if snapshot != page.ResourceVersion {
			return "", errors.New("LIST snapshot changed between pages")
		}
		for i := range page.Items {
			if err = p.enqueue(ctx, PodEvent{Pod: &page.Items[i], Type: watch.Added, Snapshot: true}); err != nil {
				return "", err
			}
		}
		if err = p.drain(ctx); err != nil {
			return "", err
		}
		if page.Continue == "" {
			break
		}
		if seen[page.Continue] {
			return "", errors.New("LIST repeated continuation token")
		}
		seen[page.Continue] = true
		options.Continue = page.Continue
	}
	if p.expired != nil {
		// The lost window ends when the relist has been read and sent.
		gap := *p.expired
		gap.DetectedAt = time.Now().UTC()
		if gap.LastCommittedAt.After(gap.DetectedAt) {
			gap.LastCommittedAt = gap.DetectedAt // server and watcher clocks differ
		}
		if err := p.config.GapSink(ctx, gap); err != nil {
			return "", err
		}
		p.expired = nil
	}
	return snapshot, p.commitCursor(ctx, snapshot)
}

// markExpired remembers a watch-history loss; list reports it.
func (p *Producer) markExpired() {
	if p.expired != nil {
		return // the earlier detection already covers the window
	}
	since := p.committedAt
	if since.IsZero() {
		since = p.started
	}
	p.expired = &Gap{Scope: "namespace/" + p.config.Namespace, LastCommittedResourceVersion: p.committed, Reason: "WATCH_HISTORY_EXPIRED", Epoch: p.identity.epoch, LastCommittedAt: since}
}

// Run is a single producer loop. A missing/failed adapter cannot silently skip a
// fact or relist over unknown history. Stop with context cancellation then Close.
func (p *Producer) Run(ctx context.Context) error {
	forceList := false
	for {
		if err := p.drain(ctx); err != nil && !errors.Is(err, delivery.ErrCheckpointRefresh) {
			return err
		}
		cp, err := p.resumeCheckpoint(ctx)
		if err != nil {
			return err
		}
		p.committed, p.committedAt = "", time.Time{}
		if cp != nil {
			p.committed = cp.ResourceVersion
			if t, err := time.Parse(time.RFC3339Nano, cp.CommittedAt); err == nil {
				p.committedAt = t.UTC()
			}
		}
		rv := p.committed
		if forceList || rv == "" {
			rv, err = p.list(ctx)
			if errors.Is(err, delivery.ErrCheckpointRefresh) {
				forceList = false
				continue
			}
			if err != nil {
				return err
			}
		}
		forceList = false
		err = p.watch(ctx, rv)
		if errors.Is(err, errRelist) {
			forceList = true
			continue
		}
		if errors.Is(err, delivery.ErrCheckpointRefresh) {
			continue
		}
		return err
	}
}

type watchClient struct {
	workers  sync.WaitGroup
	producer *Producer
	fail     chan error
	cancel   context.CancelFunc
}

func (w *watchClient) WatchWithContext(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
	raw, err := w.producer.config.Core.Pods(w.producer.config.Namespace).Watch(ctx, options)
	if apierrors.IsGone(err) || apierrors.IsResourceExpired(err) {
		// RetryWatcher retries initial HTTP410 forever; the stream Error410 path
		// instead terminates and reaches the producer's mandatory durable gap sink.
		status := apierrors.NewResourceExpired("watch history expired").ErrStatus
		status.Code = http.StatusGone
		ch := make(chan watch.Event, 1)
		ch <- watch.Event{Type: watch.Error, Object: &status}
		close(ch)
		return watch.NewProxyWatcher(ch), nil
	}
	if err != nil {
		return nil, err
	}
	out := make(chan watch.Event)
	wrapped := watch.NewProxyWatcher(out)
	w.workers.Add(1)
	go func() {
		defer w.workers.Done()
		defer close(out)
		defer raw.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-wrapped.StopChan():
				return
			case event, ok := <-raw.ResultChan():
				if !ok {
					return
				}
				var err error
				switch event.Type {
				case watch.Added, watch.Modified, watch.Deleted:
					pod, ok := event.Object.(*corev1.Pod)
					if !ok {
						err = errors.New("watch event is not a Pod")
						break
					}
					if err = w.producer.observe(ctx, PodEvent{Pod: pod, Type: event.Type}); err == nil {
						err = w.producer.commitCursor(ctx, pod.ResourceVersion)
					}
				case watch.Bookmark:
					metadata, ok := event.Object.(metav1.Object)
					if !ok {
						err = errors.New("bookmark lacks metadata")
						break
					}
					err = w.producer.commitCursor(ctx, metadata.GetResourceVersion())
				case watch.Error: // Preserve only typed status, never log arbitrary raw objects.
					if _, ok := event.Object.(*metav1.Status); !ok {
						err = errors.New("watch error is not a Status")
					}
				default:
					err = errors.New("unsupported watch event")
				}
				if err != nil {
					select {
					case w.fail <- err:
					default:
					}
					w.cancel()
					return
				}
				select {
				case out <- event:
				case <-ctx.Done():
					return
				case <-wrapped.StopChan():
					return
				}
				if event.Type == watch.Error {
					return
				}
			}
		}
	}()
	return wrapped, nil
}
func (p *Producer) watch(ctx context.Context, rv string) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	failure := make(chan error, 1)
	client := &watchClient{producer: p, fail: failure, cancel: cancel}
	retry, err := watchtools.NewRetryWatcherWithContext(child, rv, client)
	if err != nil {
		return err
	}
	defer func() { cancel(); retry.Stop(); <-retry.Done(); client.workers.Wait() }()
	for {
		select {
		case err := <-failure:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-retry.ResultChan():
			if !ok {
				select {
				case err := <-failure:
					return err
				default:
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return errors.New("RetryWatcher stopped without a recoverable status")
			}
			if event.Type == watch.Error {
				err := apierrors.FromObject(event.Object)
				if apierrors.IsGone(err) || apierrors.IsResourceExpired(err) {
					p.markExpired()
					return errRelist
				}
				return errors.New("Kubernetes watch failed")
			}
		}
	}
}
