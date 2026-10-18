package recorder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/delivery"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	eventtypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/types"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// SourceSAN is the runtime lifecycle source (COMMON Lifecycle source table).
const SourceSAN = "spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder"

// MappingVersion of the runtime mapping (TASK-09 3.6, PR #207).
const MappingVersion = 1

// MissingReason for records with an unfilled optional runtime field.
const MissingReason = "runtime_metadata_partial"

// Gap is a RUNTIME_RECORD_MISSING interval: the subscription was not
// receiving events between Start and End.
type Gap struct {
	Epoch, NodeUID, BootID string
	Start, End             time.Time
}

type Config struct {
	Directory  string
	ClusterUID string
	NodeUID    string
	BootID     string
	Epoch      string // runtime epoch: node 32hex + boot SHA-256 64hex + instance 32hex
	Source     Source
	Collector  *batch.Client
	GapSink    func(context.Context, Gap) error
	CgroupRoot string // read-only host /sys/fs/cgroup mount
	Capacity   int64
	Now        func() time.Time
}

// Status is the lease input: subscription state and last event time.
type Status struct {
	Subscribed bool
	LastEvent  time.Time
	Failed     bool
}

type Recorder struct {
	c       Config
	journal *wal.Journal
	pump    *delivery.Pump
	started time.Time
	mu      sync.Mutex
	status  Status
}

const stateFile = "recorder-state.json"

func validUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u != uuid.Nil && u.String() == s
}

func Open(c Config) (*Recorder, error) {
	if c.Directory == "" || !validUUID(c.ClusterUID) || !validUUID(c.NodeUID) || c.BootID == "" || c.Epoch == "" || c.Source == nil || c.Collector == nil || c.GapSink == nil || c.CgroupRoot == "" {
		return nil, errors.New("recorder requires spool, identity, epoch, source, collector, gap sink and cgroup root")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if err := os.MkdirAll(c.Directory, 0o700); err != nil {
		return nil, err
	}
	j, err := wal.Open(filepath.Join(c.Directory, "wal"), c.Epoch, c.Capacity)
	if err != nil {
		return nil, err
	}
	pump, err := delivery.New(delivery.Config{Journal: j, Client: c.Collector, SourceID: SourceSAN, Stream: batch.Lifecycle, RecoveryReason: "wal_segment_corrupt"})
	if err != nil {
		j.Close()
		return nil, err
	}
	r := &Recorder{c: c, journal: j, pump: pump, started: c.Now().UTC()}
	if t, err := r.loadLastEvent(); err == nil {
		r.status.LastEvent = t
	} else if !os.IsNotExist(err) {
		j.Close()
		return nil, err
	}
	return r, nil
}

func (r *Recorder) Close() error { return r.journal.Close() }

// Journal exposes the spool for health sampling.
func (r *Recorder) Journal() *wal.Journal { return r.journal }

func (r *Recorder) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

func (r *Recorder) loadLastEvent() (time.Time, error) {
	b, err := os.ReadFile(filepath.Join(r.c.Directory, stateFile))
	if err != nil {
		return time.Time{}, err
	}
	var s struct {
		LastEvent time.Time `json:"last_event_at"`
		NodeUID   string    `json:"node_uid"`
	}
	if err := json.Unmarshal(b, &s); err != nil || s.LastEvent.IsZero() {
		return time.Time{}, errors.New("invalid recorder state")
	}
	if s.NodeUID != "" && s.NodeUID != r.c.NodeUID {
		return time.Time{}, nil
	}
	// Older state files did not bind the node. A retained pending gap can
	// still establish that the spool came from a different node.
	if s.NodeUID == "" {
		if b, err := os.ReadFile(filepath.Join(r.c.Directory, pendingGapFile)); err == nil {
			var pending GapRequest
			if json.Unmarshal(b, &pending) == nil && pending.Gap.NodeUID != "" && pending.Gap.NodeUID != r.c.NodeUID {
				return time.Time{}, nil
			}
		}
	}
	return s.LastEvent, nil
}

// saveLastEvent durably records the time of the last processed event so a
// restart can bound the RUNTIME_RECORD_MISSING gap.
func (r *Recorder) saveLastEvent(t time.Time) error {
	b, _ := json.Marshal(map[string]any{"last_event_at": t.UTC(), "node_uid": r.c.NodeUID})
	f, err := os.CreateTemp(r.c.Directory, stateFile+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(r.c.Directory, stateFile)); err != nil {
		return err
	}
	d, err := os.Open(r.c.Directory)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// record is the LifecycleRecord wire object (COMMON); optional nil fields are
// omitted, received_at is server-owned.
type record struct {
	ID                  string            `json:"lifecycle_event_id"`
	SourceID            string            `json:"source_id"`
	Epoch               string            `json:"source_epoch"`
	Sequence            uint64            `json:"source_sequence"`
	ClusterUID          string            `json:"cluster_uid"`
	PodUID              string            `json:"pod_uid"`
	Namespace           string            `json:"namespace"`
	PodName             string            `json:"pod_name"`
	NodeUID             *string           `json:"node_uid,omitempty"`
	BootID              *string           `json:"boot_id,omitempty"`
	ContainerID         *string           `json:"container_id,omitempty"`
	CgroupsPath         *string           `json:"cgroups_path,omitempty"`
	CgroupInode         *int64            `json:"cgroup_inode,omitempty"`
	ContainerName       *string           `json:"container_name,omitempty"`
	RestartInstance     *int32            `json:"restart_instance,omitempty"`
	ImageID             *string           `json:"image_id,omitempty"`
	ImageManifestDigest *string           `json:"image_manifest_digest,omitempty"`
	Transition          string            `json:"transition"`
	SourceTime          *string           `json:"source_time,omitempty"`
	MappingVersion      int32             `json:"mapping_version"`
	EvidenceRefs        []json.RawMessage `json:"evidence_refs"`
	MissingReason       *string           `json:"missing_reason,omitempty"`
	Digest              string            `json:"record_digest,omitempty"`
}

func str(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// CgroupDir converts an OCI cgroupsPath to its cgroup v2 directory under
// root. The systemd form "slice:prefix:id" expands nested slices
// ("a-b.slice" -> "a.slice/a-b.slice") and the scope "prefix-id.scope"
// (TASK-09 3.6; the exact GKE rule is a Q0 item).
func CgroupDir(root, cgroupsPath string) (string, error) {
	if strings.HasPrefix(cgroupsPath, "/") {
		return filepath.Join(root, filepath.Clean(cgroupsPath)), nil
	}
	parts := strings.Split(cgroupsPath, ":")
	if len(parts) != 3 || !strings.HasSuffix(parts[0], ".slice") || parts[1] == "" || parts[2] == "" || strings.ContainsAny(cgroupsPath, "/\\") {
		return "", errors.New("unsupported cgroupsPath")
	}
	name := strings.TrimSuffix(parts[0], ".slice")
	var dirs []string
	acc := ""
	for _, seg := range strings.Split(name, "-") {
		if seg == "" {
			return "", errors.New("invalid slice name")
		}
		if acc == "" {
			acc = seg
		} else {
			acc += "-" + seg
		}
		dirs = append(dirs, acc+".slice")
	}
	dirs = append(dirs, parts[1]+"-"+parts[2]+".scope")
	return filepath.Join(append([]string{root}, dirs...)...), nil
}

func (r *Recorder) inode(cgroupsPath string) *int64 {
	dir, err := CgroupDir(r.c.CgroupRoot, cgroupsPath)
	if err != nil {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	n := int64(st.Ino)
	return &n
}

// build turns one container fact into a WAL record builder.
func (r *Recorder) build(ctx context.Context, c Container, transition string, at *time.Time) (func(string, uint64) ([]byte, error), bool, error) {
	if !validUUID(c.PodUID) || c.PodNamespace == "" || c.PodName == "" {
		return nil, false, nil // not a Pod container: not recorded
	}
	rec := record{SourceID: SourceSAN, ClusterUID: r.c.ClusterUID, PodUID: c.PodUID, Namespace: c.PodNamespace, PodName: c.PodName,
		NodeUID: str(r.c.NodeUID), BootID: str(r.c.BootID), ContainerID: str(c.ID), ContainerName: str(c.ContainerName), RestartInstance: c.RestartCount,
		Transition: transition, MappingVersion: MappingVersion, EvidenceRefs: []json.RawMessage{}}
	if at != nil {
		rec.SourceTime = str(at.UTC().Format(time.RFC3339Nano))
	}
	if transition == "container_created" || transition == "container_present" {
		rec.CgroupsPath = str(c.CgroupsPath)
		rec.CgroupInode = r.inode(c.CgroupsPath)
		if !c.Sandbox {
			if id, err := r.c.Source.ImageID(ctx, c.ID); err == nil {
				rec.ImageID = &id
			}
		}
	}
	// image_manifest_digest is never filled by the recorder (it comes from
	// Admission/watcher records, #207), so every runtime record carries
	// runtime_metadata_partial; the null fields show what is missing.
	m := MissingReason
	rec.MissingReason = &m
	return func(epoch string, seq uint64) ([]byte, error) {
		out := rec
		id, err := canonical.LifecycleEventID(SourceSAN, epoch, int64(seq))
		if err != nil {
			return nil, err
		}
		out.ID, out.Epoch, out.Sequence = id, epoch, seq
		raw, err := canonical.CanonicalJSON(out)
		if err != nil {
			return nil, err
		}
		out.Digest, err = canonical.DigestWithoutKeys(raw, "record_digest", "received_at")
		if err != nil {
			return nil, err
		}
		return canonical.CanonicalJSON(out)
	}, true, nil
}

func (r *Recorder) append(ctx context.Context, c Container, transition string, at *time.Time) error {
	b, ok, err := r.build(ctx, c, transition, at)
	if err != nil || !ok {
		return err
	}
	_, err = r.journal.Append(b, wal.Checkpoint{})
	return err
}

// handle maps one task event (TASK-09 3.6 mapping table).
func (r *Recorder) handle(ctx context.Context, env *types.Envelope, onGapRetry ...func()) error {
	if env.GetNamespace() != Namespace || env.GetEvent() == nil {
		return nil
	}
	msg, err := anypb.UnmarshalNew(env.GetEvent(), proto.UnmarshalOptions{})
	if err != nil {
		return fmt.Errorf("undecodable %s event: %w", env.GetTopic(), err)
	}
	var id, transition string
	switch e := msg.(type) {
	case *eventtypes.TaskCreate:
		id, transition = e.GetContainerID(), "container_created"
	case *eventtypes.TaskStart:
		id, transition = e.GetContainerID(), "container_started"
	case *eventtypes.TaskExit:
		if e.GetID() != e.GetContainerID() {
			return nil // exec process inside the container, not the init task
		}
		id, transition = e.GetContainerID(), "container_exited"
	case *eventtypes.TaskDelete:
		if e.GetID() != "" && e.GetID() != e.GetContainerID() {
			return nil
		}
		id, transition = e.GetContainerID(), "container_deleted"
	default:
		return nil // other task topics (OOM, exec, pause) are not lifecycle records
	}
	at := r.c.Now().UTC()
	if ts := env.GetTimestamp(); ts != nil {
		at = ts.AsTime()
	}
	c, err := r.c.Source.Container(ctx, id)
	if err != nil {
		if transition == "container_deleted" {
			return nil // the record is gone after delete; nothing trustworthy to map
		}
		if status.Code(err) == codes.NotFound {
			// TASK-09 3.6: the container record vanished (for example a
			// container that failed and was removed at once). Its Pod cannot
			// be identified, so the event becomes a one-instant gap.
			return r.reportGap(ctx, Gap{Epoch: r.c.Epoch, NodeUID: r.c.NodeUID, BootID: r.c.BootID, Start: at, End: at}, onGapRetry...)
		}
		return &resubscribeError{fmt.Errorf("container %s record unavailable: %w", id, err)}
	}
	if err := r.append(ctx, c, transition, &at); err != nil {
		return err
	}
	return r.markEvent(at)
}

// resubscribeError is a lookup failure handled like a broken stream: the
// recorder resubscribes, reconciles and reports the gap.
type resubscribeError struct{ err error }

func (e *resubscribeError) Error() string { return e.err.Error() }
func (e *resubscribeError) Unwrap() error { return e.err }

// reportGap retries the gap sink until it acknowledges, the context ends, or
// it refuses permanently.
func (r *Recorder) reportGap(ctx context.Context, gap Gap, onRetry ...func()) error {
	delay := time.Second
	interrupted := false
	for {
		err := r.c.GapSink(ctx, gap)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			if interrupted {
				return &resubscribeError{errors.New("gap acknowledged after subscription interrupted")}
			}
			return nil
		}
		var permanent interface{ Permanent() bool }
		if errors.As(err, &permanent) && permanent.Permanent() {
			return err
		}
		if !interrupted && len(onRetry) > 0 {
			// Stop an unread subscription before waiting on control-health. Once
			// the durable gap is acknowledged, reconcile a new subscription to
			// cover the interruption instead of trusting a buffered stream.
			for _, f := range onRetry {
				f()
			}
			interrupted = true
		}
		if werr := wait(ctx, delay); werr != nil {
			return werr
		}
		delay = min(2*delay, 30*time.Second)
	}
}

func (r *Recorder) markEvent(at time.Time) error {
	r.mu.Lock()
	r.status.LastEvent = at
	r.mu.Unlock()
	return r.saveLastEvent(at)
}

// reconcile records every Pod container present at (re)subscription and
// returns the RUNTIME_RECORD_MISSING interval that ends now.
func (r *Recorder) reconcile(ctx context.Context) (Gap, error) {
	list, err := r.c.Source.Containers(ctx)
	if err != nil {
		return Gap{}, err
	}
	for _, c := range list {
		if err := r.append(ctx, c, "container_present", nil); err != nil {
			return Gap{}, err
		}
	}
	r.mu.Lock()
	start := r.status.LastEvent
	r.mu.Unlock()
	if start.IsZero() {
		start = r.started
	}
	end := r.c.Now().UTC()
	if start.After(end) {
		start = end
	}
	return Gap{Epoch: r.c.Epoch, NodeUID: r.c.NodeUID, BootID: r.c.BootID, Start: start, End: end}, nil
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run subscribes, reconciles, reports the gap, then follows events until the
// stream breaks; a broken stream repeats the cycle. Delivery runs alongside.
func (r *Recorder) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	delivered := make(chan error, 1)
	var deliveryErr error
	var deliveryDone bool
	go func() { delivered <- r.pump.Run(ctx) }()
	join := func() {
		if !deliveryDone {
			deliveryErr, deliveryDone = <-delivered, true
		}
	}
	fail := func(err error) error {
		r.mu.Lock()
		r.status.Subscribed, r.status.Failed = false, true
		r.mu.Unlock()
		cancel()
		join()
		return err
	}
	delay := time.Second
	for {
		if ctx.Err() != nil {
			join()
			return ctx.Err()
		}
		// Subscribe before listing so nothing between them is missed.
		streamCtx, stopStream := context.WithCancel(ctx)
		interruptStream := func() {
			stopStream()
			r.mu.Lock()
			r.status.Subscribed = false
			r.mu.Unlock()
		}
		next, err := r.c.Source.Subscribe(streamCtx)
		if err == nil {
			var gap Gap
			if gap, err = r.reconcile(ctx); err == nil {
				// The reconcile is complete only once the gap is durable.
				if err = r.reportGap(ctx, gap, interruptStream); err != nil && ctx.Err() == nil {
					var resub *resubscribeError
					if !errors.As(err, &resub) {
						return fail(err)
					}
				}
				if err == nil {
					if err = r.markEvent(gap.End); err != nil {
						return fail(err)
					}
				}
			}
		}
		if err != nil {
			stopStream()
			if ctx.Err() != nil {
				continue
			}
			if errors.Is(err, wal.ErrFull) {
				return fail(err)
			}
			if err := wait(ctx, delay); err != nil {
				continue
			}
			delay = min(2*delay, 30*time.Second)
			continue
		}
		delay = time.Second
		r.mu.Lock()
		r.status.Subscribed = true
		r.mu.Unlock()
		for {
			env, err := next()
			if err != nil {
				break // stream broken: resubscribe, reconcile, report the gap
			}
			if err := r.handle(ctx, env, interruptStream); err != nil {
				var resub *resubscribeError
				if errors.As(err, &resub) && ctx.Err() == nil {
					break
				}
				return fail(err)
			}
		}
		stopStream()
		r.mu.Lock()
		r.status.Subscribed = false
		r.mu.Unlock()
		if ctx.Err() != nil {
			join()
			return ctx.Err()
		}
		select {
		case deliveryErr = <-delivered:
			deliveryDone = true
			return fail(fmt.Errorf("delivery stopped: %w", deliveryErr))
		default:
		}
	}
}
