package observe

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/healthreport"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/podmeta"
)

type Health interface {
	Challenges(ctx context.Context, nodeUID string) (healthreport.Challenges, error)
	ReportWorker(ctx context.Context, r healthreport.WorkerResult) (healthreport.EvidenceAck, error)
	ReportPod(ctx context.Context, r healthreport.PodResult) (healthreport.EvidenceAck, error)
}

type Containers interface {
	Container(id string) (podmeta.Container, bool)
}

type Config struct {
	NodeUID, BootID, RuleHash string
	SensorGeneration          int64
	// WorkerBinaries are the fixed worker executables of the approved runtime
	// image (COMMON session-dedicated worker contract 4: "fixed worker command").
	WorkerBinaries []string
	Health         Health
	Proc           Proc
	Containers     Containers
	Index          *Index
	// Ready is the sensor's own fresh health state (capture verified, loss
	// known, WAL append/fsync and ACK progress healthy); healthreport.Monitor.
	Ready func(time.Time) bool
	Now   func() time.Time
	// Poll is the challenge polling interval (default 1s).
	Poll time.Duration
	Log  func(string)
}

const (
	// resultTimeout keeps a POST inside control-health's 3 s node result age.
	resultTimeout = 2 * time.Second
	// deadlineMargin: do not start a report that cannot arrive before the
	// challenge deadline.
	deadlineMargin = 500 * time.Millisecond
	maxSent        = 8
	maxObserved    = 4096
)

type observedWorker struct {
	hostPID, startTicks     int64
	rootExecID, containerID string
	execRef, evidenceID     string
}

type sent struct {
	worker   []healthreport.WorkerResult
	pod      []healthreport.PodResult
	binding  string
	deadline time.Time
}

type Responder struct {
	c        Config
	binaries map[string]bool
	mu       sync.Mutex
	done     map[string]time.Time // challenge_id -> deadline
	sent     map[string]*sent     // challenge_id -> bodies posted without a known ack
	observed map[string]observedWorker
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func New(c Config) (*Responder, error) {
	if c.NodeUID == "" || c.BootID == "" || !hex64.MatchString(c.RuleHash) || c.SensorGeneration < 1 || len(c.WorkerBinaries) == 0 ||
		c.Health == nil || c.Proc == nil || c.Containers == nil || c.Index == nil || c.Ready == nil {
		return nil, errors.New("incomplete observation responder configuration")
	}
	r := &Responder{c: c, binaries: map[string]bool{}, done: map[string]time.Time{}, sent: map[string]*sent{}, observed: map[string]observedWorker{}}
	for _, b := range c.WorkerBinaries {
		if !path.IsAbs(b) || path.Clean(b) != b {
			return nil, errors.New("worker binaries must be absolute clean paths")
		}
		// The KernelEvent keeps a non-allowlisted path as its SHA-256.
		r.binaries[b], r.binaries[canonical.SHA256Hex([]byte(b))] = true, true
	}
	if r.c.Now == nil {
		r.c.Now = time.Now
	}
	if r.c.Poll <= 0 {
		r.c.Poll = time.Second
	}
	if r.c.Log == nil {
		r.c.Log = func(string) {}
	}
	return r, nil
}

// Run polls the node-scope snapshot until ctx ends. Errors are logged and the
// next poll retries; the responder never answers from stale state.
func (r *Responder) Run(ctx context.Context) error {
	tick := time.NewTicker(r.c.Poll)
	defer tick.Stop()
	for {
		if err := r.Step(ctx); err != nil && ctx.Err() == nil {
			r.c.Log("observation challenges: " + err.Error())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// Step handles one snapshot.
func (r *Responder) Step(ctx context.Context) error {
	call, cancel := context.WithTimeout(ctx, 4*time.Second)
	list, err := r.c.Health.Challenges(call, r.c.NodeUID)
	cancel()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pending := map[string]bool{}
	for _, ch := range list.Worker {
		pending[ch.ChallengeID] = true
	}
	for _, ch := range list.Readiness {
		pending[ch.ChallengeID] = true
	}
	r.recoverAcks(ctx, pending)
	for _, ch := range list.Worker {
		if _, ok := r.done[ch.ChallengeID]; !ok {
			r.worker(ctx, ch)
		}
	}
	for _, ch := range list.Readiness {
		if _, ok := r.done[ch.ChallengeID]; !ok {
			r.pod(ctx, ch)
		}
	}
	now := r.c.Now()
	for id, deadline := range r.done {
		if now.After(deadline.Add(time.Minute)) {
			delete(r.done, id)
		}
	}
	return nil
}

// recoverAcks: a challenge that left the pending list after a POST whose
// response was lost was answered by one of the bodies already sent. Only an
// identical replay returns that acknowledgement (200 existing).
func (r *Responder) recoverAcks(ctx context.Context, pending map[string]bool) {
	now := r.c.Now()
	for id, s := range r.sent {
		if pending[id] {
			continue
		}
		// Retry only while some replay failed in transit; a decided rejection
		// of every body means none was stored (the nonce expired instead).
		recovered, transient := false, false
		for _, body := range s.worker {
			ack, err := r.postWorker(ctx, body)
			if err == nil {
				r.recordWorker(body, ack)
				recovered = true
				break
			}
			transient = transient || !final(err)
		}
		for _, body := range s.pod {
			_, err := r.postPod(ctx, body)
			if err == nil {
				recovered = true
				break
			}
			transient = transient || !final(err)
		}
		if recovered || !transient || now.After(s.deadline.Add(30*time.Second)) {
			delete(r.sent, id)
			r.done[id] = s.deadline
		}
	}
}

func (r *Responder) finish(id string, deadline time.Time, why string) {
	r.done[id] = deadline
	delete(r.sent, id)
	if why != "" {
		r.c.Log(fmt.Sprintf("challenge %s not answered: %s", id, why))
	}
}

// common checks the challenge is for this node/boot and this sensor.
func (r *Responder) common(id string, b healthreport.InstanceBinding, generation int64, rule *string, deadline time.Time) (bool, string) {
	switch {
	case b.NodeUID != r.c.NodeUID || b.BootID != r.c.BootID:
		return false, "other node or boot"
	case generation != r.c.SensorGeneration:
		return false, "sensor generation mismatch"
	case rule != nil && *rule != r.c.RuleHash:
		return false, "rule hash mismatch"
	case !r.c.Now().Add(deadlineMargin).Before(deadline):
		return false, "deadline passed"
	}
	return true, ""
}

// localContainer is the bare containerd ID the exporter's KernelEvents and
// podmeta use. SPEC-QUESTION: lifecycle bindings may carry the CRI scheme
// ("containerd://"); the challenge's own value is echoed unchanged.
func localContainer(id string) string { return strings.TrimPrefix(id, "containerd://") }

func imageDigest(imageID string) (string, bool) {
	_, digest, ok := strings.Cut(imageID, "@")
	if !ok {
		digest = imageID
	}
	hex, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || !hex64.MatchString(hex) {
		return "", false
	}
	return digest, true
}

// container checks the binding's container against the node Pod API and the
// cgroup filesystem. retry is true when the answer may still appear.
func (r *Responder) container(b healthreport.InstanceBinding) (podmeta.Container, string, bool, string) {
	c, ok := r.c.Containers.Container(localContainer(b.ContainerID))
	if !ok {
		return c, "", true, "container metadata pending"
	}
	if c.PodUID != b.PodUID || c.Deleted || !c.Running {
		return c, "", false, "container is not the running container of the Pod"
	}
	digest, ok := imageDigest(c.ImageID)
	if !ok {
		return c, "", false, "image digest not reported"
	}
	inode, err := r.c.Proc.CgroupInode(localContainer(b.ContainerID))
	if err != nil {
		return c, "", true, "container cgroup unavailable"
	}
	if inode != b.CgroupInode {
		return c, "", false, "cgroup inode mismatch"
	}
	return c, digest, false, ""
}

// resolve finds the one live host process of a supervisor-reported hint:
// innermost NSpid = local PID, /proc start ticks equal, in the container's
// cgroup. Zero or several candidates is unresolved.
func (r *Responder) resolve(h healthreport.ProcessHint, containerID string) (int64, Status, bool) {
	pids, err := r.c.Proc.PIDs()
	if err != nil {
		return 0, Status{}, false
	}
	var host int64
	var status Status
	matches := 0
	for _, pid := range pids {
		s, err := r.c.Proc.Status(pid)
		if err != nil || len(s.NSpid) < 2 || s.NSpid[0] != pid || s.NSpid[len(s.NSpid)-1] != h.LocalPID {
			continue
		}
		if ticks, err := r.c.Proc.StartTicks(pid); err != nil || ticks != h.StartTicks {
			continue
		}
		if cg, err := r.c.Proc.Cgroup(pid); err != nil || !strings.Contains(path.Base(cg), containerID) {
			continue
		}
		host, status = pid, s
		matches++
	}
	return host, status, matches == 1
}

func (r *Responder) alive(pid, ticks int64, containerID string) bool {
	t, err := r.c.Proc.StartTicks(pid)
	if err != nil || t != ticks {
		return false
	}
	cg, err := r.c.Proc.Cgroup(pid)
	return err == nil && strings.Contains(path.Base(cg), containerID)
}

// controls records only /proc values the kernel printed. Dumpable and seccomp
// filter content cannot be read without ptrace access and stay "unknown".
func controls(s Status) map[string]any {
	out := map[string]any{"source": "proc_status", "dumpable": "unknown", "seccomp_filter": "unknown"}
	if s.NoNewPrivs != nil {
		out["no_new_privs"] = *s.NoNewPrivs
	} else {
		out["no_new_privs"] = "unknown"
	}
	if s.Seccomp != nil {
		out["seccomp_mode"] = *s.Seccomp
	} else {
		out["seccomp_mode"] = "unknown"
	}
	if s.UID != nil {
		out["uid"] = s.UID
	} else {
		out["uid"] = "unknown"
	}
	if s.CapEff != nil {
		out["cap_eff"] = *s.CapEff
	} else {
		out["cap_eff"] = "unknown"
	}
	return out
}

func (r *Responder) worker(ctx context.Context, ch healthreport.WorkerChallenge) {
	b := ch.InstanceBinding
	if ok, why := r.common(ch.ChallengeID, b, ch.ExpectedSensorGeneration, ch.RuleHash, ch.Deadline); !ok {
		r.finish(ch.ChallengeID, ch.Deadline, why)
		return
	}
	if !r.c.Ready(r.c.Now()) {
		return // sensor not healthy now; retry until the deadline
	}
	_, digest, retry, why := r.container(b)
	if why != "" {
		if !retry {
			r.finish(ch.ChallengeID, ch.Deadline, why)
		}
		return
	}
	local := localContainer(b.ContainerID)
	supervisorPID, _, ok := r.resolve(ch.SupervisorProcessHint, local)
	if !ok {
		return
	}
	workerPID, status, ok := r.resolve(ch.WorkerProcessHint, local)
	if !ok || supervisorPID == workerPID || status.PPid != supervisorPID {
		return
	}
	// The worker's final exec: the only committed exec of this host PID in the
	// container (PID reuse or a second exec is ambiguous), still running.
	execs := r.c.Index.ByPID(local, workerPID)
	if len(execs) != 1 {
		return
	}
	exec := execs[0]
	parent, ok := r.c.Index.ByExecID(exec.ParentExecID)
	switch {
	case exec.Exited || !r.binaries[exec.Binary] || exec.PIDNS == 0 || int64(exec.PIDNS) != ch.WorkerProcessHint.PIDNSInode,
		exec.NodeUID != r.c.NodeUID || exec.BootID != r.c.BootID || exec.SensorGeneration != r.c.SensorGeneration || exec.RuleHash != r.c.RuleHash || exec.PodUID != b.PodUID,
		exec.ParentExecID == "" || !ok || parent.Exited || parent.HostPID != supervisorPID || parent.ContainerID != local,
		parent.PIDNS == 0 || int64(parent.PIDNS) != ch.SupervisorProcessHint.PIDNSInode:
		return
	}
	// Re-read after matching: the same processes must still be alive.
	if !r.alive(supervisorPID, ch.SupervisorProcessHint.StartTicks, local) || !r.alive(workerPID, ch.WorkerProcessHint.StartTicks, local) {
		return
	}
	b.ImageManifestDigest = &digest
	body := healthreport.WorkerResult{WorkerBindingID: ch.WorkerBindingID, ChallengeID: ch.ChallengeID, InstanceBinding: b,
		SupervisorIdentity: healthreport.NodeProcessIdentity{ProcessHint: ch.SupervisorProcessHint, HostPID: supervisorPID},
		WorkerIdentity:     healthreport.NodeProcessIdentity{ProcessHint: ch.WorkerProcessHint, HostPID: workerPID},
		RootExecID:         exec.ExecID, ExecEventRef: exec.SourceEventID, WorkerAlive: true, ObservedControls: controls(status),
		SensorGeneration: r.c.SensorGeneration, ReportedAt: r.c.Now().UTC(),
		EvidenceRefs: []string{"kernel_event:" + exec.SourceEventID, "kernel_event:" + parent.SourceEventID}}
	if !r.c.Now().Add(deadlineMargin).Before(ch.Deadline) {
		r.finish(ch.ChallengeID, ch.Deadline, "deadline passed")
		return
	}
	r.remember(ch.ChallengeID, ch.WorkerBindingID, ch.Deadline, &body, nil)
	ack, err := r.postWorker(ctx, body)
	if lost(err) && r.c.Now().Sub(body.ReportedAt) < resultTimeout {
		ack, err = r.postWorker(ctx, body) // identical replay is idempotent
	}
	r.settle(ch.ChallengeID, ch.Deadline, err, func() { r.recordWorker(body, ack) })
}

func (r *Responder) recordWorker(body healthreport.WorkerResult, ack healthreport.EvidenceAck) {
	if len(r.observed) >= maxObserved {
		for id, w := range r.observed {
			if !r.alive(w.hostPID, w.startTicks, w.containerID) {
				delete(r.observed, id)
			}
		}
	}
	if len(r.observed) < maxObserved {
		r.observed[body.WorkerBindingID] = observedWorker{hostPID: body.WorkerIdentity.HostPID, startTicks: body.WorkerIdentity.StartTicks,
			rootExecID: body.RootExecID, containerID: localContainer(body.InstanceBinding.ContainerID), execRef: body.ExecEventRef, evidenceID: ack.EvidenceID}
	}
}

func (r *Responder) pod(ctx context.Context, ch healthreport.ReadinessChallenge) {
	b := ch.InstanceBinding
	if ok, why := r.common(ch.ChallengeID, b, ch.ExpectedSensorGeneration, ch.RuleHash, ch.Deadline); !ok {
		r.finish(ch.ChallengeID, ch.Deadline, why)
		return
	}
	if !r.c.Ready(r.c.Now()) {
		return
	}
	c, digest, retry, why := r.container(b)
	if why != "" {
		if !retry {
			r.finish(ch.ChallengeID, ch.Deadline, why)
		}
		return
	}
	if b.ImageManifestDigest == nil || *b.ImageManifestDigest != digest {
		r.finish(ch.ChallengeID, ch.Deadline, "image digest mismatch")
		return
	}
	w, ok := r.observed[ch.WorkerBindingID]
	if !ok || w.rootExecID != ch.RootExecID || w.containerID != localContainer(b.ContainerID) {
		// This exporter process did not witness the worker; it cannot vouch
		// for its identity now (for example after an exporter restart).
		r.finish(ch.ChallengeID, ch.Deadline, "worker not witnessed by this sensor")
		return
	}
	exec, known := r.c.Index.ByExecID(w.rootExecID)
	alive := r.alive(w.hostPID, w.startTicks, w.containerID) && known && !exec.Exited
	if !alive {
		delete(r.observed, ch.WorkerBindingID)
	}
	// The container's events demonstrably pass the filter: an exec of it was
	// committed to the audit store, and its Namespace is observed.
	filter := c.Observed && r.c.Index.HasContainer(w.containerID)
	binding, root := ch.WorkerBindingID, ch.RootExecID
	body := healthreport.PodResult{CheckID: ch.CheckID, ChallengeID: ch.ChallengeID, InstanceBinding: b, SensorGeneration: r.c.SensorGeneration,
		RuleHash: r.c.RuleHash, FilterIncluded: filter, WALFsyncReady: true, WorkerBindingID: &binding, RootExecID: &root, WorkerAlive: &alive,
		WorkerEvidenceRefs: []string{"worker_evidence:" + w.evidenceID}, ReportedAt: r.c.Now().UTC(), EvidenceRefs: []string{"kernel_event:" + w.execRef}}
	if !r.c.Now().Add(deadlineMargin).Before(ch.Deadline) {
		r.finish(ch.ChallengeID, ch.Deadline, "deadline passed")
		return
	}
	r.remember(ch.ChallengeID, ch.WorkerBindingID, ch.Deadline, nil, &body)
	_, err := r.postPod(ctx, body)
	if lost(err) && r.c.Now().Sub(body.ReportedAt) < resultTimeout {
		_, err = r.postPod(ctx, body)
	}
	r.settle(ch.ChallengeID, ch.Deadline, err, func() {})
}

func (r *Responder) remember(id, binding string, deadline time.Time, w *healthreport.WorkerResult, p *healthreport.PodResult) {
	s := r.sent[id]
	if s == nil {
		s = &sent{binding: binding, deadline: deadline}
		r.sent[id] = s
	}
	if w != nil {
		s.worker = append(s.worker, *w)
		if len(s.worker) > maxSent {
			s.worker = s.worker[len(s.worker)-maxSent:]
		}
	}
	if p != nil {
		s.pod = append(s.pod, *p)
		if len(s.pod) > maxSent {
			s.pod = s.pod[len(s.pod)-maxSent:]
		}
	}
}

// final: control-health decided; only 503 (not committed / unavailable) and
// transport failures are retried within the nonce.
func final(err error) bool {
	var status *healthreport.StatusError
	return errors.As(err, &status) && status.Status != 503
}

// lost: no HTTP decision arrived, so the result may or may not be stored.
func lost(err error) bool {
	var status *healthreport.StatusError
	return err != nil && !errors.As(err, &status)
}

func (r *Responder) settle(id string, deadline time.Time, err error, ok func()) {
	var status *healthreport.StatusError
	switch {
	case err == nil:
		ok()
		r.finish(id, deadline, "")
	case errors.As(err, &status) && status.Has("EVENT_ID_CONFLICT"):
		// An earlier body was stored; recoverAcks replays it once the
		// challenge leaves the pending list.
	case final(err):
		r.finish(id, deadline, err.Error())
	default:
		r.c.Log(fmt.Sprintf("challenge %s: %v (retrying)", id, err))
	}
}

func (r *Responder) postWorker(ctx context.Context, body healthreport.WorkerResult) (healthreport.EvidenceAck, error) {
	call, cancel := context.WithTimeout(ctx, resultTimeout)
	defer cancel()
	return r.c.Health.ReportWorker(call, body)
}

func (r *Responder) postPod(ctx context.Context, body healthreport.PodResult) (healthreport.EvidenceAck, error) {
	call, cancel := context.WithTimeout(ctx, resultTimeout)
	defer cancel()
	return r.c.Health.ReportPod(call, body)
}
