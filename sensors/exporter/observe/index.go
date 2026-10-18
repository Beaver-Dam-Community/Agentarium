// Package observe answers the TASK-10 node nonce challenges for this node:
// session worker observation (TASK-09 independent session worker observation) and the Pod work
// readiness check (TASK-09 observation readiness check of the runtime Pod). It reports only
// what it observed itself: committed kernel exec rows, the node's /proc and
// cgroup filesystem and the node-scoped Pod API. Anything it cannot observe
// leaves the challenge unanswered, so control-health times it out.
package observe

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

// Exec is one process_exec KernelEvent that the audit collector acknowledged
// as committed (delivery.Config.Committed). PIDNS is Tetragon's PID namespace
// inode of the same exec_id (0 if Tetragon did not report it).
type Exec struct {
	SourceEventID, ExecID, ParentExecID string
	ContainerID, PodUID                 string
	NodeUID, BootID, RuleHash           string
	Binary                              string // safe_attributes.binary: path or SHA-256 of path
	HostPID                             int64
	SensorGeneration                    int64
	PIDNS                               uint64
	Exited                              bool
	exitedAt                            time.Time
}

const (
	maxExecs      = 1 << 16
	maxNamespaces = 1 << 16
	exitRetention = 10 * time.Minute
)

// Index holds committed process_exec/process_exit rows of this exporter
// process lifetime. It starts empty after a restart: processes that executed
// before then cannot be witnessed (fail closed).
type Index struct {
	mu     sync.Mutex
	now    func() time.Time
	execs  map[string]*Exec    // exec_id
	byPID  map[string][]string // container_id/host_pid -> exec_ids in commit order
	exits  map[string]time.Time
	pidNS  map[string]uint32 // exec_id -> Tetragon ns.pid.inum, before commit
	order  []string
	nsSeen []string
	lastGC time.Time
}

func NewIndex(now func() time.Time) *Index {
	if now == nil {
		now = time.Now
	}
	return &Index{now: now, execs: map[string]*Exec{}, byPID: map[string][]string{}, exits: map[string]time.Time{}, pidNS: map[string]uint32{}}
}

func pidKey(container string, pid int64) string { return container + "/" + strconv.FormatInt(pid, 10) }

// Namespace records Tetragon's PID namespace inode for an exec_id. It is
// normalize.Config.ExecNamespace and runs before the WAL append.
func (x *Index) Namespace(execID string, inode uint32) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if _, ok := x.pidNS[execID]; !ok {
		x.nsSeen = append(x.nsSeen, execID)
	}
	x.pidNS[execID] = inode
	if e := x.execs[execID]; e != nil {
		e.PIDNS = uint64(inode)
	}
	for len(x.nsSeen) > maxNamespaces {
		delete(x.pidNS, x.nsSeen[0])
		x.nsSeen = x.nsSeen[1:]
	}
}

type record struct {
	EventType        string  `json:"event_type"`
	SourceEventID    string  `json:"source_event_id"`
	ProcessExecID    *string `json:"process_exec_id"`
	ParentExecID     *string `json:"parent_exec_id"`
	HostPID          *int64  `json:"host_pid"`
	ContainerID      *string `json:"container_id"`
	PodUID           *string `json:"pod_uid"`
	NodeUID          string  `json:"node_uid"`
	BootID           string  `json:"boot_id"`
	RuleHash         string  `json:"rule_hash"`
	SensorGeneration int64   `json:"sensor_generation"`
	SafeAttributes   struct {
		Binary string `json:"binary"`
	} `json:"safe_attributes"`
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Committed indexes one committed KernelEvent payload. It is
// delivery.Config.Committed; records the witness does not use are ignored.
func (x *Index) Committed(payload []byte) {
	var r record
	if json.Unmarshal(payload, &r) != nil || r.ProcessExecID == nil || *r.ProcessExecID == "" {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	now := x.now()
	id := *r.ProcessExecID
	switch r.EventType {
	case "process_exit":
		x.exits[id] = now
		if e := x.execs[id]; e != nil && !e.Exited {
			e.Exited, e.exitedAt = true, now
		}
	case "process_exec":
		if r.HostPID == nil || r.ContainerID == nil || x.execs[id] != nil {
			return
		}
		e := &Exec{SourceEventID: r.SourceEventID, ExecID: id, ParentExecID: deref(r.ParentExecID), ContainerID: *r.ContainerID, PodUID: deref(r.PodUID),
			NodeUID: r.NodeUID, BootID: r.BootID, RuleHash: r.RuleHash, Binary: r.SafeAttributes.Binary, HostPID: *r.HostPID, SensorGeneration: r.SensorGeneration,
			PIDNS: uint64(x.pidNS[id])}
		if at, ok := x.exits[id]; ok {
			e.Exited, e.exitedAt = true, at
		}
		x.execs[id] = e
		k := pidKey(e.ContainerID, e.HostPID)
		x.byPID[k] = append(x.byPID[k], id)
		x.order = append(x.order, id)
	}
	x.gc(now)
}

func (x *Index) gc(now time.Time) {
	if now.Sub(x.lastGC) < 10*time.Second && len(x.order) <= maxExecs {
		return
	}
	x.lastGC = now
	for id, at := range x.exits {
		if now.Sub(at) > exitRetention {
			delete(x.exits, id)
		}
	}
	keep := x.order[:0]
	for _, id := range x.order {
		e := x.execs[id]
		if e == nil {
			continue
		}
		if e.Exited && now.Sub(e.exitedAt) > exitRetention {
			x.drop(e)
			continue
		}
		keep = append(keep, id)
	}
	// Over capacity the oldest rows go first. A dropped row can only make a
	// later lookup miss (no report), never invent a match.
	for len(keep) > maxExecs {
		x.drop(x.execs[keep[0]])
		keep = keep[1:]
	}
	x.order = keep
}

func (x *Index) drop(e *Exec) {
	delete(x.execs, e.ExecID)
	k := pidKey(e.ContainerID, e.HostPID)
	ids := x.byPID[k][:0]
	for _, id := range x.byPID[k] {
		if id != e.ExecID {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		delete(x.byPID, k)
	} else {
		x.byPID[k] = ids
	}
}

// ByPID returns every committed exec of one host PID in one container,
// including exited ones, in commit order.
func (x *Index) ByPID(container string, pid int64) []Exec {
	x.mu.Lock()
	defer x.mu.Unlock()
	var out []Exec
	for _, id := range x.byPID[pidKey(container, pid)] {
		out = append(out, *x.execs[id])
	}
	return out
}

func (x *Index) ByExecID(id string) (Exec, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	e := x.execs[id]
	if e == nil {
		return Exec{}, false
	}
	return *e, true
}

// HasContainer reports whether any committed exec of the container exists:
// the container's events pass the exporter filter and reach the audit store.
func (x *Index) HasContainer(container string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, e := range x.execs {
		if e.ContainerID == container {
			return true
		}
	}
	return false
}
