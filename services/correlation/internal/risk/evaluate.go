// Package risk is the deterministic TASK-10 3.2 risk-event evaluator. Inputs
// are stored kernel events with their historical workload mapping; AI output
// and NetworkFinding are never inputs. A decision becomes a workload
// risk_event hold request; candidates that cannot be judged stay marked only.
package risk

import (
	"slices"
	"strings"
	"time"
)

const (
	DetailConnect = "unregistered_connect_established"
	DetailWrite   = "protected_path_write"
	DetailExec    = "unexpected_child_exec"
)

// maxLineage bounds the parent walk; a longer chain is undeterminable.
const maxLineage = 64

// Event is one stored kernel event. WorkloadID is set only when the event's
// container maps to exactly one historical Pod with a verified workload.
type Event struct {
	ID, EventType, NodeUID, BootID, ContainerID string
	ProcessExecID, ParentExecID                 string
	SourceTime                                  time.Time
	WorkloadID                                  *string
	// tcp_connect only
	Established, DestinationAllowed, Confirmed bool
	// file_open/openat only
	Path  string
	Flags *int64
}

// Config carries installation facts. FlagsVerified stays false until TASK-09
// Q0 confirms that open flags distinguish write access; until then protected
// path opens are candidates only (TASK-10 3.2 limitations).
type Config struct {
	ProtectedPaths []string
	FlagsVerified  bool
	// ContainerRoots maps node/boot/container to the exec ID of the container's
	// start process; WorkerRoots are registered session worker root execs.
	ContainerRoots map[string]string
	WorkerRoots    map[string]bool
}

// RootKey identifies a container start process within one node boot.
func RootKey(node, boot, container string) string { return node + "/" + boot + "/" + container }

type Decision struct {
	WorkloadID, Detail, KernelEventID string
}

type Candidate struct {
	KernelEventID, Detail, Limitation string
}

// O_WRONLY|O_RDWR (Linux open flags access mode bits).
const writeAccessMask = 0x3

// Evaluate returns hold decisions and marked-only candidates. Events without
// a workload never produce a decision. A sensor gap does not suppress the
// judgement of events that were observed.
func Evaluate(events []Event, cfg Config) ([]Decision, []Candidate) {
	execs := map[string]Event{}
	for _, e := range events {
		if e.EventType == "process_exec" && e.ProcessExecID != "" {
			execs[e.NodeUID+"/"+e.BootID+"/"+e.ProcessExecID] = e
		}
	}
	var decisions []Decision
	var candidates []Candidate
	for _, e := range events {
		if e.WorkloadID == nil {
			continue
		}
		switch e.EventType {
		case "tcp_connect":
			if e.Established && !e.DestinationAllowed && !e.Confirmed {
				decisions = append(decisions, Decision{*e.WorkloadID, DetailConnect, e.ID})
			}
		case "file_open", "openat":
			if !slices.Contains(cfg.ProtectedPaths, e.Path) {
				continue
			}
			if !cfg.FlagsVerified {
				candidates = append(candidates, Candidate{e.ID, DetailWrite, "open flags write access unverified (TASK-09 Q0)"})
				continue
			}
			if e.Flags != nil && *e.Flags&writeAccessMask != 0 {
				decisions = append(decisions, Decision{*e.WorkloadID, DetailWrite, e.ID})
			}
		case "process_exec":
			switch lineage(e, execs, cfg) {
			case broken:
				decisions = append(decisions, Decision{*e.WorkloadID, DetailExec, e.ID})
			case undetermined:
				candidates = append(candidates, Candidate{e.ID, DetailExec, "parent exec evidence missing; lineage undeterminable"})
			case rootUnknown:
				candidates = append(candidates, Candidate{e.ID, DetailExec, "container start process not observed at lifecycle start; lineage undeterminable"})
			}
		}
	}
	slices.SortFunc(decisions, func(a, b Decision) int {
		return strings.Compare(a.WorkloadID+a.KernelEventID, b.WorkloadID+b.KernelEventID)
	})
	return decisions, candidates
}

type verdict int

const (
	attached verdict = iota
	broken
	undetermined
	rootUnknown
)

// lineage walks kernel parent evidence inside the container until it reaches
// the container start process or a registered worker root. A parent observed
// in another container (or on the host) breaks the lineage; a missing parent
// leaves it undetermined.
func lineage(e Event, execs map[string]Event, cfg Config) verdict {
	root := cfg.ContainerRoots[RootKey(e.NodeUID, e.BootID, e.ContainerID)]
	if root == "" {
		return rootUnknown
	}
	current := e
	for i := 0; i < maxLineage; i++ {
		if current.ProcessExecID == root || cfg.WorkerRoots[current.ProcessExecID] {
			return attached
		}
		if current.ParentExecID == "" {
			return undetermined
		}
		if current.ParentExecID == root || cfg.WorkerRoots[current.ParentExecID] {
			return attached
		}
		parent, ok := execs[e.NodeUID+"/"+e.BootID+"/"+current.ParentExecID]
		if !ok {
			return undetermined
		}
		if parent.ContainerID != e.ContainerID {
			return broken
		}
		current = parent
	}
	return undetermined
}
