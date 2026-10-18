// Package join implements the pure TASK-10 3.1 socket matching calculation.
// Its types are verified repository inputs, not HTTP/JSON contracts. Callers
// must authenticate/deduplicate sources and select authoritative lifecycle
// revisions before invoking Match. No request hint, AI output or current Pod
// lookup is an input to this engine.
package join

import (
	"net/netip"
	"time"
)

const ClockSkew = 2 * time.Second

type Confidence string

const (
	Confirmed        Confidence = "confirmed"
	WorkloadInferred Confidence = "workload_inferred"
	Unlinked         Confidence = "unlinked"
)

type Tuple struct{ Local, Peer netip.AddrPort }

type Connect struct {
	EventID, NodeUID, BootID, ContainerID, ProcessExecID string
	// PodUID is optional sensor metadata. A supplied value must agree with history.
	PodUID         string
	NetNS, SockPtr uint64
	SourceTime     time.Time
	Tuple          Tuple
}

// State deliberately has no process, Pod, container or userspace SO_COOKIE
// fields: softirq metadata must never establish attribution.
type State struct {
	EventID, NodeUID, BootID string
	SockPtr                  uint64
	SourceTime               time.Time
	Tuple                    Tuple
	NewState                 string
}

// Lifecycle is an already derived, verified historical interval. The adapter
// must resolve workload namespace/KSA from trusted historical evidence, not
// from current Pod/IP/PID state. Missing starts/unknown ends cannot prove a map.
type Lifecycle struct {
	IntervalID, ClusterUID, NodeUID, BootID, ContainerID, PodUID, WorkloadID string
	StartedAt                                                                time.Time
	EndedAt                                                                  *time.Time
	EndQuality                                                               string // observed, inferred_from_other_source, unknown, open
	EvidenceRefs                                                             []string
}

// Observation is an authenticated TASK-03 attempt_observations row plus its
// verified action relation. It carries no process ID or claimed socket cookie.
type Observation struct {
	AttemptID, ActionID, PodUID     string
	NetNS                           uint64
	Tuple                           Tuple
	ConnectStartedAt, SendStartedAt time.Time
}

type Side string

const (
	VIP      Side = "vip"
	Endpoint Side = "endpoint"
)

// Rule corresponds to TASK-10 tuple_normalization_rules. A rule is usable only
// with the selected algorithm version and an actual Q0 measured_run_id.
type Rule struct {
	AlgorithmVersion, MeasuredRunID string
	Service                         netip.AddrPort
	EndpointCIDR                    netip.Prefix
	EndpointPort                    uint16
	KernelSide, AdapterSide         Side
}

// Snapshot must contain every potentially matching connect and observation in
// the selected matching windows, including overlapping windows and late data.
// Matching a caller-trimmed singleton does not prove bidirectional uniqueness.
// This pure engine cannot verify the completeness of a future DB adapter.
type Snapshot struct {
	ClusterUID, AlgorithmVersion string
	Connects                     []Connect
	States                       []State
	Lifecycles                   []Lifecycle
	Observations                 []Observation
	Rules                        []Rule
}

// Attribution is present only for confirmed results. There is no session field:
// COMMON Correlation has none, and worker/session attribution is a separate path.
type Attribution struct{ AttemptID, ActionID, ProcessExecID string }

// Result is an internal calculation, not a serialized COMMON Correlation row.
// A persistence adapter must supply correlation_id/revision, translate diagnostics
// to agreed method/reason/evidence refs, and atomically append the audit event.
type Result struct {
	KernelEventID       string
	WorkloadID          string
	Confidence          Confidence
	Attribution         *Attribution
	CandidateCount      int // pairs satisfying every socket condition, including state
	CandidateAttemptIDs []string
	EvidenceRefs        []string
	AlgorithmVersion    string
	// Diagnostic and Limitations are local explanations, not new wire enums.
	Diagnostic  string
	Limitations []string
}
