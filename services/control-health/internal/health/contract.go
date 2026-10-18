// Package health holds the TASK-10 3.2 health_contract, the install profile
// that decides required components, and the pure scope-state evaluation used
// by GET /internal/control-health and the lease response.
package health

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// health_contract (TASK-10 3.2, COMMON "error, status and health defaults").
const (
	HeartbeatInterval    = 5 * time.Second
	LeaseTTL             = 15 * time.Second
	MaxIngestionLag      = 10 * time.Second
	MaxClockSkew         = 2 * time.Second
	OwnerComponent       = "control-health" // owner_component of holds this Task decides
	GlobalScopeID        = "*"
	ReasonLeaseExpired   = "lease_expired"
	StartupGuarded       = "guarded"
	StartupUnsupported   = "unsupported"
	StateHealthy         = "healthy"
	StateDegraded        = "degraded"
	StateUnhealthy       = "unhealthy"
	ComponentNetpol      = "netpol-collector"
	ComponentRuntimeGrd  = "runtime-guard"
	ComponentStartCoord  = "start-coordinator"
	ComponentAdapter     = "adapter"
	ComponentDestination = "destination-evidence"
)

// Scopes are the hold/lease scopes (TASK-10 3.6 CHECK).
var Scopes = []string{"global", "node", "workload", "target", "session"}

// Components is the COMMON ControlHealthLease.component enum.
var Components = []string{
	"gateway", "coordinator", "adapter", "audit-db", "audit-export", "destination-evidence",
	"node-sensors", "lifecycle-recorder", "runtime-guard", "start-coordinator", "node-readiness",
	"releaser", "netpol-collector",
}

// HoldReasons is the TASK-10 3.6 holds.reason CHECK.
var HoldReasons = []string{
	"export_lag", "db_unavailable", "probe_failed", "lease_expired", "start_unknown", "sensor_degraded",
	"control_drift", "bypass_detected", "sensor_tampering", "alignment_mismatch", "audit_integrity", "risk_event",
	"policy_activation", "operator_stop",
}

// ObservedStates are the ControlHealthLease.observed_state values.
var ObservedStates = []string{StateHealthy, StateDegraded, StateUnhealthy}

// RequiredGlobal, RequiredPerNode and the other lists are
// health_contract.required_components.
var (
	RequiredGlobal         = []string{"audit-db", "audit-export", "gateway", "coordinator", "node-readiness"}
	RequiredPerAdapter     = []string{ComponentAdapter}
	RequiredPerNode        = []string{"node-sensors", "lifecycle-recorder"}
	RequiredPerGuardedNode = []string{ComponentRuntimeGrd}
	RequiredPerGuardedProf = []string{ComponentStartCoord}
	RequiredPerTarget      = []string{ComponentDestination}
)

// ExpiryScope is the scope a component's lease belongs to and where its
// lease_expired hold goes (TASK-10 3.2): node-sensors, lifecycle-recorder,
// runtime-guard and netpol-collector -> node, destination-evidence -> target,
// adapter -> workload, the rest -> global. netpol-collector never gets a hold.
func ExpiryScope(component string) string {
	switch component {
	case "node-sensors", "lifecycle-recorder", ComponentRuntimeGrd, ComponentNetpol:
		return "node"
	case ComponentDestination:
		return "target"
	case ComponentAdapter:
		return "workload"
	default:
		return "global"
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// ValidComponent reports whether c is in the COMMON component enum.
func ValidComponent(c string) bool { return contains(Components, c) }

// ValidScope reports whether s is a hold/lease scope.
func ValidScope(s string) bool { return contains(Scopes, s) }

// ValidObservedState reports whether s is a ControlHealthLease.observed_state.
func ValidObservedState(s string) bool { return contains(ObservedStates, s) }

// ValidHoldReason reports whether r is a holds.reason.
func ValidHoldReason(r string) bool { return contains(HoldReasons, r) }

// NodeSourceID reports whether sourceID is the per-node lease source
// `<component>-node/<node_uid>` for nodeUID. The component token is a
// lowercase DNS label; the node part must be the lease's canonical node UID.
func NodeSourceID(sourceID, nodeUID string) bool {
	prefix, node, ok := strings.Cut(sourceID, "-node/")
	if !ok || node != nodeUID || len(prefix) == 0 || len(prefix) > 63 || prefix[0] < 'a' || prefix[0] > 'z' {
		return false
	}
	for _, c := range prefix {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	u, err := uuid.Parse(node)
	return err == nil && u.String() == node
}
