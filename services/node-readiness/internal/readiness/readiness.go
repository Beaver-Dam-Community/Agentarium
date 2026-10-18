// Package readiness decides whether a node's start taint may be removed,
// from the TASK-10 node-scope control-health response (TASK-10 3.2
// "node readiness controller integration", TASK-01 3.5).
package readiness

import (
	"fmt"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/node-readiness/internal/controlhealth"
)

const (
	ComponentNodeSensors       = "node-sensors"
	ComponentLifecycleRecorder = "lifecycle-recorder"
	ComponentRuntimeGuard      = "runtime-guard"

	StartupCaptureGuarded     = "guarded"
	StartupCaptureUnsupported = "unsupported"

	// RequiredConsecutivePasses is "two consecutive answer-probe passes".
	RequiredConsecutivePasses = 2

	// ProbeFreshnessMargin: the latest judgement must be later than
	// ProbesNotBefore by judge delay (25s) + probe interval (60s) + clock skew
	// (2s), from TASK-10 health_contract. A judgement at J covers the stimulus
	// at J-25s, and the previous consecutive pass a stimulus at most 60s
	// earlier, so both stimuli postdate ProbesNotBefore.
	// SPEC-QUESTION: the TASK-10 chapter 4 response carries no boot_id or per-pass
	// timestamps, so this assumes consecutive probes are at most 60s apart.
	ProbeFreshnessMargin = (25 + 60 + 2) * time.Second
)

// RequiredProbeKinds are the three answer-key probe kinds (TASK-10 3.2 "answer probe").
var RequiredProbeKinds = []string{"process", "tcp", "file"}

type Input struct {
	NodeUID string
	BootID  string
	Health  *controlhealth.NodeHealth
	Now     time.Time
	// ProbesNotBefore is the earliest point the controller can vouch for the
	// node's current boot: max(process start, observed boot change). Probe
	// stimuli at or before it may belong to an earlier boot. The controller
	// always sets it; zero disables the check (unit use only).
	ProbesNotBefore time.Time
}

type Decision struct {
	Ready   bool
	Reasons []string
}

// Evaluate returns Ready only when every TASK-10 condition holds. Any doubt
// keeps the node not ready; reasons are for logs, not COMMON reason_codes.
func Evaluate(in Input) Decision {
	var reasons []string
	fail := func(format string, a ...any) { reasons = append(reasons, fmt.Sprintf(format, a...)) }

	h := in.Health
	if h == nil {
		return Decision{Reasons: []string{"control_health_unavailable"}}
	}
	if in.BootID == "" {
		fail("boot_id_unknown")
	}
	if h.Scope != "node" || h.ScopeID != in.NodeUID {
		fail("scope_mismatch")
	}
	for _, m := range h.MissingComponents {
		fail("missing_component:%s", m)
	}
	// SPEC-QUESTION: TASK-01 3.5 / TASK-10 3.2 gate on "unreleased node-scope hold"
	// only. If the node query also lists global holds, they are not treated as
	// node holds here (a policy_activation global hold would otherwise re-taint
	// every node on each release).
	for _, hd := range h.OpenHolds {
		if hd.Scope == "node" && hd.ScopeID == in.NodeUID {
			fail("open_node_hold:%s", hd.Reason)
		}
	}

	required := []string{ComponentNodeSensors, ComponentLifecycleRecorder}
	switch {
	case h.StartupCapture == nil:
		// node_boot_generation has no row yet; guarded-ness is unknown.
		fail("startup_capture_unknown")
	case *h.StartupCapture == StartupCaptureGuarded:
		required = append(required, ComponentRuntimeGuard)
	case *h.StartupCapture == StartupCaptureUnsupported:
	default:
		fail("startup_capture_invalid:%s", *h.StartupCapture)
	}
	for _, comp := range required {
		if !hasValidLease(h, comp, in.Now, in.BootID) {
			fail("lease_not_valid:%s", comp)
		}
	}

	for _, kind := range RequiredProbeKinds {
		if r := probeProblem(h, kind, in.ProbesNotBefore, in.BootID); r != "" {
			fail("%s", r)
		}
	}

	return Decision{Ready: len(reasons) == 0, Reasons: reasons}
}

// hasValidLease requires a healthy lease that is unexpired both at the
// server's evaluation time and on the local clock, and that is not bound to
// a different boot when the server reports one.
func hasValidLease(h *controlhealth.NodeHealth, component string, now time.Time, bootID string) bool {
	for _, l := range h.Leases {
		if l.Component != component || l.ObservedState != "healthy" || otherBoot(l.BootID, bootID) {
			continue
		}
		if l.LeaseUntil.After(now) && l.LeaseUntil.After(h.EvaluatedAt) {
			return true
		}
	}
	return false
}

func probeProblem(h *controlhealth.NodeHealth, kind string, notBefore time.Time, bootID string) string {
	found := false
	for _, p := range h.Probes {
		if p.ProbeKind != kind {
			continue
		}
		// Every entry of a kind must pass; a duplicate cannot hide a failure.
		found = true
		if otherBoot(p.BootID, bootID) {
			return "probe_other_boot:" + kind
		}
		if p.LastResult != "pass" || p.ConsecutivePasses < RequiredConsecutivePasses {
			return "probe_not_passing:" + kind
		}
		if !notBefore.IsZero() && (p.LastJudgedAt == nil || !p.LastJudgedAt.After(notBefore.Add(ProbeFreshnessMargin))) {
			return "probe_not_fresh:" + kind
		}
	}
	if !found {
		return "probe_missing:" + kind
	}
	return ""
}

// otherBoot is true when the server bound an entry to a boot other than the
// node's current one. The chapter 4 schema has no boot_id; it is honored only if present.
func otherBoot(reported *string, current string) bool {
	return reported != nil && *reported != current
}
