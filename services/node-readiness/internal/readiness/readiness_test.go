package readiness

import (
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/node-readiness/internal/controlhealth"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

const nodeUID = "6f1c2b9e-0000-4000-8000-000000000001"

func str(s string) *string { return &s }

func ts(t time.Time) *time.Time { return &t }

func healthyResponse(capture string) *controlhealth.NodeHealth {
	lease := func(c string) controlhealth.LeaseStatus {
		return controlhealth.LeaseStatus{Component: c, SourceID: c + "-0", ObservedState: "healthy", LeaseUntil: now.Add(10 * time.Second)}
	}
	h := &controlhealth.NodeHealth{
		Scope: "node", ScopeID: nodeUID, EvaluatedAt: now.Add(-time.Second), State: "healthy",
		Leases:            []controlhealth.LeaseStatus{lease(ComponentNodeSensors), lease(ComponentLifecycleRecorder)},
		MissingComponents: []string{},
		OpenHolds:         []controlhealth.Hold{},
		StartupCapture:    str(capture),
	}
	if capture == StartupCaptureGuarded {
		h.Leases = append(h.Leases, lease(ComponentRuntimeGuard))
	}
	for _, k := range RequiredProbeKinds {
		h.Probes = append(h.Probes, controlhealth.Probe{ProbeKind: k, LastJudgedAt: ts(now.Add(-5 * time.Second)), LastResult: "pass", ConsecutivePasses: 2})
	}
	return h
}

func eval(h *controlhealth.NodeHealth) Decision {
	return Evaluate(Input{NodeUID: nodeUID, BootID: "boot-1", Health: h, Now: now})
}

func TestEvaluateReadyWhenAllConditionsHold(t *testing.T) {
	for _, capture := range []string{StartupCaptureUnsupported, StartupCaptureGuarded} {
		if d := eval(healthyResponse(capture)); !d.Ready {
			t.Fatalf("%s: want ready, got reasons %v", capture, d.Reasons)
		}
	}
}

func TestEvaluateNotReady(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(h *controlhealth.NodeHealth)
		in     func(in *Input)
		reason string
	}{
		{"nil response", nil, func(in *Input) { in.Health = nil }, "control_health_unavailable"},
		{"empty boot id", nil, func(in *Input) { in.BootID = "" }, "boot_id_unknown"},
		{"scope mismatch", func(h *controlhealth.NodeHealth) { h.ScopeID = "other" }, nil, "scope_mismatch"},
		{"missing component", func(h *controlhealth.NodeHealth) { h.MissingComponents = []string{"node-sensors"} }, nil, "missing_component:node-sensors"},
		{"node hold", func(h *controlhealth.NodeHealth) {
			h.OpenHolds = []controlhealth.Hold{{Scope: "node", ScopeID: nodeUID, Reason: "probe_failed"}}
		}, nil, "open_node_hold:probe_failed"},
		{"sensor lease expired", func(h *controlhealth.NodeHealth) { h.Leases[0].LeaseUntil = now.Add(-time.Second) }, nil, "lease_not_valid:node-sensors"},
		{"lease expired at evaluation", func(h *controlhealth.NodeHealth) {
			h.EvaluatedAt = now.Add(20 * time.Second)
		}, nil, "lease_not_valid:node-sensors"},
		{"recorder lease degraded", func(h *controlhealth.NodeHealth) { h.Leases[1].ObservedState = "degraded" }, nil, "lease_not_valid:lifecycle-recorder"},
		{"recorder lease absent", func(h *controlhealth.NodeHealth) { h.Leases = h.Leases[:1] }, nil, "lease_not_valid:lifecycle-recorder"},
		{"guarded without guard lease", func(h *controlhealth.NodeHealth) { h.StartupCapture = str(StartupCaptureGuarded) }, nil, "lease_not_valid:runtime-guard"},
		{"startup capture null", func(h *controlhealth.NodeHealth) { h.StartupCapture = nil }, nil, "startup_capture_unknown"},
		{"startup capture invalid", func(h *controlhealth.NodeHealth) { h.StartupCapture = str("maybe") }, nil, "startup_capture_invalid:maybe"},
		{"probe one pass", func(h *controlhealth.NodeHealth) { h.Probes[1].ConsecutivePasses = 1 }, nil, "probe_not_passing:tcp"},
		{"probe failed", func(h *controlhealth.NodeHealth) { h.Probes[2].LastResult = "fail" }, nil, "probe_not_passing:file"},
		{"probe unknown", func(h *controlhealth.NodeHealth) { h.Probes[0].LastResult = "unknown" }, nil, "probe_not_passing:process"},
		{"probe missing", func(h *controlhealth.NodeHealth) { h.Probes = h.Probes[1:] }, nil, "probe_missing:process"},
		{"probe predates boot", nil, func(in *Input) { in.ProbesNotBefore = now.Add(-time.Second) }, "probe_not_fresh:process"},
		{"probe within freshness margin", nil, func(in *Input) {
			// Judged 5s ago, 80s after the boot change: the stimulus pair may straddle it.
			in.ProbesNotBefore = now.Add(-85 * time.Second)
		}, "probe_not_fresh:process"},
		{"probe without judgement time", func(h *controlhealth.NodeHealth) { h.Probes[0].LastJudgedAt = nil },
			func(in *Input) { in.ProbesNotBefore = now.Add(-time.Hour) }, "probe_not_fresh:process"},
		{"duplicate failing probe entry", func(h *controlhealth.NodeHealth) {
			h.Probes = append(h.Probes, controlhealth.Probe{ProbeKind: "tcp", LastResult: "fail"})
		}, nil, "probe_not_passing:tcp"},
		{"lease bound to other boot", func(h *controlhealth.NodeHealth) { h.Leases[0].BootID = str("boot-0") }, nil, "lease_not_valid:node-sensors"},
		{"probe bound to other boot", func(h *controlhealth.NodeHealth) { h.Probes[2].BootID = str("boot-0") }, nil, "probe_other_boot:file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := healthyResponse(StartupCaptureUnsupported)
			if tc.mutate != nil {
				tc.mutate(h)
			}
			in := Input{NodeUID: nodeUID, BootID: "boot-1", Health: h, Now: now}
			if tc.in != nil {
				tc.in(&in)
			}
			d := Evaluate(in)
			if d.Ready {
				t.Fatal("want not ready")
			}
			if !strings.Contains(strings.Join(d.Reasons, ","), tc.reason) {
				t.Fatalf("want reason %q, got %v", tc.reason, d.Reasons)
			}
		})
	}
}

func TestEvaluateIgnoresNonNodeHolds(t *testing.T) {
	h := healthyResponse(StartupCaptureUnsupported)
	h.OpenHolds = []controlhealth.Hold{{Scope: "global", ScopeID: "*", Reason: "policy_activation"}}
	if d := eval(h); !d.Ready {
		t.Fatalf("global hold must not gate node taint: %v", d.Reasons)
	}
}

func TestEvaluateProbesAfterBootChange(t *testing.T) {
	h := healthyResponse(StartupCaptureUnsupported)
	// Judged 5s ago, 95s after ProbesNotBefore: both stimuli postdate it.
	d := Evaluate(Input{NodeUID: nodeUID, BootID: "boot-2", Health: h, Now: now, ProbesNotBefore: now.Add(-100 * time.Second)})
	if !d.Ready {
		t.Fatalf("probes judged after the freshness margin should pass: %v", d.Reasons)
	}
	for i := range h.Leases {
		h.Leases[i].BootID = str("boot-2")
	}
	h.Probes[0].BootID = str("boot-2")
	if d := Evaluate(Input{NodeUID: nodeUID, BootID: "boot-2", Health: h, Now: now}); !d.Ready {
		t.Fatalf("matching boot binding: %v", d.Reasons)
	}
}
