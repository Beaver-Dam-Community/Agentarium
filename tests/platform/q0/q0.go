// Package q0 is the TASK-01 Q0 harness: the support table, probe records,
// gate decisions and the run record (COMMON "result record contract").
//
// Probes that need a real cluster live in *_integration_test.go behind the
// `integration` build tag. This file and aggregate.go hold only pure logic.
package q0

import "time"

type Area string

const (
	AreaCompatibility      Area = "compatibility"
	AreaPlacement          Area = "placement"
	AreaPermissions        Area = "permissions"
	AreaRuntimeObservation Area = "runtime_observation"
	AreaStartupGuard       Area = "startup_guard_injection"
)

// Gate says which decision a row feeds. The platform gate and
// startup_guard_gate are independent (TASK-01 chapter 1, chapter 3 item 9).
type Gate string

const (
	GatePlatform     Gate = "platform"
	GateStartupGuard Gate = "startup_guard_gate"
)

type Outcome string

const (
	OutcomePass    Outcome = "pass"
	OutcomeFail    Outcome = "fail"
	OutcomeUnknown Outcome = "unknown"
	OutcomeNotRun  Outcome = "not_run"
)

type Support string

const (
	Supported   Support = "supported"
	Unsupported Support = "unsupported"
)

// ReportStatus values from COMMON enum "report status".
const (
	StatusPass       = "pass"
	StatusFail       = "fail"
	StatusIncomplete = "incomplete"
	StatusNotRun     = "not_run"
)

const (
	StartupCaptureGuarded     = "guarded"
	StartupCaptureUnsupported = "unsupported"
)

// MinStimuliPerKind is "30 or more per kind" (TASK-01 chapter 7 runtime observation).
const MinStimuliPerKind = 30

// MinP95Samples: p95 only with 100+ samples (COMMON result record contract, TASK-01 3.4.1).
const MinP95Samples = 100

// Probe judgement window around a stimulus at t: [t-2s, t+10s] (TASK-10 3.2 probe judgement).
const (
	WindowBefore = 2 * time.Second
	WindowAfter  = 10 * time.Second
)

// ProbeRecord is one Q0 result line (TASK-01 chapter 4):
// probe_id, stimulus, expected_event_type, observed_event_ids, outcome, coverage_limit.
type ProbeRecord struct {
	ProbeID           string   `json:"probe_id"`
	Stimulus          string   `json:"stimulus"`
	ExpectedEventType string   `json:"expected_event_type"`
	ObservedEventIDs  []string `json:"observed_event_ids"`
	Outcome           Outcome  `json:"outcome"`
	CoverageLimit     *string  `json:"coverage_limit"`
}

// Rate stores numerator, denominator and the 95% interval (Wilson score).
type Rate struct {
	Numerator   int     `json:"numerator"`
	Denominator int     `json:"denominator"`
	Value       float64 `json:"value"`
	CI95Low     float64 `json:"ci95_low"`
	CI95High    float64 `json:"ci95_high"`
}

// Row is one line of the Q0 support table.
type Row struct {
	RowID       string  `json:"row_id"`
	Area        Area    `json:"area"`
	Gate        Gate    `json:"gate"`
	Required    bool    `json:"required"`
	SpecRef     string  `json:"spec_ref"`
	Description string  `json:"description"`
	Outcome     Outcome `json:"outcome"`
	// Support is null until the row has a determinate result.
	Support *Support `json:"support"`
	// ObservationRate is measured only for runtime_observation rows.
	ObservationRate *Rate `json:"observation_rate"`
	// TargetRate stays null until TASK-13 fixes the target (TASK-01 chapter 7).
	TargetRate   *float64 `json:"target_rate"`
	UnknownCount *int     `json:"unknown_count"`
	EvidenceRefs []string `json:"evidence_refs"`
	Limitations  []string `json:"limitations"`
}

// Catalog returns every Q0 row in the not_run state.
func Catalog() []Row {
	rows := []Row{
		// Compatibility (TASK-01 chapter 3 item 8, 3.1, chapter 4 lock, COMMON common Q0 list).
		row("compat.node_inventory", AreaCompatibility, GatePlatform, true, "TASK-01 3장 4·8, 4장 lock",
			"pool nodes report COS_CONTAINERD image, kernel and containerd versions"),
		row("compat.hook_support", AreaCompatibility, GatePlatform, true, "TASK-01 3장 8",
			"required Tetragon hooks load on the pinned kernel/runtime"),
		row("compat.event_loss", AreaCompatibility, GatePlatform, true, "TASK-01 3장 8",
			"event loss counters are readable and recorded"),
		row("compat.cgroup_container_identity", AreaCompatibility, GatePlatform, true, "TASK-01 3장 8",
			"cgroup and container identity resolve for observed events"),
		row("compat.host_proc_pid_resolve", AreaCompatibility, GatePlatform, true, "TASK-01 3.1 세션 전용 프로세스",
			"node-sensors resolve host /proc PID namespace and start ticks"),
		row("compat.tetragon_enable_process_ns", AreaCompatibility, GatePlatform, true, "TASK-01 4장",
			"tetragon.enableProcessNs is true and the Helm values digest matches the lock"),

		// Placement (TASK-01 chapter 7 placement bypass, exec profile separation).
		row("placement.control_pool_selector", AreaPlacement, GatePlatform, true, "TASK-01 7장 배치 우회",
			"exec Pod selecting the control pool is rejected"),
		row("placement.host_network", AreaPlacement, GatePlatform, true, "TASK-01 7장 배치 우회",
			"exec Pod with hostNetwork is rejected"),
		row("placement.privileged", AreaPlacement, GatePlatform, true, "TASK-01 7장 배치 우회",
			"privileged exec Pod is rejected"),
		row("placement.runtime_class", AreaPlacement, GatePlatform, true, "TASK-01 7장 배치 우회",
			"exec Pod with a runtimeClass outside the allowlist is rejected"),
		row("placement.start_taint_toleration", AreaPlacement, GatePlatform, true, "TASK-01 7장 배치 우회",
			"exec Pod tolerating the start taint is rejected"),
		row("placement.node_name", AreaPlacement, GatePlatform, true, "TASK-01 3.1",
			"exec Pod with spec.nodeName is rejected"),
		row("placement.no_exec_pod_on_control_or_unready", AreaPlacement, GatePlatform, true, "TASK-01 7장 배치 우회",
			"no agent-exec Pod runs on a control-pool node or a node with the start taint"),
		row("placement.profile_runtime_label_probe_image", AreaPlacement, GatePlatform, true, "TASK-01 7장 exec profile 분리",
			"runtime label with a probe image is rejected"),
		row("placement.profile_probe_label_runtime_sa", AreaPlacement, GatePlatform, true, "TASK-01 7장 exec profile 분리",
			"probe-runner label with the agent-runtime SA is rejected"),
		row("placement.profile_fixture_restart_always", AreaPlacement, GatePlatform, true, "TASK-01 7장 exec profile 분리",
			"start-fixture Pod with restartPolicy Always is rejected"),

		// Permissions (TASK-01 chapter 7 permission separation, drift probe permissions, node-readiness scope).
		row("permissions.exec_sa_no_management_api", AreaPermissions, GatePlatform, true, "TASK-01 7장 권한 분리",
			"agent-runtime token cannot use management APIs"),
		row("permissions.drift_probe_read_only", AreaPermissions, GatePlatform, true, "TASK-01 7장 drift probe 권한",
			"drift-probe token is denied secrets and writes, allowed baseline reads"),
		row("permissions.node_readiness_start_taint", AreaPermissions, GatePlatform, true, "TASK-01 7장 node-readiness 범위",
			"node-readiness token may remove the start taint"),
		row("permissions.node_readiness_other_taint", AreaPermissions, GatePlatform, true, "TASK-01 7장 node-readiness 범위",
			"node-readiness token adding another taint gets NODE_READINESS_SCOPE_INVALID"),
		row("permissions.node_readiness_label", AreaPermissions, GatePlatform, true, "TASK-01 7장 node-readiness 범위",
			"node-readiness token changing a protected label gets NODE_READINESS_SCOPE_INVALID"),
		row("permissions.node_readiness_unschedulable", AreaPermissions, GatePlatform, true, "TASK-01 7장 node-readiness 범위",
			"node-readiness token changing unschedulable gets NODE_READINESS_SCOPE_INVALID"),

		// Runtime observation (TASK-01 chapter 7 runtime observation; stimuli per TASK-10 3.2 answer probe).
		row("runtime.process", AreaRuntimeObservation, GatePlatform, true, "TASK-01 7장 런타임 관측",
			"process exec/exit stimuli observed against an independent answer key"),
		row("runtime.tcp", AreaRuntimeObservation, GatePlatform, true, "TASK-01 7장 런타임 관측",
			"TCP connect/state stimuli observed against an independent answer key"),
		row("runtime.protected_path", AreaRuntimeObservation, GatePlatform, true, "TASK-01 7장 런타임 관측",
			"protected path access stimuli observed against an independent answer key"),

		// startup_guard_gate inputs (TASK-01 3.4.1 Q0 verification items and failure injection table).
		row("startup.gke_nri_socket", AreaCompatibility, GateStartupGuard, true, "TASK-01 3.4.1",
			"GKE node image enables NRI, exposes the socket and accepts an external plugin"),
		row("startup.required_plugins_stage", AreaCompatibility, GateStartupGuard, true, "TASK-01 3.4.1",
			"stage at which required_plugins is checked on the pinned containerd"),
	}
	for _, id := range InjectionRowIDs {
		rows = append(rows, row(id, AreaStartupGuard, GateStartupGuard, true, "TASK-01 3.4.1 Q0 실패 주입", injectionDescriptions[id]))
	}
	return rows
}

func row(id string, area Area, gate Gate, required bool, ref, desc string) Row {
	return Row{
		RowID: id, Area: area, Gate: gate, Required: required, SpecRef: ref, Description: desc,
		Outcome: OutcomeNotRun, EvidenceRefs: []string{}, Limitations: []string{},
	}
}

// Injection rows, one per line of the TASK-01 3.4.1 failure-injection table.
const (
	InjectSensorUnreachable    = "inject.hook_sensor_unreachable"
	InjectPluginMissing        = "inject.plugin_missing"
	InjectCloseBeforeStart     = "inject.plugin_closed_between_create_start"
	InjectGuardTimeout         = "inject.guard_timeout"
	InjectGuardKill            = "inject.guard_kill_socket_drop"
	InjectAdmissionBypass      = "inject.admission_bypass_variants"
	InjectGenerationChange     = "inject.generation_change_before_start"
	InjectNodeLifecycleRestart = "inject.node_upgrade_repair_restart"
)

var InjectionRowIDs = []string{
	InjectSensorUnreachable, InjectPluginMissing, InjectCloseBeforeStart, InjectGuardTimeout,
	InjectGuardKill, InjectAdmissionBypass, InjectGenerationChange, InjectNodeLifecycleRestart,
}

var injectionDescriptions = map[string]string{
	InjectSensorUnreachable:    "hook present but sensor/bridge/socket fails: first-code witness 0, runtime rejects",
	InjectPluginMissing:        "NRI plugin unregistered, hook missing, guard binary/config removed: start rejected, witness 0",
	InjectCloseBeforeStart:     "plugin connection closed after create, before start: start rejected",
	InjectGuardTimeout:         "guard response exceeds plugin_request_timeout: guard deadline returns non-fatal error first",
	InjectGuardKill:            "guard kill or socket drop: if start is allowed, start_guard_bypass_detected and workload hold",
	InjectAdmissionBypass:      "tolerate-missing annotation, other runtimeClass, stale taint removal, node recreation: bypass execution 0",
	InjectGenerationChange:     "rule/sensor generation change between create and start: re-check before start",
	InjectNodeLifecycleRestart: "node pool upgrade, auto-repair, containerd restart: start taint kept until guard re-verified",
}
