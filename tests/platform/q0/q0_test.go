package q0

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

func bp(b bool) *bool { return &b }

var base = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func passAll(rows []Row, gate Gate) {
	for i := range rows {
		if rows[i].Gate != gate {
			continue
		}
		if rows[i].Area == AreaRuntimeObservation {
			ApplyObservation(&rows[i], Tally{Pass: MinStimuliPerKind})
		} else {
			rows[i].Outcome = OutcomePass
		}
	}
}

func TestCatalogIsNotRunAndUnique(t *testing.T) {
	rows := Catalog()
	seen := map[string]bool{}
	areas := map[Area]int{}
	for _, r := range rows {
		if seen[r.RowID] {
			t.Fatalf("duplicate row %s", r.RowID)
		}
		seen[r.RowID] = true
		areas[r.Area]++
		if r.Outcome != OutcomeNotRun || r.Support != nil || r.ObservationRate != nil || r.TargetRate != nil {
			t.Fatalf("row %s must start not_run with null measurements", r.RowID)
		}
	}
	for _, a := range []Area{AreaCompatibility, AreaPlacement, AreaPermissions, AreaRuntimeObservation, AreaStartupGuard} {
		if areas[a] == 0 {
			t.Fatalf("no rows for area %s", a)
		}
	}
	if areas[AreaStartupGuard] != 8 {
		t.Fatalf("want 8 injection rows (TASK-01 3.4.1 table), got %d", areas[AreaStartupGuard])
	}
	if areas[AreaRuntimeObservation] != 3 {
		t.Fatalf("want process/tcp/protected path rows, got %d", areas[AreaRuntimeObservation])
	}
}

func TestPlatformGate(t *testing.T) {
	rows := Catalog()
	if g := PlatformGate(rows); g.Status != StatusNotRun {
		t.Fatalf("fresh catalog: %s", g.Status)
	}
	passAll(rows, GatePlatform)
	if g := PlatformGate(rows); g.Status != StatusPass {
		t.Fatalf("all supported: %+v", g)
	}

	// Any required row unsupported -> platform gate fails.
	FindRow(rows, "runtime.tcp").Outcome = OutcomeFail
	g := PlatformGate(rows)
	if g.Status != StatusFail || !reflect.DeepEqual(g.FailedRows, []string{"runtime.tcp"}) {
		t.Fatalf("unsupported row: %+v", g)
	}

	// Unknown without failures -> incomplete, never pass.
	FindRow(rows, "runtime.tcp").Outcome = OutcomeUnknown
	if g := PlatformGate(rows); g.Status != StatusIncomplete || g.PendingRows[0] != "runtime.tcp" {
		t.Fatalf("unknown row: %+v", g)
	}

	// A runtime row marked pass without a measured rate is not enough.
	tcp := FindRow(rows, "runtime.tcp")
	tcp.Outcome, tcp.ObservationRate = OutcomePass, nil
	if g := PlatformGate(rows); g.Status != StatusIncomplete {
		t.Fatalf("unmeasured supported row: %+v", g)
	}
}

func TestPlatformGateIgnoresStartupRows(t *testing.T) {
	rows := Catalog()
	passAll(rows, GatePlatform)
	FindRow(rows, InjectGuardKill).Outcome = OutcomeFail
	if g := PlatformGate(rows); g.Status != StatusPass {
		t.Fatalf("startup_guard_gate failure must not block the platform gate: %+v", g)
	}
}

func TestStartupGuardGate(t *testing.T) {
	rows := Catalog()
	passAll(rows, GatePlatform)
	if active, capture, _ := StartupGuardGate(rows); active || capture != StartupCaptureUnsupported {
		t.Fatal("not run must be inactive/unsupported")
	}
	passAll(rows, GateStartupGuard)
	if active, capture, g := StartupGuardGate(rows); !active || capture != StartupCaptureGuarded || g.Status != StatusPass {
		t.Fatalf("all injection rows pass: active=%v capture=%s %+v", active, capture, g)
	}
	for _, id := range InjectionRowIDs {
		for _, o := range []Outcome{OutcomeFail, OutcomeUnknown, OutcomeNotRun} {
			rows := Catalog()
			passAll(rows, GateStartupGuard)
			FindRow(rows, id).Outcome = o
			if active, capture, _ := StartupGuardGate(rows); active || capture != StartupCaptureUnsupported {
				t.Fatalf("%s=%s must deactivate startup_guard_gate", id, o)
			}
		}
	}
	// The NRI compatibility rows are startup_guard_gate inputs too.
	rows = Catalog()
	passAll(rows, GateStartupGuard)
	FindRow(rows, "startup.gke_nri_socket").Outcome = OutcomeFail
	if active, _, _ := StartupGuardGate(rows); active {
		t.Fatal("NRI socket unsupported must deactivate startup_guard_gate")
	}
}

func TestFinalizeSupport(t *testing.T) {
	rows := []Row{{RowID: "a", Outcome: OutcomePass}, {RowID: "b", Outcome: OutcomeFail}, {RowID: "c", Outcome: OutcomeUnknown}, {RowID: "d", Outcome: OutcomeNotRun}}
	Finalize(rows)
	if *rows[0].Support != Supported || *rows[1].Support != Unsupported || rows[2].Support != nil || rows[3].Support != nil {
		t.Fatalf("support mapping wrong: %+v", rows)
	}
}

func TestNewRateWilson(t *testing.T) {
	r := NewRate(29, 30)
	if r.Numerator != 29 || r.Denominator != 30 || math.Abs(r.Value-29.0/30) > 1e-12 {
		t.Fatalf("%+v", r)
	}
	// Reference Wilson interval for 29/30: [0.8333, 0.9941].
	if math.Abs(r.CI95Low-0.8333) > 1e-3 || math.Abs(r.CI95High-0.9941) > 1e-3 {
		t.Fatalf("ci %+v", r)
	}
	if NewRate(0, 0) != nil || NewRate(3, 2) != nil {
		t.Fatal("invalid rates must be nil")
	}
	if z := NewRate(0, 30); z.CI95Low != 0 || z.Value != 0 {
		t.Fatalf("zero rate %+v", z)
	}
}

func TestP95(t *testing.T) {
	var s []time.Duration
	for i := 1; i <= 99; i++ {
		s = append(s, time.Duration(i)*time.Millisecond)
	}
	if v, insufficient := P95(s); v != nil || !insufficient {
		t.Fatal("99 samples must be insufficient")
	}
	s = append(s, 100*time.Millisecond)
	v, insufficient := P95(s)
	if insufficient || v == nil || *v != 95 {
		t.Fatalf("p95 of 1..100ms: %v %v", v, insufficient)
	}
}

func processStimulus(i int, truth bool) Stimulus {
	return Stimulus{
		StimulusID: fmt.Sprintf("proc-%03d", i), Kind: "process", At: base.Add(time.Duration(i) * time.Minute),
		ContainerID: "c1", TruthAvailable: truth,
		Expected: []ExpectedEvent{
			{EventType: "process_exec", Attrs: map[string]string{"binary": "/probe/bin/marker"}},
			{EventType: "process_exit", Attrs: map[string]string{"binary": "/probe/bin/marker"}},
		},
	}
}

func processEvents(i int, offset time.Duration, types ...string) []ObservedEvent {
	var out []ObservedEvent
	for _, ty := range types {
		out = append(out, ObservedEvent{
			EventID: fmt.Sprintf("ev-%03d-%s", i, ty), EventType: ty, ContainerID: "c1",
			SourceTime: base.Add(time.Duration(i)*time.Minute + offset), Attrs: map[string]string{"binary": "/probe/bin/marker"},
		})
	}
	return out
}

func TestCountStimuli(t *testing.T) {
	stimuli := []Stimulus{processStimulus(0, true), processStimulus(1, true), processStimulus(2, false), processStimulus(3, true), processStimulus(4, true)}
	var events []ObservedEvent
	events = append(events, processEvents(0, time.Second, "process_exec", "process_exit")...)
	events = append(events, processEvents(1, time.Second, "process_exec")...)                    // exit missing
	events = append(events, processEvents(2, time.Second, "process_exec", "process_exit")...)    // no answer key
	events = append(events, processEvents(3, 11*time.Second, "process_exec", "process_exit")...) // outside window
	ev4 := processEvents(4, -time.Second, "process_exec", "process_exit")
	ev4[0].ContainerID = "other" // wrong container
	events = append(events, ev4...)

	recs, tally := CountStimuli(stimuli, events)
	if tally != (Tally{Pass: 1, Fail: 3, Unknown: 1}) {
		t.Fatalf("tally %+v", tally)
	}
	if len(recs) != 10 {
		t.Fatalf("want one record per expected event, got %d", len(recs))
	}
	if recs[0].Outcome != OutcomePass || recs[0].ObservedEventIDs[0] != "ev-000-process_exec" || recs[0].ExpectedEventType != "process_exec" {
		t.Fatalf("rec0 %+v", recs[0])
	}
	if recs[3].Outcome != OutcomeFail || len(recs[3].ObservedEventIDs) != 0 {
		t.Fatalf("missing exit must fail: %+v", recs[3])
	}
	if recs[4].Outcome != OutcomeUnknown || recs[4].CoverageLimit == nil {
		t.Fatalf("no answer key must be unknown: %+v", recs[4])
	}
}

func TestCountStimuliDoesNotReuseEvents(t *testing.T) {
	a, b := processStimulus(0, true), processStimulus(0, true)
	b.StimulusID = "proc-dup"
	_, tally := CountStimuli([]Stimulus{a, b}, processEvents(0, 0, "process_exec", "process_exit"))
	if tally.Pass != 1 || tally.Fail != 1 {
		t.Fatalf("one event set satisfies one stimulus only: %+v", tally)
	}
}

func TestApplyObservation(t *testing.T) {
	r := FindRow(Catalog(), "runtime.process")
	ApplyObservation(r, Tally{Pass: 20, Fail: 5, Unknown: 9})
	if r.Outcome != OutcomeUnknown || r.ObservationRate.Denominator != 25 || *r.UnknownCount != 9 || r.TargetRate != nil {
		t.Fatalf("below 30 determinate stimuli must be unknown: %+v", r)
	}

	r = FindRow(Catalog(), "runtime.process")
	ApplyObservation(r, Tally{Pass: 28, Fail: 2})
	if r.Outcome != OutcomePass || r.ObservationRate.Value != 28.0/30 {
		t.Fatalf("observed behavior must be supported with a rate: %+v", r)
	}

	r = FindRow(Catalog(), "runtime.process")
	ApplyObservation(r, Tally{Fail: 30})
	if r.Outcome != OutcomeFail || r.ObservationRate.Numerator != 0 {
		t.Fatalf("never observed must be unsupported: %+v", r)
	}
}

func TestFirstCodeVerdict(t *testing.T) {
	notExec := InjectionEvidence{MarkerPathVerified: bp(true), GuardJournalRejected: bp(true), CRIStartedAt: bp(false), MarkerReceived: bp(false)}
	if v := FirstCodeVerdict(notExec); v != FirstCodeNotExecuted {
		t.Fatalf("all three witnesses: %s", v)
	}
	cases := map[string]InjectionEvidence{
		"marker path unverified": {GuardJournalRejected: bp(true), CRIStartedAt: bp(false), MarkerReceived: bp(false)},
		"no journal record":      {MarkerPathVerified: bp(true), CRIStartedAt: bp(false), MarkerReceived: bp(false)},
		"started_at unknown":     {MarkerPathVerified: bp(true), GuardJournalRejected: bp(true), MarkerReceived: bp(false)},
	}
	for name, e := range cases {
		if v := FirstCodeVerdict(e); v != FirstCodeUnknown {
			t.Fatalf("%s: want unknown, got %s", name, v)
		}
	}
	if v := FirstCodeVerdict(InjectionEvidence{GuardJournalRejected: bp(true), MarkerReceived: bp(true)}); v != FirstCodeExecuted {
		t.Fatalf("marker received means executed: %s", v)
	}
	if v := FirstCodeVerdict(InjectionEvidence{CRIStartedAt: bp(true)}); v != FirstCodeExecuted {
		t.Fatalf("StartedAt means executed: %s", v)
	}
}

func TestEvaluateInjectionSample(t *testing.T) {
	notExec := func(id string) InjectionEvidence {
		return InjectionEvidence{RowID: id, MarkerPathVerified: bp(true), GuardJournalRejected: bp(true), CRIStartedAt: bp(false), MarkerReceived: bp(false)}
	}
	exec := func(id string) InjectionEvidence {
		return InjectionEvidence{RowID: id, MarkerPathVerified: bp(true), CRIStartedAt: bp(true), MarkerReceived: bp(true)}
	}
	for _, id := range []string{InjectSensorUnreachable, InjectPluginMissing, InjectCloseBeforeStart, InjectGuardTimeout, InjectGenerationChange} {
		if o := EvaluateInjectionSample(notExec(id)); o != OutcomePass {
			t.Fatalf("%s rejected start: %s", id, o)
		}
		if o := EvaluateInjectionSample(exec(id)); o != OutcomeFail {
			t.Fatalf("%s fail-open start: %s", id, o)
		}
		if o := EvaluateInjectionSample(InjectionEvidence{RowID: id}); o != OutcomeUnknown {
			t.Fatalf("%s no evidence: %s", id, o)
		}
	}

	kill := exec(InjectGuardKill)
	if o := EvaluateInjectionSample(kill); o != OutcomeUnknown {
		t.Fatalf("guard kill executed, detection unknown: %s", o)
	}
	kill.BypassDetected, kill.BypassHold = bp(true), bp(true)
	if o := EvaluateInjectionSample(kill); o != OutcomePass {
		t.Fatalf("guard kill detected and held: %s", o)
	}
	kill.BypassHold = bp(false)
	if o := EvaluateInjectionSample(kill); o != OutcomeFail {
		t.Fatalf("guard kill without hold: %s", o)
	}
	if o := EvaluateInjectionSample(notExec(InjectGuardKill)); o != OutcomePass {
		t.Fatalf("guard kill rejected: %s", o)
	}

	adm := notExec(InjectAdmissionBypass)
	if o := EvaluateInjectionSample(adm); o != OutcomeUnknown {
		t.Fatalf("admission result missing: %s", o)
	}
	adm.AdmissionRejected = bp(true)
	if o := EvaluateInjectionSample(adm); o != OutcomePass {
		t.Fatalf("admission and runtime both block: %s", o)
	}
	adm.AdmissionRejected = bp(false)
	if o := EvaluateInjectionSample(adm); o != OutcomeFail {
		t.Fatalf("admission accepted bypass: %s", o)
	}

	life := notExec(InjectNodeLifecycleRestart)
	life.StartTaintHeld = bp(true)
	if o := EvaluateInjectionSample(life); o != OutcomePass {
		t.Fatalf("taint held: %s", o)
	}
	life.StartTaintHeld = bp(false)
	if o := EvaluateInjectionSample(life); o != OutcomeFail {
		t.Fatalf("taint dropped before re-verification: %s", o)
	}
}

func TestApplyInjection(t *testing.T) {
	good := InjectionEvidence{RowID: InjectPluginMissing, MarkerPathVerified: bp(true), GuardJournalRejected: bp(true), CRIStartedAt: bp(false), MarkerReceived: bp(false), EvidenceRefs: []string{"ref-1"}}
	unknown := InjectionEvidence{RowID: InjectPluginMissing}
	bad := InjectionEvidence{RowID: InjectPluginMissing, CRIStartedAt: bp(true)}

	r := FindRow(Catalog(), InjectPluginMissing)
	ApplyInjection(r, nil)
	if r.Outcome != OutcomeNotRun {
		t.Fatal("no samples is not_run")
	}
	ApplyInjection(r, []InjectionEvidence{good, good})
	if r.Outcome != OutcomePass || len(r.EvidenceRefs) != 2 {
		t.Fatalf("%+v", r)
	}
	r = FindRow(Catalog(), InjectPluginMissing)
	ApplyInjection(r, []InjectionEvidence{good, unknown})
	if r.Outcome != OutcomeUnknown {
		t.Fatalf("one unknown sample: %s", r.Outcome)
	}
	r = FindRow(Catalog(), InjectPluginMissing)
	ApplyInjection(r, []InjectionEvidence{bad, unknown, good})
	if r.Outcome != OutcomeFail {
		t.Fatalf("one failing sample: %s", r.Outcome)
	}
}

func TestApplyAttestation(t *testing.T) {
	r := FindRow(Catalog(), "compat.hook_support")
	ApplyAttestation(r, Attestation{RowID: r.RowID, Outcome: OutcomePass})
	if r.Outcome != OutcomeUnknown {
		t.Fatal("pass without evidence must be unknown")
	}
	r = FindRow(Catalog(), "compat.hook_support")
	ApplyAttestation(r, Attestation{RowID: r.RowID, Outcome: OutcomePass, EvidenceRefs: []string{"gs://private/run/hooks.json"}})
	if r.Outcome != OutcomePass {
		t.Fatal("pass with evidence")
	}
	r = FindRow(Catalog(), "compat.hook_support")
	ApplyAttestation(r, Attestation{RowID: r.RowID, Outcome: "maybe", EvidenceRefs: []string{"x"}})
	if r.Outcome != OutcomeUnknown {
		t.Fatal("invalid outcome must be unknown")
	}
}

func TestBuildReportNotRun(t *testing.T) {
	rep := BuildReport(RunMeta{}, Catalog(), nil, nil)
	b, _ := json.Marshal(rep.Summary)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	commonKeys := []string{"task_id", "status", "implementation_commit", "image_digest", "environment_manifest",
		"policy_bundle_id", "policy_epoch", "run_id", "run_kind", "fixture_set_digest", "baseline_bundle_digest",
		"candidate_digest", "expected_cases", "observed_cases", "passed", "failed", "unknown", "metrics",
		"invariants", "release_eligible", "startup_capture", "evidence_refs", "limitations"}
	sort.Strings(commonKeys)
	var got []string
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, commonKeys) {
		t.Fatalf("summary keys differ from COMMON 결과 기록 계약:\n%v\n%v", got, commonKeys)
	}
	if m["task_id"] != "TASK-01" || m["status"] != "not_run" {
		t.Fatalf("summary %v", m)
	}
	for _, k := range []string{"expected_cases", "passed", "metrics", "invariants", "startup_capture", "release_eligible"} {
		if m[k] != nil {
			t.Fatalf("%s must be null in a not_run record", k)
		}
	}
}

func TestBuildReportAndWrite(t *testing.T) {
	rows := Catalog()
	passAll(rows, GatePlatform)
	FindRow(rows, "runtime.tcp").ObservationRate = nil
	ApplyObservation(FindRow(rows, "runtime.tcp"), Tally{Pass: 1, Fail: 40})
	FindRow(rows, InjectGuardTimeout).Outcome = OutcomeFail

	var lat []time.Duration
	for i := 0; i < 120; i++ {
		lat = append(lat, time.Duration(i)*time.Millisecond)
	}
	recs, _ := CountStimuli([]Stimulus{processStimulus(0, true)}, processEvents(0, 0, "process_exec", "process_exit"))
	rep := BuildReport(RunMeta{}, rows, recs, lat)

	s := rep.Summary
	if s.Status != StatusPass || *s.StartupCapture != StartupCaptureUnsupported || s.Invariants.StartupGuardOn {
		t.Fatalf("platform pass with startup gate failure: %+v", s)
	}
	if s.Invariants.StartupGuardGate.Status != StatusFail || s.Invariants.StartupGuardGate.FailedRows[0] != InjectGuardTimeout {
		t.Fatalf("startup gate %+v", s.Invariants.StartupGuardGate)
	}
	if *s.ExpectedCases != len(rows) || *s.Failed != 1 || s.ReleaseEligible != nil {
		t.Fatalf("counts %+v", s)
	}
	if s.Metrics.ObservationRates["runtime.process"].Denominator != 30 || s.Metrics.StartLatencyP95MS == nil {
		t.Fatalf("metrics %+v", s.Metrics)
	}
	if r := s.Metrics.ObservationRates["runtime.tcp"]; r.Numerator != 1 || r.Denominator != 41 {
		t.Fatalf("tcp rate %+v", r)
	}

	dir := t.TempDir()
	if err := rep.Write(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"summary.json", "support_table.json", "expected.json", "observed.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	fh, _ := os.Open(filepath.Join(dir, "observed.jsonl"))
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	lines := 0
	for sc.Scan() {
		var line map[string]any
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"probe_id", "stimulus", "expected_event_type", "observed_event_ids", "outcome", "coverage_limit"} {
			if _, ok := line[k]; !ok {
				t.Fatalf("observed.jsonl line missing %s", k)
			}
		}
		lines++
	}
	if lines != 2 {
		t.Fatalf("want 2 probe lines, got %d", lines)
	}
	var table []Row
	b, _ := os.ReadFile(filepath.Join(dir, "support_table.json"))
	if err := json.Unmarshal(b, &table); err != nil {
		t.Fatal(err)
	}
	if r := FindRow(table, "runtime.tcp"); *r.Support != Supported || r.TargetRate != nil || r.ObservationRate.Denominator != 41 {
		t.Fatalf("support table row %+v", r)
	}
	if r := FindRow(table, InjectGuardKill); r.Support != nil {
		t.Fatal("not_run row must have null support")
	}
}
