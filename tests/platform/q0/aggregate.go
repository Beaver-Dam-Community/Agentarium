package q0

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ---- Rates ----

// NewRate returns the rate with a Wilson 95% interval, or nil if den == 0.
func NewRate(num, den int) *Rate {
	if den <= 0 || num < 0 || num > den {
		return nil
	}
	const z = 1.959963984540054
	n := float64(den)
	p := float64(num) / n
	d := 1 + z*z/n
	c := (p + z*z/(2*n)) / d
	h := z * math.Sqrt(p*(1-p)/n+z*z/(4*n*n)) / d
	return &Rate{Numerator: num, Denominator: den, Value: p, CI95Low: math.Max(0, c-h), CI95High: math.Min(1, c+h)}
}

// P95 returns the nearest-rank p95 in milliseconds, or nil with
// insufficient=true below MinP95Samples.
func P95(samples []time.Duration) (ms *float64, insufficient bool) {
	if len(samples) < MinP95Samples {
		return nil, true
	}
	s := append([]time.Duration(nil), samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(math.Ceil(0.95*float64(len(s)))) - 1
	v := float64(s[idx]) / float64(time.Millisecond)
	return &v, false
}

// ---- Runtime observation stimulus counting ----

// ExpectedEvent is one kernel event a stimulus must produce. Attrs must all
// match the observed event's attrs.
type ExpectedEvent struct {
	EventType string            `json:"event_type"`
	Attrs     map[string]string `json:"attrs"`
}

// Stimulus is one answer-key action executed by the probe runner.
// TruthAvailable is false when the runner could not independently confirm
// the action happened; such stimuli count as unknown, never as observed.
type Stimulus struct {
	StimulusID     string          `json:"stimulus_id"`
	Kind           string          `json:"kind"`
	At             time.Time       `json:"at"`
	ContainerID    string          `json:"container_id"`
	TruthAvailable bool            `json:"truth_available"`
	Expected       []ExpectedEvent `json:"expected"`
}

// ObservedEvent is a stored kernel event reduced to what matching needs.
type ObservedEvent struct {
	EventID     string            `json:"event_id"`
	EventType   string            `json:"event_type"`
	ContainerID string            `json:"container_id"`
	SourceTime  time.Time         `json:"source_time"`
	Attrs       map[string]string `json:"attrs"`
}

// Tally counts stimuli, not events.
type Tally struct {
	Pass    int
	Fail    int
	Unknown int
}

// CountStimuli matches each stimulus' expected events against observed
// events of the same container within [at-2s, at+10s]. Each observed event
// satisfies at most one expectation. A stimulus passes only if every
// expected event is found.
func CountStimuli(stimuli []Stimulus, events []ObservedEvent) ([]ProbeRecord, Tally) {
	sorted := append([]Stimulus(nil), stimuli...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].At.Before(sorted[j].At) })
	used := map[string]bool{}
	var recs []ProbeRecord
	var t Tally

	for _, s := range sorted {
		stim := s.StimulusID
		outcome := OutcomePass
		if len(s.Expected) == 0 {
			outcome = OutcomeUnknown
		}
		for i, exp := range s.Expected {
			rec := ProbeRecord{
				ProbeID:           fmt.Sprintf("%s/%d", s.StimulusID, i),
				Stimulus:          stim,
				ExpectedEventType: exp.EventType,
				ObservedEventIDs:  []string{},
			}
			for _, e := range events {
				if used[e.EventID] || !matches(s, exp, e) {
					continue
				}
				used[e.EventID] = true
				rec.ObservedEventIDs = append(rec.ObservedEventIDs, e.EventID)
				break
			}
			switch {
			case !s.TruthAvailable:
				rec.Outcome = OutcomeUnknown
				lim := "no independent answer key for this stimulus"
				rec.CoverageLimit = &lim
			case len(rec.ObservedEventIDs) > 0:
				rec.Outcome = OutcomePass
			default:
				rec.Outcome = OutcomeFail
			}
			outcome = combine(outcome, rec.Outcome)
			recs = append(recs, rec)
		}
		switch outcome {
		case OutcomePass:
			t.Pass++
		case OutcomeFail:
			t.Fail++
		default:
			t.Unknown++
		}
	}
	return recs, t
}

func matches(s Stimulus, exp ExpectedEvent, e ObservedEvent) bool {
	if e.EventType != exp.EventType || e.ContainerID != s.ContainerID {
		return false
	}
	if e.SourceTime.Before(s.At.Add(-WindowBefore)) || e.SourceTime.After(s.At.Add(WindowAfter)) {
		return false
	}
	for k, v := range exp.Attrs {
		if e.Attrs[k] != v {
			return false
		}
	}
	return true
}

// combine: unknown dominates (never counted as pass), then fail.
func combine(a, b Outcome) Outcome {
	switch {
	case a == OutcomeUnknown || b == OutcomeUnknown:
		return OutcomeUnknown
	case a == OutcomeFail || b == OutcomeFail:
		return OutcomeFail
	default:
		return OutcomePass
	}
}

// ApplyObservation sets a runtime_observation row from a tally.
// The rate is pass / (pass + fail); unknown stimuli are reported separately.
// SPEC-QUESTION: the support threshold is not fixed; a behavior is
// "supported" once it is observed at least once over >= 30 determinate
// stimuli and "unsupported" if never observed. The target rate stays null.
func ApplyObservation(r *Row, t Tally) {
	den := t.Pass + t.Fail
	unknown := t.Unknown
	r.UnknownCount = &unknown
	r.ObservationRate = NewRate(t.Pass, den)
	r.TargetRate = nil
	switch {
	case den < MinStimuliPerKind:
		r.Outcome = OutcomeUnknown
		r.Limitations = append(r.Limitations,
			fmt.Sprintf("only %d determinate stimuli; %d required", den, MinStimuliPerKind))
	case t.Pass == 0:
		r.Outcome = OutcomeFail
	default:
		r.Outcome = OutcomePass
	}
}

// ---- startup_guard_gate failure injection ----

// InjectionEvidence is one injection sample. Nil means not established.
type InjectionEvidence struct {
	RowID string `json:"row_id"`
	// MarkerPathVerified: a normal fixture's marker arrived over the same path
	// right before the test (TASK-06 chapter 3), so marker absence is meaningful.
	MarkerPathVerified   *bool    `json:"marker_path_verified"`
	GuardJournalRejected *bool    `json:"guard_journal_rejected"`
	CRIStartedAt         *bool    `json:"cri_started_at_present"`
	MarkerReceived       *bool    `json:"marker_received"`
	BypassDetected       *bool    `json:"start_guard_bypass_detected"`
	BypassHold           *bool    `json:"bypass_detected_hold"`
	AdmissionRejected    *bool    `json:"admission_rejected"`
	StartTaintHeld       *bool    `json:"start_taint_held"`
	StartLatencyMS       *float64 `json:"start_latency_ms"`
	EvidenceRefs         []string `json:"evidence_refs"`
}

type FirstCode string

const (
	FirstCodeNotExecuted FirstCode = "not_executed"
	FirstCodeExecuted    FirstCode = "executed"
	FirstCodeUnknown     FirstCode = "unknown"
)

func isTrue(b *bool) bool  { return b != nil && *b }
func isFalse(b *bool) bool { return b != nil && !*b }

// FirstCodeVerdict applies COMMON "first-code not-executed verdict": not executed only
// with a guard journal rejection, no CRI StartedAt and no marker (over a
// verified marker path). Any positive start evidence means executed.
func FirstCodeVerdict(e InjectionEvidence) FirstCode {
	if isTrue(e.CRIStartedAt) || isTrue(e.MarkerReceived) {
		return FirstCodeExecuted
	}
	if isTrue(e.GuardJournalRejected) && isFalse(e.CRIStartedAt) && isFalse(e.MarkerReceived) && isTrue(e.MarkerPathVerified) {
		return FirstCodeNotExecuted
	}
	return FirstCodeUnknown
}

// EvaluateInjectionSample applies the "required verdict" column of the TASK-01 3.4.1 table.
func EvaluateInjectionSample(e InjectionEvidence) Outcome {
	fc := FirstCodeVerdict(e)
	switch e.RowID {
	case InjectSensorUnreachable, InjectPluginMissing, InjectCloseBeforeStart, InjectGuardTimeout, InjectGenerationChange:
		return firstCodeOutcome(fc)
	case InjectGuardKill:
		switch fc {
		case FirstCodeNotExecuted:
			return OutcomePass
		case FirstCodeExecuted:
			// Fail-open path: acceptable only when detected and held.
			if isTrue(e.BypassDetected) && isTrue(e.BypassHold) {
				return OutcomePass
			}
			if isFalse(e.BypassDetected) || isFalse(e.BypassHold) {
				return OutcomeFail
			}
		}
		return OutcomeUnknown
	case InjectAdmissionBypass:
		if isFalse(e.AdmissionRejected) || fc == FirstCodeExecuted {
			return OutcomeFail
		}
		if isTrue(e.AdmissionRejected) && fc == FirstCodeNotExecuted {
			return OutcomePass
		}
		return OutcomeUnknown
	case InjectNodeLifecycleRestart:
		if isFalse(e.StartTaintHeld) || fc == FirstCodeExecuted {
			return OutcomeFail
		}
		if isTrue(e.StartTaintHeld) && fc == FirstCodeNotExecuted {
			return OutcomePass
		}
		return OutcomeUnknown
	}
	return OutcomeUnknown
}

func firstCodeOutcome(fc FirstCode) Outcome {
	switch fc {
	case FirstCodeNotExecuted:
		return OutcomePass
	case FirstCodeExecuted:
		return OutcomeFail
	}
	return OutcomeUnknown
}

// ApplyInjection sets an injection row: any failing sample fails the row;
// it passes only if every sample passes.
func ApplyInjection(r *Row, samples []InjectionEvidence) {
	if len(samples) == 0 {
		r.Outcome = OutcomeNotRun
		return
	}
	out := OutcomePass
	for _, s := range samples {
		switch EvaluateInjectionSample(s) {
		case OutcomeFail:
			out = OutcomeFail
		case OutcomeUnknown:
			if out != OutcomeFail {
				out = OutcomeUnknown
			}
		}
		r.EvidenceRefs = append(r.EvidenceRefs, s.EvidenceRefs...)
	}
	r.Outcome = out
}

// ---- Gates ----

type GateResult struct {
	Status      string   `json:"status"`
	FailedRows  []string `json:"failed_rows"`
	PendingRows []string `json:"pending_rows"`
}

// Attestation is an operator-recorded result for a row that the harness
// cannot measure itself (node-level checks).
type Attestation struct {
	RowID        string   `json:"row_id"`
	Outcome      Outcome  `json:"outcome"`
	EvidenceRefs []string `json:"evidence_refs"`
	Limitations  []string `json:"limitations"`
}

// ApplyAttestation records an attested outcome. A pass or fail without an
// evidence reference is downgraded to unknown.
func ApplyAttestation(r *Row, a Attestation) {
	out := a.Outcome
	switch out {
	case OutcomePass, OutcomeFail:
		if len(a.EvidenceRefs) == 0 {
			out = OutcomeUnknown
			r.Limitations = append(r.Limitations, "attested result without evidence reference")
		}
	case OutcomeUnknown:
	default:
		out = OutcomeUnknown
	}
	r.Outcome = out
	r.EvidenceRefs = append(r.EvidenceRefs, a.EvidenceRefs...)
	r.Limitations = append(r.Limitations, a.Limitations...)
}

// Finalize derives Support from Outcome: pass -> supported,
// fail -> unsupported, anything else -> null.
func Finalize(rows []Row) {
	for i := range rows {
		r := &rows[i]
		r.Support = nil
		switch r.Outcome {
		case OutcomePass:
			s := Supported
			r.Support = &s
		case OutcomeFail:
			s := Unsupported
			r.Support = &s
		}
	}
}

func evaluateGate(rows []Row, gate Gate) GateResult {
	g := GateResult{FailedRows: []string{}, PendingRows: []string{}}
	ran := false
	for _, r := range rows {
		if r.Gate != gate || !r.Required {
			continue
		}
		if r.Outcome != OutcomeNotRun {
			ran = true
		}
		switch {
		case r.Outcome == OutcomeFail:
			g.FailedRows = append(g.FailedRows, r.RowID)
		case r.Outcome == OutcomePass && measured(r):
		default:
			g.PendingRows = append(g.PendingRows, r.RowID)
		}
	}
	switch {
	case !ran:
		g.Status = StatusNotRun
	case len(g.FailedRows) > 0:
		g.Status = StatusFail
	case len(g.PendingRows) > 0:
		g.Status = StatusIncomplete
	default:
		g.Status = StatusPass
	}
	return g
}

// measured: a supported runtime_observation row must carry a rate over at
// least MinStimuliPerKind determinate stimuli (TASK-01 chapter 7 runtime observation).
func measured(r Row) bool {
	if r.Area != AreaRuntimeObservation {
		return true
	}
	return r.ObservationRate != nil && r.ObservationRate.Denominator >= MinStimuliPerKind
}

// PlatformGate fails if any required platform row is unsupported, and passes
// only if every required platform row is supported (TASK-01 chapter 3 item 9, chapter 7).
func PlatformGate(rows []Row) GateResult { return evaluateGate(rows, GatePlatform) }

// StartupGuardGate is active only if every startup_guard_gate row passes
// (TASK-01 chapter 7 startup guarantee). Otherwise startup_capture = unsupported.
// It never changes the platform gate.
func StartupGuardGate(rows []Row) (active bool, capture string, g GateResult) {
	g = evaluateGate(rows, GateStartupGuard)
	if g.Status == StatusPass {
		return true, StartupCaptureGuarded, g
	}
	return false, StartupCaptureUnsupported, g
}

// ---- Run record (COMMON result record contract) ----

// Summary has exactly the COMMON record keys; unmeasured values stay null.
type Summary struct {
	TaskID               string      `json:"task_id"`
	Status               string      `json:"status"`
	ImplementationCommit *string     `json:"implementation_commit"`
	ImageDigest          *string     `json:"image_digest"`
	EnvironmentManifest  *string     `json:"environment_manifest"`
	PolicyBundleID       *string     `json:"policy_bundle_id"`
	PolicyEpoch          *int64      `json:"policy_epoch"`
	RunID                *string     `json:"run_id"`
	RunKind              *string     `json:"run_kind"`
	FixtureSetDigest     *string     `json:"fixture_set_digest"`
	BaselineBundleDigest *string     `json:"baseline_bundle_digest"`
	CandidateDigest      *string     `json:"candidate_digest"`
	ExpectedCases        *int        `json:"expected_cases"`
	ObservedCases        *int        `json:"observed_cases"`
	Passed               *int        `json:"passed"`
	Failed               *int        `json:"failed"`
	Unknown              *int        `json:"unknown"`
	Metrics              *Metrics    `json:"metrics"`
	Invariants           *Invariants `json:"invariants"`
	ReleaseEligible      *bool       `json:"release_eligible"`
	StartupCapture       *string     `json:"startup_capture"`
	EvidenceRefs         []string    `json:"evidence_refs"`
	Limitations          []string    `json:"limitations"`
}

// SPEC-QUESTION: COMMON leaves the inner shape of metrics/invariants open.
// TASK-01 keys are used: per-row observation rates, start latency p95, and
// the two gate decisions.
type Metrics struct {
	ObservationRates        map[string]*Rate `json:"observation_rates"`
	StartLatencyP95MS       *float64         `json:"start_latency_p95_ms"`
	StartLatencySampleCount int              `json:"start_latency_sample_count"`
	InsufficientSample      bool             `json:"insufficient_sample"`
}

type Invariants struct {
	PlatformGate     GateResult `json:"platform_gate"`
	StartupGuardGate GateResult `json:"startup_guard_gate"`
	StartupGuardOn   bool       `json:"startup_guard_gate_active"`
}

// RunMeta are values fixed before a run; nil stays null in the record.
type RunMeta struct {
	ImplementationCommit *string
	ImageDigest          *string
	EnvironmentManifest  *string
	RunID                *string
	EvidenceRefs         []string
	Limitations          []string
}

type Report struct {
	Summary Summary
	Rows    []Row
	Probes  []ProbeRecord
}

// BuildReport finalizes rows and builds the summary. A run with no executed
// row is a not_run record with every measured field null.
func BuildReport(meta RunMeta, rows []Row, probes []ProbeRecord, startLatencies []time.Duration) Report {
	Finalize(rows)
	platform := PlatformGate(rows)
	active, capture, startup := StartupGuardGate(rows)

	s := Summary{
		TaskID:               "TASK-01",
		Status:               platform.Status,
		ImplementationCommit: meta.ImplementationCommit,
		ImageDigest:          meta.ImageDigest,
		EnvironmentManifest:  meta.EnvironmentManifest,
		RunID:                meta.RunID,
		EvidenceRefs:         append([]string{}, meta.EvidenceRefs...),
		Limitations:          append([]string{}, meta.Limitations...),
	}
	var observed, passed, failed, unknown int
	for _, r := range rows {
		switch r.Outcome {
		case OutcomePass:
			passed++
		case OutcomeFail:
			failed++
		case OutcomeUnknown:
			unknown++
		}
		if r.Outcome != OutcomeNotRun {
			observed++
		}
	}
	if observed == 0 {
		s.Status = StatusNotRun
		s.Limitations = append(s.Limitations, "실제 기능 시험 없음")
		if probes == nil {
			probes = []ProbeRecord{}
		}
		return Report{Summary: s, Rows: rows, Probes: probes}
	}

	expected := len(rows)
	s.ExpectedCases, s.ObservedCases = &expected, &observed
	s.Passed, s.Failed, s.Unknown = &passed, &failed, &unknown
	s.StartupCapture = &capture

	m := &Metrics{ObservationRates: map[string]*Rate{}, StartLatencySampleCount: len(startLatencies)}
	for _, r := range rows {
		if r.Area == AreaRuntimeObservation {
			m.ObservationRates[r.RowID] = r.ObservationRate
		}
	}
	m.StartLatencyP95MS, m.InsufficientSample = P95(startLatencies)
	s.Metrics = m
	s.Invariants = &Invariants{PlatformGate: platform, StartupGuardGate: startup, StartupGuardOn: active}
	if probes == nil {
		probes = []ProbeRecord{}
	}
	return Report{Summary: s, Rows: rows, Probes: probes}
}

// Write stores summary.json, support_table.json, expected.json and
// observed.jsonl under dir (evidence/gcp/runs/<run_id>/ layout).
func (r Report) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "summary.json"), r.Summary); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "support_table.json"), r.Rows); err != nil {
		return err
	}
	type expectation struct {
		RowID       string `json:"row_id"`
		Gate        Gate   `json:"gate"`
		Required    bool   `json:"required"`
		SpecRef     string `json:"spec_ref"`
		Description string `json:"description"`
	}
	exp := make([]expectation, 0, len(r.Rows))
	for _, row := range r.Rows {
		exp = append(exp, expectation{row.RowID, row.Gate, row.Required, row.SpecRef, row.Description})
	}
	if err := writeJSON(filepath.Join(dir, "expected.json"), exp); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, p := range r.Probes {
		if err := enc.Encode(p); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "observed.jsonl"), buf.Bytes(), 0o640)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o640)
}

// FindRow returns a pointer into rows, or nil.
func FindRow(rows []Row, id string) *Row {
	for i := range rows {
		if rows[i].RowID == id {
			return &rows[i]
		}
	}
	return nil
}
