package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/certs"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/gwclient"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/ipc"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/isolation"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/procinfo"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/spawn"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/worker"
)

// fakeSpawner runs worker.Run in-process over a pipe.
type fakeSpawner struct {
	mu      sync.Mutex
	spawns  int
	apply   func() (isolation.Report, error)
	outcome string
	err     error
}

type fakeWorker struct {
	conn *ipc.Conn
	done chan struct{}
	peer net.Conn
}

func (w *fakeWorker) Conn() *ipc.Conn { return w.conn }
func (w *fakeWorker) Pid() int        { return 4242 }
func (w *fakeWorker) Wait() error     { <-w.done; return nil }
func (w *fakeWorker) Kill() error     { _ = w.peer.Close(); return nil }

func (f *fakeSpawner) Spawn(sessionID, wid string) (spawn.Worker, error) {
	f.mu.Lock()
	f.spawns++
	f.mu.Unlock()
	a, b := net.Pipe()
	w := &fakeWorker{conn: ipc.New(a), done: make(chan struct{}), peer: b}
	go func() {
		out, err := worker.Run(ipc.New(b), f.apply, nil)
		f.mu.Lock()
		f.outcome, f.err = out, err
		f.mu.Unlock()
		_ = b.Close()
		close(w.done)
	}()
	return w, nil
}

func okApply() (isolation.Report, error) {
	return isolation.Report{Profile: isolation.Expected(), Arch: "test", Checks: map[string]string{"dumpable": "0"}}, nil
}

func fakeHint(pid int) (procinfo.Hint, error) {
	return procinfo.Hint{LocalPID: int64(pid), PIDNSInode: 4026531836, StartTicks: int64(pid) * 10}, nil
}

type harness struct {
	g  *fakeGateway
	sp *fakeSpawner
	s  *Supervisor
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pki := newPKI(t)
	g := newFakeGateway(t, pki)
	m := &certs.Manager{TokenFile: tokenFile(t), Roots: pki.roots, Namespace: "agent-exec", KSA: "agent-runtime"}
	gw, err := gwclient.New(g.srv.URL, pki.roots, gatewaySAN, m.GetClientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(context.Background(), gw); err != nil {
		t.Fatal(err)
	}
	if m.SAN() != g.podSAN {
		t.Fatalf("issued SAN %q, gateway saw %q", m.SAN(), g.podSAN)
	}
	digest, _ := isolation.Digest()
	sp := &fakeSpawner{apply: okApply}
	s := &Supervisor{GW: gw, Spawn: sp, Epoch: uuid.NewString(), Cfg: Config{
		Task:                   Task{TargetID: "receiver-primary", Summary: "합성 요약 SYN-USER-0001"},
		AllowedOperations:      []string{worker.OperationReceiverSubmit},
		IsolationProfileDigest: digest, Hint: fakeHint, SupervisorPID: 1, SourceVersion: "runtime-test",
		AssignmentPoll: 10 * time.Millisecond, AssignmentTimeout: 2 * time.Second,
		ObservePoll: 10 * time.Millisecond, ObserveTimeout: 2 * time.Second,
		CheckPoll: 10 * time.Millisecond, CheckTimeout: 2 * time.Second,
		ApprovalPoll: 20 * time.Millisecond, ApprovalTimeout: 3 * time.Second,
		ResultPoll: 10 * time.Millisecond, ResultTimeout: 2 * time.Second,
		WorkerExitTimeout: time.Second, Backoff503: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond},
	}}
	return &harness{g: g, sp: sp, s: s}
}

func (h *harness) run(t *testing.T) (Outcome, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return h.s.Run(ctx)
}

func TestHappyPath(t *testing.T) {
	h := newHarness(t)
	out, err := h.run(t)
	if err != nil {
		t.Fatalf("run: %v (%+v)", err, out)
	}
	g := h.g
	if h.sp.spawns != 1 || g.claims != 1 || len(g.registrations) != 1 {
		t.Fatalf("spawns %d claims %d registrations %d", h.sp.spawns, g.claims, len(g.registrations))
	}
	reg := g.registrations[0]
	for _, k := range []string{"worker_instance_id", "runtime_process_epoch", "supervisor_process_hint", "worker_process_hint", "isolation_profile_digest", "controls_report"} {
		if _, ok := reg[k]; !ok {
			t.Errorf("registration lacks %s", k)
		}
	}
	var wh procinfo.Hint
	_ = json.Unmarshal(reg["worker_process_hint"], &wh)
	if wh.LocalPID != 4242 || wh.StartTicks != 42420 || wh.PIDNSInode != 4026531836 {
		t.Errorf("worker hint %+v", wh)
	}
	if g.workerGets <= g.observeAfter {
		t.Errorf("work released after %d binding polls (observed after %d)", g.workerGets, g.observeAfter)
	}
	if want := []string{"agent_work_start_requested", "agent_work_started", "agent_work_finished"}; !slices.Equal(g.events, want) {
		t.Errorf("events %v, want %v", g.events, want)
	}
	if len(g.submits) != 1 {
		t.Fatalf("submits %d", len(g.submits))
	}
	sub := g.submits[0]
	if sub.Checkpoint != "control_step" || sub.WorkRunID != out.WorkRunID || sub.SessionID != g.sessionID {
		t.Errorf("submit %+v, outcome %+v", sub, out)
	}
	var op string
	_ = json.Unmarshal(sub.Body["operation_id"], &op)
	if op != "receiver.submit" || !strings.Contains(string(sub.Body["requested_target"]), `"receiver-primary"`) ||
		!strings.Contains(string(sub.Body["arguments"]), `"email":null`) {
		t.Errorf("body %s %s %s", op, sub.Body["requested_target"], sub.Body["arguments"])
	}
	if out.ExecutionState != "effect_verified" || out.Verdict != "allow" || !out.WorkStarted || out.RootExecID != "root-exec-1" {
		t.Errorf("outcome %+v", out)
	}
	if len(out.CheckIDs) != 2 || out.CheckIDs[1] != sub.CheckID {
		t.Errorf("check ids %v, submit check %s", out.CheckIDs, sub.CheckID)
	}
	if !slices.Equal(g.closes, []string{"work_finished"}) {
		t.Errorf("closes %v", g.closes)
	}
	if h.sp.outcome != "effect_verified" || h.sp.err != nil {
		t.Errorf("worker outcome %q %v", h.sp.outcome, h.sp.err)
	}
}

// A 2xx that is not a TASK-07 ack for this event is not an ack either.
func TestWorkEventWithoutAckReleasesNoWork(t *testing.T) {
	for _, status := range []int{200, 201, 202, 204} {
		h := newHarness(t)
		h.g.workEventAck = status
		out, err := h.run(t)
		if err == nil || !strings.HasPrefix(out.Error, ErrWorkEventUnacked) {
			t.Fatalf("%d: err %v outcome %+v", status, err, out)
		}
		if out.WorkStarted || len(h.g.submits) != 0 || h.sp.outcome != "stopped" {
			t.Fatalf("%d: work started %v submits %d worker %q", status, out.WorkStarted, len(h.g.submits), h.sp.outcome)
		}
	}
}

// Without a work-events relay (gateway before the #234 follow-up) the start
// intent is never acknowledged, so the worker is never released and nothing
// is submitted.
func TestWorkEventsUnavailableReleasesNoWork(t *testing.T) {
	h := newHarness(t)
	h.g.workEvents404 = true
	out, err := h.run(t)
	if err == nil || !strings.HasPrefix(out.Error, ErrWorkEventUnacked) {
		t.Fatalf("err %v outcome %+v", err, out)
	}
	if out.WorkStarted || len(h.g.submits) != 0 || h.sp.outcome != "stopped" {
		t.Fatalf("work started %v submits %d worker %q", out.WorkStarted, len(h.g.submits), h.sp.outcome)
	}
	if !slices.Equal(h.g.closes, []string{"supervisor_aborted"}) {
		t.Errorf("closes %v", h.g.closes)
	}
}

func TestIsolationFailureRegistersNothing(t *testing.T) {
	h := newHarness(t)
	h.sp.apply = func() (isolation.Report, error) { return isolation.Report{}, errors.New("no seccomp") }
	out, err := h.run(t)
	if err == nil || !strings.HasPrefix(out.Error, ErrIsolation) {
		t.Fatalf("err %v outcome %+v", err, out)
	}
	if len(h.g.registrations) != 0 || len(h.g.closes) != 0 || len(h.g.submits) != 0 {
		t.Fatalf("registrations %d closes %d submits %d", len(h.g.registrations), len(h.g.closes), len(h.g.submits))
	}
}

func TestBlockedCheckStartsNothing(t *testing.T) {
	h := newHarness(t)
	h.g.checkState = "blocked"
	out, err := h.run(t)
	if err == nil || !strings.HasPrefix(out.Error, "POD_OBSERVATION_NOT_READY") {
		t.Fatalf("err %v outcome %+v", err, out)
	}
	if out.WorkStarted || len(h.g.events) != 0 || len(h.g.submits) != 0 {
		t.Fatalf("started %v events %v submits %d", out.WorkStarted, h.g.events, len(h.g.submits))
	}
}

func TestBindingNeverObserved(t *testing.T) {
	h := newHarness(t)
	h.g.observeAfter = 1 << 30
	h.s.Cfg.ObserveTimeout = 100 * time.Millisecond
	out, err := h.run(t)
	if err == nil || !strings.HasPrefix(out.Error, ErrWorkerNotReady) || len(h.g.checks) != 0 {
		t.Fatalf("err %v outcome %+v checks %d", err, out, len(h.g.checks))
	}
}

// A lapsed readiness result is re-sent as the same request (same
// client_request_key) with a new control_step check, never a new action.
func TestSubmit503ResendsSameRequest(t *testing.T) {
	h := newHarness(t)
	h.g.submit503 = 1
	out, err := h.run(t)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	s := h.g.submits
	if len(s) != 2 || s[0].ClientKey != s[1].ClientKey || s[0].CheckID == s[1].CheckID || s[1].Checkpoint != "control_step" {
		t.Fatalf("submits %+v", s)
	}
	if out.ExecutionState != "effect_verified" {
		t.Fatalf("outcome %+v", out)
	}
}

func TestApprovalWaitThenReevaluate(t *testing.T) {
	h := newHarness(t)
	h.g.approvalMode = true
	// approve after the second resume attempt
	go func() {
		for {
			time.Sleep(5 * time.Millisecond)
			h.g.mu.Lock()
			if len(h.g.reevals) >= 2 {
				h.g.approved = true
				h.g.mu.Unlock()
				return
			}
			h.g.mu.Unlock()
		}
	}()
	out, err := h.run(t)
	if err != nil {
		t.Fatalf("run: %v (%+v)", err, out)
	}
	if len(h.g.submits) != 1 {
		t.Fatalf("submits %d", len(h.g.submits))
	}
	if len(h.g.reevals) < 3 {
		t.Fatalf("reevaluations %d", len(h.g.reevals))
	}
	seen := map[string]bool{}
	for _, r := range h.g.reevals {
		if r.Checkpoint != "resume" || r.WorkRunID != out.WorkRunID || seen[r.CheckID] {
			t.Errorf("reevaluate %+v", r)
		}
		seen[r.CheckID] = true
	}
	if out.Verdict != "allow" || out.ExecutionState != "effect_verified" {
		t.Fatalf("outcome %+v", out)
	}
}

func TestApprovalTimeoutStops(t *testing.T) {
	h := newHarness(t)
	h.g.approvalMode = true
	h.s.Cfg.ApprovalTimeout = 80 * time.Millisecond
	out, err := h.run(t)
	if err == nil || out.Verdict != "approval_required" || out.ExecutionState != "" {
		t.Fatalf("err %v outcome %+v", err, out)
	}
	if len(h.g.submits) != 1 {
		t.Fatalf("submits %d", len(h.g.submits))
	}
}

func TestUnlistedOperationNotForwarded(t *testing.T) {
	h := newHarness(t)
	h.s.Cfg.AllowedOperations = []string{"k8s.pods.list"}
	out, err := h.run(t)
	if err == nil || len(h.g.submits) != 0 || !slices.Equal(out.ReasonCodes, []string{"SCHEMA_INVALID"}) {
		t.Fatalf("err %v submits %d outcome %+v", err, len(h.g.submits), out)
	}
}

func TestModelConversationCannotEscapeWorkerSession(t *testing.T) {
	s := &Supervisor{sessionID: "own-session", Cfg: Config{AllowedOperations: []string{"model.generate"}}}
	for _, tc := range []struct{ target, args string }{
		{`{"profile":"agent"}`, `{"conversation_id":"other-session"}`},
		{`{"profile":"discovery"}`, `{"conversation_id":"own-session"}`},
		{`{"profile":"agent"}`, `{"conversation_id":"other-session","CONVERSATION_ID":"own-session"}`},
		{`{"profile":"agent"}`, `{"CONVERSATION_ID":"own-session"}`},
		{`{"profile":"discovery","profile":"agent"}`, `{"conversation_id":"own-session"}`},
	} {
		// GW is nil: any readiness/network call would fail this test.
		out := s.action(context.Background(), &ipc.ActionRequest{OperationID: "model.generate", RequestedTarget: json.RawMessage(tc.target), Arguments: json.RawMessage(tc.args)}, "", "", "", nil, nil)
		if !slices.Equal(out.ReasonCodes, []string{"PREFLIGHT_MISMATCH"}) {
			t.Fatalf("unexpected result: %+v", out)
		}
	}
}

func TestFinalGatewayResultDecodedAndOmittedFromRunSummary(t *testing.T) {
	h := newHarness(t)
	h.g.resultBody = json.RawMessage(`{"text":"private-model-result"}`)
	out, err := h.run(t)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "private-model-result") {
		t.Fatal("result body leaked to run summary")
	}
	// The fake gateway HTTP client retains the sanitized body for IPC forwarding.
	r, err := h.s.GW.GetResult(context.Background(), h.g.token, h.g.actionID)
	if err != nil || string(r.ResultBody) != string(h.g.resultBody) || !r.Final {
		t.Fatalf("result %+v, error %v", r, err)
	}
}

func TestApprovalReevaluationRetriesAreBounded(t *testing.T) {
	for _, tc := range []struct {
		code     string
		attempts int
	}{
		{"HOLD_ACTIVE", 1}, {"CONTROL_HEALTH_UNAVAILABLE", 1},
		{"WORK_READINESS_EXPIRED", 4}, {"POLICY_EPOCH_STALE", 2},
	} {
		t.Run(tc.code, func(t *testing.T) {
			h := newHarness(t)
			h.g.approvalMode = true
			h.g.reevaluateError = tc.code
			out, err := h.run(t)
			if err == nil || len(h.g.submits) != 1 || len(h.g.reevals) != tc.attempts || !slices.Equal(out.ReasonCodes, []string{tc.code}) {
				t.Fatalf("err=%v submits=%d reevaluations=%d outcome=%+v", err, len(h.g.submits), len(h.g.reevals), out)
			}
		})
	}
}
