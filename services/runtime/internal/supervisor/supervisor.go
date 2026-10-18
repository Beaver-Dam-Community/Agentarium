// Package supervisor is the trusted supervisor / application session bridge
// of the minimal M3-1 runtime (TASK-15 3.1 session flow, COMMON agent work
// start contract and session-dedicated worker contract). One run handles one session:
//
//  1. poll GET /v1/runtime/assignments and claim the first live assignment
//     with its claim_code (TASK-03 3.3);
//  2. exec one fresh worker, wait for its bootstrap controls ack;
//  3. register it (POST /v1/runtime/session-workers) with the supervisor and
//     worker process hints while the worker waits, and poll the binding
//     until the node witness makes it observed;
//  4. request a start WorkReadinessCheck and wait for ready;
//  5. report agent_work_start_requested and require its ack, then release
//     the worker (go) only while the check is still valid;
//  6. for the worker's one typed request, request a control_step check and
//     submit the ClientAction with X-Agentarium-Work-Run-Id and
//     X-Agentarium-Work-Readiness-Check-Id immediately after ready;
//  7. on approval_required, re-run a resume check and :reevaluate until the
//     verdict changes (TASK-15 3.2), then poll the result;
//  8. hand the outcome to the worker, report agent_work_finished, close the
//     binding and reap the worker.
//
// Everything fails closed: any failure before step 5 releases no work, and
// no step is retried by creating a new action.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/gwclient"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/ipc"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/procinfo"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/spawn"
)

// Gateway is the subset of gwclient.Client the supervisor uses.
type Gateway interface {
	Assignments(ctx context.Context) ([]gwclient.Assignment, error)
	Claim(ctx context.Context, sessionID, code string) (gwclient.SessionToken, error)
	Refresh(ctx context.Context, sessionID, token string) (gwclient.SessionToken, error)
	RegisterWorker(ctx context.Context, token string, r gwclient.WorkerRegistration) (gwclient.WorkerBinding, error)
	GetWorker(ctx context.Context, token, id string) (gwclient.WorkerBinding, error)
	CloseWorker(ctx context.Context, token, id string, r gwclient.WorkerClose) (gwclient.WorkerBinding, error)
	RequestCheck(ctx context.Context, token string, r gwclient.ReadinessRequest) (gwclient.ReadinessCheck, error)
	GetCheck(ctx context.Context, token, id string) (gwclient.ReadinessCheck, error)
	ReportWorkEvent(ctx context.Context, token string, ev gwclient.WorkEvent) (gwclient.WorkEventAck, error)
	SubmitAction(ctx context.Context, token string, a gwclient.ClientAction, ref gwclient.Readiness) (gwclient.ActionResponse, error)
	Reevaluate(ctx context.Context, token, actionID, digest string, ref gwclient.Readiness) (gwclient.ActionResponse, error)
	GetAction(ctx context.Context, token, id string) (gwclient.ActionView, error)
	GetResult(ctx context.Context, token, id string) (gwclient.ActionResult, error)
}

// Spawner starts one worker.
type Spawner interface {
	Spawn(sessionID, workerInstanceID string) (spawn.Worker, error)
}

// Task is the deterministic demo task (operator install input).
type Task struct {
	TargetID string
	Summary  string
	Email    *string
}

// Config holds the timings and inputs of one run. Zero durations take the
// defaults in withDefaults.
type Config struct {
	Task Task
	// AllowedOperations are the worker requests the supervisor forwards.
	AllowedOperations []string
	// IsolationProfileDigest is isolation.Digest().
	IsolationProfileDigest string
	// Hint reads process hints (procinfo.Of on Linux).
	Hint func(pid int) (procinfo.Hint, error)
	// SupervisorPID is os.Getpid().
	SupervisorPID int
	// SourceVersion is the deployed runtime version, the AuditEvent
	// source_version of every agent_work_* report.
	SourceVersion string

	AssignmentPoll    time.Duration // 2s
	AssignmentTimeout time.Duration // 0: wait for ctx
	BootstrapTimeout  time.Duration // 10s for the worker controls ack
	ObservePoll       time.Duration // 1s (#232: exec ACK flush ≤1s)
	ObserveTimeout    time.Duration // 45s (three 15s nonces)
	CheckPoll         time.Duration // 200ms
	CheckTimeout      time.Duration // 20s (challenge timeout 15s)
	StartMargin       time.Duration // 300ms of check validity left before use
	ApprovalPoll      time.Duration // 15s between resume :reevaluate attempts
	ApprovalTimeout   time.Duration // 10m
	ResultPoll        time.Duration // 1s
	ResultTimeout     time.Duration // 60s (receiver evidence deadline 30s)
	RefreshBefore     time.Duration // 5m before token expiry
	WorkerExitTimeout time.Duration // 10s
	// Backoff503 are the waits before re-submitting the same request after
	// a 503 (TASK-15 3.1: 1s·2s·4s, at most three times).
	Backoff503 []time.Duration
}

func (c *Config) withDefaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&c.AssignmentPoll, 2*time.Second)
	def(&c.BootstrapTimeout, 10*time.Second)
	def(&c.ObservePoll, time.Second)
	def(&c.ObserveTimeout, 45*time.Second)
	def(&c.CheckPoll, 200*time.Millisecond)
	def(&c.CheckTimeout, 20*time.Second)
	def(&c.StartMargin, 300*time.Millisecond)
	def(&c.ApprovalPoll, 15*time.Second)
	def(&c.ApprovalTimeout, 10*time.Minute)
	def(&c.ResultPoll, time.Second)
	def(&c.ResultTimeout, 60*time.Second)
	def(&c.RefreshBefore, 5*time.Minute)
	def(&c.WorkerExitTimeout, 10*time.Second)
	if c.Backoff503 == nil {
		c.Backoff503 = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	}
}

// actionBudget bounds readiness/retries, human approval and result collection.
// Each 30s allowance covers multiple bounded HTTP calls. A response may
// fail earlier, but worker IPC must never time out before this context.
func (c Config) actionBudget() time.Duration {
	c.withDefaults()
	budget := c.ApprovalTimeout + c.ApprovalPoll + c.ResultTimeout + 30*time.Second
	budget += time.Duration(len(c.Backoff503)+1) * (c.CheckTimeout + 30*time.Second)
	for _, wait := range c.Backoff503 {
		budget += wait
	}
	return budget
}

// Outcome is the run report (printed as one JSON line by the binary).
type Outcome struct {
	RuntimeProcessEpoch string   `json:"runtime_process_epoch"`
	SessionID           string   `json:"session_id,omitempty"`
	WorkerInstanceID    string   `json:"worker_instance_id,omitempty"`
	WorkerBindingID     string   `json:"worker_binding_id,omitempty"`
	RootExecID          string   `json:"root_exec_id,omitempty"`
	WorkRunID           string   `json:"work_run_id,omitempty"`
	CheckIDs            []string `json:"check_ids,omitempty"`
	WorkStarted         bool     `json:"work_started"`
	ActionID            string   `json:"action_id,omitempty"`
	DecisionID          string   `json:"decision_id,omitempty"`
	Verdict             string   `json:"verdict,omitempty"`
	ExecutionState      string   `json:"execution_state,omitempty"`
	ReasonCodes         []string `json:"reason_codes,omitempty"`
	Error               string   `json:"error,omitempty"`
}

// Supervisor runs one session.
type Supervisor struct {
	GW    Gateway
	Spawn Spawner
	Cfg   Config
	Epoch string // runtime_process_epoch, new UUID per process start
	Log   *slog.Logger

	sessionID string
	token     gwclient.SessionToken
	out       Outcome
}

// Error codes of the supervisor's own failures (reported in Outcome.Error;
// COMMON codes where one exists).
const (
	ErrIsolation        = "WORKER_ISOLATION_NOT_READY"
	ErrWorkerNotReady   = "WORKER_OBSERVATION_NOT_READY"
	ErrWorkerExited     = "WORKER_EXITED"
	ErrReadinessExpired = "WORK_READINESS_EXPIRED"
	// SPEC-QUESTION: no COMMON code names a missing work-events ack.
	ErrWorkEventUnacked = "WORK_START_NOT_ACKNOWLEDGED"
)

type runError struct {
	code string
	err  error
}

func (e *runError) Error() string {
	if e.err == nil {
		return e.code
	}
	return e.code + ": " + e.err.Error()
}

func fail(code string, err error) error { return &runError{code: code, err: err} }

func (s *Supervisor) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Run handles one session and returns its outcome. The error is also in
// Outcome.Error.
func (s *Supervisor) Run(ctx context.Context) (Outcome, error) {
	s.Cfg.withDefaults()
	s.out = Outcome{RuntimeProcessEpoch: s.Epoch}
	err := s.run(ctx)
	if err != nil {
		s.out.Error = err.Error()
	}
	return s.out, err
}

func (s *Supervisor) run(ctx context.Context) (err error) {
	if !canonicalUUID(s.Epoch) || s.Cfg.Hint == nil || s.Cfg.SupervisorPID <= 0 || len(s.Cfg.IsolationProfileDigest) != 64 || s.Cfg.SourceVersion == "" {
		return errors.New("supervisor: incomplete configuration")
	}
	a, err := s.claim(ctx)
	if err != nil {
		return err
	}
	s.sessionID, s.out.SessionID = a.SessionID, a.SessionID

	wid := uuid.NewString()
	s.out.WorkerInstanceID = wid
	w, err := s.Spawn.Spawn(s.sessionID, wid)
	if err != nil {
		return fmt.Errorf("supervisor: spawn worker: %w", err)
	}
	exited := make(chan struct{})
	go func() { _ = w.Wait(); close(exited) }()
	msgs := make(chan msgOrErr, 4)
	go func() {
		for {
			m, err := w.Conn().Recv()
			msgs <- msgOrErr{m, err}
			if err != nil {
				return
			}
		}
	}()
	bindingID := ""
	defer func() { s.shutdown(w, exited, bindingID, err != nil || s.out.Error != "") }()

	controls, err := s.bootstrapAck(ctx, msgs, exited)
	if err != nil {
		return err
	}
	supHint, err := s.Cfg.Hint(s.Cfg.SupervisorPID)
	if err != nil {
		return fmt.Errorf("supervisor: own process hint: %w", err)
	}
	wrkHint, err := s.Cfg.Hint(w.Pid())
	if err != nil {
		return fmt.Errorf("supervisor: worker process hint: %w", err)
	}
	b, err := s.GW.RegisterWorker(ctx, s.tok(ctx), gwclient.WorkerRegistration{
		WorkerInstanceID: wid, RuntimeProcessEpoch: s.Epoch,
		SupervisorProcessHint: supHint, WorkerProcessHint: wrkHint,
		IsolationProfileDigest: s.Cfg.IsolationProfileDigest, ControlsReport: controls,
	})
	if err != nil {
		return fmt.Errorf("supervisor: register worker: %w", err)
	}
	if b.WorkerBindingID == "" || b.WorkerInstanceID != wid || b.SessionID != s.sessionID {
		return errors.New("supervisor: registration answered another binding")
	}
	bindingID, s.out.WorkerBindingID = b.WorkerBindingID, b.WorkerBindingID
	s.log().Info("worker registered", "session_id", s.sessionID, "worker_binding_id", bindingID, "state", b.State)
	if err := s.awaitObserved(ctx, bindingID, exited); err != nil {
		return err
	}

	runID := uuid.NewString()
	s.out.WorkRunID = runID
	ref := func(checkID string) gwclient.Readiness { return gwclient.Readiness{WorkRunID: runID, CheckID: checkID} }

	// Start gate: ready check → start-intent ack → release, all inside the
	// check's validity (COMMON work start 6).
	var startCheck string
	for attempt := 0; ; attempt++ {
		chk, deadline, err := s.ready(ctx, runID, "start", wid, bindingID, exited)
		if err != nil {
			return err
		}
		if _, err := s.GW.ReportWorkEvent(ctx, s.tok(ctx), s.event("agent_work_start_requested", runID, chk.CheckID, wid, bindingID, nil, nil)); err != nil {
			return fail(ErrWorkEventUnacked, err)
		}
		if time.Until(deadline) > s.Cfg.StartMargin {
			startCheck = chk.CheckID
			break
		}
		if attempt >= 2 {
			return fail(ErrReadinessExpired, errors.New("check expired while waiting for the start ack"))
		}
	}
	if err := w.Conn().Send(ipc.Message{Type: ipc.TypeGo, WorkRunID: runID, Task: &ipc.Task{
		ActionTimeoutMS: (s.Cfg.actionBudget() + 30*time.Second).Milliseconds(),
		ConversationID:  s.sessionID, TaskStatement: a.TaskStatement, TargetID: s.Cfg.Task.TargetID, Summary: s.Cfg.Task.Summary, Email: s.Cfg.Task.Email,
	}}); err != nil {
		return fmt.Errorf("supervisor: release worker: %w", err)
	}
	s.out.WorkStarted = true

	// From here on nothing is retried automatically except the same request.
	finished := func(outcome string) {
		if _, err := s.GW.ReportWorkEvent(ctx, s.tok(ctx), s.event("agent_work_finished", runID, startCheck, wid, bindingID, &outcome, nil)); err != nil {
			s.log().Warn("agent_work_finished not acknowledged", "err", err)
		}
	}
	for {
		m, err := s.next(ctx, msgs, exited, 0)
		if err != nil {
			finished("worker_failed")
			return err
		}
		switch m.Type {
		case ipc.TypeStarted:
			if _, err := s.GW.ReportWorkEvent(ctx, s.tok(ctx), s.event("agent_work_started", runID, startCheck, wid, bindingID, nil, nil)); err != nil {
				s.log().Warn("agent_work_started not acknowledged", "err", err)
			}
		case ipc.TypeSubmitAction:
			res := s.action(ctx, m.Action, runID, wid, bindingID, ref, exited)
			if err := w.Conn().Send(ipc.Message{Type: ipc.TypeActionResult, Result: &res}); err != nil {
				finished("worker_failed")
				return fmt.Errorf("supervisor: deliver result: %w", err)
			}
		case ipc.TypeDone:
			finished(m.Outcome)
			if m.Outcome == "failed" {
				return errors.New("worker task failed")
			}
			if s.out.Error != "" {
				return errors.New(s.out.Error)
			}
			return nil
		default:
			finished("protocol_error")
			return fmt.Errorf("supervisor: unexpected worker message %q", m.Type)
		}
	}
}

type msgOrErr struct {
	m   ipc.Message
	err error
}

// next waits for one worker message; timeout 0 waits for ctx.
func (s *Supervisor) next(ctx context.Context, msgs <-chan msgOrErr, exited <-chan struct{}, timeout time.Duration) (ipc.Message, error) {
	var tc <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		tc = t.C
	}
	select {
	case r := <-msgs:
		if r.err != nil {
			return ipc.Message{}, fail(ErrWorkerExited, r.err)
		}
		return r.m, nil
	case <-tc:
		return ipc.Message{}, fail(ErrIsolation, errors.New("worker did not acknowledge bootstrap"))
	case <-ctx.Done():
		return ipc.Message{}, ctx.Err()
	}
}

func (s *Supervisor) bootstrapAck(ctx context.Context, msgs <-chan msgOrErr, exited <-chan struct{}) (json.RawMessage, error) {
	m, err := s.next(ctx, msgs, exited, s.Cfg.BootstrapTimeout)
	if err != nil {
		return nil, err
	}
	if m.Type != ipc.TypeBootstrapAck || m.Controls == nil || m.Error != "" {
		return nil, fail(ErrIsolation, errors.New(m.Error))
	}
	raw, err := json.Marshal(m.Controls)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// claim polls assignments and claims the first unexpired one. A claim lost
// to another replica (CLAIM_CODE_INVALID) goes back to polling.
func (s *Supervisor) claim(ctx context.Context) (gwclient.Assignment, error) {
	var stop <-chan time.Time
	if s.Cfg.AssignmentTimeout > 0 {
		t := time.NewTimer(s.Cfg.AssignmentTimeout)
		defer t.Stop()
		stop = t.C
	}
	for {
		as, err := s.GW.Assignments(ctx)
		if err != nil {
			s.log().Warn("assignments poll failed", "err", err)
		}
		for _, a := range as {
			if !canonicalUUID(a.SessionID) || a.ClaimCode == "" || !time.Now().Before(a.ClaimExpiresAt) {
				continue
			}
			tok, err := s.GW.Claim(ctx, a.SessionID, a.ClaimCode)
			if err != nil {
				s.log().Warn("claim failed", "session_id", a.SessionID, "err", err)
				continue
			}
			if tok.Token == "" {
				continue
			}
			s.token = tok
			s.log().Info("session claimed", "session_id", a.SessionID, "expires_at", tok.ExpiresAt)
			return a, nil
		}
		select {
		case <-ctx.Done():
			return gwclient.Assignment{}, ctx.Err()
		case <-stop:
			return gwclient.Assignment{}, errors.New("supervisor: no assignment before timeout")
		case <-time.After(s.Cfg.AssignmentPoll):
		}
	}
}

// tok returns the session token, refreshing it when it expires soon. A
// failed refresh keeps the current token; the gateway answers 401 once it
// has expired.
func (s *Supervisor) tok(ctx context.Context) string {
	if time.Until(s.token.ExpiresAt) < s.Cfg.RefreshBefore {
		if t, err := s.GW.Refresh(ctx, s.sessionID, s.token.Token); err == nil && t.Token != "" {
			s.token = t
		} else {
			s.log().Warn("session refresh failed", "err", err)
		}
	}
	return s.token.Token
}

// awaitObserved polls the binding until observed (the node witness is
// independent; GET also re-issues an expired nonce, #228/#232).
func (s *Supervisor) awaitObserved(ctx context.Context, id string, exited <-chan struct{}) error {
	deadline := time.Now().Add(s.Cfg.ObserveTimeout)
	for {
		b, err := s.GW.GetWorker(ctx, s.tok(ctx), id)
		switch {
		case err != nil:
			s.log().Warn("binding poll failed", "err", err)
		case b.State == "observed":
			if b.RootExecID != nil {
				s.out.RootExecID = *b.RootExecID
			}
			s.log().Info("worker observed", "worker_binding_id", id, "root_exec_id", s.out.RootExecID)
			return nil
		case b.State != "pending":
			return fail(ErrWorkerNotReady, fmt.Errorf("binding %s %v", b.State, b.ReasonCodes))
		}
		if time.Now().After(deadline) {
			return fail(ErrWorkerNotReady, errors.New("binding not observed before timeout"))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exited:
			return fail(ErrWorkerExited, nil)
		case <-time.After(s.Cfg.ObservePoll):
		}
	}
}

// ready requests one check and polls it to a final state. It returns the
// ready check and the local deadline: the time the GET that returned ready
// was sent plus remaining_valid_ms (COMMON: subtract the GET round-trip time).
func (s *Supervisor) ready(ctx context.Context, runID, checkpoint, wid, bindingID string, exited <-chan struct{}) (gwclient.ReadinessCheck, time.Time, error) {
	select {
	case <-exited:
		return gwclient.ReadinessCheck{}, time.Time{}, fail(ErrWorkerExited, nil)
	default:
	}
	c, err := s.GW.RequestCheck(ctx, s.tok(ctx), gwclient.ReadinessRequest{
		WorkRunID: runID, RuntimeProcessEpoch: s.Epoch, Checkpoint: checkpoint,
		WorkerInstanceID: wid, WorkerBindingID: bindingID,
	})
	if err != nil {
		return c, time.Time{}, fmt.Errorf("supervisor: request %s check: %w", checkpoint, err)
	}
	if !canonicalUUID(c.CheckID) {
		return c, time.Time{}, errors.New("supervisor: check without check_id")
	}
	s.out.CheckIDs = append(s.out.CheckIDs, c.CheckID)
	stop := time.Now().Add(s.Cfg.CheckTimeout)
	for {
		sent := time.Now()
		got, err := s.GW.GetCheck(ctx, s.tok(ctx), c.CheckID)
		if err != nil {
			s.log().Warn("check poll failed", "check_id", c.CheckID, "err", err)
		} else {
			if got.CheckID != c.CheckID || got.WorkRunID != runID || got.WorkerBindingID != bindingID || got.SessionID != s.sessionID {
				return got, time.Time{}, errors.New("supervisor: check answered for another run or binding")
			}
			switch got.State {
			case "ready":
				if got.RemainingValidMS <= 0 {
					return got, time.Time{}, fail(ErrReadinessExpired, nil)
				}
				s.log().Info("work readiness ready", "check_id", got.CheckID, "checkpoint", checkpoint, "remaining_valid_ms", got.RemainingValidMS)
				return got, sent.Add(time.Duration(got.RemainingValidMS) * time.Millisecond), nil
			case "pending":
			default:
				code := ErrReadinessExpired
				if len(got.ReasonCodes) > 0 {
					code = got.ReasonCodes[0]
				}
				return got, time.Time{}, fail(code, fmt.Errorf("check %s", got.State))
			}
		}
		if time.Now().After(stop) {
			return c, time.Time{}, fail(ErrReadinessExpired, errors.New("check still pending at timeout"))
		}
		select {
		case <-ctx.Done():
			return c, time.Time{}, ctx.Err()
		case <-exited:
			return c, time.Time{}, fail(ErrWorkerExited, nil)
		case <-time.After(s.Cfg.CheckPoll):
		}
	}
}

// action submits one worker request and follows it to an outcome
// (TASK-15 3.2 response table). It never creates a second action for the request.
func (s *Supervisor) action(ctx context.Context, req *ipc.ActionRequest, runID, wid, bindingID string,
	ref func(string) gwclient.Readiness, exited <-chan struct{}) ipc.ActionOutcome {
	out := ipc.ActionOutcome{ReasonCodes: []string{}}
	record := func() ipc.ActionOutcome {
		s.out.ActionID, s.out.Verdict, s.out.ExecutionState, s.out.ReasonCodes = out.ActionID, out.Verdict, out.ExecutionState, out.ReasonCodes
		return out
	}
	if req == nil || !slices.Contains(s.Cfg.AllowedOperations, req.OperationID) || !jsonObject(req.RequestedTarget) || !jsonObject(req.Arguments) {
		out.ReasonCodes = []string{"SCHEMA_INVALID"}
		s.out.Error = "worker request refused by the supervisor"
		return record()
	}
	if req.OperationID == "model.generate" {
		var target, args map[string]json.RawMessage
		var profile, conversation string
		if canonical.CheckStrictJSON(req.RequestedTarget) != nil || canonical.CheckStrictJSON(req.Arguments) != nil ||
			json.Unmarshal(req.RequestedTarget, &target) != nil || json.Unmarshal(req.Arguments, &args) != nil ||
			json.Unmarshal(target["profile"], &profile) != nil || json.Unmarshal(args["conversation_id"], &conversation) != nil ||
			profile != "agent" || conversation != s.sessionID {
			out.ReasonCodes = []string{"PREFLIGHT_MISMATCH"}
			return record()
		}
	}
	// The worker receives a longer timeout derived from this same budget.
	// Every HTTP request and approval/result poll observes this context.
	ctx, cancel := context.WithTimeout(ctx, s.Cfg.actionBudget())
	defer cancel()
	ca := gwclient.ClientAction{
		SessionID: s.sessionID, OperationID: req.OperationID,
		RequestedTarget: req.RequestedTarget, Arguments: req.Arguments,
		ClientRequestKey: uuid.NewString(), // kept for every re-send of this request
	}
	var res gwclient.ActionResponse
	var err error
	for attempt := 0; ; attempt++ {
		var chk gwclient.ReadinessCheck
		var deadline time.Time
		chk, deadline, err = s.ready(ctx, runID, "control_step", wid, bindingID, exited)
		if err != nil {
			break
		}
		if time.Until(deadline) <= s.Cfg.StartMargin {
			err = fail(ErrReadinessExpired, nil)
		} else {
			res, err = s.GW.SubmitAction(ctx, s.tok(ctx), ca, ref(chk.CheckID))
		}
		if !retry503(err) || attempt >= len(s.Cfg.Backoff503) {
			break
		}
		s.log().Warn("submit unavailable; same request again", "err", err, "attempt", attempt+1)
		if !sleep(ctx, s.Cfg.Backoff503[attempt]) {
			err = ctx.Err()
			break
		}
	}
	if err != nil {
		return record2(&out, err, s, record)
	}
	out.ActionID, out.Verdict, out.ReasonCodes = res.ActionID, res.Verdict, nonNil(res.ReasonCodes)
	s.out.DecisionID = res.DecisionID
	s.log().Info("action decided", "action_id", res.ActionID, "verdict", res.Verdict, "reason_codes", res.ReasonCodes)
	if res.Verdict == "approval_required" {
		res, err = s.awaitApproval(ctx, res.ActionID, runID, wid, bindingID, ref, exited)
		if err != nil {
			return record2(&out, err, s, record)
		}
		out.Verdict, out.ReasonCodes = res.Verdict, nonNil(res.ReasonCodes)
		s.out.DecisionID = res.DecisionID
	}
	if res.Verdict != "allow" {
		if v, err := s.GW.GetAction(ctx, s.tok(ctx), out.ActionID); err == nil {
			out.ExecutionState = v.ExecutionState
		}
		return record()
	}
	result := s.awaitResult(ctx, out.ActionID)
	out.ExecutionState = result.ExecutionState
	if result.Final {
		out.ResultFinal = true
		out.ResultBody, out.Truncated = result.ResultBody, result.Truncated
		out.ReasonCodes = nonNil(result.ReasonCodes)
	}
	return record()
}

// record2 maps a request error into the outcome.
func record2(out *ipc.ActionOutcome, err error, s *Supervisor, record func() ipc.ActionOutcome) ipc.ActionOutcome {
	var ae *gwclient.APIError
	var re *runError
	switch {
	case errors.As(err, &ae):
		out.HTTPStatus, out.ReasonCodes, out.ActionID = ae.Status, nonNil(ae.ReasonCodes), ae.ActionID
	case errors.As(err, &re):
		out.ReasonCodes = []string{re.code}
	default:
		out.ReasonCodes = []string{"unknown"}
	}
	s.out.Error = err.Error()
	return record()
}

// awaitApproval waits for a human approval. The runtime cannot see the
// approval itself, so it re-runs a resume check and :reevaluate every
// ApprovalPoll until the verdict is no longer approval_required (TASK-15
// 3.2). SPEC-QUESTION: the specs say ":reevaluate after approval" but give the
// runtime no approval signal or poll interval.
func (s *Supervisor) awaitApproval(ctx context.Context, actionID, runID, wid, bindingID string,
	ref func(string) gwclient.Readiness, exited <-chan struct{}) (gwclient.ActionResponse, error) {
	v, err := s.GW.GetAction(ctx, s.tok(ctx), actionID)
	if err != nil {
		return gwclient.ActionResponse{}, err
	}
	if v.ActionDigest == nil || *v.ActionDigest == "" {
		return gwclient.ActionResponse{}, errors.New("supervisor: approval_required action without action_digest")
	}
	digest := *v.ActionDigest
	stop := time.Now().Add(s.Cfg.ApprovalTimeout)
	readinessFailures := 0
	epochRetried := false
	retryReadiness := func(err error) bool {
		if !retry503(err) || readinessFailures >= len(s.Cfg.Backoff503) {
			return false
		}
		wait := s.Cfg.Backoff503[readinessFailures]
		readinessFailures++
		return sleep(ctx, wait)
	}
	s.log().Info("approval pending; waiting for console approval", "action_id", actionID)
	for {
		if !sleep(ctx, s.Cfg.ApprovalPoll) {
			return gwclient.ActionResponse{}, ctx.Err()
		}
		if time.Now().After(stop) {
			return gwclient.ActionResponse{}, errors.New("supervisor: approval not granted before timeout")
		}
		chk, deadline, err := s.ready(ctx, runID, "resume", wid, bindingID, exited)
		if err != nil {
			if retryReadiness(err) {
				continue
			}
			return gwclient.ActionResponse{}, err
		}
		if time.Until(deadline) <= s.Cfg.StartMargin {
			err := fail(ErrReadinessExpired, nil)
			if retryReadiness(err) {
				continue
			}
			return gwclient.ActionResponse{}, err
		}
		res, err := s.GW.Reevaluate(ctx, s.tok(ctx), actionID, digest, ref(chk.CheckID))
		var ae *gwclient.APIError
		switch {
		case err == nil && res.Verdict == "approval_required":
			readinessFailures = 0
			continue
		case err == nil:
			s.log().Info("action reevaluated", "action_id", actionID, "verdict", res.Verdict)
			return res, nil
		case retryReadiness(err):
			continue
		case errors.As(err, &ae) && ae.Status == 409 && ae.Code() == "POLICY_EPOCH_STALE" && !epochRetried:
			epochRetried = true
			continue
		default:
			return gwclient.ActionResponse{}, err
		}
	}
}

// terminal execution_state values (COMMON enum table).
var terminal = map[string]bool{
	"denied": true, "preflight_rejected": true, "accepted": true, "effect_verified": true,
	"effect_mismatch": true, "failed": true, "unknown": true,
}

func (s *Supervisor) awaitResult(ctx context.Context, actionID string) gwclient.ActionResult {
	stop := time.Now().Add(s.Cfg.ResultTimeout)
	state := "dispatch_pending"
	for {
		r, err := s.GW.GetResult(ctx, s.tok(ctx), actionID)
		if err == nil {
			state = r.ExecutionState
			if r.Final && terminal[state] {
				return r
			}
		}
		if time.Now().After(stop) || !sleep(ctx, s.Cfg.ResultPoll) {
			return gwclient.ActionResult{ActionID: actionID, ExecutionState: state}
		}
	}
}

// shutdown stops the worker, closes the binding and reaps the process.
func (s *Supervisor) shutdown(w spawn.Worker, exited <-chan struct{}, bindingID string, failed bool) {
	_ = w.Conn().Send(ipc.Message{Type: ipc.TypeStop})
	ctx, cancel := context.WithTimeout(context.Background(), 2*s.Cfg.WorkerExitTimeout)
	defer cancel()
	if bindingID != "" {
		reason := "work_finished"
		if failed {
			reason = "supervisor_aborted"
		}
		if _, err := s.GW.CloseWorker(ctx, s.token.Token, bindingID, gwclient.WorkerClose{Reason: reason, EvidenceRefs: []string{}}); err != nil {
			s.log().Warn("binding close failed", "worker_binding_id", bindingID, "err", err)
		}
	}
	select {
	case <-exited:
	case <-time.After(s.Cfg.WorkerExitTimeout):
		_ = w.Kill()
		<-exited
	}
	_ = w.Conn().Close()
}

func (s *Supervisor) event(typ, runID, checkID, wid, bindingID string, outcome, reason *string) gwclient.WorkEvent {
	return gwclient.WorkEvent{
		EventID: uuid.NewString(), EventType: typ, SourceVersion: s.Cfg.SourceVersion, SourceTime: time.Now().UTC(),
		SafePayload: gwclient.WorkEventPayload{
			WorkRunID: runID, CheckID: checkID, RuntimeProcessEpoch: s.Epoch,
			WorkerInstanceID: wid, WorkerBindingID: bindingID, Outcome: outcome, Reason: reason,
		},
	}
}

// readinessRetry are the 503 codes of a readiness result that lapsed between
// ready and the submit (3 s window). Only these re-send the same request
// (same client_request_key, so never a new action) after a new check;
// HOLD_ACTIVE, CONTROL_HEALTH_UNAVAILABLE and every other 503 stop the run
// (TASK-15 3.2: stop execution; the user resumes after the server recovers).
var readinessRetry = map[string]bool{
	"WORK_READINESS_EXPIRED": true, "POD_OBSERVATION_NOT_READY": true, "WORKER_OBSERVATION_NOT_READY": true,
}

func retry503(err error) bool {
	var ae *gwclient.APIError
	if errors.As(err, &ae) {
		return ae.Status == 503 && readinessRetry[ae.Code()]
	}
	var re *runError
	return errors.As(err, &re) && re.code == ErrReadinessExpired
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func jsonObject(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(raw, &m) == nil && m != nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func canonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}
