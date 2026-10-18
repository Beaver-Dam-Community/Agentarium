// Package gateway is the TASK-04 policy gateway: POST /v1/actions,
// :reevaluate, GET /v1/actions/{action_id} and /result, and the
// execute_requests worker that hands allow decisions to the adapters.
//
// A request is authenticated (session or service-session token bound to the
// caller's mTLS SAN), normalized with packages/canonical against the
// data.catalog of the loaded bundle snapshot, evaluated by the embedded OPA
// query of that same snapshot, checked with packages/decisions, and stored in
// one transaction (actions, action_contents, decision_inputs, decisions,
// execute_requests, audit events).
//
// The objects this service reads or calls from other Tasks are reached
// through the interfaces below: active_policy (TASK-14), holds and leases and
// work readiness (TASK-10), workload_data_state, adapter_executions and
// action_results (TASK-05), audit_append and enqueue_decision_input (TASK-07),
// activation probe binding (TASK-03) and the intent checker (TASK-04 M5).
// Every method that reads state gets the caller's transaction and must use
// only it. Until a dependency is wired its default fails, so a
// state-changing request answers 503 and stores nothing. The unwired intent
// checker is the exception: its result is not_run, which by contract keeps
// the deterministic Rego verdict (TASK-04 3.3).
package gateway

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// Timings and limits (COMMON implementation defaults, TASK-04 chapter 3).
const (
	DecisionTTL    = 10 * time.Second
	EvalTimeout    = 500 * time.Millisecond
	IntentTimeout  = 3 * time.Second
	LockTimeout    = "2s"
	ContentTTLDays = 30

	// Execute delivery (TASK-04 3.5): first retry after 200 ms, doubling,
	// only while the decision is unexpired.
	FirstBackoff = 200 * time.Millisecond
	// ExecuteTimeout bounds one POST /internal/adapter/{id}/execute call and
	// ClaimLease the worker's claim on a row while it calls. SPEC-QUESTION:
	// the specs give no value for either; both are package values below the
	// 10 s decision TTL.
	ExecuteTimeout = 2 * time.Second
	ClaimLease     = 3 * time.Second
	WorkerPoll     = 100 * time.Millisecond
)

// Header names (TASK-04 chapter 3 work-start gate).
const (
	WorkRunHeader        = "X-Agentarium-Work-Run-Id"
	ReadinessCheckHeader = "X-Agentarium-Work-Readiness-Check-Id"
)

// ---- dependencies owned by other Tasks ---------------------------------------

// ActivePolicy is this environment's active_policy row (TASK-14).
type ActivePolicy struct {
	Epoch               int64
	ExpectedOPARevision string
}

// PolicySource reads active_policy in tx (TASK-14). The gateway compares
// ExpectedOPARevision with the revision of the snapshot it evaluates.
type PolicySource interface {
	ActivePolicy(ctx context.Context, tx pgx.Tx) (ActivePolicy, error)
}

// HoldScope lists the hold scopes of one request (COMMON hold selection): global
// plus each non-empty field. node scope is checked by the coordinator.
type HoldScope struct {
	WorkloadID       string // user sessions only
	TargetID         string
	SessionID        string // session_id or service_session_id
	SessionIsService bool
}

// Hold is an unreleased holds row (TASK-10).
type Hold struct {
	HoldID  string `json:"hold_id"`
	Scope   string `json:"scope"`
	ScopeID string `json:"scope_id"`
	Reason  string `json:"reason"`
}

// LeaseKey names one required component. AdapterID is set for
// component = adapter, NodeUID for node-sensors, TargetID for
// destination-evidence (its lease scope is target, TASK-10 3.2).
type LeaseKey struct {
	Component string
	AdapterID string
	NodeUID   string
	TargetID  string
}

// LeaseRow is one control_health_leases row (one replica).
type LeaseRow struct {
	Component     string
	SourceID      string
	ObservedState string // healthy, degraded, unhealthy
	LeaseUntil    time.Time
	ActiveVersion *string // reported artifact_digest
}

// ControlHealth reads TASK-10 holds and leases in tx.
type ControlHealth interface {
	Holds(ctx context.Context, tx pgx.Tx, scope HoldScope) ([]Hold, error)
	// Leases returns every lease row (valid or not) of the component.
	Leases(ctx context.Context, tx pgx.Tx, key LeaseKey) ([]LeaseRow, error)
}

// ReadinessRef is the work-readiness reference a runtime sends with a new
// action or :reevaluate (TASK-04 chapter 3 work-start gate).
type ReadinessRef struct {
	WorkRunID string
	CheckID   string
}

// Readiness checks a runtime's current work-readiness result (TASK-10). It
// returns an *Error (503 when not ready or expired, 403 when the reference
// belongs to another caller or session) or nil.
type Readiness interface {
	Check(ctx context.Context, c Caller, ref ReadinessRef) error
}

// DataStateKey selects the workload_data_state row: (workload_id) for a user
// session, (service_session_id) for a service session.
type DataStateKey struct {
	WorkloadID       string
	ServiceSessionID string
}

// DataState is a workload_data_state row (TASK-05).
type DataState struct {
	DataClassHighWater string
	DataSources        []string
}

// AdapterState reads TASK-05 tables in tx.
type AdapterState interface {
	// DataState returns the row, or found = false when there is none (the
	// gateway then uses "none").
	DataState(ctx context.Context, tx pgx.Tx, key DataStateKey) (DataState, bool, error)
	// ExecutionState returns adapter_executions.state of the decision, or
	// found = false.
	ExecutionState(ctx context.Context, tx pgx.Tx, decisionID string) (string, bool, error)
	// Result returns the action_results row of the action, or nil.
	Result(ctx context.Context, tx pgx.Tx, actionID string) (*ActionResult, error)
}

// ActionResult is COMMON ActionResult as TASK-05 stores it.
type ActionResult struct {
	ActionID         string    `json:"action_id"`
	AttemptID        string    `json:"attempt_id"`
	ExecutionState   string    `json:"execution_state"`
	DataClass        string    `json:"data_class"`
	ResultBody       any       `json:"result_body"`
	Truncated        bool      `json:"truncated"`
	TruncationReason *string   `json:"truncation_reason"`
	EvidenceLevel    string    `json:"evidence_level"`
	ResultDigest     string    `json:"result_digest"`
	CreatedAt        time.Time `json:"created_at"`
}

// Event is an AuditEvent appended with TASK-07 audit_append().
type Event struct {
	Type      string
	Tenant    string // the caller's tenant (AuditEvent.tenant)
	Actor     string // authenticated_actor
	SessionID string // session_id or service_session_id
	// ActionID and RequestID are the envelope action_id and request_id of
	// the event (AuditEvent index columns); empty when it has none.
	ActionID, RequestID string
	Payload             map[string]any
}

// Auditor appends events and enqueues decision inputs inside tx (TASK-07).
// If either fails, the decision transaction rolls back.
type Auditor interface {
	Append(ctx context.Context, tx pgx.Tx, ev Event) error
	EnqueueDecisionInput(ctx context.Context, tx pgx.Tx, digest string, record []byte) error
}

// ActivationProbe is the coordinator.activation_probes row of a probe
// submission, with action_id set to the submitted action (TASK-04 3.2).
type ActivationProbe struct {
	ActivationProbeID string `json:"activation_probe_id"`
	ChangeID          string `json:"change_id"`
	ServiceSessionID  string `json:"service_session_id"`
	ActionID          string `json:"action_id"`
	TargetEpoch       int64  `json:"target_epoch"`
	ExpiresAt         string `json:"expires_at"`
}

// Probes reads and binds activation probes (TASK-03
// bind_activation_probe_action). Used only for activation_probe service
// sessions.
type Probes interface {
	Lookup(ctx context.Context, tx pgx.Tx, serviceSessionID, clientRequestKey, actionID string) (*ActivationProbe, error)
	Bind(ctx context.Context, tx pgx.Tx, serviceSessionID, clientRequestKey, actionID string) error
}

// IntentRequest is the standing-rule intent check request (TASK-04 3.3).
type IntentRequest struct {
	ActionID  string
	SessionID string
	Envelope  any
}

// IntentResult is the part of IntentCheckResult the gateway uses.
type IntentResult struct {
	IntentCheckID string // empty when no intent_checks row exists
	Status        string // completed, not_run
	Overall       string // consistent, divergent, unclear; empty for not_run
}

// IntentChecker calls POST /internal/intent-checks (TASK-04 M5).
type IntentChecker interface {
	Check(ctx context.Context, req IntentRequest) (IntentResult, error)
}

var ErrUnwired = errors.New("gateway: dependency not wired")

// Unwired is the default of every dependency until its Task's objects exist.
// Each method fails, so the gateway answers 503 and stores nothing; Check of
// the intent checker returns not_run.
type Unwired struct{}

func (Unwired) ActivePolicy(context.Context, pgx.Tx) (ActivePolicy, error) {
	return ActivePolicy{}, ErrUnwired
}
func (Unwired) Holds(context.Context, pgx.Tx, HoldScope) ([]Hold, error)     { return nil, ErrUnwired }
func (Unwired) Leases(context.Context, pgx.Tx, LeaseKey) ([]LeaseRow, error) { return nil, ErrUnwired }
func (Unwired) Check(context.Context, Caller, ReadinessRef) error            { return ErrUnwired }
func (Unwired) DataState(context.Context, pgx.Tx, DataStateKey) (DataState, bool, error) {
	return DataState{}, false, ErrUnwired
}
func (Unwired) ExecutionState(context.Context, pgx.Tx, string) (string, bool, error) {
	return "", false, ErrUnwired
}
func (Unwired) Result(context.Context, pgx.Tx, string) (*ActionResult, error) { return nil, ErrUnwired }
func (Unwired) Append(context.Context, pgx.Tx, Event) error                   { return ErrUnwired }
func (Unwired) EnqueueDecisionInput(context.Context, pgx.Tx, string, []byte) error {
	return ErrUnwired
}
func (Unwired) Lookup(context.Context, pgx.Tx, string, string, string) (*ActivationProbe, error) {
	return nil, ErrUnwired
}
func (Unwired) Bind(context.Context, pgx.Tx, string, string, string) error { return ErrUnwired }

// UnwiredIntent returns not_run for every check.
type UnwiredIntent struct{}

func (UnwiredIntent) Check(context.Context, IntentRequest) (IntentResult, error) {
	return IntentResult{Status: "not_run"}, nil
}

// ---- errors -------------------------------------------------------------------

// Error carries a COMMON reason code and its HTTP status. ActionID and
// DecisionID are set when the error is about a stored action.
type Error struct {
	Status     int
	Code       string
	Msg        string
	ActionID   string
	DecisionID string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func fail(status int, code, msg string) *Error { return &Error{Status: status, Code: code, Msg: msg} }

func unavailable(code, msg string) *Error { return fail(http.StatusServiceUnavailable, code, msg) }

// depErr maps a dependency failure: an *Error passes through, anything else
// becomes 503 with code.
func depErr(err error, code, what string) error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return unavailable(code, what+": "+err.Error())
}
