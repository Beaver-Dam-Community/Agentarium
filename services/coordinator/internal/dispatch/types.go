// Package dispatch is the TASK-03 3.2 dispatch coordinator: the reservation
// transaction, the dispatch permit claim, the attempt outcome transitions
// (pre-claim release with its budget restore, and the post-claim
// transitions with their AdapterObservation), activation probe registration,
// and the sweeper for unclaimed expired permits and missing outcomes.
//
// The objects it reads from other Tasks (active_policy, decisions, holds,
// leases, node_boot_generation, audit_append) are reached through the
// interfaces below. Each method gets the caller's transaction and must use
// only it, so that every read and lock follows the global lock order this
// package drives. Until a dependency is wired its default fails, and no
// permit is issued or claimed.
package dispatch

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// Timings (COMMON implementation defaults, TASK-03 3.2 sweeper).
const (
	PermitTTL      = 10 * time.Second
	OutcomeTimeout = 60 * time.Second
	SweepInterval  = 5 * time.Second
	SweepBatch     = 100
	LockTimeout    = "2s"
	MaxBodyBytes   = 16 << 10
	releaseRetries = 3
)

// ActivePolicy is the active_policy row (TASK-14) locked FOR SHARE, with the
// catalog digest of its bundle.
type ActivePolicy struct {
	Epoch               int64
	CatalogDigest       string
	ExpectedOPARevision string
}

// PolicySource locks the active_policy row FOR SHARE in tx.
type PolicySource interface {
	LockActivePolicy(ctx context.Context, tx pgx.Tx) (ActivePolicy, error)
}

// Decision is the part of a TASK-04 decision (and its action) that the
// reservation checks. Decisions are immutable, so they are read unlocked.
type Decision struct {
	DecisionID        string
	RequestID         string
	ActionID          string
	ActionDigest      string
	AdapterID         string
	Verdict           string
	DecisionBasis     string
	ApprovalID        string
	StandingRuleID    string
	ServiceSessionID  string
	ActivationProbeID string
	PolicyEpoch       int64
	OPABundleRevision string
	CatalogDigest     string
	ExpiresAt         time.Time
	// From the action: hold scopes, the budget counter and the lease set.
	SessionID   string // user sessions only
	WorkloadID  string // user sessions only
	OperationID string
	TargetID    string
}

// DecisionSource reads one decision in tx. ErrNotFound if it does not exist.
type DecisionSource interface {
	Decision(ctx context.Context, tx pgx.Tx, decisionID string) (Decision, error)
}

// HoldScope is the set of hold scopes a reservation must check (TASK-03 3.2
// hold/lease reads): global plus each non-empty field.
type HoldScope struct {
	NodeUID          string
	WorkloadID       string
	TargetID         string
	SessionID        string
	ServiceSessionID string
}

// Hold is an unreleased holds row.
type Hold struct {
	HoldID string
	Reason string
}

// NodeBoot is the node_boot_generation row of the adapter's node.
type NodeBoot struct {
	BootID           string
	SensorGeneration int64
	GuardGeneration  int64
	State            string // preparing, ready, held, retired
}

// Health reads the TASK-10 control-health state in tx, in the lock order
// holds → node_boot_generation (leases are not locked).
type Health interface {
	// LockHolds returns the unreleased holds matching scope, FOR SHARE.
	LockHolds(ctx context.Context, tx pgx.Tx, scope HoldScope) ([]Hold, error)
	// LockNodeBoot returns the node's current row, FOR SHARE. ErrNotFound if
	// the node has none; an error if it has more than one.
	LockNodeBoot(ctx context.Context, tx pgx.Tx, nodeUID string) (NodeBoot, error)
	// CheckLeases returns an error unless every lease that TASK-10
	// required_sources lists for the operation and target is unexpired.
	CheckLeases(ctx context.Context, tx pgx.Tx, operationID, targetID string) error
	// LockActivationHold returns the open policy_activation hold of the
	// change, FOR SHARE. ErrNotFound if there is none.
	//
	// SPEC-QUESTION: holds rows carry no change_id. TASK-14 3.2 creates the
	// hold with scope = global and at most one is open (holds_open_unique),
	// so with the current schema an implementation can only return the open
	// global policy_activation hold; it cannot check that the hold belongs to
	// changeID.
	LockActivationHold(ctx context.Context, tx pgx.Tx, changeID string) (Hold, error)
}

// Event is an AuditEvent appended through TASK-07 audit_append().
type Event struct {
	Type    string
	Payload map[string]any
}

// Auditor appends ev inside tx. If it fails the transaction rolls back.
type Auditor interface {
	Append(ctx context.Context, tx pgx.Tx, ev Event) error
}

// LeaseReporter reports the component = coordinator lease (TASK-10).
type LeaseReporter interface {
	Report(ctx context.Context) error
}

var (
	ErrNotFound = errors.New("dispatch: not found")
	ErrUnwired  = errors.New("dispatch: dependency not wired")
)

// Unwired is the default for every dependency until its Task's objects
// exist. Each method fails, which the coordinator answers with 503.
type Unwired struct{}

func (Unwired) LockActivePolicy(context.Context, pgx.Tx) (ActivePolicy, error) {
	return ActivePolicy{}, ErrUnwired
}
func (Unwired) Decision(context.Context, pgx.Tx, string) (Decision, error) {
	return Decision{}, ErrUnwired
}
func (Unwired) LockHolds(context.Context, pgx.Tx, HoldScope) ([]Hold, error) { return nil, ErrUnwired }
func (Unwired) LockNodeBoot(context.Context, pgx.Tx, string) (NodeBoot, error) {
	return NodeBoot{}, ErrUnwired
}
func (Unwired) CheckLeases(context.Context, pgx.Tx, string, string) error { return ErrUnwired }
func (Unwired) LockActivationHold(context.Context, pgx.Tx, string) (Hold, error) {
	return Hold{}, ErrUnwired
}
func (Unwired) Append(context.Context, pgx.Tx, Event) error { return ErrUnwired }
func (Unwired) Report(context.Context) error                { return ErrUnwired }

// Adapter is a caller authenticated by its client certificate and the
// matching identity.issued_certificates row.
type Adapter struct {
	AdapterID string
	SAN       string
	NodeUID   string
	BootID    string
}

// Error carries a COMMON reason code and its HTTP status.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func fail(status int, code, msg string) *Error { return &Error{Status: status, Code: code, Msg: msg} }

func conflict(code, msg string) *Error { return fail(http.StatusConflict, code, msg) }

func unavailable(code, msg string) *Error { return fail(http.StatusServiceUnavailable, code, msg) }
