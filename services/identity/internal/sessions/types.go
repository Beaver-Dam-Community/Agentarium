// Package sessions implements TASK-03 3.4: user sessions (create, runtime
// assignments, claim, refresh, revoke), service sessions and the standing
// rule session budgets.
//
// Callers reach it with an already verified principal: a console Actor (set
// by the console BFF, PR D) or a RuntimePrincipal from a verified mTLS SAN.
// Every state change and its audit event go into one transaction through
// Auditor.Append; without a wired Auditor the service refuses to change state.
package sessions

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Lifetimes (TASK-03 3.1 time values).
const (
	SessionTTL     = 30 * time.Minute
	SessionMaxLife = 8 * time.Hour
	ClaimCodeTTL   = 60 * time.Second
	// MaxTaskStatement is the sessions.task_statement CHECK.
	MaxTaskStatement = 4000
)

// Actor is a console user verified by the BFF (OIDC, PR D).
type Actor struct {
	AuthenticatedActor string
	Tenant             string
	Roles              []string // operator, approver, release_operator, viewer
	// AuthTime proves recency of authentication for the approval re-auth
	// window. The verifier sets it to the ID token auth_time when present
	// (browser PKCE console) and otherwise to iat (CLI ID tokens from
	// `gcloud auth print-identity-token`, which carry no auth_time). Approval
	// POSTs require it within the last 5 minutes (TASK-03 3.1 re-authentication).
	AuthTime time.Time
}

// HasRole reports whether the actor has role.
func (a Actor) HasRole(role string) bool {
	for _, r := range a.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// RuntimePrincipal is a workload verified by mTLS: either the direct client
// certificate or the SAN the gateway forwarded in X-Agentarium-Peer-Identity
// over its own verified connection.
type RuntimePrincipal struct {
	SAN       string
	Namespace string
	KSA       string
}

// WorkloadID is "<namespace>/<ksa>".
func (p RuntimePrincipal) WorkloadID() string { return p.Namespace + "/" + p.KSA }

// StandingRule is the part of data.standing_rules this package reads.
type StandingRule struct {
	StandingRuleID string   `json:"standing_rule_id"`
	SessionKind    string   `json:"session_kind"`
	OperationIDs   []string `json:"operation_ids"`
	TargetPattern  string   `json:"target_pattern"`
	SessionBudget  int      `json:"session_budget"`
}

// Policy is the active bundle seen through one snapshot, so the catalog and
// the standing rules always come from the same bundle. The gateway's
// packages/policyloader snapshot provides it in production.
type Policy struct {
	Catalog       canonical.Catalog
	StandingRules map[string]StandingRule
	// Epoch is the active_policy epoch read in the same row that matched the
	// snapshot. Zero means the source does not report an epoch.
	Epoch int64
}

// PolicySource returns the current Policy. ErrPolicyUnavailable means no
// bundle is loaded yet.
type PolicySource interface {
	Policy(ctx context.Context) (Policy, error)
}

var ErrPolicyUnavailable = errors.New("sessions: no active policy bundle")

// ErrPolicyVersionMismatch means a bundle is loaded but it is not the active
// revision (COMMON 503 POLICY_VERSION_MISMATCH), e.g. during activation.
var ErrPolicyVersionMismatch = errors.New("sessions: loaded bundle is not the active revision")

// Querier is a pgx.Tx or pool used for one plain SELECT.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// TxPolicySource reads the active policy row through the caller's transaction,
// so the matched bundle and its epoch come from a single read.
type TxPolicySource interface {
	PolicyIn(ctx context.Context, q Querier) (Policy, error)
}

// PolicyError maps a PolicySource error to its COMMON 503 code.
func PolicyError(err error) *Error {
	if errors.Is(err, ErrPolicyVersionMismatch) {
		return Fail(http.StatusServiceUnavailable, "POLICY_VERSION_MISMATCH", err.Error())
	}
	return Fail(http.StatusServiceUnavailable, "POLICY_UNAVAILABLE", err.Error())
}

// Event is an AuditEvent the store appends (COMMON event_type registry).
type Event struct {
	Tenant     string // validated actor/request tenant or locked session tenant
	Type       string
	Actor      string // authenticated_actor
	SessionID  string // session_id or service_session_id
	ActionID   string // validated action or stored approval action
	WorkloadID string // validated workload or locked user-session workload
	Payload    map[string]any
}

// Auditor appends an event inside the caller's transaction (TASK-07
// audit_append). If Append fails, the whole state change rolls back.
type Auditor interface {
	Append(ctx context.Context, tx pgx.Tx, ev Event) error
}

// UnwiredAuditor fails every Append. It is the default until TASK-07's
// audit_append() exists, so no state change is committed without its event.
type UnwiredAuditor struct{}

var ErrAuditUnwired = errors.New("sessions: audit_append is not wired (TASK-07)")

func (UnwiredAuditor) Append(context.Context, pgx.Tx, Event) error { return ErrAuditUnwired }

// Error carries a COMMON reason code and HTTP status.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func fail(status int, code, msg string) *Error { return &Error{Status: status, Code: code, Msg: msg} }

// Fail builds an *Error for other identity packages.
func Fail(status int, code, msg string) *Error { return fail(status, code, msg) }
