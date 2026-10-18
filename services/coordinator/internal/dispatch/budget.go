package dispatch

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
)

// budget names the one row a reservation consumes (TASK-03 3.2 decision_basis
// table) and the session row locked before it.
//
// Every transaction here locks in the global order of TASK-03 3.2 lock order
// (COMMON lock order): active_policy → holds → node_boot_generation →
// sessions → service_sessions → service_session_counters · session_budgets →
// issue_candidate_counters → approvals → reservations → attempts →
// dispatch_permits. issue_candidates sits between service_sessions and the
// counters in that order, but only the identity transaction that issues a
// service session locks it; the coordinator never does.
type budget struct {
	Basis            string
	ApprovalID       *string
	ApprovalRevision *int32
	SessionID        *string
	StandingRuleID   *string
	ServiceSessionID *string
	Counter          *string

	// IssueID and CandidateID are the policy_proposal candidate of a service
	// session, read by lockSession from identity.service_sessions (nil for a
	// user session or a service session without a candidate). They are not
	// part of the reservation row, so same() leaves them out. A candidate's
	// usage is the one issue_candidate_counters row shared by all its
	// sessions (TASK-03 3.4 candidate counter).
	IssueID     *string
	CandidateID *string
}

// counterFor maps an operation to its service_session_counters counter
// (TASK-03 3.4: model.generate → model, evidence.* → read_tools,
// discovery.* → snapshot_reads). Probes use probeCounter whatever their
// operation (budgetFor).
func counterFor(operationID string) string {
	switch {
	case operationID == "model.generate":
		return "model"
	case strings.HasPrefix(operationID, "evidence."):
		return "read_tools"
	case strings.HasPrefix(operationID, "discovery."):
		return "snapshot_reads"
	}
	return ""
}

// probeCounter is the counter an activation_probe reservation consumes
// (TASK-03 3.2 decision_basis table).
const probeCounter = "probe_actions"

// exhaustedCode is the code for an unusable budget of this basis.
func (b budget) exhaustedCode() string {
	switch b.Basis {
	case "approval":
		return "APPROVAL_UNAVAILABLE"
	case "standing_rule":
		return "SESSION_BUDGET_EXHAUSTED"
	}
	return "TOOL_BUDGET_EXHAUSTED"
}

func (b budget) exhausted(msg string) error { return conflict(b.exhaustedCode(), msg) }

func (b budget) same(o budget) bool {
	eq := func(x, y *string) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	return b.Basis == o.Basis && eq(b.ApprovalID, o.ApprovalID) && eq(b.SessionID, o.SessionID) &&
		eq(b.StandingRuleID, o.StandingRuleID) && eq(b.ServiceSessionID, o.ServiceSessionID) &&
		eq(b.Counter, o.Counter) &&
		(b.ApprovalRevision == nil) == (o.ApprovalRevision == nil) &&
		(b.ApprovalRevision == nil || *b.ApprovalRevision == *o.ApprovalRevision)
}

// budgetFor derives the budget of a decision. An inconsistent decision row is
// a state-store fault, not a caller error.
func budgetFor(d Decision) (budget, error) {
	str := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	b := budget{Basis: d.DecisionBasis}
	bad := unavailable("STATE_STORE_UNAVAILABLE", "decision "+d.DecisionID+" lacks the fields of its basis")
	switch d.DecisionBasis {
	case "approval":
		if d.ApprovalID == "" || d.SessionID == "" {
			return b, bad
		}
		b.ApprovalID, b.SessionID = str(d.ApprovalID), str(d.SessionID)
	case "standing_rule":
		if d.StandingRuleID == "" || d.SessionID == "" {
			return b, bad
		}
		b.StandingRuleID, b.SessionID = str(d.StandingRuleID), str(d.SessionID)
	case "service_scope":
		if d.ServiceSessionID == "" {
			return b, bad
		}
		b.ServiceSessionID = str(d.ServiceSessionID)
		c := counterFor(d.OperationID)
		if c == "" {
			return b, b.exhausted("operation " + d.OperationID + " has no service counter")
		}
		b.Counter = &c
	case "activation_probe":
		// The activation_probes row is checked separately (probeUsable).
		if d.ServiceSessionID == "" || d.ActivationProbeID == "" {
			return b, bad
		}
		c := probeCounter
		b.ServiceSessionID, b.Counter = str(d.ServiceSessionID), &c
	default:
		return b, bad
	}
	return b, nil
}

// lockSession locks the session row (sessions → service_sessions in the
// global order) and reports whether it is live: a claimed user session or an
// active service session, unexpired. For a service session it also records
// the session's candidate in b.
func (b *budget) lockSession(ctx context.Context, tx pgx.Tx, share bool) (bool, error) {
	mode := "FOR UPDATE"
	if share {
		mode = "FOR SHARE"
	}
	var live bool
	var err error
	if b.SessionID != nil {
		err = tx.QueryRow(ctx, `SELECT state = 'claimed' AND expires_at > statement_timestamp()
FROM identity.sessions WHERE session_id = $1 `+mode, *b.SessionID).Scan(&live)
	} else {
		err = tx.QueryRow(ctx, `SELECT state = 'active' AND expires_at > statement_timestamp(), issue_id::text, candidate_id::text
FROM identity.service_sessions WHERE service_session_id = $1 `+mode, *b.ServiceSessionID).Scan(&live, &b.IssueID, &b.CandidateID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return live, err
}

// lockForReserve locks the budget row for a new consumption. For approvals it
// picks the latest revision of the action and records it in b.
func (b *budget) lockForReserve(ctx context.Context, tx pgx.Tx, actionID string) error {
	var err error
	switch b.Basis {
	case "approval":
		var rev int32
		var sess string
		err = tx.QueryRow(ctx, `
SELECT revision, session_id::text FROM identity.approvals
WHERE approval_id = $1 AND action_id = $2
ORDER BY revision DESC LIMIT 1 FOR UPDATE`, *b.ApprovalID, actionID).Scan(&rev, &sess)
		if err == nil && sess != *b.SessionID {
			return b.exhausted("approval belongs to another session")
		}
		b.ApprovalRevision = &rev
	case "standing_rule":
		err = tx.QueryRow(ctx, `SELECT 1 FROM identity.session_budgets
WHERE session_id = $1 AND standing_rule_id = $2 FOR UPDATE`, *b.SessionID, *b.StandingRuleID).Scan(new(int))
	case "service_scope", "activation_probe":
		err = tx.QueryRow(ctx, `SELECT 1 FROM identity.service_session_counters
WHERE service_session_id = $1 AND counter = $2 FOR UPDATE`, *b.ServiceSessionID, *b.Counter).Scan(new(int))
		if errors.Is(err, pgx.ErrNoRows) {
			return b.exhausted("no budget row")
		}
		if err != nil {
			return err
		}
		return b.lockCandidate(ctx, tx)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return b.exhausted("no budget row")
	}
	return err
}

// lockCandidate locks the candidate counter row after the session counter
// row (service_session_counters → issue_candidate_counters in the global
// order). identity creates the row with the candidate's first session, so a
// missing row is a state-store fault, not a spent budget.
func (b budget) lockCandidate(ctx context.Context, tx pgx.Tx) error {
	if b.CandidateID == nil {
		return nil
	}
	if b.IssueID == nil {
		return unavailable("STATE_STORE_UNAVAILABLE", "service session has a candidate without an issue")
	}
	err := tx.QueryRow(ctx, `SELECT 1 FROM identity.issue_candidate_counters
WHERE issue_id = $1 AND candidate_id = $2 AND counter = $3 FOR UPDATE`, *b.IssueID, *b.CandidateID, *b.Counter).Scan(new(int))
	if errors.Is(err, pgx.ErrNoRows) {
		return unavailable("STATE_STORE_UNAVAILABLE", "candidate counter row is missing")
	}
	return err
}

// lockForRestore locks the exact row a reservation consumed, and for a
// candidate session the candidate counter row after it.
func (b budget) lockForRestore(ctx context.Context, tx pgx.Tx) error {
	var err error
	switch b.Basis {
	case "approval":
		err = tx.QueryRow(ctx, `SELECT 1 FROM identity.approvals
WHERE approval_id = $1 AND revision = $2 FOR UPDATE`, *b.ApprovalID, *b.ApprovalRevision).Scan(new(int))
	case "standing_rule":
		err = tx.QueryRow(ctx, `SELECT 1 FROM identity.session_budgets
WHERE session_id = $1 AND standing_rule_id = $2 FOR UPDATE`, *b.SessionID, *b.StandingRuleID).Scan(new(int))
	case "service_scope", "activation_probe":
		err = tx.QueryRow(ctx, `SELECT 1 FROM identity.service_session_counters
WHERE service_session_id = $1 AND counter = $2 FOR UPDATE`, *b.ServiceSessionID, *b.Counter).Scan(new(int))
	default:
		return unavailable("STATE_STORE_UNAVAILABLE", "reservation has unknown basis "+b.Basis)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return unavailable("STATE_STORE_UNAVAILABLE", "consumed budget row is missing")
	}
	if err != nil || b.Basis != "service_scope" {
		return err
	}
	return b.lockCandidate(ctx, tx)
}

// consume adds one use. No row means the budget is spent, expired or revoked.
//
// For a candidate session the candidate counter is the authoritative usage:
// it goes up first, and only while it is below this session's max_value. The
// session row then counts the use made through this session. The session's
// used_value is part of the candidate's sum, so it cannot be at max_value
// when the candidate is below it; if the books disagree anyway the error
// rolls the whole transaction back, the candidate increment included.
func (b budget) consume(ctx context.Context, tx pgx.Tx) error {
	if b.Basis == "service_scope" && b.CandidateID != nil {
		tag, err := tx.Exec(ctx, `
UPDATE identity.issue_candidate_counters cc SET used_value = cc.used_value + 1
FROM identity.service_session_counters sc
WHERE cc.issue_id = $1 AND cc.candidate_id = $2 AND cc.counter = $3
  AND sc.service_session_id = $4 AND sc.counter = $3
  AND cc.used_value < sc.max_value`, *b.IssueID, *b.CandidateID, *b.Counter, *b.ServiceSessionID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return b.exhausted("candidate budget is spent")
		}
	}
	var sql string
	var args []any
	switch b.Basis {
	case "approval":
		sql = `UPDATE identity.approvals SET used_actions = used_actions + 1
WHERE approval_id = $1 AND revision = $2
  AND revoked_at IS NULL AND expires_at > statement_timestamp() AND used_actions < max_actions`
		args = []any{*b.ApprovalID, *b.ApprovalRevision}
	case "standing_rule":
		sql = `UPDATE identity.session_budgets SET used_actions = used_actions + 1
WHERE session_id = $1 AND standing_rule_id = $2
  AND expires_at > statement_timestamp() AND used_actions < max_actions`
		args = []any{*b.SessionID, *b.StandingRuleID}
	case "service_scope", "activation_probe":
		sql = `UPDATE identity.service_session_counters SET used_value = used_value + 1
WHERE service_session_id = $1 AND counter = $2 AND used_value < max_value`
		args = []any{*b.ServiceSessionID, *b.Counter}
	}
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return b.exhausted("budget is spent, expired or revoked")
	}
	return nil
}

// restore gives one use back. The row must have a use to give back;
// otherwise the books disagree and the release rolls back. For a candidate
// session the candidate counter gives the use back too, even when the session
// has expired and a later session of the candidate is live: that session can
// then use it (TASK-03 3.2 budget restoration on released).
func (b budget) restore(ctx context.Context, tx pgx.Tx) error {
	var sql string
	var args []any
	switch b.Basis {
	case "approval":
		sql = `UPDATE identity.approvals SET used_actions = used_actions - 1
WHERE approval_id = $1 AND revision = $2 AND used_actions > 0`
		args = []any{*b.ApprovalID, *b.ApprovalRevision}
	case "standing_rule":
		sql = `UPDATE identity.session_budgets SET used_actions = used_actions - 1
WHERE session_id = $1 AND standing_rule_id = $2 AND used_actions > 0`
		args = []any{*b.SessionID, *b.StandingRuleID}
	case "service_scope", "activation_probe":
		sql = `UPDATE identity.service_session_counters SET used_value = used_value - 1
WHERE service_session_id = $1 AND counter = $2 AND used_value > 0`
		args = []any{*b.ServiceSessionID, *b.Counter}
	}
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fail(http.StatusServiceUnavailable, "STATE_STORE_UNAVAILABLE", "budget row has no use to restore")
	}
	if b.Basis == "service_scope" && b.CandidateID != nil {
		tag, err := tx.Exec(ctx, `UPDATE identity.issue_candidate_counters SET used_value = used_value - 1
WHERE issue_id = $1 AND candidate_id = $2 AND counter = $3 AND used_value > 0`, *b.IssueID, *b.CandidateID, *b.Counter)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fail(http.StatusServiceUnavailable, "STATE_STORE_UNAVAILABLE", "candidate counter has no use to restore")
		}
	}
	return nil
}
