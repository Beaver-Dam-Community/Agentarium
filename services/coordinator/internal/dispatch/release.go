package dispatch

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5"
)

// Release origins (attempt_released.released_by).
const (
	ByAdapter = "adapter"
	BySweeper = "sweeper"
)

// ReleaseResult is the outcome API answer for a released transition.
type ReleaseResult struct {
	AttemptID      string   `json:"attempt_id"`
	State          string   `json:"state"`
	ReasonCodes    []string `json:"reason_codes"`
	BudgetRestored bool     `json:"budget_restored"`
}

var (
	errStale      = errors.New("dispatch: reservation changed between key read and lock")
	errNotExpired = errors.New("dispatch: permit not expired yet")
)

// release moves a planned, unclaimed attempt to released and gives its budget
// back exactly once (COMMON released handling). The keys are read without locks,
// then locked in the global order sessions | service_sessions → budget row
// (→ issue_candidate_counters for a candidate session) → reservations →
// attempts → dispatch_permits and verified again. The candidate is read from
// the locked service session, not from the reservation. A release that already
// happened returns the stored result without touching the budget. adapter is
// the caller for ByAdapter and nil for BySweeper; the sweeper only releases
// expired permits.
func (s *Service) release(ctx context.Context, attemptID, by string, reasons []string, adapter *Adapter) (*ReleaseResult, error) {
	for i := 0; i < releaseRetries; i++ {
		res, err := s.releaseOnce(ctx, attemptID, by, reasons, adapter)
		if !errors.Is(err, errStale) {
			return res, err
		}
	}
	return nil, unavailable("LOCK_TIMEOUT", "reservation kept changing during release")
}

func (s *Service) releaseOnce(ctx context.Context, attemptID, by string, reasons []string, adapter *Adapter) (*ReleaseResult, error) {
	var resID, adapterID string
	var b budget
	err := s.Pool.QueryRow(ctx, `
SELECT t.reservation_id::text, t.adapter_id, r.decision_basis, r.approval_id::text, r.approval_revision,
       r.session_id::text, r.standing_rule_id, r.service_session_id::text, r.budget_counter
FROM coordinator.attempts t JOIN coordinator.reservations r ON r.reservation_id = t.reservation_id
WHERE t.attempt_id = $1`, attemptID).Scan(&resID, &adapterID, &b.Basis, &b.ApprovalID, &b.ApprovalRevision,
		&b.SessionID, &b.StandingRuleID, &b.ServiceSessionID, &b.Counter)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && adapter != nil && adapterID != adapter.AdapterID) {
		return nil, fail(http.StatusNotFound, "RESOURCE_NOT_FOUND", "no such attempt for this adapter")
	}
	if err != nil {
		return nil, err
	}
	if b.SessionID == nil && b.ServiceSessionID == nil {
		return nil, unavailable("STATE_STORE_UNAVAILABLE", "reservation has no session")
	}

	var out *ReleaseResult
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := b.lockSession(ctx, tx, false); err != nil {
			return err
		}
		if err := b.lockForRestore(ctx, tx); err != nil {
			return err
		}
		var now budget
		var resState string
		if err := tx.QueryRow(ctx, `
SELECT decision_basis, approval_id::text, approval_revision, session_id::text, standing_rule_id,
       service_session_id::text, budget_counter, state
FROM coordinator.reservations WHERE reservation_id = $1 FOR UPDATE`, resID).Scan(&now.Basis, &now.ApprovalID,
			&now.ApprovalRevision, &now.SessionID, &now.StandingRuleID, &now.ServiceSessionID, &now.Counter, &resState); err != nil {
			return err
		}
		var attState string
		var stored []string
		if err := tx.QueryRow(ctx, `SELECT state, reason_codes FROM coordinator.attempts WHERE attempt_id = $1 FOR UPDATE`,
			attemptID).Scan(&attState, &stored); err != nil {
			return err
		}
		if attState == "released" {
			// Released before (by the adapter or the sweeper): same answer,
			// no second restore.
			out = &ReleaseResult{AttemptID: attemptID, State: "released", ReasonCodes: stored, BudgetRestored: true}
			return nil
		}
		if !b.same(now) {
			return errStale
		}
		var claimed, expired bool
		if err := tx.QueryRow(ctx, `SELECT claimed_at IS NOT NULL, expires_at <= statement_timestamp()
FROM coordinator.dispatch_permits WHERE attempt_id = $1 FOR UPDATE`, attemptID).Scan(&claimed, &expired); err != nil {
			return err
		}
		if attState != "planned" || resState != "reserved" || claimed {
			// After a claim only failed or unknown are allowed (TASK-03 3.2).
			return conflict("PERMIT_INVALID", "attempt is not planned and unclaimed; released is not allowed")
		}
		if by == BySweeper && !expired {
			return errNotExpired
		}
		if _, err := tx.Exec(ctx, `UPDATE coordinator.attempts SET state = 'released', reason_codes = $2, updated_at = statement_timestamp()
WHERE attempt_id = $1`, attemptID, reasons); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE coordinator.reservations SET state = 'released', updated_at = statement_timestamp()
WHERE reservation_id = $1`, resID); err != nil {
			return err
		}
		if err := b.restore(ctx, tx); err != nil {
			return err
		}
		if err := s.audit().Append(ctx, tx, Event{Type: "attempt_released", Payload: map[string]any{
			"attempt_id": attemptID, "reservation_id": resID, "reason_codes": reasons,
			"budget_restored": true, "released_by": by,
		}}); err != nil {
			return depErr(err, "STATE_STORE_UNAVAILABLE", "audit_append")
		}
		out = &ReleaseResult{AttemptID: attemptID, State: "released", ReasonCodes: reasons, BudgetRestored: true}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// preClaimReasons are the COMMON reason codes an adapter can report for a
// failure before the permit claim (COMMON failure classification: credential, permit
// refusal, hold, and the checks the permit claim repeats).
var preClaimReasons = []string{
	"CREDENTIAL_UNAVAILABLE", "PERMIT_INVALID", "HOLD_ACTIVE", "CONTROL_HEALTH_UNAVAILABLE",
	"POLICY_EPOCH_STALE", "CATALOG_DIGEST_MISMATCH", "LOCK_TIMEOUT", "STATE_STORE_UNAVAILABLE",
}

func validReleaseReasons(codes []string) bool {
	if len(codes) == 0 || len(codes) > len(preClaimReasons) {
		return false
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] || !slices.Contains(preClaimReasons, c) {
			return false
		}
		seen[c] = true
	}
	return true
}
