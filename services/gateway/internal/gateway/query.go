package gateway

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/decisions"
)

// ActionView is the GET /v1/actions/{action_id} body: the latest decision,
// its matched rules, execution_state and, while dispatch is pending,
// dispatch_status (TASK-04 chapter 4). action_digest is what :reevaluate expects.
// SPEC-QUESTION: the specs list the contents but no exact schema; these
// field names are the GatewayDecision and COMMON names.
type ActionView struct {
	ActionID       string    `json:"action_id"`
	ActionDigest   *string   `json:"action_digest"`
	DecisionID     string    `json:"decision_id"`
	Verdict        string    `json:"verdict"`
	ReasonCodes    []string  `json:"reason_codes"`
	DecisionBasis  *string   `json:"decision_basis"`
	MatchedRuleIDs []string  `json:"matched_rule_ids"`
	ExpiresAt      time.Time `json:"expires_at"`
	ExecutionState string    `json:"execution_state"`
	DispatchStatus *string   `json:"dispatch_status,omitempty"`
}

// PendingResult is the 202 body of /result while there is no ActionResult.
type PendingResult struct {
	ActionID       string  `json:"action_id"`
	ExecutionState string  `json:"execution_state"`
	DispatchStatus *string `json:"dispatch_status,omitempty"`
}

// GetAction handles GET /v1/actions/{action_id}.
func (s *Service) GetAction(ctx context.Context, c Caller, actionID string) (*ActionView, error) {
	var out *ActionView
	err := s.readTx(ctx, func(tx pgx.Tx) error {
		a, err := loadAction(ctx, tx, c, actionID)
		if err != nil {
			return err
		}
		st, ds, _, err := s.executionState(ctx, tx, a, false)
		if err != nil {
			return err
		}
		out = &ActionView{
			ActionID: a.actionID, ActionDigest: a.actionDigest, DecisionID: a.decisionID, Verdict: a.verdict,
			ReasonCodes: nonNil(a.reasonCodes), DecisionBasis: a.basis, MatchedRuleIDs: a.matched,
			ExpiresAt: a.expiresAt, ExecutionState: st, DispatchStatus: ds,
		}
		return nil
	})
	return out, err
}

// GetResult handles GET /v1/actions/{action_id}/result: the ActionResult
// (200), or 202 with the current execution_state while there is none.
func (s *Service) GetResult(ctx context.Context, c Caller, actionID string) (any, int, error) {
	var out any
	status := http.StatusOK
	err := s.readTx(ctx, func(tx pgx.Tx) error {
		a, err := loadAction(ctx, tx, c, actionID)
		if err != nil {
			return err
		}
		st, ds, res, err := s.executionState(ctx, tx, a, true)
		if err != nil {
			return err
		}
		if res != nil {
			out = res
			return nil
		}
		status = http.StatusAccepted
		out = &PendingResult{ActionID: a.actionID, ExecutionState: st, DispatchStatus: ds}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return out, status, nil
}

// executionState derives execution_state (COMMON execution_state derivation): the
// first matching row of
//
//	latest decision deny                          → denied
//	latest decision approval_required             → approval_pending
//	adapter_executions.state = preflight_rejected → preflight_rejected
//	allow, no attempt                             → dispatch_pending (+ dispatch_status)
//	latest attempt planned / claimed              → attempt_planned
//	latest attempt dispatched                     → dispatched
//	latest attempt response_received              → action_results.execution_state
//	latest attempt failed / released              → failed
//	latest attempt unknown                        → unknown
//
// With wantResult it also returns the ActionResult when one exists. The
// TASK-05 reads (adapter_executions, action_results) go through
// AdapterState; unwired, an allow action answers 503.
func (s *Service) executionState(ctx context.Context, tx pgx.Tx, a storedAction, wantResult bool) (string, *string, *ActionResult, error) {
	switch a.verdict {
	case decisions.Deny:
		return "denied", nil, nil, nil
	case decisions.ApprovalRequired:
		// SPEC-QUESTION: COMMON says "approval_required and no usable
		// approval"; with a usable approval but no :reevaluate yet no row of
		// the table matches. approval_pending is kept until the new decision.
		return "approval_pending", nil, nil, nil
	}
	es, found, err := s.adapters().ExecutionState(ctx, tx, a.decisionID)
	if err != nil {
		return "", nil, nil, depErr(err, "STATE_STORE_UNAVAILABLE", "adapter_executions")
	}
	if found && es == "preflight_rejected" {
		return "preflight_rejected", nil, nil, nil
	}
	var attempt string
	err = tx.QueryRow(ctx, `
SELECT state FROM coordinator.attempts WHERE action_id = $1 ORDER BY created_at DESC, attempt_id DESC LIMIT 1`, a.actionID).Scan(&attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		var ds string
		err := tx.QueryRow(ctx, `SELECT state FROM decisions.execute_requests WHERE decision_id = $1`, a.decisionID).Scan(&ds)
		if err != nil {
			return "", nil, nil, err
		}
		return "dispatch_pending", &ds, nil, nil
	}
	if err != nil {
		return "", nil, nil, err
	}
	var res *ActionResult
	if wantResult || attempt == "response_received" {
		if res, err = s.adapters().Result(ctx, tx, a.actionID); err != nil {
			return "", nil, nil, depErr(err, "STATE_STORE_UNAVAILABLE", "action_results")
		}
	}
	switch attempt {
	case "planned", "claimed":
		return "attempt_planned", nil, res, nil
	case "dispatched":
		return "dispatched", nil, res, nil
	case "response_received":
		if res == nil {
			// SPEC-QUESTION: the adapter writes action_results after its
			// outcome report (COMMON adapter commit order), so this window
			// exists; it is shown as dispatched until the result row is there.
			return "dispatched", nil, nil, nil
		}
		return res.ExecutionState, nil, res, nil
	case "failed", "released":
		return "failed", nil, res, nil
	case "unknown":
		return "unknown", nil, res, nil
	default:
		// resolved: the resolution is read from TASK-11, not wired yet.
		return "", nil, nil, unavailable("STATE_STORE_UNAVAILABLE", "attempt state "+attempt+" needs TASK-11")
	}
}
