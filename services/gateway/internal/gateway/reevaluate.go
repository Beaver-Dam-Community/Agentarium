package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/decisions"
)

// ReevaluateRequest is the :reevaluate body (TASK-04 3.5).
type ReevaluateRequest struct {
	ExpectedActionDigest string `json:"expected_action_digest"`
}

var notFound = fail(http.StatusNotFound, "RESOURCE_NOT_FOUND", "no such action")

// storedAction is the part of an action row :reevaluate and GET read.
type storedAction struct {
	actionID     string
	sessionKind  string
	sessionID    string
	clientKey    string
	operationID  string
	actionDigest *string
	envelope     []byte
	decisionID   string
	verdict      string
	reasonCodes  []string
	basis        *string
	matched      []string
	expiresAt    time.Time
	stage        string
}

// loadAction reads the action and its latest decision in tx. A missing
// action and an action of another caller are both 404 RESOURCE_NOT_FOUND,
// so existence is not revealed (TASK-04 3.5).
func loadAction(ctx context.Context, tx pgx.Tx, c Caller, actionID string) (storedAction, error) {
	if _, err := uuid.Parse(actionID); err != nil {
		return storedAction{}, notFound
	}
	var a storedAction
	err := tx.QueryRow(ctx, `
SELECT a.action_id::text, a.session_kind, a.session_id::text, a.client_request_key, a.operation_id, a.action_digest, a.envelope,
       d.decision_id::text, d.verdict, d.reason_codes, d.decision_basis, d.matched_rule_ids, d.expires_at, d.decision_stage
FROM decisions.actions a
JOIN LATERAL (SELECT * FROM decisions.decisions x WHERE x.action_id = a.action_id ORDER BY x.seq DESC LIMIT 1) d ON true
WHERE a.action_id = $1`, actionID).Scan(&a.actionID, &a.sessionKind, &a.sessionID, &a.clientKey, &a.operationID, &a.actionDigest,
		&a.envelope, &a.decisionID, &a.verdict, &a.reasonCodes, &a.basis, &a.matched, &a.expiresAt, &a.stage)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedAction{}, notFound
	}
	if err != nil {
		return storedAction{}, err
	}
	if !c.owns(a.sessionKind, a.sessionID) {
		return storedAction{}, notFound
	}
	return a, nil
}

// Reevaluate handles POST /v1/actions/{action_id}:reevaluate (TASK-04 3.5):
// the stored envelope is evaluated again with the current facts, giving a
// new request_id, decision_id and 10 s TTL (action_reevaluated).
//   - expected_action_digest differs from the stored value: 409
//     ACTION_DIGEST_MISMATCH;
//   - the envelope's catalog_digest is not the loaded catalog's: 409
//     CATALOG_DIGEST_MISMATCH (submit a new action);
//   - the action already has a reservation: 409 PERMIT_INVALID (COMMON API
//     implementation contract). SPEC-QUESTION: TASK-04 3.5 answers this case with the
//     current state and 200 instead. It is checked before the evaluation
//     and again in the decision transaction (guardReevaluate);
//   - another :reevaluate of the action stored a decision after this one
//     read the previous decision: nothing is stored and the answer is that
//     latest decision (guardReevaluate).
func (s *Service) Reevaluate(ctx context.Context, c Caller, actionID string, req ReevaluateRequest, ref ReadinessRef) (*ActionResponse, int, error) {
	snap, err := s.snapshot()
	if err != nil {
		return nil, 0, err
	}
	var a storedAction
	var reserved bool
	err = s.readTx(ctx, func(tx pgx.Tx) error {
		var err error
		if a, err = loadAction(ctx, tx, c, actionID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM coordinator.reservations WHERE action_id = $1)`, a.actionID).Scan(&reserved)
	})
	if err != nil {
		return nil, 0, err
	}
	withAction := func(e *Error) *Error { e.ActionID, e.DecisionID = a.actionID, a.decisionID; return e }
	if a.actionDigest == nil || *a.actionDigest != req.ExpectedActionDigest || len(a.envelope) == 0 {
		return nil, 0, withAction(fail(http.StatusConflict, "ACTION_DIGEST_MISMATCH", "expected_action_digest differs"))
	}
	var env canonical.ActionEnvelope
	if err := json.Unmarshal(a.envelope, &env); err != nil {
		return nil, 0, err
	}
	cat, err := s.catalog(snap)
	if err != nil {
		return nil, 0, policyUnavailable
	}
	if env.CatalogDigest != cat.CatalogDigest {
		return nil, 0, withAction(fail(http.StatusConflict, "CATALOG_DIGEST_MISMATCH", "catalog changed; submit a new action"))
	}
	if reserved {
		return nil, 0, withAction(fail(http.StatusConflict, "PERMIT_INVALID", "action already reserved"))
	}
	op, ok := cat.Operations[env.OperationID]
	if !ok {
		return nil, 0, policyUnavailable
	}
	if c.Kind == KindUser {
		if ref.WorkRunID == "" || ref.CheckID == "" {
			return nil, 0, unavailable("WORK_READINESS_EXPIRED", "work readiness reference missing")
		}
		if err := s.readiness().Check(ctx, c, ref); err != nil {
			return nil, 0, depErr(err, "WORK_READINESS_EXPIRED", "work readiness")
		}
	}
	requestID := uuid.NewString()
	var in opaInput
	var f facts
	err = s.readTx(ctx, func(tx pgx.Tx) error {
		now, err := evaluatedAt(ctx, tx)
		if err != nil {
			return err
		}
		ds, err := s.dataState(ctx, tx, c)
		if err != nil {
			return err
		}
		in, f, err = s.collect(ctx, tx, c, env, a.clientKey, op.AdapterID, now, ds, snap.ArtifactDigest())
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	if f.active.ExpectedOPARevision != snap.Revision() {
		return nil, 0, s.evaluationFailed(ctx, c, requestID, a.actionID, snap, f.active,
			unavailable("POLICY_VERSION_MISMATCH", "loaded revision differs from active_policy"))
	}
	ev, err := evaluate(ctx, snap, in, f, c)
	if err != nil {
		return nil, 0, s.evaluationFailed(ctx, c, requestID, a.actionID, snap, f.active, err)
	}
	s.applyIntent(ctx, &ev, op, c, env)
	row := opaDecision(a.actionID, requestID, env, op, &ev, f, snap, cat)
	row.reevaluateOf = a.decisionID
	row.clientKey = a.clientKey
	if s.beforeReevaluateStore != nil {
		s.beforeReevaluateStore(a.actionID)
	}
	res, err := s.storeDecision(ctx, c, nil, row)
	if err != nil {
		return nil, 0, err
	}
	if l := res.superseded; l != nil {
		// Another :reevaluate of this action stored its decision after this
		// request read a.decisionID (guardReevaluate). This one stored
		// nothing and answers with that latest decision, in the same shape
		// and status as the request that stored it, the way a resubmission
		// replays the latest decision (existing, afterRace). Retrying is
		// safe: the answer names the decision that was stored, so the caller
		// does not wait for a decision_id that does not exist, and calling
		// :reevaluate again only creates a new decision through the same
		// guarded path. A 409 instead would make a caller that lost the race
		// retry until it creates a needless extra decision.
		out := respond(l.requestID, a.actionID, l.decisionID, l.derived())
		out.ExpiresAt = &l.expiresAt
		return out, decisions.HTTPStatus(l.verdict, l.reasonCodes), nil
	}
	if row.derived.Verdict == decisions.Allow {
		s.Kick()
	}
	out := respond(requestID, a.actionID, row.decisionID, row.derived)
	out.ExpiresAt = &res.expiresAt
	return out, decisions.HTTPStatus(row.derived.Verdict, row.derived.ReasonCodes), nil
}
