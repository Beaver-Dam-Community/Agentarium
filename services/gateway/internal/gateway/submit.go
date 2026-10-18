package gateway

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/decisions"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

// ActionResponse is the body of POST /v1/actions and :reevaluate (COMMON API
// implementation contract): request_id, action_id?, decision_id?, verdict,
// execution_allowed, reason_codes; :reevaluate adds expires_at.
//
// decision_basis tells the caller what an allow rests on (TASK-04 chapter 4
// POST /v1/actions): approval, standing_rule, service_scope or
// activation_probe. It is always present and is null unless the verdict is
// allow (COMMON enum decision_basis). A first submission, a resubmission
// replay and :reevaluate all carry it; GET /v1/actions/{id} carries it in
// ActionView.
// SPEC-QUESTION: the COMMON API table lists this body without
// decision_basis, while TASK-04 chapter 4 includes it. This follows TASK-04; the
// difference only adds a field.
type ActionResponse struct {
	RequestID        string     `json:"request_id"`
	ActionID         string     `json:"action_id,omitempty"`
	DecisionID       string     `json:"decision_id,omitempty"`
	Verdict          string     `json:"verdict"`
	ExecutionAllowed bool       `json:"execution_allowed"`
	ReasonCodes      []string   `json:"reason_codes"`
	DecisionBasis    *string    `json:"decision_basis"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

// Submit handles POST /v1/actions for an authenticated caller (TASK-04 chapter 3):
// strict ClientAction decode, resubmission check, work readiness (user
// sessions), facts + normalization in one read snapshot, revision check, OPA
// evaluation, intent check, and the decision transaction. It returns the
// response and its HTTP status; err is an *Error for responses without a
// decision.
func (s *Service) Submit(ctx context.Context, c Caller, raw []byte, ref ReadinessRef) (*ActionResponse, int, error) {
	snap, err := s.snapshot()
	if err != nil {
		return nil, 0, err
	}
	ca, ne := canonical.DecodeClientAction(raw)
	if ne != nil {
		return nil, 0, s.reject(ctx, c, "", ne.HTTPStatus, ne.ReasonCodes, raw)
	}
	// The token decides the session; a body naming another session is a
	// binding error, not a different action.
	if ca.SessionID != c.SessionID {
		return nil, 0, s.reject(ctx, c, ca.OperationID, http.StatusForbidden, []string{"SESSION_BINDING_INVALID"}, raw)
	}
	rawDigest := canonical.RawBodyDigest(raw)
	if out, status, found, err := s.existing(ctx, c, ca.ClientRequestKey, rawDigest); found || err != nil {
		return out, status, err
	}
	if c.Kind == KindUser {
		if ref.WorkRunID == "" || ref.CheckID == "" {
			// SPEC-QUESTION: no reason code is defined for a missing reference;
			// it is treated like an expired readiness result (503).
			return nil, 0, unavailable("WORK_READINESS_EXPIRED", "work readiness reference missing")
		}
		if err := s.readiness().Check(ctx, c, ref); err != nil {
			return nil, 0, depErr(err, "WORK_READINESS_EXPIRED", "work readiness")
		}
	}
	cat, err := s.catalog(snap)
	if err != nil {
		return nil, 0, policyUnavailable
	}
	act := &newAction{actionID: uuid.NewString(), requestID: uuid.NewString(), clientKey: ca.ClientRequestKey,
		rawBodyDigest: rawDigest, operationID: ca.OperationID}

	var (
		env     canonical.ActionEnvelope
		content canonical.Content
		nerr    *canonical.NormalizeError
		in      opaInput
		f       facts
	)
	op, opKnown := cat.Operations[ca.OperationID]
	err = s.readTx(ctx, func(tx pgx.Tx) error {
		now, err := evaluatedAt(ctx, tx)
		if err != nil {
			return err
		}
		ds, err := s.dataState(ctx, tx, c)
		if err != nil {
			return err
		}
		trusted := canonical.TrustedContext{
			ActionID: act.actionID, RequestID: act.requestID, AuthenticatedActor: c.AuthenticatedActor,
			SessionKind: c.Kind, SessionID: c.SessionID, Tenant: c.Tenant, Environment: s.Environment,
			WorkloadDataState: ds,
		}
		if c.Kind == KindUser {
			w := c.WorkloadID
			trusted.WorkloadID = &w
		}
		env, content, nerr = canonical.Normalize(ca, raw, trusted, cat)
		if nerr != nil {
			if !storesNormalizeDecision(nerr) {
				return nil
			}
			// A normalize-stage decision carries the active policy_epoch like
			// an OPA-stage one (GatewayDecision, policy_decided). It is read in
			// this snapshot at the same point collect reads it.
			f.active, err = s.policy().ActivePolicy(ctx, tx)
			if err != nil {
				return depErr(err, "POLICY_UNAVAILABLE", "active_policy")
			}
			return nil
		}
		in, f, err = s.collect(ctx, tx, c, env, ca.ClientRequestKey, op.AdapterID, now, ds, snap.ArtifactDigest())
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	if nerr != nil {
		return s.normalizeRejected(ctx, c, act, nerr, snap, cat, f.active, raw)
	}
	act.env, act.content = &env, content
	if !opKnown {
		return nil, 0, policyUnavailable
	}
	if f.active.ExpectedOPARevision != snap.Revision() {
		return nil, 0, s.evaluationFailed(ctx, c, act.requestID, act.actionID, snap, f.active,
			unavailable("POLICY_VERSION_MISMATCH", "loaded revision differs from active_policy"))
	}
	ev, err := evaluate(ctx, snap, in, f, c)
	if err != nil {
		return nil, 0, s.evaluationFailed(ctx, c, act.requestID, act.actionID, snap, f.active, err)
	}
	s.applyIntent(ctx, &ev, op, c, env)

	row := opaDecision(act.actionID, act.requestID, env, op, &ev, f, snap, cat)
	_, err = s.storeDecision(ctx, c, act, row)
	if errors.Is(err, errExistingAction) {
		return s.afterRace(ctx, c, ca.ClientRequestKey, rawDigest)
	}
	if err != nil {
		return nil, 0, err
	}
	if row.derived.Verdict == decisions.Allow {
		s.Kick()
	}
	return respond(act.requestID, act.actionID, row.decisionID, row.derived), decisions.HTTPStatus(row.derived.Verdict, row.derived.ReasonCodes), nil
}

// opaDecision builds the decision row of an OPA-stage decision.
func opaDecision(actionID, requestID string, env canonical.ActionEnvelope, op canonical.CatalogOperation, ev *evaluation,
	f facts, snap *policyloader.Snapshot, cat canonical.Catalog) decisionRow {
	digest, adapter, rev := env.ActionDigest, op.AdapterID, snap.Revision()
	epoch := f.active.Epoch
	row := decisionRow{
		decisionID: uuid.NewString(), requestID: requestID, actionID: actionID,
		actionDigest: &digest, adapterID: &adapter, derived: ev.derived, stage: "opa", input: ev,
		bundleID: snap.BundleID(), epoch: &epoch, revision: &rev, catalog: cat, probe: f.probe,
	}
	if ev.intent.IntentCheckID != "" {
		id := ev.intent.IntentCheckID
		row.intentID = &id
	}
	return row
}

func respond(requestID, actionID, decisionID string, d decisions.Derived) *ActionResponse {
	return &ActionResponse{
		RequestID: requestID, ActionID: actionID, DecisionID: decisionID, Verdict: d.Verdict,
		ExecutionAllowed: d.Verdict == decisions.Allow, ReasonCodes: nonNil(d.ReasonCodes),
		DecisionBasis: nullStr(d.DecisionBasis),
	}
}

// normalizeRejected handles a Normalize error. Only CONTENT_PATTERN_DENIED
// has an action and a normalize-stage decision; every other rejection
// stores no action (COMMON recording of normalization-stage refusals and evaluation failures).
// SPEC-QUESTION: TASK-04 3.1 also records ENDPOINT_NOT_REGISTERED and
// operation-schema rejections as normalize-stage decisions; this follows
// COMMON.
func (s *Service) normalizeRejected(ctx context.Context, c Caller, act *newAction, ne *canonical.NormalizeError,
	snap *policyloader.Snapshot, cat canonical.Catalog, active ActivePolicy, raw []byte) (*ActionResponse, int, error) {
	if !storesNormalizeDecision(ne) {
		return nil, 0, s.reject(ctx, c, act.operationID, ne.HTTPStatus, ne.ReasonCodes, raw)
	}
	row := normalizeDecision(ne, snap, cat, active)
	row.decisionID, row.requestID, row.actionID = uuid.NewString(), act.requestID, act.actionID
	_, err := s.storeDecision(ctx, c, act, row)
	if errors.Is(err, errExistingAction) {
		return s.afterRace(ctx, c, act.clientKey, act.rawBodyDigest)
	}
	if err != nil {
		return nil, 0, err
	}
	return respond(act.requestID, act.actionID, row.decisionID, row.derived), decisions.HTTPStatus(decisions.Deny, row.derived.ReasonCodes), nil
}

// storesNormalizeDecision reports whether a Normalize error is the one
// rejection that stores an action and a normalize-stage decision.
func storesNormalizeDecision(ne *canonical.NormalizeError) bool {
	return len(ne.ReasonCodes) == 1 && ne.ReasonCodes[0] == canonical.ReasonContentPatternDenied && ne.RuleID != ""
}

// existing answers a resubmission: the same (actor, session, key) with the
// same raw_body_digest returns the action and its latest decision; a
// different body is 409 CLIENT_KEY_BODY_CONFLICT (TASK-04 chapter 3 step 2).
func (s *Service) existing(ctx context.Context, c Caller, key, rawDigest string) (*ActionResponse, int, bool, error) {
	var (
		actionID, storedDigest, decisionID, requestID, verdict string
		codes                                                  []string
		basis                                                  *string
	)
	err := s.readTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
SELECT a.action_id::text, a.raw_body_digest, d.decision_id::text, d.request_id::text, d.verdict, d.reason_codes, d.decision_basis
FROM decisions.actions a
JOIN LATERAL (SELECT * FROM decisions.decisions x WHERE x.action_id = a.action_id ORDER BY x.seq DESC LIMIT 1) d ON true
WHERE a.authenticated_actor = $1 AND a.session_id = $2 AND a.client_request_key = $3`,
			c.AuthenticatedActor, c.SessionID, key).Scan(&actionID, &storedDigest, &decisionID, &requestID, &verdict, &codes, &basis)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	if storedDigest != rawDigest {
		e := fail(http.StatusConflict, "CLIENT_KEY_BODY_CONFLICT", "client_request_key reused with another body")
		e.ActionID = actionID
		return nil, 0, true, e
	}
	d := decisions.Derived{Verdict: verdict, ReasonCodes: codes, DecisionBasis: derefStr(basis)}
	return respond(requestID, actionID, decisionID, d), decisions.HTTPStatus(verdict, codes), true, nil
}

// afterRace answers the loser of two concurrent first submissions with the
// winner's action.
func (s *Service) afterRace(ctx context.Context, c Caller, key, rawDigest string) (*ActionResponse, int, error) {
	out, status, found, err := s.existing(ctx, c, key, rawDigest)
	if err != nil {
		return nil, 0, err
	}
	if !found {
		return nil, 0, unavailable("STATE_STORE_UNAVAILABLE", "concurrent action not visible")
	}
	return out, status, nil
}

// reject answers a request that stores no action. request_rejected is
// appended in its own transaction; if that fails the rejection is still
// returned and the failure logged.
// SPEC-QUESTION: whether a failed request_rejected append must turn the
// response into 503 is not specified.
func (s *Service) reject(ctx context.Context, c Caller, operationID string, status int, codes []string, raw []byte) error {
	codes = decisions.SortedCodes(codes)
	requestID := uuid.NewString()
	payload := map[string]any{"request_id": requestID, "session_id": c.SessionID, "reason_codes": codes,
		"raw_body_digest": canonical.RawBodyDigest(raw)}
	if operationID != "" {
		payload["operation_id"] = operationID
	}
	if err := s.inTx(ctx, func(tx pgx.Tx) error {
		return s.audit().Append(ctx, tx, Event{Type: "request_rejected", Tenant: c.Tenant, Actor: c.AuthenticatedActor, SessionID: c.SessionID, Payload: payload})
	}); err != nil {
		s.log().Warn("request_rejected not recorded", "request_id", requestID, "err", err)
	}
	code := "SCHEMA_INVALID"
	if len(codes) > 0 {
		code = codes[0]
		if status == 0 {
			status = decisions.HTTPStatus(decisions.Deny, codes)
		}
	}
	return &Error{Status: status, Code: code, Msg: "request rejected"}
}

// evaluationFailed records policy_evaluation_failed (own transaction, best
// effort) and returns err; no action or decision exists.
func (s *Service) evaluationFailed(ctx context.Context, c Caller, requestID, actionID string, snap *policyloader.Snapshot,
	active ActivePolicy, err error) error {
	var e *Error
	if !errors.As(err, &e) || (e.Code != "POLICY_UNAVAILABLE" && e.Code != "POLICY_VERSION_MISMATCH") {
		return err
	}
	payload := map[string]any{"request_id": requestID, "action_id": actionID, "reason_codes": []string{e.Code},
		"loaded_revision": snap.Revision(), "expected_revision": active.ExpectedOPARevision}
	if aerr := s.inTx(ctx, func(tx pgx.Tx) error {
		return s.audit().Append(ctx, tx, Event{Type: "policy_evaluation_failed", Tenant: c.Tenant, Actor: c.AuthenticatedActor, SessionID: c.SessionID, Payload: payload})
	}); aerr != nil {
		s.log().Warn("policy_evaluation_failed not recorded", "request_id", requestID, "err", aerr)
	}
	s.log().Error("policy evaluation failed", "request_id", requestID, "code", e.Code, "msg", e.Msg)
	return e
}
