package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/decisions"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

// errExistingAction means another request stored the same
// (authenticated_actor, session_id, client_request_key) first; the caller
// answers with that action (TASK-04 chapter 3 step 2).
var errExistingAction = errors.New("gateway: action exists")

// newAction is the actions row of a new submission. env is nil for a
// normalize-stage rejection that has no envelope.
type newAction struct {
	actionID      string
	requestID     string
	clientKey     string
	rawBodyDigest string
	operationID   string
	env           *canonical.ActionEnvelope
	content       canonical.Content
}

// decisionRow is one GatewayDecision to insert.
type decisionRow struct {
	decisionID   string
	requestID    string
	actionID     string
	actionDigest *string
	adapterID    *string
	derived      decisions.Derived
	stage        string // normalize or opa
	input        *evaluation
	bundleID     string
	epoch        *int64
	revision     *string
	catalog      canonical.Catalog
	probe        *ActivationProbe
	// clientKey is the action's client_request_key. :reevaluate stores a
	// decision without a new action, so the probe binding needs it here.
	clientKey    string
	intentID     *string
	reevaluateOf string // previous decision_id for :reevaluate
}

// latestDecision is the latest stored decision of an action, as a
// :reevaluate response needs it.
type latestDecision struct {
	decisionID  string
	requestID   string
	verdict     string
	reasonCodes []string
	basis       *string
	expiresAt   time.Time
}

func (l latestDecision) derived() decisions.Derived {
	return decisions.Derived{Verdict: l.verdict, ReasonCodes: l.reasonCodes, DecisionBasis: derefStr(l.basis)}
}

// storeResult is the outcome of storeDecision. superseded is set, and
// nothing is stored, when another :reevaluate of the same action stored its
// decision after this one read the previous decision.
type storeResult struct {
	expiresAt  time.Time
	superseded *latestDecision
}

// storeDecision writes one decision transaction (COMMON decision storage
// transaction): the action (when act != nil), its content, the decision
// input and its export enqueue, the immutable decision, the execute request
// for an allow, the probe binding, and the audit events. It returns the
// decision's expires_at. Any failure rolls everything back.
//
// A :reevaluate decision (d.reevaluateOf set) first goes through
// guardReevaluate, which can refuse it (409 PERMIT_INVALID) or report that
// another re-evaluation won (storeResult.superseded).
func (s *Service) storeDecision(ctx context.Context, c Caller, act *newAction, d decisionRow) (storeResult, error) {
	var res storeResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if d.reevaluateOf != "" {
			latest, err := guardReevaluate(ctx, tx, d)
			if err != nil {
				return err
			}
			if latest != nil {
				res.superseded = latest
				return nil // nothing written; the empty transaction commits
			}
		}
		if act != nil {
			if err := insertAction(ctx, tx, c, s.Environment, act); err != nil {
				return err
			}
			if act.content.ContentDigest != "" {
				if _, err := tx.Exec(ctx, `
INSERT INTO decisions.action_contents (content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, statement_timestamp(), statement_timestamp() + make_interval(days => $6))
ON CONFLICT (content_digest, action_id) DO NOTHING`,
					act.content.ContentDigest, act.content.Tenant, act.actionID, act.content.AdapterID, act.content.ContentBytes, ContentTTLDays); err != nil {
					return err
				}
			}
		}
		var inputRef *string
		if d.input != nil {
			inputRef = &d.input.inputDigest
			tag, err := tx.Exec(ctx, `
INSERT INTO decisions.decision_inputs (decision_input_digest, tenant, sanitized_input, policy_bundle_id, created_at)
VALUES ($1, $2, $3, $4, statement_timestamp())
ON CONFLICT (decision_input_digest) DO NOTHING`, d.input.inputDigest, c.Tenant, d.input.inputJSON, d.bundleID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				record, err := canonical.JCS(d.input.inputJSON)
				if err != nil {
					return err
				}
				if err := s.audit().EnqueueDecisionInput(ctx, tx, d.input.inputDigest, record); err != nil {
					return depErr(err, "STATE_STORE_UNAVAILABLE", "enqueue_decision_input")
				}
			}
		}
		dv := d.derived
		regoResult, err := regoResultJSON(d)
		if err != nil {
			return err
		}
		var probeID *string
		if dv.ActivationProbeID != "" {
			probeID = &dv.ActivationProbeID
		}
		err = tx.QueryRow(ctx, `
INSERT INTO decisions.decisions (decision_id, request_id, action_id, action_digest, adapter_id, verdict, reason_codes,
    decision_basis, approval_id, standing_rule_id, service_session_id, activation_probe_id, intent_check_id,
    matched_rule_ids, evaluated_rule_ids, rego_result, gateway_added_rule_ids, decision_stage,
    decision_input_ref, decision_input_digest, policy_bundle_id, policy_epoch, opa_bundle_revision,
    catalog_digest, catalog_version, expires_at, authenticated_gateway, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $19, $20, $21, $22,
    $23, $24, statement_timestamp() + make_interval(secs => $25), $26, statement_timestamp())
RETURNING expires_at`,
			d.decisionID, d.requestID, d.actionID, d.actionDigest, d.adapterID, dv.Verdict, nonNil(dv.ReasonCodes),
			nullStr(dv.DecisionBasis), nullStr(dv.ApprovalID), nullStr(dv.StandingRuleID), nullStr(dv.ServiceSessionID), probeID, d.intentID,
			dv.MatchedRuleIDs, dv.EvaluatedRuleIDs, regoResult, nonNil(dv.GatewayAddedRuleIDs), d.stage,
			inputRef, d.bundleID, d.epoch, d.revision,
			d.catalog.CatalogDigest, d.catalog.CatalogVersion, DecisionTTL.Seconds(), s.GatewayIdentity).Scan(&res.expiresAt)
		if err != nil {
			return err
		}
		if dv.Verdict == decisions.Allow {
			if _, err := tx.Exec(ctx, `
INSERT INTO decisions.execute_requests (decision_id, action_id, adapter_id, state, attempts, next_attempt_at, updated_at)
VALUES ($1, $2, $3, 'pending', 0, statement_timestamp(), statement_timestamp())`, d.decisionID, d.actionID, *d.adapterID); err != nil {
				return err
			}
		}
		if d.probe != nil {
			key := d.clientKey
			if act != nil {
				key = act.clientKey
			}
			if err := s.probes().Bind(ctx, tx, c.SessionID, key, d.actionID); err != nil {
				return depErr(err, "STATE_STORE_UNAVAILABLE", "bind_activation_probe_action")
			}
		}
		for _, ev := range decisionEvents(c, act, d) {
			if err := s.audit().Append(ctx, tx, ev); err != nil {
				return depErr(err, "STATE_STORE_UNAVAILABLE", "audit_append "+ev.Type)
			}
		}
		return nil
	})
	return res, err
}

// guardReevaluate serializes the store of :reevaluate decisions of one
// action and re-checks, under that lock, what Reevaluate checked before the
// evaluation:
//
//  1. the action still has no coordinator.reservations row; otherwise the
//     answer is the same 409 PERMIT_INVALID as the pre-check and nothing is
//     stored;
//  2. compare-and-set: the action's latest decision is still d.reevaluateOf,
//     the decision this request read before it evaluated. Otherwise another
//     :reevaluate stored first; this one stores nothing and returns that
//     latest decision.
//
// Without (2), concurrent :reevaluate calls on an approval_required action
// with a usable approval each stored an allow decision and an
// execute_requests row, and the adapter (idempotency key decision_id) would
// execute the action once per decision.
//
// Lock: the agreed design was SELECT ... FOR UPDATE on the decisions.actions
// row, but PostgreSQL requires UPDATE privilege for any row-locking clause
// and gateway_app has only SELECT and INSERT on decisions.actions (actions
// are immutable; migration 20261016181826 and TestDecisionsAreImmutable).
// A transaction-scoped advisory lock keyed by the action_id gives the same
// per-action serialization without widening that grant. lock_timeout
// applies to it, so a long wait is 503 LOCK_TIMEOUT like a row lock (inTx).
//
// Lock order: this lock is not in the COMMON global order (active_policy →
// ... → work_readiness_checks), and no coordinator or identity transaction
// takes it. The gateway takes it first in its decision transaction, before
// any row lock, and the re-checks below are plain reads. A transaction that
// waits for it therefore holds no other lock, so it cannot be part of a
// deadlock cycle with the coordinator paths.
//
// Scope: the lock serializes gateway re-evaluations only. Full mutual
// exclusion with the coordinator's reservation INSERT would need a lock
// convention shared with TASK-03, which is out of scope here. Re-checking (1)
// right before the INSERTs narrows the window but does not close it: a
// reservation committed after this read is not seen here. The coordinator
// keeps one reservation row per action (UNIQUE (action_id)), so that
// decision still meets the existing reservation when it is reserved.
func guardReevaluate(ctx context.Context, tx pgx.Tx, d decisionRow) (*latestDecision, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('decisions.actions/' || $1::text, 0))`, d.actionID); err != nil {
		return nil, err
	}
	var l latestDecision
	err := tx.QueryRow(ctx, `
SELECT decision_id::text, request_id::text, verdict, reason_codes, decision_basis, expires_at
FROM decisions.decisions WHERE action_id = $1 ORDER BY seq DESC LIMIT 1`, d.actionID).Scan(
		&l.decisionID, &l.requestID, &l.verdict, &l.reasonCodes, &l.basis, &l.expiresAt)
	if err != nil {
		return nil, err
	}
	var reserved bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM coordinator.reservations WHERE action_id = $1)`, d.actionID).Scan(&reserved); err != nil {
		return nil, err
	}
	if reserved {
		e := fail(http.StatusConflict, "PERMIT_INVALID", "action already reserved")
		e.ActionID, e.DecisionID = d.actionID, l.decisionID
		return nil, e
	}
	if l.decisionID != d.reevaluateOf {
		return &l, nil
	}
	return nil, nil
}

func insertAction(ctx context.Context, tx pgx.Tx, c Caller, environment string, a *newAction) error {
	var workload *string
	if c.Kind == KindUser {
		workload = &c.WorkloadID
	}
	var (
		schemaVersion, endpointID, dataClass, catalogDigest, catalogVersion, canonVersion, actionDigest *string
		target, limits, envelope                                                                        []byte
		disclosure, sources                                                                             []string
		contentDigest, contentRef                                                                       *string
		size                                                                                            *int64
	)
	if e := a.env; e != nil {
		var err error
		if target, err = json.Marshal(e.CanonicalTarget); err != nil {
			return err
		}
		if limits, err = json.Marshal(e.Limits); err != nil {
			return err
		}
		// The actions CHECK requires the envelope jsonb to equal the columns, and
		// the columns store empty arrays, never null. Marshal the same values.
		e.DisclosureFields, e.DataSources = nonNil(e.DisclosureFields), nonNil(e.DataSources)
		if envelope, err = json.Marshal(e); err != nil {
			return err
		}
		schemaVersion, endpointID, dataClass = &e.SchemaVersion, &e.EndpointID, &e.DataClass
		catalogDigest, catalogVersion, canonVersion = &e.CatalogDigest, &e.CatalogVersion, &e.CanonicalizationVersion
		actionDigest = &e.ActionDigest
		disclosure, sources = nonNil(e.DisclosureFields), nonNil(e.DataSources)
		contentDigest, contentRef = e.ContentDigest, e.ContentRef
		size = &e.Bytes
	}
	var id string
	err := tx.QueryRow(ctx, `
INSERT INTO decisions.actions (action_id, request_id, authenticated_actor, session_kind, session_id, workload_id,
    client_request_key, raw_body_digest, tenant, environment, operation_id, schema_version, endpoint_id,
    canonical_target, disclosure_fields, data_class, data_sources, content_digest, content_ref, bytes, limits,
    catalog_digest, catalog_version, canonicalization_version, action_digest, envelope, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
    $24, $25, $26, statement_timestamp())
ON CONFLICT (authenticated_actor, session_id, client_request_key) DO NOTHING
RETURNING action_id::text`,
		a.actionID, a.requestID, c.AuthenticatedActor, c.Kind, c.SessionID, workload,
		a.clientKey, a.rawBodyDigest, c.Tenant, environment, a.operationID, schemaVersion, endpointID,
		target, sliceOrNil(a.env != nil, disclosure), dataClass, sliceOrNil(a.env != nil, sources), contentDigest, contentRef, size, limits,
		catalogDigest, catalogVersion, canonVersion, actionDigest, envelope).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return errExistingAction
	}
	return err
}

// regoResultJSON is rego_result: the original {verdict, reason_codes,
// matched_rule_ids}, or null at the normalize stage.
func regoResultJSON(d decisionRow) ([]byte, error) {
	if d.stage == "normalize" {
		return nil, nil
	}
	r := d.derived.RegoResult
	r.ReasonCodes = nonNil(r.ReasonCodes)
	return json.Marshal(r)
}

// decisionEvents are the audit events of one decision transaction (COMMON
// event_type registry).
func decisionEvents(c Caller, act *newAction, d decisionRow) []Event {
	dv := d.derived
	mk := func(t string, p map[string]any) Event {
		return Event{Type: t, Tenant: c.Tenant, Actor: c.AuthenticatedActor, SessionID: c.SessionID,
			ActionID: d.actionID, RequestID: d.requestID, Payload: p}
	}
	var evs []Event
	if act != nil {
		evs = append(evs, mk("request_received", map[string]any{
			"action_id": act.actionID, "request_id": act.requestID, "session_id": c.SessionID,
			"operation_id": act.operationID, "client_request_key_digest": canonical.ClientRequestKeyDigest(act.clientKey),
		}))
	} else {
		evs = append(evs, mk("action_reevaluated", map[string]any{
			"action_id": d.actionID, "previous_decision_id": d.reevaluateOf, "decision_id": d.decisionID, "policy_epoch": d.epoch,
		}))
	}
	pd := map[string]any{
		"decision_id": d.decisionID, "decision_stage": d.stage, "verdict": dv.Verdict, "reason_codes": nonNil(dv.ReasonCodes),
		"decision_basis": nullStr(dv.DecisionBasis), "matched_rule_ids": dv.MatchedRuleIDs, "evaluated_rule_ids": dv.EvaluatedRuleIDs,
		"gateway_added_rule_ids": nonNil(dv.GatewayAddedRuleIDs), "policy_bundle_id": d.bundleID, "policy_epoch": d.epoch,
		"opa_bundle_revision": d.revision, "catalog_digest": d.catalog.CatalogDigest,
	}
	for k, v := range map[string]string{"approval_id": dv.ApprovalID, "standing_rule_id": dv.StandingRuleID,
		"service_session_id": dv.ServiceSessionID, "activation_probe_id": dv.ActivationProbeID} {
		if v != "" {
			pd[k] = v
		}
	}
	evs = append(evs, mk("policy_decided", pd))
	switch dv.Verdict {
	case decisions.ApprovalRequired:
		evs = append(evs, mk("approval_requested", map[string]any{
			"action_id": d.actionID, "decision_id": d.decisionID, "reason_codes": dv.ReasonCodes,
		}))
	case decisions.Allow:
		evs = append(evs, mk("dispatch_enqueued", map[string]any{"decision_id": d.decisionID, "adapter_id": *d.adapterID}))
	}
	return evs
}

// normalizeDecision is the decision of a normalize-stage rejection (COMMON:
// CONTENT_PATTERN_DENIED): verdict deny, the normalize rule as matched and
// evaluated rule, no rego_result, no opa_bundle_revision and no decision
// input. policy_epoch is the active_policy epoch read in the facts snapshot;
// it is required in the decision and in policy_decided.
func normalizeDecision(ne *canonical.NormalizeError, snap *policyloader.Snapshot, cat canonical.Catalog, active ActivePolicy) decisionRow {
	epoch := active.Epoch
	return decisionRow{
		derived: decisions.Derived{
			Verdict: decisions.Deny, ReasonCodes: decisions.SortedCodes(ne.ReasonCodes),
			MatchedRuleIDs: []string{ne.RuleID}, EvaluatedRuleIDs: []string{ne.RuleID}, GatewayAddedRuleIDs: []string{},
		},
		stage:    "normalize",
		bundleID: snap.BundleID(),
		epoch:    &epoch,
		catalog:  cat,
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func sliceOrNil(ok bool, s []string) []string {
	if !ok {
		return nil
	}
	return s
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
