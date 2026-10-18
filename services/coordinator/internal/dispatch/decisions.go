package dispatch

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// PGDecisions reads a TASK-04 decision from decisions.decisions (migration
// 20261016181826_gateway_decisions). The action fields (session, workload,
// operation, target) are copied into the decision row from its action, so
// only decisions.decisions is read. Decisions are immutable, so the row is
// read without a lock.
type PGDecisions struct{}

var _ DecisionSource = PGDecisions{}

// Decision returns the decision. SessionID and WorkloadID are set only for a
// user-session action; a service-session decision carries its
// service_session_id instead. ErrNotFound if the decision does not exist.
func (PGDecisions) Decision(ctx context.Context, tx pgx.Tx, decisionID string) (Decision, error) {
	var d Decision
	var actionDigest, adapterID, basis, approvalID, standingRuleID, serviceSessionID, probeID, opaRevision, sessionID, workloadID, targetID *string
	var epoch *int64
	err := tx.QueryRow(ctx, `
SELECT decision_id::text, request_id::text, action_id::text, action_digest, adapter_id, verdict,
       decision_basis, approval_id::text, standing_rule_id, service_session_id::text,
       activation_probe_id::text, policy_epoch, opa_bundle_revision, catalog_digest, expires_at,
       CASE WHEN session_kind = 'user' THEN session_id::text END, workload_id, operation_id, target_id
FROM decisions.decisions
WHERE decision_id = $1`, decisionID).Scan(
		&d.DecisionID, &d.RequestID, &d.ActionID, &actionDigest, &adapterID, &d.Verdict,
		&basis, &approvalID, &standingRuleID, &serviceSessionID,
		&probeID, &epoch, &opaRevision, &d.CatalogDigest, &d.ExpiresAt,
		&sessionID, &workloadID, &d.OperationID, &targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Decision{}, ErrNotFound
	}
	if err != nil {
		return Decision{}, err
	}
	d.ActionDigest = deref(actionDigest)
	d.AdapterID = deref(adapterID)
	d.DecisionBasis = deref(basis)
	d.ApprovalID = deref(approvalID)
	d.StandingRuleID = deref(standingRuleID)
	d.ServiceSessionID = deref(serviceSessionID)
	d.ActivationProbeID = deref(probeID)
	d.OPABundleRevision = deref(opaRevision)
	d.SessionID = deref(sessionID)
	d.WorkloadID = deref(workloadID)
	d.TargetID = deref(targetID)
	if epoch != nil {
		d.PolicyEpoch = *epoch
	}
	return d, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
