package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// opaInput is the OPA input (COMMON OPA input and result, TASK-04 3.2): exactly
// the five keys decision.rego reads.
type opaInput struct {
	Envelope          canonical.ActionEnvelope    `json:"envelope"`
	VerifiedSession   verifiedSession             `json:"verified_session"`
	ApprovalSnapshot  *approvalSnapshot           `json:"approval_snapshot"`
	WorkloadDataState canonical.WorkloadDataState `json:"workload_data_state"`
	ControlHealth     controlHealth               `json:"control_health"`
}

type verifiedSession struct {
	Kind                string        `json:"kind"`
	SessionID           string        `json:"session_id"`
	AuthenticatedActor  string        `json:"authenticated_actor"`
	Tenant              string        `json:"tenant"`
	WorkloadID          *string       `json:"workload_id,omitempty"`      // user
	CallerPrincipal     *string       `json:"caller_principal,omitempty"` // service
	State               string        `json:"state"`
	ExpiresAt           string        `json:"expires_at"`
	AllowedOperationIDs []string      `json:"allowed_operation_ids"`
	ServiceScope        *serviceScope `json:"service_scope"`
}

type serviceScope struct {
	Profile     string  `json:"profile"`
	IssueID     *string `json:"issue_id"`
	CandidateID *string `json:"candidate_id"`
	ChangeID    *string `json:"change_id"`
	SnapshotID  *string `json:"snapshot_id"`
	ActionID    *string `json:"action_id"`
}

type approvalSnapshot struct {
	ApprovalID         string          `json:"approval_id"`
	ActionID           string          `json:"action_id"`
	Revision           int64           `json:"revision"`
	ApprovalKind       string          `json:"approval_kind"`
	SessionID          string          `json:"session_id"`
	AuthenticatedActor string          `json:"authenticated_actor"`
	AllowedOperation   string          `json:"allowed_operation"`
	CanonicalTarget    json.RawMessage `json:"canonical_target"`
	DisclosureFields   []string        `json:"disclosure_fields"`
	ContentDigest      *string         `json:"content_digest"`
	MaxActions         int64           `json:"max_actions"`
	UsedActions        int64           `json:"used_actions"`
	PolicyEpoch        int64           `json:"policy_epoch"`
	ExpiresAt          string          `json:"expires_at"`
	RevokedAt          *string         `json:"revoked_at"`
}

type controlHealth struct {
	EvaluatedAt          string           `json:"evaluated_at"`
	ActiveArtifactDigest string           `json:"active_artifact_digest"`
	ActiveHolds          []Hold           `json:"active_holds"`
	RequiredLeases       []lease          `json:"required_leases"`
	ActivationProbe      *ActivationProbe `json:"activation_probe"`
}

type lease struct {
	Component     string  `json:"component"`
	SourceID      *string `json:"source_id"`
	ObservedState string  `json:"observed_state"`
	LeaseUntil    string  `json:"lease_until"`
	ActiveVersion *string `json:"active_version"`
}

// facts is what one evaluation read besides the OPA input.
type facts struct {
	evaluatedAt time.Time
	active      ActivePolicy
	approvalID  string
	probe       *ActivationProbe
}

// evaluatedAt reads statement_timestamp() of the facts transaction (COMMON
// fact reads).
func evaluatedAt(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var t time.Time
	err := tx.QueryRow(ctx, `SELECT statement_timestamp()`).Scan(&t)
	return t, err
}

// dataState reads the caller's workload_data_state (TASK-05). No row means
// {"none", []}.
func (s *Service) dataState(ctx context.Context, tx pgx.Tx, c Caller) (canonical.WorkloadDataState, error) {
	key := DataStateKey{WorkloadID: c.WorkloadID}
	if c.Kind == KindService {
		key = DataStateKey{ServiceSessionID: c.SessionID}
	}
	d, found, err := s.adapters().DataState(ctx, tx, key)
	if err != nil {
		return canonical.WorkloadDataState{}, depErr(err, "STATE_STORE_UNAVAILABLE", "workload_data_state")
	}
	if !found {
		return canonical.WorkloadDataState{DataClassHighWater: "none", DataSources: []string{}}, nil
	}
	ws := canonical.WorkloadDataState{DataClassHighWater: d.DataClassHighWater, DataSources: append([]string{}, d.DataSources...)}
	return ws, nil
}

// collect reads the remaining facts for env in tx and builds the OPA input.
func (s *Service) collect(ctx context.Context, tx pgx.Tx, c Caller, env canonical.ActionEnvelope, clientKey string,
	adapterID string, now time.Time, ds canonical.WorkloadDataState, artifactDigest string) (opaInput, facts, error) {
	f := facts{evaluatedAt: now}
	var err error
	if f.active, err = s.policy().ActivePolicy(ctx, tx); err != nil {
		return opaInput{}, facts{}, depErr(err, "POLICY_UNAVAILABLE", "active_policy")
	}
	vs, err := verifiedSessionOf(ctx, tx, c)
	if err != nil {
		return opaInput{}, facts{}, err
	}
	snap, err := approvalOf(ctx, tx, env.ActionID)
	if err != nil {
		return opaInput{}, facts{}, err
	}
	if snap != nil {
		f.approvalID = snap.ApprovalID
	}

	scope := HoldScope{TargetID: env.CanonicalTarget.TargetID, SessionID: c.SessionID, SessionIsService: c.Kind == KindService}
	if c.Kind == KindUser {
		scope.WorkloadID = c.WorkloadID
	}
	holds, err := s.health().Holds(ctx, tx, scope)
	if err != nil {
		return opaInput{}, facts{}, depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "holds")
	}
	if holds == nil {
		holds = []Hold{}
	}
	leases := []lease{}
	for _, k := range requiredLeases(env.OperationID, adapterID, env.CanonicalTarget.TargetID, c) {
		rows, err := s.health().Leases(ctx, tx, k)
		if err != nil {
			return opaInput{}, facts{}, depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "leases")
		}
		leases = append(leases, aggregate(k.Component, rows, now))
	}

	if c.Kind == KindService && c.Profile == "activation_probe" {
		p, err := s.probes().Lookup(ctx, tx, c.SessionID, clientKey, env.ActionID)
		if err != nil {
			return opaInput{}, facts{}, depErr(err, "STATE_STORE_UNAVAILABLE", "activation_probes")
		}
		f.probe = p
	}
	in := opaInput{
		Envelope:          env,
		VerifiedSession:   vs,
		ApprovalSnapshot:  snap,
		WorkloadDataState: ds,
		ControlHealth: controlHealth{
			EvaluatedAt:          rfc3339(now),
			ActiveArtifactDigest: artifactDigest,
			ActiveHolds:          holds,
			RequiredLeases:       leases,
			ActivationProbe:      f.probe,
		},
	}
	return in, f, nil
}

// requiredLeases is the lease set of one request (COMMON required leases): gateway,
// coordinator, audit-db, audit-export and the operation's adapter; plus
// destination-evidence of the request's target for receiver.submit and
// node-sensors of the caller's node for user sessions.
// SPEC-QUESTION: TASK-04 3.2 lists only coordinator, audit-db, adapter and
// destination-evidence; this follows COMMON.
func requiredLeases(operationID, adapterID, targetID string, c Caller) []LeaseKey {
	keys := []LeaseKey{
		{Component: "gateway"}, {Component: "coordinator"}, {Component: "audit-db"},
		{Component: "audit-export"}, {Component: "adapter", AdapterID: adapterID},
	}
	if operationID == canonical.OpReceiverSubmit {
		keys = append(keys, LeaseKey{Component: "destination-evidence", TargetID: targetID})
	}
	if c.Kind == KindUser {
		keys = append(keys, LeaseKey{Component: "node-sensors", NodeUID: c.NodeUID})
	}
	return keys
}

var stateRank = map[string]int{"healthy": 0, "degraded": 1, "unhealthy": 2}

// aggregate folds the replicas of one component into one lease (TASK-04 3.2):
// only leases with lease_until > evaluated_at count; observed_state is the
// worst of them, lease_until the latest, active_version the common value or
// "mixed". With no valid replica the component is unhealthy.
// SPEC-QUESTION: source_id of the aggregate is not specified; it is the
// source_id of the replica with the latest lease_until.
func aggregate(component string, rows []LeaseRow, now time.Time) lease {
	var valid []LeaseRow
	for _, r := range rows {
		if r.Component == component && r.LeaseUntil.After(now) {
			valid = append(valid, r)
		}
	}
	if len(valid) == 0 {
		return lease{Component: component, ObservedState: "unhealthy", LeaseUntil: rfc3339(now)}
	}
	sort.Slice(valid, func(i, j int) bool {
		if !valid[i].LeaseUntil.Equal(valid[j].LeaseUntil) {
			return valid[i].LeaseUntil.After(valid[j].LeaseUntil)
		}
		return valid[i].SourceID < valid[j].SourceID
	})
	out := lease{Component: component, LeaseUntil: rfc3339(valid[0].LeaseUntil), ObservedState: "healthy"}
	src := valid[0].SourceID
	out.SourceID = &src
	worst := 0
	mixed := false
	var version *string
	for i, r := range valid {
		rank, ok := stateRank[r.ObservedState]
		if !ok {
			rank = stateRank["unhealthy"]
		}
		if rank > worst {
			worst = rank
		}
		if i == 0 {
			version = r.ActiveVersion
		} else if (version == nil) != (r.ActiveVersion == nil) || (version != nil && *version != *r.ActiveVersion) {
			mixed = true
		}
	}
	for st, rank := range stateRank {
		if rank == worst {
			out.ObservedState = st
		}
	}
	if mixed {
		m := "mixed"
		out.ActiveVersion = &m
	} else if version != nil {
		v := *version
		out.ActiveVersion = &v
	}
	return out
}

// verifiedSessionOf re-reads the caller's session in the facts transaction
// (TASK-04 3.2 verified_session).
func verifiedSessionOf(ctx context.Context, tx pgx.Tx, c Caller) (verifiedSession, error) {
	vs := verifiedSession{Kind: c.Kind, SessionID: c.SessionID}
	var expires time.Time
	switch c.Kind {
	case KindUser:
		var workload string
		err := tx.QueryRow(ctx, `
SELECT authenticated_actor, tenant, workload_id, state, expires_at, allowed_operation_ids
FROM identity.sessions WHERE session_id = $1`, c.SessionID).Scan(
			&vs.AuthenticatedActor, &vs.Tenant, &workload, &vs.State, &expires, &vs.AllowedOperationIDs)
		if err != nil {
			return verifiedSession{}, storeErr(err, "sessions")
		}
		vs.WorkloadID = &workload
	case KindService:
		var principal string
		sc := serviceScope{}
		err := tx.QueryRow(ctx, `
SELECT authenticated_actor, tenant, caller_principal, state, expires_at, profile,
       issue_id::text, candidate_id::text, change_id::text, snapshot_id::text, action_id::text
FROM identity.service_sessions WHERE service_session_id = $1`, c.SessionID).Scan(
			&vs.AuthenticatedActor, &vs.Tenant, &principal, &vs.State, &expires, &sc.Profile,
			&sc.IssueID, &sc.CandidateID, &sc.ChangeID, &sc.SnapshotID, &sc.ActionID)
		if err != nil {
			return verifiedSession{}, storeErr(err, "service_sessions")
		}
		vs.CallerPrincipal = &principal
		vs.ServiceScope = &sc
	default:
		return verifiedSession{}, authRequired
	}
	if vs.AllowedOperationIDs == nil {
		vs.AllowedOperationIDs = []string{}
	}
	vs.ExpiresAt = rfc3339(expires)
	return vs, nil
}

// approvalOf returns the latest unrevoked, unexpired approval revision of the
// action, or nil (COMMON approval_snapshot). A used-up approval is still
// returned; Rego answers it with APPROVAL_UNAVAILABLE.
func approvalOf(ctx context.Context, tx pgx.Tx, actionID string) (*approvalSnapshot, error) {
	var a approvalSnapshot
	var expires time.Time
	var target []byte
	err := tx.QueryRow(ctx, `
SELECT approval_id::text, action_id::text, revision, approval_kind, session_id::text, authenticated_actor,
       allowed_operation, canonical_target, disclosure_fields, content_digest, max_actions, used_actions,
       policy_epoch, expires_at
FROM identity.approvals
WHERE action_id = $1 AND revoked_at IS NULL AND expires_at > statement_timestamp()
ORDER BY revision DESC LIMIT 1`, actionID).Scan(
		&a.ApprovalID, &a.ActionID, &a.Revision, &a.ApprovalKind, &a.SessionID, &a.AuthenticatedActor,
		&a.AllowedOperation, &target, &a.DisclosureFields, &a.ContentDigest, &a.MaxActions, &a.UsedActions,
		&a.PolicyEpoch, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, storeErr(err, "approvals")
	}
	a.CanonicalTarget = target
	if a.DisclosureFields == nil {
		a.DisclosureFields = []string{}
	}
	a.ExpiresAt = rfc3339(expires)
	return &a, nil
}

func storeErr(err error, what string) error {
	return depErr(err, "STATE_STORE_UNAVAILABLE", what)
}
