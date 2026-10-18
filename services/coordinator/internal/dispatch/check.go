package dispatch

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// CheckRequest is the POST /internal/dispatch/permits/{permit_id}/check body.
type CheckRequest struct {
	AttemptID      string `json:"attempt_id"`
	ActionDigest   string `json:"action_digest"`
	PolicyEpoch    int64  `json:"policy_epoch"`
	WireBodyDigest string `json:"wire_body_digest"`
}

// CheckResult answers the first claim of a permit; later checks are 409.
type CheckResult struct {
	PermitID         string    `json:"permit_id"`
	AttemptID        string    `json:"attempt_id"`
	ExecutionAllowed bool      `json:"execution_allowed"`
	ClaimedAt        time.Time `json:"claimed_at"`
}

// Check claims a permit once (TASK-03 3.2 permit claim). It runs the
// decision (verdict, expiry, epoch, catalog, OPA revision), hold, node boot,
// lease, session and approval checks again in the global lock order,
// compares the body with the values fixed in the permit at reservation, and
// then sets claimed_at, reservation committed and attempt claimed together.
func (s *Service) Check(ctx context.Context, a Adapter, permitID string, req CheckRequest) (*CheckResult, error) {
	if !isUUID(permitID) || !isUUID(req.AttemptID) || !isDigest(req.ActionDigest) || !isDigest(req.WireBodyDigest) || req.PolicyEpoch <= 0 {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "malformed check request")
	}
	notFound := fail(http.StatusNotFound, "RESOURCE_NOT_FOUND", "no such permit for this adapter")

	// Keys first, unlocked; the transaction locks in the global order and
	// verifies them again.
	var k struct {
		decisionID, attemptID, reservationID, adapterID string
		b                                               budget
	}
	err := s.Pool.QueryRow(ctx, `
SELECT p.decision_id::text, p.attempt_id::text, t.reservation_id::text, p.adapter_id,
       r.decision_basis, r.session_id::text, r.service_session_id::text, r.approval_id::text, r.approval_revision
FROM coordinator.dispatch_permits p
JOIN coordinator.attempts t ON t.attempt_id = p.attempt_id
JOIN coordinator.reservations r ON r.reservation_id = t.reservation_id
WHERE p.permit_id = $1`, permitID).Scan(&k.decisionID, &k.attemptID, &k.reservationID, &k.adapterID,
		&k.b.Basis, &k.b.SessionID, &k.b.ServiceSessionID, &k.b.ApprovalID, &k.b.ApprovalRevision)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && k.adapterID != a.AdapterID) {
		return nil, notFound
	}
	if err != nil {
		return nil, err
	}
	if k.b.SessionID == nil && k.b.ServiceSessionID == nil {
		return nil, unavailable("STATE_STORE_UNAVAILABLE", "reservation has no session")
	}

	var out *CheckResult
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		active, err := s.policy().LockActivePolicy(ctx, tx)
		if err != nil {
			return depErr(err, "STATE_STORE_UNAVAILABLE", "active_policy")
		}
		dec, err := s.decision(ctx, tx, k.decisionID, a)
		if err != nil {
			return err
		}
		// The decision may have expired or the policy moved since the
		// reservation; the permit TTL alone does not cover that.
		if err := s.checkDecision(ctx, tx, dec, active); err != nil {
			return err
		}
		if err := s.checkHealth(ctx, tx, a, dec, active); err != nil {
			return err
		}
		live, err := k.b.lockSession(ctx, tx, true)
		if err != nil {
			return err
		}
		if live && k.b.Basis == "approval" {
			// A revoked approval cancels the permit (TASK-03 3.2 permit
			// claim: cancel). Locked in the global order before reservations.
			if k.b.ApprovalID == nil || k.b.ApprovalRevision == nil {
				return unavailable("STATE_STORE_UNAVAILABLE", "approval reservation without its approval")
			}
			if err := tx.QueryRow(ctx, `SELECT revoked_at IS NULL FROM identity.approvals
WHERE approval_id = $1 AND revision = $2 FOR SHARE`, *k.b.ApprovalID, *k.b.ApprovalRevision).Scan(&live); err != nil {
				return err
			}
		}
		if live && k.b.Basis == "activation_probe" {
			// The activation probe row FOR SHARE, at the same place as in
			// the reservation (after the session, before reservations): the
			// unlocked read in checkHealth runs only under a hold and could
			// be stale. A probe that expired, changed epoch or lost its
			// binding cancels the permit.
			if live, err = s.probeUsable(ctx, tx, dec, active, true); err != nil {
				return err
			}
		}
		var resState string
		if err := tx.QueryRow(ctx, `SELECT state FROM coordinator.reservations WHERE reservation_id = $1 FOR UPDATE`,
			k.reservationID).Scan(&resState); err != nil {
			return err
		}
		var attState, nodeUID string
		if err := tx.QueryRow(ctx, `SELECT state, adapter_node_uid::text FROM coordinator.attempts WHERE attempt_id = $1 FOR UPDATE`,
			k.attemptID).Scan(&attState, &nodeUID); err != nil {
			return err
		}
		var p struct {
			attemptID, actionDigest, wireDigest, catalog string
			epoch                                        int64
			claimed, expired                             bool
		}
		if err := tx.QueryRow(ctx, `
SELECT attempt_id::text, action_digest, wire_body_digest, catalog_digest, policy_epoch,
       claimed_at IS NOT NULL, expires_at <= statement_timestamp()
FROM coordinator.dispatch_permits WHERE permit_id = $1 FOR UPDATE`, permitID).Scan(
			&p.attemptID, &p.actionDigest, &p.wireDigest, &p.catalog, &p.epoch, &p.claimed, &p.expired); err != nil {
			return err
		}
		switch {
		case p.attemptID != req.AttemptID || p.actionDigest != req.ActionDigest ||
			p.wireDigest != req.WireBodyDigest || p.epoch != req.PolicyEpoch:
			return conflict("PERMIT_INVALID", "check body differs from the permit")
		case p.claimed:
			return conflict("PERMIT_INVALID", "permit already claimed")
		case p.expired:
			return conflict("PERMIT_INVALID", "permit expired")
		case attState != "planned" || resState != "reserved":
			return conflict("PERMIT_INVALID", "attempt is no longer planned")
		case nodeUID != a.NodeUID:
			return conflict("PERMIT_INVALID", "permit was issued to another adapter node")
		case !live:
			return conflict("PERMIT_INVALID", "session, approval or activation probe is no longer usable")
		case p.epoch != active.Epoch:
			return conflict("POLICY_EPOCH_STALE", "policy changed since the reservation")
		case p.catalog != active.CatalogDigest:
			return conflict("CATALOG_DIGEST_MISMATCH", "catalog changed since the reservation")
		}
		var claimedAt time.Time
		if err := tx.QueryRow(ctx, `UPDATE coordinator.dispatch_permits SET claimed_at = statement_timestamp()
WHERE permit_id = $1 AND claimed_at IS NULL RETURNING claimed_at`, permitID).Scan(&claimedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE coordinator.reservations SET state = 'committed', updated_at = statement_timestamp()
WHERE reservation_id = $1`, k.reservationID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE coordinator.attempts SET state = 'claimed', claimed_at = $2, updated_at = statement_timestamp()
WHERE attempt_id = $1`, k.attemptID, claimedAt); err != nil {
			return err
		}
		out = &CheckResult{PermitID: permitID, AttemptID: k.attemptID, ExecutionAllowed: true, ClaimedAt: claimedAt}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
