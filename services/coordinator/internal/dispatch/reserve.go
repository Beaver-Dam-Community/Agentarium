package dispatch

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ReserveRequest is the POST /internal/dispatch/reservations body (COMMON API
// implementation contract).
type ReserveRequest struct {
	DecisionID     string `json:"decision_id"`
	ActionID       string `json:"action_id"`
	RequestID      string `json:"request_id"`
	ActionDigest   string `json:"action_digest"`
	WireBodyDigest string `json:"wire_body_digest"`
	PolicyEpoch    int64  `json:"policy_epoch"`
	CatalogDigest  string `json:"catalog_digest"`
}

func (r ReserveRequest) valid() bool {
	return isUUID(r.DecisionID) && isUUID(r.ActionID) && isUUID(r.RequestID) &&
		isDigest(r.ActionDigest) && isDigest(r.WireBodyDigest) && isDigest(r.CatalogDigest) && r.PolicyEpoch > 0
}

// Permit is the COMMON DispatchPermit.
type Permit struct {
	PermitID       string     `json:"permit_id"`
	DecisionID     string     `json:"decision_id"`
	ActionID       string     `json:"action_id"`
	RequestID      string     `json:"request_id"`
	AttemptID      string     `json:"attempt_id"`
	ReservationID  string     `json:"reservation_id"`
	AdapterID      string     `json:"adapter_id"`
	ActionDigest   string     `json:"action_digest"`
	WireBodyDigest string     `json:"wire_body_digest"`
	PolicyEpoch    int64      `json:"policy_epoch"`
	CatalogDigest  string     `json:"catalog_digest"`
	ExpiresAt      time.Time  `json:"expires_at"`
	ClaimedAt      *time.Time `json:"claimed_at,omitempty"`
}

// Reserve runs the reservation transaction (COMMON reservation transaction) for an
// authenticated adapter. Every lock follows the global order; any failure
// rolls everything back and no permit exists.
func (s *Service) Reserve(ctx context.Context, a Adapter, req ReserveRequest) (*Permit, error) {
	if !req.valid() {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "malformed reservation request")
	}
	var out *Permit
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// active_policy FOR SHARE
		active, err := s.policy().LockActivePolicy(ctx, tx)
		if err != nil {
			return depErr(err, "STATE_STORE_UNAVAILABLE", "active_policy")
		}
		dec, err := s.decision(ctx, tx, req.DecisionID, a)
		if err != nil {
			return err
		}
		if err := checkRequest(dec, req); err != nil {
			return err
		}
		if err := s.checkDecision(ctx, tx, dec, active); err != nil {
			return err
		}
		b, err := budgetFor(dec)
		if err != nil {
			return err
		}
		// holds → node_boot_generation (+ leases)
		if err := s.checkHealth(ctx, tx, a, dec, active); err != nil {
			return err
		}
		// sessions | service_sessions FOR UPDATE (and the session's candidate)
		live, err := b.lockSession(ctx, tx, false)
		if err != nil {
			return err
		}
		if !live {
			return b.exhausted("session is not live")
		}
		// service_session_counters (→ issue_candidate_counters for a
		// candidate session) | session_budgets | approvals FOR UPDATE
		if err := b.lockForReserve(ctx, tx, dec.ActionID); err != nil {
			return err
		}
		if b.Basis == "activation_probe" {
			// activation_probes FOR SHARE, with the budget rows (TASK-03 3.2
			// decision_basis table). SPEC-QUESTION: the global lock order does
			// not list activation_probes; it is locked here, after
			// service_session_counters and before reservations.
			ok, err := s.probeUsable(ctx, tx, dec, active, true)
			if err != nil {
				return err
			}
			if !ok {
				return b.exhausted("activation probe registration is missing, expired, unbound or for another epoch")
			}
		}
		// reservations
		resID, fresh, err := s.lockReservation(ctx, tx, dec, req, b)
		if err != nil {
			return err
		}
		if !fresh {
			// An unchanged replay of a pending permit gets that permit back.
			p, err := s.pendingPermit(ctx, tx, resID, dec, req, a)
			if err != nil || p != nil {
				out = p
				return err
			}
			return conflict("PERMIT_INVALID", "action already has a reservation in use")
		}
		if err := b.consume(ctx, tx); err != nil {
			return err
		}
		// attempts
		attemptID := uuid.NewString()
		if _, err := tx.Exec(ctx, `
INSERT INTO coordinator.attempts (attempt_id, action_id, reservation_id, adapter_id, adapter_node_uid, state, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, 'planned', statement_timestamp(), statement_timestamp())`,
			attemptID, dec.ActionID, resID, a.AdapterID, a.NodeUID); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return conflict("PERMIT_INVALID", "action has an active attempt")
			}
			return err
		}
		// dispatch_permits
		p := &Permit{PermitID: uuid.NewString(), DecisionID: dec.DecisionID, ActionID: dec.ActionID, RequestID: dec.RequestID,
			AttemptID: attemptID, ReservationID: resID, AdapterID: a.AdapterID, ActionDigest: dec.ActionDigest,
			WireBodyDigest: req.WireBodyDigest, PolicyEpoch: dec.PolicyEpoch, CatalogDigest: dec.CatalogDigest}
		if err := tx.QueryRow(ctx, `
INSERT INTO coordinator.dispatch_permits (permit_id, attempt_id, decision_id, action_id, adapter_id, action_digest,
    wire_body_digest, policy_epoch, catalog_digest, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, statement_timestamp() + make_interval(secs => $10))
RETURNING expires_at`,
			p.PermitID, p.AttemptID, p.DecisionID, p.ActionID, p.AdapterID, p.ActionDigest,
			p.WireBodyDigest, p.PolicyEpoch, p.CatalogDigest, PermitTTL.Seconds()).Scan(&p.ExpiresAt); err != nil {
			return err
		}
		if err := s.audit().Append(ctx, tx, Event{Type: "attempt_planned", Payload: map[string]any{
			"attempt_id": attemptID, "reservation_id": resID, "action_digest": dec.ActionDigest, "policy_epoch": dec.PolicyEpoch,
		}}); err != nil {
			return depErr(err, "STATE_STORE_UNAVAILABLE", "audit_append")
		}
		out = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decision reads the decision and hides one meant for another adapter.
func (s *Service) decision(ctx context.Context, tx pgx.Tx, id string, a Adapter) (Decision, error) {
	dec, err := s.decisions().Decision(ctx, tx, id)
	if errors.Is(err, ErrNotFound) || (err == nil && dec.AdapterID != a.AdapterID) {
		return Decision{}, fail(http.StatusNotFound, "RESOURCE_NOT_FOUND", "no such decision for this adapter")
	}
	if err != nil {
		return Decision{}, depErr(err, "STATE_STORE_UNAVAILABLE", "decisions")
	}
	return dec, nil
}

// checkRequest compares the adapter's request with the stored decision.
func checkRequest(dec Decision, req ReserveRequest) error {
	switch {
	case dec.ActionID != req.ActionID || dec.RequestID != req.RequestID || dec.ActionDigest != req.ActionDigest:
		return conflict("ACTION_DIGEST_MISMATCH", "request does not match the decision")
	case dec.PolicyEpoch != req.PolicyEpoch:
		return conflict("POLICY_EPOCH_STALE", "request epoch differs from the decision")
	case dec.CatalogDigest != req.CatalogDigest:
		return conflict("CATALOG_DIGEST_MISMATCH", "request catalog differs from the decision")
	}
	return nil
}

// checkDecision verifies the decision against the locked active policy.
func (s *Service) checkDecision(ctx context.Context, tx pgx.Tx, dec Decision, active ActivePolicy) error {
	if dec.Verdict != "allow" {
		return conflict("PERMIT_INVALID", "decision is not allow")
	}
	var expired bool
	if err := tx.QueryRow(ctx, `SELECT $1::timestamptz <= statement_timestamp()`, dec.ExpiresAt).Scan(&expired); err != nil {
		return err
	}
	switch {
	case expired:
		return conflict("DECISION_EXPIRED", "decision expired")
	case dec.PolicyEpoch != active.Epoch:
		return conflict("POLICY_EPOCH_STALE", "decision epoch is not the active epoch")
	case dec.CatalogDigest != active.CatalogDigest:
		return conflict("CATALOG_DIGEST_MISMATCH", "decision catalog is not the active catalog")
	case dec.OPABundleRevision != active.ExpectedOPARevision:
		// SPEC-QUESTION: COMMON lists this check without a code; a stale
		// revision needs :reevaluate like a stale epoch.
		return conflict("POLICY_EPOCH_STALE", "decision OPA revision is not the expected revision")
	}
	return nil
}

// checkHealth reads holds and the node boot row FOR SHARE, then the leases
// (TASK-03 3.2 hold/lease reads). Matching holds refuse with HOLD_ACTIVE
// unless they are all policy_activation holds and the decision is a usable
// activation probe (COMMON reservation transaction, activation-probe-only dispatch).
func (s *Service) checkHealth(ctx context.Context, tx pgx.Tx, a Adapter, dec Decision, active ActivePolicy) error {
	h := s.health()
	holds, err := h.LockHolds(ctx, tx, HoldScope{NodeUID: a.NodeUID, WorkloadID: dec.WorkloadID, TargetID: dec.TargetID,
		SessionID: dec.SessionID, ServiceSessionID: dec.ServiceSessionID})
	if err != nil {
		return depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "holds")
	}
	if len(holds) > 0 {
		exempt := dec.DecisionBasis == "activation_probe"
		for _, hd := range holds {
			if hd.Reason != "policy_activation" {
				exempt = false
			}
		}
		if exempt {
			// Read without a lock here: activation_probes comes after the
			// session rows in this transaction's order. The budget step
			// locks the row and checks it again; the rows read here are
			// immutable once bound, except for expiry.
			if exempt, err = s.probeUsable(ctx, tx, dec, active, false); err != nil {
				return err
			}
		}
		if !exempt {
			return unavailable("HOLD_ACTIVE", "hold "+holds[0].HoldID+" ("+holds[0].Reason+")")
		}
	}
	nb, err := h.LockNodeBoot(ctx, tx, a.NodeUID)
	if err != nil {
		return depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "node_boot_generation")
	}
	if nb.State != "ready" || nb.BootID != a.BootID {
		return unavailable("CONTROL_HEALTH_UNAVAILABLE", "adapter node boot is not the ready boot")
	}
	// SPEC-QUESTION: COMMON lock_dispatch_node has the coordinator check the
	// row against "the adapter certificate's boot and lease generation". The adapter
	// certificate records only node and boot, and the spec does not say which
	// lease's generation (control_health_leases.sensor_generation has no guard
	// counterpart) is compared with nb.SensorGeneration or nb.GuardGeneration.
	// The boot is checked above; the generations are left to the lease check
	// (CheckLeases), whose required set does not carry them either.
	if err := h.CheckLeases(ctx, tx, dec.OperationID, dec.TargetID); err != nil {
		return depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "leases")
	}
	return nil
}

// lockReservation locks or creates the action's reservation. fresh means the
// caller must consume the budget: a new row, or a released one taken again
// (TASK-03 3.2: released has already returned its budget).
func (s *Service) lockReservation(ctx context.Context, tx pgx.Tx, dec Decision, req ReserveRequest, b budget) (string, bool, error) {
	var id, digest, state string
	err := tx.QueryRow(ctx, `SELECT reservation_id::text, action_digest, state FROM coordinator.reservations
WHERE action_id = $1 FOR UPDATE`, dec.ActionID).Scan(&id, &digest, &state)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		id = uuid.NewString()
		tag, err := tx.Exec(ctx, `
INSERT INTO coordinator.reservations (reservation_id, action_id, decision_id, action_digest, decision_basis,
    approval_id, approval_revision, session_id, standing_rule_id, service_session_id, budget_counter,
    state, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'reserved', statement_timestamp(), statement_timestamp())
ON CONFLICT (action_id) DO NOTHING`,
			id, dec.ActionID, dec.DecisionID, dec.ActionDigest, b.Basis,
			b.ApprovalID, b.ApprovalRevision, b.SessionID, b.StandingRuleID, b.ServiceSessionID, b.Counter)
		if err != nil {
			return "", false, err
		}
		if tag.RowsAffected() != 1 {
			return "", false, conflict("PERMIT_INVALID", "concurrent reservation of the action")
		}
		return id, true, nil
	case err != nil:
		return "", false, err
	}
	if digest != dec.ActionDigest {
		return "", false, conflict("ACTION_DIGEST_MISMATCH", "reservation holds another action digest")
	}
	if state != "released" {
		return id, false, nil
	}
	_, err = tx.Exec(ctx, `
UPDATE coordinator.reservations SET state = 'reserved', decision_id = $2, decision_basis = $3,
    approval_id = $4, approval_revision = $5, session_id = $6, standing_rule_id = $7,
    service_session_id = $8, budget_counter = $9, updated_at = statement_timestamp()
WHERE reservation_id = $1`,
		id, dec.DecisionID, b.Basis, b.ApprovalID, b.ApprovalRevision, b.SessionID, b.StandingRuleID, b.ServiceSessionID, b.Counter)
	return id, true, err
}

// pendingPermit returns the permit of a replayed reservation: the same
// decision, wire body and adapter node, still planned, unclaimed and
// unexpired. Anything else is nil (a conflict for the caller). The
// reservation row is already locked, and every change to its attempts and
// permits locks it first, so the rows read here cannot change under us.
func (s *Service) pendingPermit(ctx context.Context, tx pgx.Tx, resID string, dec Decision, req ReserveRequest, a Adapter) (*Permit, error) {
	p := &Permit{ReservationID: resID, RequestID: dec.RequestID}
	err := tx.QueryRow(ctx, `
SELECT p.permit_id::text, p.decision_id::text, p.action_id::text, p.attempt_id::text, p.adapter_id, p.action_digest,
       p.wire_body_digest, p.policy_epoch, p.catalog_digest, p.expires_at
FROM coordinator.reservations r
JOIN coordinator.attempts t ON t.reservation_id = r.reservation_id
JOIN coordinator.dispatch_permits p ON p.attempt_id = t.attempt_id
WHERE r.reservation_id = $1 AND r.state = 'reserved' AND t.state = 'planned'
  AND t.adapter_id = $2 AND t.adapter_node_uid = $3::uuid
  AND p.decision_id = $4 AND p.wire_body_digest = $5
  AND p.claimed_at IS NULL AND p.expires_at > statement_timestamp()`, resID, a.AdapterID, a.NodeUID, dec.DecisionID, req.WireBodyDigest).Scan(
		&p.PermitID, &p.DecisionID, &p.ActionID, &p.AttemptID, &p.AdapterID, &p.ActionDigest,
		&p.WireBodyDigest, &p.PolicyEpoch, &p.CatalogDigest, &p.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}
