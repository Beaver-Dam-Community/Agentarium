package approvals

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/sessions"
)

// ApproveRequest is the POST /v1/approvals body (COMMON API implementation contract).
// max_actions is set by the server; it is accepted only absent or 1, for
// clients written against TASK-03 3.1.
type ApproveRequest struct {
	ActionID                string   `json:"action_id"`
	DisplayedContractDigest string   `json:"displayed_contract_digest"`
	Nonce                   string   `json:"nonce"`
	AcknowledgedFindings    []string `json:"acknowledged_findings"`
	MaxActions              *int     `json:"max_actions"`
}

type ApproveResponse struct {
	ApprovalID     string    `json:"approval_id"`
	Revision       int       `json:"revision"`
	ContractDigest string    `json:"contract_digest"`
	PolicyEpoch    int64     `json:"policy_epoch"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// Approve first consumes the actor's nonce in its own transaction, so any
// attempt that presents it, failed or not, uses it up (another actor cannot
// burn it). Then, in one transaction serialized per action, it re-renders
// the contract, checks the digest the console displayed, the exact set of
// acknowledged findings and that no usable approval exists, and writes the
// next revision with approval_granted.
func (s *Service) Approve(ctx context.Context, actor sessions.Actor, req ApproveRequest) (*ApproveResponse, error) {
	now := s.now()
	if actor.AuthenticatedActor == "" {
		return nil, sessions.Fail(http.StatusUnauthorized, "AUTH_REQUIRED", "no authenticated actor")
	}
	if req.Nonce == "" {
		return nil, sessions.Fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "nonce is required")
	}
	acked := dedupe(req.AcknowledgedFindings)

	// Check re-authentication before consuming the nonce. Re-auth is a
	// recoverable condition (the caller refreshes the token and retries), so
	// unlike the other failures below it must not burn the contract nonce
	// (review #220). AuthTime is auth_time when present and iat otherwise, so
	// a CLI ID token proves recency by its issue time.
	if actor.AuthTime.IsZero() || actor.AuthTime.After(now.Add(ClockSkew)) || now.Sub(actor.AuthTime) > ReauthWindow {
		return nil, sessions.Fail(http.StatusUnauthorized, "AUTH_REQUIRED", "re-authentication required (token older than 5 minutes)")
	}

	// 1. Consume the nonce whatever happens next.
	var n struct {
		actionID, actor, digest string
		intentID                *uuid.UUID
		required                []string
		live                    bool
	}
	err := sessions.InTx(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
DELETE FROM identity.approval_nonces WHERE nonce = $1 AND authenticated_actor = $2
RETURNING action_id::text, authenticated_actor, contract_digest, intent_check_id, required_ack_finding_ids,
          expires_at > statement_timestamp()`, req.Nonce, actor.AuthenticatedActor).
			Scan(&n.actionID, &n.actor, &n.digest, &n.intentID, &n.required, &n.live)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sessions.Fail(http.StatusConflict, "APPROVAL_UNAVAILABLE", "unknown or used nonce")
	}
	if err != nil {
		return nil, err
	}
	if req.MaxActions != nil && *req.MaxActions != 1 {
		return nil, sessions.Fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "max_actions is 1")
	}
	if !n.live || n.actionID != req.ActionID || n.actor != actor.AuthenticatedActor || n.digest != req.DisplayedContractDigest {
		return nil, sessions.Fail(http.StatusConflict, "APPROVAL_UNAVAILABLE", "nonce does not match this approval")
	}
	if !slices.Equal(acked, dedupe(n.required)) {
		return nil, sessions.Fail(http.StatusUnprocessableEntity, "INTENT_ACK_REQUIRED", "acknowledged_findings must equal the divergent/unclear findings")
	}

	// 2. Approve, serialized per action by the advisory lock. The action is
	// read once (render) and the row is written from that read, so the digest
	// and the stored fields always describe the same action. The transaction
	// stays READ COMMITTED: under REPEATABLE READ the snapshot would be taken
	// before the advisory lock is granted, hiding an approval a concurrent
	// request committed while this one waited.
	var resp ApproveResponse
	err = sessions.InTx(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('identity.approvals:' || $1, 0))`, req.ActionID); err != nil {
			return err
		}
		view, digest, a, policyEpoch, err := s.renderPolicy(ctx, tx, actor, req.ActionID)
		if err != nil {
			return err
		}
		if digest != req.DisplayedContractDigest {
			return sessions.Fail(http.StatusConflict, "APPROVAL_INVALID", "contract changed since it was displayed")
		}
		if s.Epochs == nil {
			return unavailable("epoch source not wired")
		}
		epoch, err := s.Epochs.ActiveEpoch(ctx, tx)
		if err != nil {
			return unavailable("active epoch: " + err.Error())
		}
		// The contract was rendered from the snapshot that matched one
		// active_policy read (policyEpoch). Under READ COMMITTED a later read
		// can see a newer epoch CAS; recording that epoch would bind an
		// approval of bundle A to bundle B and exempt it from revocation.
		if policyEpoch != 0 && policyEpoch != epoch {
			return sessions.Fail(http.StatusServiceUnavailable, "POLICY_VERSION_MISMATCH", "active policy changed while rendering the contract")
		}

		var approvalID uuid.UUID
		var maxRev int
		var usable bool
		err = tx.QueryRow(ctx, `
SELECT approval_id, max(revision),
       bool_or(revoked_at IS NULL AND used_actions < max_actions AND expires_at > statement_timestamp())
FROM identity.approvals WHERE action_id = $1 GROUP BY approval_id`, req.ActionID).Scan(&approvalID, &maxRev, &usable)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			approvalID, maxRev = uuid.New(), 0
		case err != nil:
			return err
		case usable:
			return sessions.Fail(http.StatusConflict, "APPROVAL_UNAVAILABLE", "a usable approval already exists for this action")
		}

		resp = ApproveResponse{ApprovalID: approvalID.String(), Revision: maxRev + 1, ContractDigest: digest, PolicyEpoch: epoch}
		var content *string
		if a.ContentDigest != "" {
			content = &a.ContentDigest
		}
		if err := tx.QueryRow(ctx, `
INSERT INTO identity.approvals (approval_id, revision, approval_kind, action_id, authenticated_actor, session_id,
    contract_digest, displayed_contract_digest, allowed_operation, canonical_target, disclosure_fields, content_digest,
    max_actions, policy_epoch, contract_version, intent_check_id, acknowledged_findings, created_at, expires_at)
VALUES ($1, $2, 'action', $3, $4, $5, $6, $6, $7, $8, $9, $10, 1, $11, $12, $13, $14,
    statement_timestamp(), statement_timestamp() + $15::interval)
RETURNING expires_at`,
			approvalID, resp.Revision, req.ActionID, actor.AuthenticatedActor, a.SessionID, digest,
			view.OperationID, a.CanonicalTarget, view.DisclosureFields, content, epoch, ContractVersion,
			n.intentID, acked, ApprovalTTL.String()).Scan(&resp.ExpiresAt); err != nil {
			return err
		}
		return s.auditor().Append(ctx, tx, sessions.Event{
			Tenant: actor.Tenant, Type: "approval_granted", ActionID: req.ActionID, Actor: actor.AuthenticatedActor, SessionID: a.SessionID,
			Payload: map[string]any{"approval_id": resp.ApprovalID, "revision": resp.Revision, "action_id": req.ActionID,
				"displayed_contract_digest": digest, "policy_epoch": epoch, "acknowledged_findings": acked},
		})
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ---- POST /v1/approvals/{approval_id}/revoke ---------------------------------

type RevokeResponse struct {
	ApprovalID   string `json:"approval_id"`
	RevokeReason string `json:"revoke_reason"`
}

// Revoke revokes every live revision of an approval: user_revoked for its
// owner, operator_revoked for an operator of the same tenant (the operator-revoke
// role). The revision rows are not rewritten otherwise.
func (s *Service) Revoke(ctx context.Context, actor sessions.Actor, approvalID string) (*RevokeResponse, error) {
	if actor.AuthenticatedActor == "" {
		return nil, sessions.Fail(http.StatusUnauthorized, "AUTH_REQUIRED", "no authenticated actor")
	}
	id, err := uuid.Parse(approvalID)
	if err != nil {
		return nil, sessions.Fail(http.StatusNotFound, "APPROVAL_UNAVAILABLE", "unknown approval")
	}
	var resp RevokeResponse
	err = sessions.InTx(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		// Lock order: sessions → approvals.
		var owner, tenant, sessionID, workloadID string
		err := tx.QueryRow(ctx, `
SELECT a.authenticated_actor, s.tenant, s.session_id::text, s.workload_id
FROM identity.approvals a JOIN identity.sessions s USING (session_id)
WHERE a.approval_id = $1 LIMIT 1`, id).Scan(&owner, &tenant, &sessionID, &workloadID)
		if errors.Is(err, pgx.ErrNoRows) {
			return sessions.Fail(http.StatusNotFound, "APPROVAL_UNAVAILABLE", "unknown approval")
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM identity.sessions WHERE session_id = $1 FOR SHARE`, sessionID); err != nil {
			return err
		}
		reason := "user_revoked"
		if owner != actor.AuthenticatedActor {
			if !actor.HasRole("operator") || tenant != actor.Tenant {
				return sessions.Fail(http.StatusForbidden, "SESSION_BINDING_INVALID", "not the approval owner")
			}
			reason = "operator_revoked"
		}
		rows, err := tx.Query(ctx, `
UPDATE identity.approvals SET revoked_at = statement_timestamp(), revoke_reason = $2
WHERE approval_id = $1 AND revoked_at IS NULL
RETURNING revision, policy_epoch, action_id`, id, reason)
		if err != nil {
			return err
		}
		type rev struct {
			actionID uuid.UUID
			revision int
			epoch    int64
		}
		var gone []rev
		for rows.Next() {
			var r rev
			if err := rows.Scan(&r.revision, &r.epoch, &r.actionID); err != nil {
				rows.Close()
				return err
			}
			gone = append(gone, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range gone {
			if err := s.auditor().Append(ctx, tx, sessions.Event{
				Tenant: tenant, Type: "approval_revoked", WorkloadID: workloadID, ActionID: r.actionID.String(), Actor: actor.AuthenticatedActor, SessionID: sessionID,
				Payload: map[string]any{"approval_id": id.String(), "revision": r.revision, "revoke_reason": reason, "policy_epoch": r.epoch},
			}); err != nil {
				return err
			}
		}
		resp = RevokeResponse{ApprovalID: id.String(), RevokeReason: reason}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ---- GET /v1/approvals/pending?session_id= ------------------------------------

// PendingFor lists the actions of actor's session that wait for approval.
func (s *Service) PendingFor(ctx context.Context, actor sessions.Actor, sessionID string) ([]Pending, error) {
	if _, err := uuid.Parse(sessionID); err != nil {
		return nil, sessions.Fail(http.StatusForbidden, "SESSION_BINDING_INVALID", "unknown session")
	}
	var out []Pending
	err := sessions.InTx(ctx, s.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var owner, tenant string
		err := tx.QueryRow(ctx, `SELECT authenticated_actor, tenant FROM identity.sessions WHERE session_id = $1`, sessionID).Scan(&owner, &tenant)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (owner != actor.AuthenticatedActor || tenant != actor.Tenant)) {
			return sessions.Fail(http.StatusForbidden, "SESSION_BINDING_INVALID", "not the session owner")
		}
		if err != nil {
			return err
		}
		if s.Pending == nil {
			return unavailable("pending source not wired")
		}
		rows, err := s.Pending.Pending(ctx, tx, sessionID)
		if err != nil {
			return unavailable(err.Error())
		}
		for _, p := range rows {
			if p.SessionID == sessionID {
				out = append(out, p)
			}
		}
		return nil
	})
	if out == nil {
		out = []Pending{}
	}
	return out, err
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
