package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/sessions"
)

// GatewayStore reads the TASK-04 views registered for identity_app
// (pending_approval_actions, action_content_previews; migration
// 20261016181826_gateway_decisions) in the caller's transaction. It
// implements PendingSource and PreviewSource. identity_app has SELECT on
// these views only, never on decisions.actions or decisions.action_contents.
//
// ActionSource reads decisions.approval_contract_actions, the view #47
// proposes for the renderer's canonical_target, disclosure_fields and
// content_digest.
type GatewayStore struct{}

var (
	_ ActionSource  = GatewayStore{}
	_ PendingSource = GatewayStore{}
	_ PreviewSource = GatewayStore{}
)

// ErrNoPreview means action_content_previews has no row for the digest.
var ErrNoPreview = errors.New("approvals: no content preview")

// Pending lists the session's rows of decisions.pending_approval_actions,
// oldest first.
func (GatewayStore) Pending(ctx context.Context, tx pgx.Tx, sessionID string) ([]Pending, error) {
	rows, err := tx.Query(ctx, `
SELECT action_id::text, session_id::text, operation_id, decision_id::text, created_at
FROM decisions.pending_approval_actions WHERE session_id = $1
ORDER BY created_at, action_id`, sessionID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Pending, error) {
		var p Pending
		err := r.Scan(&p.ActionID, &p.SessionID, &p.OperationID, &p.DecisionID, &p.CreatedAt)
		return p, err
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Pending{}
	}
	return out, nil
}

// Preview reads decisions.action_content_previews.
func (GatewayStore) Preview(ctx context.Context, tx pgx.Tx, contentDigest string) (string, bool, error) {
	var text string
	var cut bool
	err := tx.QueryRow(ctx, `
SELECT preview_text, truncated FROM decisions.action_content_previews WHERE content_digest = $1`, contentDigest).Scan(&text, &cut)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrNoPreview
	}
	return text, cut, err
}

// Action reads decisions.approval_contract_actions (#47 item 1, migration
// 20261018092001_gateway_approval_contract_actions): a user-session action
// with its envelope fields and the verdict of its latest decision.
func (GatewayStore) Action(ctx context.Context, tx pgx.Tx, actionID string) (Action, error) {
	if _, err := uuid.Parse(actionID); err != nil {
		return Action{}, sessions.Fail(http.StatusNotFound, "RESOURCE_NOT_FOUND", "unknown action")
	}
	var a Action
	var target []byte
	var content *string
	err := tx.QueryRow(ctx, `
SELECT action_id::text, session_id::text, tenant, environment, operation_id, target_id,
       canonical_target, disclosure_fields, content_digest, verdict
FROM decisions.approval_contract_actions WHERE action_id = $1`, actionID).
		Scan(&a.ActionID, &a.SessionID, &a.Tenant, &a.Environment, &a.OperationID, &a.TargetID,
			&target, &a.DisclosureFields, &content, &a.Verdict)
	if errors.Is(err, pgx.ErrNoRows) {
		return Action{}, sessions.Fail(http.StatusNotFound, "RESOURCE_NOT_FOUND", "unknown action")
	}
	if err != nil {
		return Action{}, err
	}
	a.CanonicalTarget = json.RawMessage(target)
	if content != nil {
		a.ContentDigest = *content
	}
	return a, nil
}

// ReleaseEpochs reads the environment's active epoch from
// release.active_policy in the caller's transaction (plain SELECT; identity_app
// has SELECT only).
type ReleaseEpochs struct{ Environment string }

var _ EpochSource = ReleaseEpochs{}

func (e ReleaseEpochs) ActiveEpoch(ctx context.Context, tx pgx.Tx) (int64, error) {
	var epoch int64
	err := tx.QueryRow(ctx, `SELECT epoch FROM release.active_policy WHERE scope_id = $1`, e.Environment).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, errors.New("no active_policy row")
	}
	return epoch, err
}
