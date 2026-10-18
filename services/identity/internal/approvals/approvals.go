// Package approvals implements TASK-03 3.1: the approval contract, approvals
// and their revocation. The TASK-04 objects it reads (actions and decisions,
// pending_approval_actions, action_content_previews, intent_checks) and the
// active epoch (active_policy) come through small interfaces; each defaults
// to an unwired implementation that refuses, so nothing is approved against
// state this service cannot see.
package approvals

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/contractview"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/sessions"
)

// Lifetimes (TASK-03 3.1 time values).
const (
	ApprovalTTL     = contractview.ApprovalTTLSeconds * time.Second
	NonceTTL        = 10 * time.Minute
	ReauthWindow    = 5 * time.Minute
	ClockSkew       = 30 * time.Second
	IntentTimeout   = 3 * time.Second
	ContractVersion = contractview.Version
)

// Action is an action and its latest decision, read in the caller's
// transaction (TASK-04 actions, decisions).
type Action struct {
	ActionID         string
	SessionID        string
	Tenant           string
	Environment      string
	OperationID      string
	CanonicalTarget  json.RawMessage // envelope canonical_target, stored as-is in the approval
	TargetID         string
	DisclosureFields []string
	ContentDigest    string // empty when the operation carries no content
	Verdict          string // latest decision verdict
}

// ActionSource reads one action (TASK-04).
type ActionSource interface {
	Action(ctx context.Context, tx pgx.Tx, actionID string) (Action, error)
}

// Pending is one row of pending_approval_actions (TASK-04 view).
type Pending struct {
	ActionID    string    `json:"action_id"`
	SessionID   string    `json:"session_id"`
	OperationID string    `json:"operation_id"`
	DecisionID  string    `json:"decision_id"`
	CreatedAt   time.Time `json:"created_at"`
}

type PendingSource interface {
	Pending(ctx context.Context, tx pgx.Tx, sessionID string) ([]Pending, error)
}

// PreviewSource reads action_content_previews (TASK-04 view).
type PreviewSource interface {
	Preview(ctx context.Context, tx pgx.Tx, contentDigest string) (text string, truncated bool, err error)
}

// EpochSource returns the active policy_epoch (active_policy, TASK-14).
type EpochSource interface {
	ActiveEpoch(ctx context.Context, tx pgx.Tx) (int64, error)
}

// Finding is one IntentCheckResult finding.
type Finding struct {
	FindingID    string `json:"finding_id"`
	Kind         string `json:"kind"`
	ContractPath string `json:"contract_path"`
	UserTextSpan any    `json:"user_text_span"`
	Severity     string `json:"severity"`
	Explanation  string `json:"explanation"`
}

// IntentResult is the part of COMMON IntentCheckResult the console needs.
type IntentResult struct {
	IntentCheckID     string    `json:"intent_check_id,omitempty"`
	IntentCheckStatus string    `json:"intent_check_status"` // completed | not_run
	Overall           string    `json:"overall,omitempty"`   // consistent | divergent | unclear
	Findings          []Finding `json:"findings"`
	NotRunReason      string    `json:"not_run_reason,omitempty"`
}

// IntentChecker calls TASK-04 POST /internal/intent-checks.
type IntentChecker interface {
	Check(ctx context.Context, actionID, contractDigest string, view contractview.View) (IntentResult, error)
}

// Service implements the approval APIs.
type Service struct {
	Pool     *pgxpool.Pool
	Policy   sessions.PolicySource
	Actions  ActionSource
	Pending  PendingSource
	Previews PreviewSource
	Epochs   EpochSource
	Intent   IntentChecker
	Audit    sessions.Auditor
	Now      func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) auditor() sessions.Auditor {
	if s.Audit == nil {
		return sessions.UnwiredAuditor{}
	}
	return s.Audit
}

func unavailable(msg string) error {
	return sessions.Fail(http.StatusServiceUnavailable, "STATE_STORE_UNAVAILABLE", msg)
}

// ---- GET /v1/actions/{action_id}/approval-contract ---------------------------

type ContractResponse struct {
	Contract       contractview.View `json:"contract"`
	ContractDigest string            `json:"contract_digest"`
	Nonce          string            `json:"nonce"`
	IntentCheck    IntentResult      `json:"intent_check"`
}

// Contract renders the contract for the session owner, asks the intent
// checker (3 s, else not_run), and stores a one-time nonce bound to the
// actor, the action, the digest and the intent result it showed.
func (s *Service) Contract(ctx context.Context, actor sessions.Actor, actionID string) (*ContractResponse, error) {
	if _, err := uuid.Parse(actionID); err != nil {
		return nil, sessions.Fail(http.StatusNotFound, "APPROVAL_UNAVAILABLE", "unknown action")
	}
	var resp ContractResponse
	var sessionID string
	// First read and render; the intent check runs outside the transaction.
	err := sessions.InTx(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		view, digest, action, err := s.render(ctx, tx, actor, actionID)
		if err != nil {
			return err
		}
		resp.Contract, resp.ContractDigest, sessionID = view, digest, action.SessionID
		return nil
	})
	if err != nil {
		return nil, err
	}
	resp.IntentCheck = s.intent(ctx, actionID, resp.ContractDigest, resp.Contract)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	resp.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	var intentID *uuid.UUID
	if id, err := uuid.Parse(resp.IntentCheck.IntentCheckID); err == nil {
		intentID = &id
	}
	required := requiredAcks(resp.IntentCheck)
	err = sessions.InTx(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
INSERT INTO identity.approval_nonces (nonce, action_id, authenticated_actor, contract_digest, intent_check_id, required_ack_finding_ids, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, statement_timestamp() + $7::interval)`,
			resp.Nonce, actionID, actor.AuthenticatedActor, resp.ContractDigest, intentID, required, NonceTTL.String()); err != nil {
			return err
		}
		return s.auditor().Append(ctx, tx, sessions.Event{
			Tenant: actor.Tenant, Type: "contract_created", ActionID: actionID, SessionID: sessionID, Actor: actor.AuthenticatedActor,
			Payload: map[string]any{"action_id": actionID, "contract_digest": resp.ContractDigest,
				"displayed_contract_digest": resp.ContractDigest, "contract_version": ContractVersion},
		})
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// render loads the action once in tx, checks that actor owns its session and
// that it is waiting for approval, and renders the contract. It returns the
// action it rendered, so a caller writes exactly what the digest covers.
func (s *Service) render(ctx context.Context, tx pgx.Tx, actor sessions.Actor, actionID string) (contractview.View, string, Action, error) {
	view, digest, a, _, err := s.renderPolicy(ctx, tx, actor, actionID)
	return view, digest, a, err
}

// renderPolicy also returns the policy epoch that matched the rendering
// snapshot (0 when the PolicySource reports none). A TxPolicySource reads the
// active row through tx, so the catalog and the epoch come from one read.
func (s *Service) renderPolicy(ctx context.Context, tx pgx.Tx, actor sessions.Actor, actionID string) (contractview.View, string, Action, int64, error) {
	if s.Actions == nil || s.Policy == nil {
		return contractview.View{}, "", Action{}, 0, unavailable("action source not wired")
	}
	a, err := s.Actions.Action(ctx, tx, actionID)
	if err != nil {
		var se *sessions.Error
		if errors.As(err, &se) {
			return contractview.View{}, "", Action{}, 0, err
		}
		return contractview.View{}, "", Action{}, 0, unavailable(err.Error())
	}
	if err := s.ownsSession(ctx, tx, actor, a.SessionID); err != nil {
		return contractview.View{}, "", Action{}, 0, err
	}
	if a.Tenant != actor.Tenant {
		return contractview.View{}, "", Action{}, 0, sessions.Fail(http.StatusForbidden, "SESSION_BINDING_INVALID", "action is in another tenant")
	}
	if a.Verdict != "approval_required" {
		return contractview.View{}, "", Action{}, 0, sessions.Fail(http.StatusConflict, "APPROVAL_UNAVAILABLE", "action is not waiting for approval")
	}
	var pol sessions.Policy
	if txp, ok := s.Policy.(sessions.TxPolicySource); ok {
		pol, err = txp.PolicyIn(ctx, tx)
	} else {
		pol, err = s.Policy.Policy(ctx)
	}
	if err != nil {
		return contractview.View{}, "", Action{}, 0, sessions.PolicyError(err)
	}
	in := contractview.Input{
		ActionID: a.ActionID, OperationID: a.OperationID, TargetID: a.TargetID, DisclosureFields: a.DisclosureFields,
		Environment: a.Environment, Tenant: a.Tenant, Catalog: pol.Catalog, ContentDigest: a.ContentDigest,
	}
	if a.ContentDigest != "" {
		if s.Previews == nil {
			return contractview.View{}, "", Action{}, 0, unavailable("preview source not wired")
		}
		text, cut, err := s.Previews.Preview(ctx, tx, a.ContentDigest)
		if err != nil {
			return contractview.View{}, "", Action{}, 0, unavailable("content preview: " + err.Error())
		}
		in.PreviewText, in.PreviewCut = text, cut
	}
	view, err := contractview.Render(in)
	if err != nil {
		return contractview.View{}, "", Action{}, 0, sessions.Fail(http.StatusConflict, "CATALOG_DIGEST_MISMATCH", err.Error())
	}
	digest, err := contractview.Digest(view)
	return view, digest, a, pol.Epoch, err
}

// ownsSession requires actor to own a claimed, unexpired session.
func (s *Service) ownsSession(ctx context.Context, tx pgx.Tx, actor sessions.Actor, sessionID string) error {
	var owner, tenant, state string
	var live bool
	err := tx.QueryRow(ctx, `
SELECT authenticated_actor, tenant, state, expires_at > statement_timestamp()
FROM identity.sessions WHERE session_id = $1 FOR SHARE`, sessionID).Scan(&owner, &tenant, &state, &live)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (owner != actor.AuthenticatedActor || tenant != actor.Tenant)) {
		return sessions.Fail(http.StatusForbidden, "SESSION_BINDING_INVALID", "not the session owner")
	}
	if err != nil {
		return err
	}
	if state != "claimed" || !live {
		return sessions.Fail(http.StatusConflict, "APPROVAL_UNAVAILABLE", "session is not active")
	}
	return nil
}

func (s *Service) intent(ctx context.Context, actionID, digest string, view contractview.View) IntentResult {
	notRun := func(reason string) IntentResult {
		return IntentResult{IntentCheckStatus: "not_run", Findings: []Finding{}, NotRunReason: reason}
	}
	if s.Intent == nil {
		return notRun("intent checker not wired")
	}
	cctx, cancel := context.WithTimeout(ctx, IntentTimeout)
	defer cancel()
	r, err := s.Intent.Check(cctx, actionID, digest, view)
	if err != nil {
		return notRun(err.Error())
	}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	return r
}

// requiredAcks is every finding of a divergent or unclear result.
func requiredAcks(r IntentResult) []string {
	ids := []string{}
	if r.IntentCheckStatus == "completed" && (r.Overall == "divergent" || r.Overall == "unclear") {
		for _, f := range r.Findings {
			ids = append(ids, f.FindingID)
		}
	}
	sort.Strings(ids)
	return ids
}
