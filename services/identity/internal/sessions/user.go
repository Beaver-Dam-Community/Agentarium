package sessions

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service implements the session APIs over Postgres.
type Service struct {
	Pool        *pgxpool.Pool
	Policy      PolicySource
	Audit       Auditor
	Environment string // catalog target environment this deployment serves
	// ClaimKey derives each session's claim_code as HMAC(ClaimKey, session_id),
	// so the database keeps only claim_code_digest while GET
	// /v1/runtime/assignments can still return the code.
	// SPEC-QUESTION: TASK-03 3.4 stores only the digest yet returns the code
	// from assignments; this key reconciles the two.
	ClaimKey []byte
	Now      func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) auditor() Auditor {
	if s.Audit == nil {
		return UnwiredAuditor{}
	}
	return s.Audit
}

// ---- POST /v1/sessions ------------------------------------------------------

// CreateRequest is the POST /v1/sessions body (COMMON API implementation contract).
type CreateRequest struct {
	WorkloadID     string         `json:"workload_id"`
	TaskStatement  string         `json:"task_statement"`
	RequestedScope RequestedScope `json:"requested_scope"`
}

type RequestedScope struct {
	OperationIDs []string `json:"operation_ids"`
	TargetIDs    []string `json:"target_ids"`
}

type CreateResponse struct {
	SessionID           string    `json:"session_id"`
	ClaimCode           string    `json:"claim_code"`
	ClaimExpiresAt      time.Time `json:"claim_expires_at"`
	AllowedOperationIDs []string  `json:"allowed_operation_ids"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// Create makes a session for actor. actor and tenant come from the
// authenticated context, never from the body.
func (s *Service) Create(ctx context.Context, actor Actor, req CreateRequest) (*CreateResponse, error) {
	if actor.AuthenticatedActor == "" || actor.Tenant == "" {
		return nil, fail(http.StatusUnauthorized, "AUTH_REQUIRED", "no authenticated actor")
	}
	stmt := strings.TrimSpace(req.TaskStatement)
	if stmt == "" || !utf8.ValidString(req.TaskStatement) || len([]rune(req.TaskStatement)) > MaxTaskStatement {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "task_statement must be 1–4000 characters")
	}
	ns, ksa, ok := strings.Cut(req.WorkloadID, "/")
	if !ok || ns == "" || ksa == "" {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "workload_id must be <namespace>/<ksa>")
	}
	ops := dedupeSorted(req.RequestedScope.OperationIDs)
	targets := dedupeSorted(req.RequestedScope.TargetIDs)
	if len(ops) == 0 || len(targets) == 0 {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "requested_scope needs operation_ids and target_ids")
	}

	pol, err := s.Policy.Policy(ctx)
	if err != nil {
		return nil, PolicyError(err)
	}
	if err := checkScope(pol, ops, targets, actor.Tenant, s.Environment); err != nil {
		return nil, err
	}

	now := s.now()
	id := uuid.New()
	code := s.claimCode(id)
	codeDigest := sha256.Sum256([]byte(code))
	resp := &CreateResponse{
		SessionID:           id.String(),
		ClaimCode:           code,
		ClaimExpiresAt:      now.Add(ClaimCodeTTL),
		AllowedOperationIDs: ops,
		ExpiresAt:           now.Add(SessionTTL),
	}
	// One budget row per standing rule that covers a requested user operation
	// and a requested target (TASK-03 3.4 standing rules and session budgets).
	type budget struct {
		id  string
		max int
	}
	var budgets []budget
	for _, id := range sortedKeys(pol.StandingRules) {
		r := pol.StandingRules[id]
		if r.StandingRuleID != id || r.SessionKind != "user" || r.SessionBudget <= 0 {
			continue
		}
		if intersects(r.OperationIDs, ops) && anyMatch(r.TargetPattern, targets) {
			budgets = append(budgets, budget{id, r.SessionBudget})
		}
	}

	err = s.inTx(ctx, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var role string
		var enabled bool
		err := tx.QueryRow(ctx, `SELECT role, enabled FROM identity.registered_workloads WHERE namespace = $1 AND ksa = $2`,
			ns, ksa).Scan(&role, &enabled)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (role != "runtime" || !enabled)) {
			return fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "workload_id is not an enabled runtime workload")
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO identity.sessions (session_id, authenticated_actor, tenant, workload_id, task_statement,
    allowed_operation_ids, requested_target_ids, state, claim_code_digest, claim_expires_at,
    created_at, expires_at, max_expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'created', $8, $9, $10, $11, $12)`,
			id, actor.AuthenticatedActor, actor.Tenant, req.WorkloadID, req.TaskStatement,
			ops, targets, codeDigest[:], resp.ClaimExpiresAt, now, resp.ExpiresAt, now.Add(SessionMaxLife)); err != nil {
			return err
		}
		for _, b := range budgets {
			if _, err := tx.Exec(ctx, `
INSERT INTO identity.session_budgets (session_id, standing_rule_id, max_actions, expires_at)
VALUES ($1, $2, $3, $4)`, id, b.id, b.max, resp.ExpiresAt); err != nil {
				return err
			}
		}
		stDigest := sha256.Sum256([]byte(req.TaskStatement))
		return s.auditor().Append(ctx, tx, Event{
			Tenant: actor.Tenant, Type: "session_created", WorkloadID: req.WorkloadID, Actor: actor.AuthenticatedActor, SessionID: id.String(),
			Payload: map[string]any{
				"session_id": id.String(), "workload_id": req.WorkloadID,
				"task_statement_digest": fmt.Sprintf("%x", stDigest), "claim_expires_at": resp.ClaimExpiresAt,
			},
		})
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// checkScope requires every operation and target in the active catalog, every
// target in this tenant and environment, and every requested operation served
// by at least one requested target.
// SPEC-QUESTION: COMMON computes allowed_operation_ids as the requested
// operations ∩ the catalog operations the workload role may use, but no table
// lists operations per role; only catalog membership is checked here.
func checkScope(pol Policy, ops, targets []string, tenant, env string) error {
	served := map[string]bool{}
	for _, id := range targets {
		t, ok := pol.Catalog.Targets[id]
		if !ok {
			return fail(http.StatusForbidden, "ENDPOINT_NOT_REGISTERED", "unknown target "+id)
		}
		if t.Tenant != tenant || (env != "" && t.Environment != env) {
			return fail(http.StatusForbidden, "TARGET_SCOPE_DENIED", "target "+id+" is outside this tenant or environment")
		}
		for _, op := range t.OperationIDs {
			served[op] = true
		}
	}
	for _, op := range ops {
		if _, ok := pol.Catalog.Operations[op]; !ok {
			return fail(http.StatusForbidden, "ENDPOINT_NOT_REGISTERED", "unknown operation "+op)
		}
		if !served[op] {
			return fail(http.StatusForbidden, "TARGET_SCOPE_DENIED", "no requested target serves "+op)
		}
	}
	return nil
}

func (s *Service) claimCode(id uuid.UUID) string {
	m := hmac.New(sha256.New, s.ClaimKey)
	m.Write([]byte("agentarium/claim_code/v1\x00"))
	m.Write(id[:])
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// ---- GET /v1/runtime/assignments --------------------------------------------

type Assignment struct {
	SessionID      string    `json:"session_id"`
	ClaimCode      string    `json:"claim_code"`
	ClaimExpiresAt time.Time `json:"claim_expires_at"`
	TaskStatement  string    `json:"task_statement"`
}

// Assignments lists the unclaimed, unexpired sessions of the caller's
// workload. It never returns a token.
func (s *Service) Assignments(ctx context.Context, p RuntimePrincipal) ([]Assignment, error) {
	rows, err := s.Pool.Query(ctx, `
SELECT session_id, claim_expires_at, task_statement
FROM identity.sessions
WHERE workload_id = $1 AND state = 'created' AND claim_expires_at > statement_timestamp()
ORDER BY created_at`, p.WorkloadID())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Assignment{}
	for rows.Next() {
		var a Assignment
		var id uuid.UUID
		if err := rows.Scan(&id, &a.ClaimExpiresAt, &a.TaskStatement); err != nil {
			return nil, err
		}
		a.SessionID, a.ClaimCode = id.String(), s.claimCode(id)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- POST /v1/sessions/{id}:claim -------------------------------------------

type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Claim moves created → claimed exactly once and issues a token bound to the
// claiming Pod's SAN. Any mismatch is CLAIM_CODE_INVALID.
func (s *Service) Claim(ctx context.Context, p RuntimePrincipal, sessionID, code string) (*TokenResponse, error) {
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, fail(http.StatusForbidden, "CLAIM_CODE_INVALID", "unknown session")
	}
	invalid := fail(http.StatusForbidden, "CLAIM_CODE_INVALID", "claim rejected")
	token, digest, err := newToken()
	if err != nil {
		return nil, err
	}
	var resp TokenResponse
	err = s.inTx(ctx, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var workload, state, tenant string
		var codeDigest []byte
		var claimOK bool
		err := tx.QueryRow(ctx, `
SELECT workload_id, state, claim_code_digest, claim_expires_at > statement_timestamp(), expires_at, tenant
FROM identity.sessions WHERE session_id = $1 FOR UPDATE`, id).Scan(&workload, &state, &codeDigest, &claimOK, &resp.ExpiresAt, &tenant)
		if errors.Is(err, pgx.ErrNoRows) {
			return invalid
		}
		if err != nil {
			return err
		}
		got := sha256.Sum256([]byte(code))
		if workload != p.WorkloadID() || state != "created" || !claimOK || subtle.ConstantTimeCompare(got[:], codeDigest) != 1 {
			return invalid
		}
		if _, err := tx.Exec(ctx, `
UPDATE identity.sessions SET state = 'claimed', claimed_workload_identity = $2
WHERE session_id = $1 AND state = 'created'`, id, p.SAN); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO identity.session_tokens (token_digest, session_id, bound_identity, issued_at)
VALUES ($1, $2, $3, statement_timestamp())`, digest, id, p.SAN); err != nil {
			return err
		}
		return s.auditor().Append(ctx, tx, Event{
			Tenant: tenant, Type: "session_claimed", WorkloadID: workload, Actor: "workload:" + p.SAN, SessionID: id.String(),
			Payload: map[string]any{"session_id": id.String(), "workload_identity": p.SAN},
		})
	})
	if err != nil {
		return nil, err
	}
	resp.Token = token
	return &resp, nil
}

// ---- POST /v1/sessions/{id}:refresh -----------------------------------------

// Refresh (COMMON API implementation contract) rotates the token: the caller presents the
// current token over the same mTLS identity it is bound to; the old token is
// revoked and a new one issued in one transaction, and the session and its
// budgets are extended by SessionTTL up to max_expires_at.
func (s *Service) Refresh(ctx context.Context, p RuntimePrincipal, sessionID, current string) (*TokenResponse, error) {
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, fail(http.StatusUnauthorized, "AUTH_REQUIRED", "unknown session")
	}
	unauth := fail(http.StatusUnauthorized, "AUTH_REQUIRED", "token rejected")
	old := sha256.Sum256([]byte(current))
	token, digest, err := newToken()
	if err != nil {
		return nil, err
	}
	var resp TokenResponse
	err = s.inTx(ctx, pgx.TxOptions{}, func(tx pgx.Tx) error {
		// Lock order: sessions → session_budgets → session_tokens.
		var state, tenant, workload string
		var live bool
		var expires, maxExp time.Time
		err := tx.QueryRow(ctx, `
SELECT state, expires_at > statement_timestamp(), expires_at, max_expires_at, tenant, workload_id
FROM identity.sessions WHERE session_id = $1 FOR UPDATE`, id).Scan(&state, &live, &expires, &maxExp, &tenant, &workload)
		if errors.Is(err, pgx.ErrNoRows) {
			return unauth
		}
		if err != nil {
			return err
		}
		if state != "claimed" || !live {
			return unauth
		}
		var bound string
		err = tx.QueryRow(ctx, `
SELECT bound_identity FROM identity.session_tokens
WHERE token_digest = $1 AND session_id = $2 AND revoked_at IS NULL FOR UPDATE`, old[:], id).Scan(&bound)
		if errors.Is(err, pgx.ErrNoRows) {
			return unauth
		}
		if err != nil {
			return err
		}
		if bound != p.SAN {
			return unauth
		}
		next := expires.Add(SessionTTL)
		if next.After(maxExp) {
			next = maxExp
		}
		// SPEC-QUESTION: no reason code covers "already at the 8 h cap";
		// AUTH_REQUIRED is used because the caller must start a new session.
		if !next.After(expires) {
			return fail(http.StatusUnauthorized, "AUTH_REQUIRED", "session is at its 8 h maximum")
		}
		resp.ExpiresAt = next
		if _, err := tx.Exec(ctx, `UPDATE identity.sessions SET expires_at = $2 WHERE session_id = $1`, id, next); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity.session_budgets SET expires_at = $2 WHERE session_id = $1`, id, next); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity.session_tokens SET revoked_at = statement_timestamp() WHERE token_digest = $1`, old[:]); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO identity.session_tokens (token_digest, session_id, bound_identity, issued_at)
VALUES ($1, $2, $3, statement_timestamp())`, digest, id, p.SAN); err != nil {
			return err
		}
		actor := "workload:" + p.SAN
		return s.auditor().Append(ctx, tx, Event{
			Tenant: tenant, Type: "session_refreshed", WorkloadID: workload, Actor: actor, SessionID: id.String(),
			Payload: map[string]any{"session_id": id.String(), "authenticated_actor": actor, "expires_at": next},
		})
	})
	if err != nil {
		return nil, err
	}
	resp.Token = token
	return &resp, nil
}

// ---- POST /v1/sessions/{id}:revoke ------------------------------------------

type RevokeResponse struct {
	SessionID string `json:"session_id"`
	State     string `json:"state"`
}

// Revoke ends a session for its owner or an operator: the session becomes
// revoked and every live token is revoked. Attempts already reserved are not
// cancelled. Unused approvals of the session are revoked with revoke_reason
// = session_ended, each with its approval_revoked event, in the same
// transaction.
func (s *Service) Revoke(ctx context.Context, actor Actor, sessionID, reason string) (*RevokeResponse, error) {
	if actor.AuthenticatedActor == "" {
		return nil, fail(http.StatusUnauthorized, "AUTH_REQUIRED", "no authenticated actor")
	}
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, fail(http.StatusForbidden, "SESSION_BINDING_INVALID", "unknown session")
	}
	err = s.inTx(ctx, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var owner, tenant, state, workload string
		err := tx.QueryRow(ctx, `SELECT authenticated_actor, tenant, state, workload_id FROM identity.sessions WHERE session_id = $1 FOR UPDATE`,
			id).Scan(&owner, &tenant, &state, &workload)
		if errors.Is(err, pgx.ErrNoRows) {
			return fail(http.StatusForbidden, "SESSION_BINDING_INVALID", "unknown session")
		}
		if err != nil {
			return err
		}
		if owner != actor.AuthenticatedActor && !(actor.HasRole("operator") && tenant == actor.Tenant) {
			return fail(http.StatusForbidden, "SESSION_BINDING_INVALID", "not the session owner")
		}
		if state == "revoked" {
			return nil // idempotent
		}
		if _, err := tx.Exec(ctx, `UPDATE identity.sessions SET state = 'revoked' WHERE session_id = $1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity.session_tokens SET revoked_at = statement_timestamp() WHERE session_id = $1 AND revoked_at IS NULL`, id); err != nil {
			return err
		}
		// Lock order: sessions → approvals.
		rows, err := tx.Query(ctx, `
UPDATE identity.approvals SET revoked_at = statement_timestamp(), revoke_reason = 'session_ended'
WHERE session_id = $1 AND revoked_at IS NULL AND used_actions < max_actions
RETURNING approval_id, revision, policy_epoch, action_id`, id)
		if err != nil {
			return err
		}
		type revoked struct {
			id       uuid.UUID
			actionID uuid.UUID
			revision int
			epoch    int64
		}
		var gone []revoked
		for rows.Next() {
			var r revoked
			if err := rows.Scan(&r.id, &r.revision, &r.epoch, &r.actionID); err != nil {
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
			if err := s.auditor().Append(ctx, tx, Event{
				Tenant: tenant, Type: "approval_revoked", ActionID: r.actionID.String(), WorkloadID: workload, Actor: actor.AuthenticatedActor, SessionID: id.String(),
				Payload: map[string]any{"approval_id": r.id.String(), "revision": r.revision, "revoke_reason": "session_ended", "policy_epoch": r.epoch},
			}); err != nil {
				return err
			}
		}
		return s.auditor().Append(ctx, tx, Event{
			Tenant: tenant, Type: "session_revoked", WorkloadID: workload, Actor: actor.AuthenticatedActor, SessionID: id.String(),
			Payload: map[string]any{"session_id": id.String(), "authenticated_actor": actor.AuthenticatedActor, "reason": reason},
		})
	})
	if err != nil {
		return nil, err
	}
	return &RevokeResponse{SessionID: id.String(), State: "revoked"}, nil
}

// ---- helpers ----------------------------------------------------------------

// newToken returns a 256-bit random token and its SHA-256 digest.
func newToken() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	t := base64.RawURLEncoding.EncodeToString(b)
	d := sha256.Sum256([]byte(t))
	return t, d[:], nil
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func intersects(a, b []string) bool {
	set := map[string]bool{}
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if set[v] {
			return true
		}
	}
	return false
}

// anyMatch applies the standing rule target_pattern glob ('/' separated, the
// same glob.match the Rego uses) to the requested targets.
func anyMatch(pattern string, targets []string) bool {
	for _, t := range targets {
		if ok, err := path.Match(pattern, t); err == nil && ok {
			return true
		}
	}
	return false
}
