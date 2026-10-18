package sessions

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Profile is one row of the server-side service profile table (COMMON
// service profile, TASK-03 3.4).
type Profile struct {
	Caller   string         // registered_workloads.service_principal
	Scope    string         // issue_id, change_id, snapshot_id or action_id
	Counters map[string]int // counter → upper bound
	TTL      time.Duration
}

// Profiles is the TASK-03 3.4 table.
var Profiles = map[string]Profile{
	"intent_check":     {Caller: "intent-checker", Scope: "action_id", Counters: map[string]int{"model": 1}, TTL: 30 * time.Second},
	"policy_proposal":  {Caller: "policy-proposer", Scope: "issue_id", Counters: map[string]int{"read_tools": 6, "model": 8}, TTL: 15 * time.Minute},
	"discovery":        {Caller: "discovery", Scope: "snapshot_id", Counters: map[string]int{"snapshot_reads": 50, "model": 20}, TTL: 30 * time.Minute},
	"activation_probe": {Caller: "releaser", Scope: "change_id", Counters: map[string]int{"probe_actions": 4}, TTL: 10 * time.Minute},
}

// MaxCandidatesPerIssue bounds policy_proposal sessions per issue.
const MaxCandidatesPerIssue = 2

// ServiceRequest is the POST /internal/service-sessions body (COMMON API
// implementation contract). tool_budget is the COMMON ToolBudget; see applyBudget.
type ServiceRequest struct {
	Profile     string      `json:"profile"`
	IssueID     *string     `json:"issue_id"`
	CandidateID *string     `json:"candidate_id"`
	ChangeID    *string     `json:"change_id"`
	SnapshotID  *string     `json:"snapshot_id"`
	ActionID    *string     `json:"action_id"`
	Tenant      string      `json:"tenant"`
	ToolBudget  *ToolBudget `json:"tool_budget"`
	TTLSeconds  *int        `json:"ttl"`
}

type ServiceResponse struct {
	ServiceSessionID string      `json:"service_session_id"`
	Token            string      `json:"token"`
	ToolBudget       *ToolBudget `json:"tool_budget"` // applied maxima, never null
	ExpiresAt        time.Time   `json:"expires_at"`
}

// CreateService makes a service session for a registered service principal.
// The caller's profile, scope, budget and TTL are checked against Profiles;
// a budget or TTL above the profile's bound is cut down to it.
func (s *Service) CreateService(ctx context.Context, p RuntimePrincipal, req ServiceRequest) (*ServiceResponse, error) {
	prof, ok := Profiles[req.Profile]
	if !ok {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "unknown profile")
	}
	if req.Tenant == "" {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "tenant is required")
	}
	scope, err := parseScope(req)
	if err != nil {
		return nil, err
	}
	if _, ok := scope[prof.Scope]; !ok || len(scope) != 1 {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "profile "+req.Profile+" needs exactly one scope: "+prof.Scope)
	}
	var candidate *uuid.UUID
	if req.CandidateID != nil {
		if req.Profile != "policy_proposal" {
			return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "candidate_id is only for policy_proposal")
		}
		c, err := uuid.Parse(*req.CandidateID)
		if err != nil {
			return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "candidate_id is not a UUID")
		}
		candidate = &c
	} else if req.Profile == "policy_proposal" {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "policy_proposal needs candidate_id")
	}

	budget, applied, err := applyBudget(req.Profile, prof, req.ToolBudget)
	if err != nil {
		return nil, err
	}
	ttl := prof.TTL
	if req.TTLSeconds != nil {
		if *req.TTLSeconds <= 0 {
			return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "ttl must be positive")
		}
		ttl = min(ttl, time.Duration(*req.TTLSeconds)*time.Second)
	}

	token, digest, err := newToken()
	if err != nil {
		return nil, err
	}
	id := uuid.New()
	actor := "service:" + p.WorkloadID()
	var expires time.Time

	// The issue-candidate bound is a cross-row invariant, so the transaction
	// runs SERIALIZABLE and retries on a serialization failure.
	const attempts = 5
	for i := 0; ; i++ {
		err = s.inTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
			var role, principal string
			var enabled bool
			err := tx.QueryRow(ctx, `
SELECT role, coalesce(service_principal, ''), enabled FROM identity.registered_workloads
WHERE namespace = $1 AND ksa = $2`, p.Namespace, p.KSA).Scan(&role, &principal, &enabled)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && (role != "service" || !enabled || principal != prof.Caller)) {
				return fail(http.StatusForbidden, "SERVICE_SCOPE_DENIED", "caller may not use profile "+req.Profile)
			}
			if err != nil {
				return err
			}
			// inherited is the candidate's usage so far (audit only; the new
			// session's own counters start at 0); previous is the candidate's
			// latest earlier session (policy_proposal only).
			var inherited map[string]int
			var previous *uuid.UUID
			if candidate != nil {
				var err error
				inherited, previous, err = s.claimCandidate(ctx, tx, scope["issue_id"], *candidate, budget)
				if err != nil {
					return err
				}
			}
			if err := tx.QueryRow(ctx, `SELECT statement_timestamp() + $1::interval`, ttl.String()).Scan(&expires); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO identity.service_sessions (service_session_id, caller_principal, authenticated_actor, profile, tenant,
    issue_id, candidate_id, change_id, snapshot_id, action_id, state, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active', statement_timestamp(), $11)`,
				id, prof.Caller, actor, req.Profile, req.Tenant,
				scopeArg(scope, "issue_id"), candidate, scopeArg(scope, "change_id"), scopeArg(scope, "snapshot_id"), scopeArg(scope, "action_id"), expires); err != nil {
				return err
			}
			for _, counter := range sortedKeys(budget) {
				if _, err := tx.Exec(ctx, `
INSERT INTO identity.service_session_counters (service_session_id, counter, max_value, used_value) VALUES ($1, $2, $3, 0)`,
					id, counter, budget[counter]); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO identity.session_tokens (token_digest, service_session_id, bound_identity, issued_at)
VALUES ($1, $2, $3, statement_timestamp())`, digest, id, p.SAN); err != nil {
				return err
			}
			payload := map[string]any{"service_session_id": id.String(), "caller_principal": prof.Caller, "tool_budget": applied, "counters": budget}
			for k, v := range scope {
				payload[k] = v.String()
			}
			if candidate != nil {
				payload["inherited_used"] = inherited
				if previous != nil {
					payload["previous_service_session_id"] = previous.String()
				}
			}
			return s.auditor().Append(ctx, tx, Event{Tenant: req.Tenant, Type: "service_session_created", Actor: actor, SessionID: id.String(), Payload: payload})
		})
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "40001" && i < attempts-1 {
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	return &ServiceResponse{ServiceSessionID: id.String(), Token: token, ToolBudget: applied, ExpiresAt: expires}, nil
}

// CodeServiceSessionActive refuses a policy_proposal session while the same
// candidate still has an active one. The code is added to the COMMON reason
// code registry by the separate COMMON change that accompanies this PR.
const CodeServiceSessionActive = "SERVICE_SESSION_ACTIVE"

// claimCandidate enforces TASK-03 3.4 for one policy_proposal candidate: at
// most MaxCandidatesPerIssue candidates per issue, one service session per
// candidate at a time, and a per-candidate budget that a re-issue (after
// expiry, revoke or a caller restart) does not reset.
//
// The candidate's usage lives in one authoritative row per counter,
// identity.issue_candidate_counters, shared by all its sessions. The
// coordinator consumes and restores that row (TASK-03 3.2), so a late release
// of a reservation made through an earlier session also returns the use to
// the session issued after it. A new session's service_session_counters hold
// only its own maximum and the uses made through it, starting at 0; nothing is
// copied from earlier sessions.
//
// It returns the candidate's current usage per counter (the audit's
// inherited_used) and the latest earlier session, or nil for the candidate's
// first session. It runs inside the caller's SERIALIZABLE transaction and
// locks in the global order service_sessions → issue_candidates →
// issue_candidate_counters (TASK-03 3.2 lock order): first the candidate's
// earlier sessions FOR UPDATE, which waits for a reservation or release still
// holding one of them, then the candidate row, then its counter rows FOR
// UPDATE. A counter updated by a transaction that committed after this one
// started fails with a serialization error, and the retry reads the committed
// value. A first-time insert relies on SERIALIZABLE (and the primary keys).
func (s *Service) claimCandidate(ctx context.Context, tx pgx.Tx, issue, candidate uuid.UUID, budget map[string]int) (map[string]int, *uuid.UUID, error) {
	// Lock every earlier session of the candidate.
	rows, err := tx.Query(ctx, `
SELECT service_session_id, state = 'active' AND expires_at > statement_timestamp(), created_at
FROM identity.service_sessions
WHERE profile = 'policy_proposal' AND issue_id = $1 AND candidate_id = $2
ORDER BY service_session_id FOR UPDATE`, issue, candidate)
	if err != nil {
		return nil, nil, err
	}
	var previous *uuid.UUID
	var latest time.Time
	active := false
	for rows.Next() {
		var id uuid.UUID
		var live bool
		var created time.Time
		if err := rows.Scan(&id, &live, &created); err != nil {
			rows.Close()
			return nil, nil, err
		}
		active = active || live
		// Latest by created_at, ties broken by the larger ID.
		if previous == nil || created.After(latest) || (created.Equal(latest) && id.String() > previous.String()) {
			previous, latest = &id, created
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	// One session per candidate: any live session refuses, whatever its
	// tenant or remaining budget.
	if active {
		return nil, nil, fail(http.StatusConflict, CodeServiceSessionActive, "candidate already has an active service session")
	}

	var one int
	err = tx.QueryRow(ctx, `
SELECT 1 FROM identity.issue_candidates WHERE issue_id = $1 AND candidate_id = $2 FOR UPDATE`, issue, candidate).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity.issue_candidates WHERE issue_id = $1`, issue).Scan(&n); err != nil {
			return nil, nil, err
		}
		if n >= MaxCandidatesPerIssue {
			return nil, nil, fail(http.StatusConflict, "TOOL_BUDGET_EXHAUSTED", "issue already has two candidates")
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO identity.issue_candidates (issue_id, candidate_id, created_at) VALUES ($1, $2, statement_timestamp())`,
			issue, candidate); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}

	// The candidate's counter rows: created with its first session, locked
	// on every later one.
	for _, c := range sortedKeys(budget) {
		if _, err := tx.Exec(ctx, `
INSERT INTO identity.issue_candidate_counters (issue_id, candidate_id, counter, used_value) VALUES ($1, $2, $3, 0)
ON CONFLICT DO NOTHING`, issue, candidate, c); err != nil {
			return nil, nil, err
		}
	}
	used := map[string]int{}
	rows, err = tx.Query(ctx, `
SELECT counter, used_value FROM identity.issue_candidate_counters
WHERE issue_id = $1 AND candidate_id = $2
ORDER BY counter FOR UPDATE`, issue, candidate)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var c string
		var v int
		if err := rows.Scan(&c, &v); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if _, ok := budget[c]; ok {
			used[c] = v
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for _, c := range sortedKeys(budget) {
		if budget[c] < used[c] {
			return nil, nil, fail(http.StatusConflict, "TOOL_BUDGET_EXHAUSTED", "candidate already used "+strconv.Itoa(used[c])+" "+c+", above the requested maximum")
		}
	}
	return used, previous, nil
}

// parseScope returns the scope IDs that are set. candidate_id is not a scope
// of its own; it rides on issue_id.
func parseScope(req ServiceRequest) (map[string]uuid.UUID, error) {
	out := map[string]uuid.UUID{}
	for name, v := range map[string]*string{
		"issue_id": req.IssueID, "change_id": req.ChangeID, "snapshot_id": req.SnapshotID, "action_id": req.ActionID,
	} {
		if v == nil {
			continue
		}
		id, err := uuid.Parse(*v)
		if err != nil {
			return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", name+" is not a UUID")
		}
		out[name] = id
	}
	if len(out) != 1 {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "exactly one scope is allowed")
	}
	return out, nil
}

// scopeArg is the scope ID, or nil (SQL NULL) when that scope is not set.
func scopeArg(scope map[string]uuid.UUID, name string) *uuid.UUID {
	if v, ok := scope[name]; ok {
		return &v
	}
	return nil
}
