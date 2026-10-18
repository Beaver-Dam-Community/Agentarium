// Package inputs is the Postgres implementation of execute.InputStore: it
// reads the stored TASK-04 decision, action envelope and content of one
// execute request.
//
// The objects are those of the TASK-04 migration
// 20261016181826_gateway_decisions:
// the table decisions.decisions and the views
// decisions.adapter_action_envelopes and decisions.adapter_action_contents,
// which are what that migration grants to adapter_reader (no grant on
// decisions.actions or decisions.action_contents). The row mapping is declared
// here so this package does not depend on the TASK-04 Go packages.
//
// Decisions are immutable (trigger decisions_immutable) and actions are
// insert-only for the gateway, so the rows are read without a lock, in one
// read-only REPEATABLE READ transaction.
//
// Per-adapter isolation is by DB login (TASK-04 migration as revised in #46;
// COMMON contract in PR #50): each adapter connects as its own login (its
// Cloud SQL IAM DB user), a member of adapter_reader, and
// decisions.adapter_db_roles maps that login (session_user) to one
// adapter_id. Both views show only actions with an allow decision for the
// mapped adapter, so a login sees no envelope or content of another
// adapter's actions, and a login without a mapping sees none at all. SET ROLE
// adapter_reader does not change session_user. adapter_reader has no grant on
// adapter_db_roles or the base tables. The install step must register one
// adapter_db_roles row per adapter login; this package cannot check that row
// (see Check). The reader still filters content rows by its own adapter_id
// as a second check.
//
// SPEC-QUESTION: decisions.execute_requests (the durable handoff that names
// the adapter) is not in COMMON's adapter_reader grants, so it is not read.
// The adapter relies on decisions.verdict and decisions.adapter_id, which the
// engine preflight compares.
package inputs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/internal/strictjson"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// ErrInconsistent means the stored envelope jsonb does not decode as a
// COMMON ActionEnvelope (see decodeEnvelope). The engine treats it like any
// read error: the execution stays received and nothing is reserved or sent.
var ErrInconsistent = errors.New("inputs: stored action is inconsistent")

// PG reads the TASK-04 decisions table and adapter views with a pgx pool.
// AdapterID is this adapter's catalog adapter_id; only content rows of that
// adapter are read.
type PG struct {
	Pool      *pgxpool.Pool
	AdapterID string
}

var _ execute.InputStore = (*PG)(nil)

// decisionRow is the part of a decisions.decisions row the adapter reads.
// action_digest, adapter_id and policy_epoch are null for a normalize-stage
// decision.
type decisionRow struct {
	DecisionID     string
	RequestID      string
	ActionID       string
	ActionDigest   *string
	AdapterID      *string
	Verdict        string
	PolicyBundleID string
	PolicyEpoch    *int64
	CatalogDigest  string
	ExpiresAt      time.Time
	// ServiceSessionID is null for a user session decision.
	ServiceSessionID *string
}

const decisionCols = `d.decision_id::text, d.request_id::text, d.action_id::text, d.action_digest, d.adapter_id,
       d.verdict, d.policy_bundle_id, d.policy_epoch, d.catalog_digest, d.expires_at, d.service_session_id::text`

func (r *decisionRow) dest() []any {
	return []any{&r.DecisionID, &r.RequestID, &r.ActionID, &r.ActionDigest, &r.AdapterID,
		&r.Verdict, &r.PolicyBundleID, &r.PolicyEpoch, &r.CatalogDigest, &r.ExpiresAt, &r.ServiceSessionID}
}

func (r decisionRow) decision() execute.Decision {
	d := execute.Decision{
		DecisionID:     r.DecisionID,
		RequestID:      r.RequestID,
		ActionID:       r.ActionID,
		ActionDigest:   deref(r.ActionDigest),
		AdapterID:      deref(r.AdapterID),
		Verdict:        r.Verdict,
		PolicyBundleID: r.PolicyBundleID,
		CatalogDigest:  r.CatalogDigest,
		ExpiresAt:      r.ExpiresAt,
		// decisions.service_session_id is uuid, so ::text is the lowercase
		// canonical form the preflight compares with the envelope session_id.
		ServiceSessionID: deref(r.ServiceSessionID),
	}
	if r.PolicyEpoch != nil {
		d.PolicyEpoch = *r.PolicyEpoch
	}
	return d
}

func inconsistent(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInconsistent, fmt.Sprintf(format, a...))
}

// decodeEnvelope decodes the envelope jsonb of adapter_action_envelopes as a
// COMMON ActionEnvelope (strictjson: every key present, no unknown key).
//
// The CHECK on decisions.actions keeps the jsonb equal to the typed columns,
// so the columns are not read or compared. The jsonb values of
// canonical_target and limits are not shape-checked by the database (a JSON
// null or an object with other keys satisfies the CHECK), so they are decoded
// strictly here as well: canonical_target as an object with its required
// keys, limits as an object of integers (strictjson already rejects a
// fraction or an unknown target key). A row that does not decode is
// ErrInconsistent.
func decodeEnvelope(actionID string, raw []byte) (canonical.ActionEnvelope, error) {
	var env canonical.ActionEnvelope
	if err := strictjson.Decode(raw, &env); err != nil {
		return canonical.ActionEnvelope{}, inconsistent("action %s envelope: %v", actionID, err)
	}
	var target struct {
		CanonicalTarget json.RawMessage `json:"canonical_target"`
	}
	if err := json.Unmarshal(raw, &target); err != nil {
		return canonical.ActionEnvelope{}, inconsistent("action %s envelope: %v", actionID, err)
	}
	if err := strictjson.Decode(target.CanonicalTarget, &canonical.CanonicalTarget{}); err != nil {
		return canonical.ActionEnvelope{}, inconsistent("action %s canonical_target: %v", actionID, err)
	}
	if env.Limits == nil {
		return canonical.ActionEnvelope{}, inconsistent("action %s limits: not an object", actionID)
	}
	return env, nil
}

// contentRow is a decisions.adapter_action_contents row without the
// timestamps.
type contentRow struct {
	ContentDigest string
	Tenant        string
	ActionID      string
	AdapterID     string
	ContentBytes  []byte
}

const contentCols = `c.content_digest, c.tenant, c.action_id::text, c.adapter_id, c.content_bytes`

func (r *contentRow) dest() []any {
	return []any{&r.ContentDigest, &r.Tenant, &r.ActionID, &r.AdapterID, &r.ContentBytes}
}

// content maps the row as stored. The engine recomputes the digest and
// compares action_id, tenant and adapter_id (canonical.VerifyContent).
// action_contents is keyed by (content_digest, action_id) in #46, so each
// action has its own row even when two actions have byte-identical content.
func (r contentRow) content() canonical.Content {
	return canonical.Content{
		ContentDigest: r.ContentDigest,
		Tenant:        r.Tenant,
		ActionID:      r.ActionID,
		AdapterID:     r.AdapterID,
		ContentBytes:  r.ContentBytes,
	}
}

// The envelope comes from adapter_action_envelopes, which has only actions
// with an allow decision for the login's mapped adapter; for any other action
// the LEFT JOIN gives a null envelope.
const loadSQL = `
SELECT ` + decisionCols + `,
       e.envelope
FROM decisions.decisions d
LEFT JOIN decisions.adapter_action_envelopes e ON e.action_id = d.action_id
WHERE d.decision_id = $1 AND d.action_id = $2`

// The content row is looked up by the envelope's content_ref and the action
// (the action_contents key). The view already shows only rows of the login's
// mapped adapter (package comment); c.adapter_id = $3 is a second check, so
// a login mapped to another adapter_id than s.AdapterID still reads no
// content. The view hides expired rows (expires_at, 30 days).
const contentSQL = `
SELECT ` + contentCols + `
FROM decisions.adapter_action_contents c
WHERE c.content_digest = $1 AND c.action_id = $2 AND c.adapter_id = $3`

// Load reads the decision, its action's envelope and, when the envelope has
// content and the decision names this adapter, the content row.
//
//   - ErrNotFound when either ID is not a canonical UUID, the decision does
//     not exist or it belongs to another action.
//   - An action without an allow decision (a normalize-stage rejection
//     without an envelope, or an action only denied or awaiting approval)
//     gives a zero Envelope; the engine preflight rejects it on the verdict.
//   - A decision for another adapter_id than the login's mapped adapter, or
//     any decision read by a login without an adapter_db_roles row, gives a
//     zero Envelope and a zero Content (the views hide them); the preflight
//     rejects it on adapter_id and action_id. A decision for another
//     adapter_id than s.AdapterID is never read for content.
//   - A missing, expired or other-adapter content row gives a zero Content;
//     the preflight rejects it with CONTENT_DIGEST_MISMATCH.
//   - ErrInconsistent when the envelope jsonb does not decode.
func (s *PG) Load(ctx context.Context, decisionID, actionID string) (execute.Inputs, error) {
	if s.AdapterID == "" {
		return execute.Inputs{}, errors.New("inputs: AdapterID is not set")
	}
	if !execute.ValidUUID(decisionID) || !execute.ValidUUID(actionID) {
		return execute.Inputs{}, execute.ErrNotFound
	}
	var in execute.Inputs
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var d decisionRow
		var raw []byte
		if err := tx.QueryRow(ctx, loadSQL, decisionID, actionID).Scan(append(d.dest(), &raw)...); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return execute.ErrNotFound
			}
			return err
		}
		in.Decision = d.decision()
		if raw == nil {
			return nil
		}
		env, err := decodeEnvelope(actionID, raw)
		if err != nil {
			return err
		}
		in.Envelope = env
		if env.ContentRef == nil || in.Decision.AdapterID != s.AdapterID {
			return nil
		}
		var c contentRow
		err = tx.QueryRow(ctx, contentSQL, *env.ContentRef, actionID, s.AdapterID).Scan(c.dest()...)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		in.Content = c.content()
		return nil
	})
	if err != nil {
		return execute.Inputs{}, err
	}
	return in, nil
}

// Check runs the reader's queries without reading a row, so a missing
// table, view, column or SELECT grant fails at startup instead of at the
// first execution. It cannot see whether the login has an adapter_db_roles
// row (adapter_reader has no grant on that table): an unmapped login passes
// Check, reads zero envelopes and every execution is rejected in preflight.
func (s *PG) Check(ctx context.Context) error {
	if s.AdapterID == "" {
		return errors.New("inputs: AdapterID is not set")
	}
	return pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		zero := "00000000-0000-0000-0000-000000000000"
		for _, c := range []struct {
			sql  string
			args []any
		}{
			{loadSQL + ` AND false`, []any{zero, zero}},
			{contentSQL + ` AND false`, []any{"", zero, s.AdapterID}},
		} {
			rows, err := tx.Query(ctx, c.sql, c.args...)
			if err != nil {
				return fmt.Errorf("inputs: check TASK-04 views: %w", err)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return fmt.Errorf("inputs: check TASK-04 views: %w", err)
			}
		}
		return nil
	})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
