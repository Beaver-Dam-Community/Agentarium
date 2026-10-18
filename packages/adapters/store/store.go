// Package store is the Postgres implementation of execute.Store over the
// TASK-05 tables in schema adapter (migrations/20261016110000_adapter_results
// and 20261018115000_adapter_model_turns).
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
)

// PG implements execute.Store with a pgx pool.
type PG struct {
	Pool *pgxpool.Pool
}

var _ execute.Store = (*PG)(nil)

// Begin is INSERT ... ON CONFLICT DO NOTHING; an existing row is returned
// unchanged.
func (s *PG) Begin(ctx context.Context, decisionID, actionID, adapterID string) (execute.Execution, bool, error) {
	var e execute.Execution
	var attempt *string
	err := s.Pool.QueryRow(ctx, `
INSERT INTO adapter.adapter_executions (decision_id, action_id, adapter_id, state, updated_at)
VALUES ($1, $2, $3, 'received', statement_timestamp())
ON CONFLICT (decision_id) DO NOTHING
RETURNING decision_id::text, action_id::text, adapter_id, state, attempt_id::text, updated_at`,
		decisionID, actionID, adapterID).Scan(&e.DecisionID, &e.ActionID, &e.AdapterID, &e.State, &attempt, &e.UpdatedAt)
	if err == nil {
		e.AttemptID = deref(attempt)
		return e, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return e, false, err
	}
	err = s.Pool.QueryRow(ctx, `
SELECT decision_id::text, action_id::text, adapter_id, state, attempt_id::text, updated_at
FROM adapter.adapter_executions WHERE decision_id = $1`, decisionID).
		Scan(&e.DecisionID, &e.ActionID, &e.AdapterID, &e.State, &attempt, &e.UpdatedAt)
	e.AttemptID = deref(attempt)
	return e, false, err
}

// SetState is a compare-and-set on state.
func (s *PG) SetState(ctx context.Context, decisionID string, from []string, to, attemptID string) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `
UPDATE adapter.adapter_executions
SET state = $3, attempt_id = COALESCE($4::uuid, attempt_id), updated_at = statement_timestamp()
WHERE decision_id = $1 AND state = ANY($2)`, decisionID, from, to, nullable(attemptID))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Unfinished lists received and reserved rows of the adapter, oldest first.
func (s *PG) Unfinished(ctx context.Context, adapterID string) ([]execute.Execution, error) {
	rows, err := s.Pool.Query(ctx, `
SELECT decision_id::text, action_id::text, adapter_id, state, attempt_id::text, updated_at
FROM adapter.adapter_executions
WHERE adapter_id = $1 AND state IN ('received', 'reserved')
ORDER BY updated_at, decision_id`, adapterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []execute.Execution
	for rows.Next() {
		var e execute.Execution
		var attempt *string
		if err := rows.Scan(&e.DecisionID, &e.ActionID, &e.AdapterID, &e.State, &attempt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		e.AttemptID = deref(attempt)
		out = append(out, e)
	}
	return out, rows.Err()
}

// SavePending writes the recovery record and runs step ① in one
// transaction. The raise is GREATEST(current, response class): running it
// again never changes the result. With p.ModelTurn the model turn is written
// in the same transaction (savePendingWithTurn).
func (s *PG) SavePending(ctx context.Context, p execute.PendingOutcome, raise *execute.DataStateRaise) error {
	obs, err := json.Marshal(p.Observation)
	if err != nil {
		return err
	}
	var ev, res []byte
	if p.Event != nil {
		if ev, err = json.Marshal(p.Event); err != nil {
			return err
		}
	}
	if p.ModelTurn != nil || p.BuildResult != nil {
		return s.savePendingWithTurn(ctx, p, raise, obs, ev)
	}
	if p.Result != nil {
		if res, err = json.Marshal(p.Result); err != nil {
			return err
		}
	}
	codes := p.ReasonCodes
	if codes == nil {
		codes = []string{}
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if raise != nil {
			if err := raiseDataState(ctx, tx, *raise); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `
INSERT INTO adapter.pending_outcomes (decision_id, attempt_id, transition, reason_codes, observation, event, result, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, statement_timestamp())
ON CONFLICT (decision_id) DO NOTHING`, p.DecisionID, p.AttemptID, p.Transition, codes, obs, nullJSON(ev), nullJSON(res))
		return err
	})
}

// savePendingWithTurn is SavePending for a response with a model turn, in
// one transaction: ① raise, then the execution row is locked (FOR UPDATE) so
// writers of one decision are serialized. If the decision already has a
// recovery record nothing else is written (the first record and its turn
// stay). Otherwise the conversation's next turn_index is taken from
// model_conversations with INSERT ... ON CONFLICT DO UPDATE ... RETURNING
// (the row lock orders concurrent turns of one conversation), the model_turns
// row is inserted, p.BuildResult makes the result from the allocated key, and
// the recovery record is inserted with that result. raw_parts is stored only
// in model_turns.
//
// A conversation owned by another session, a row the table rejects or a
// BuildResult error is an *execute.AuxWriteError; any other error is the
// store's. Both roll everything back.
func (s *PG) savePendingWithTurn(ctx context.Context, p execute.PendingOutcome, raise *execute.DataStateRaise, obs, ev []byte) error {
	t := p.ModelTurn
	switch {
	case t == nil || p.BuildResult == nil:
		return errors.New("store: a model turn needs both ModelTurn and BuildResult")
	case p.Result != nil:
		return errors.New("store: a model turn record gets its result from BuildResult")
	case p.Transition != execute.TransitionResponseReceived:
		return errors.New("store: a model turn belongs to a response_received record")
	}
	codes := p.ReasonCodes
	if codes == nil {
		codes = []string{}
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if raise != nil {
			if err := raiseDataState(ctx, tx, *raise); err != nil {
				return err
			}
		}
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM adapter.adapter_executions WHERE decision_id = $1 FOR UPDATE`, p.DecisionID).Scan(&one); err != nil {
			return fmt.Errorf("store: lock adapter_executions: %w", err)
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM adapter.pending_outcomes WHERE decision_id = $1)`, p.DecisionID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return nil
		}
		// SPEC-QUESTION: TASK-05 3.1 does not bind a conversation_id to one
		// session. The first turn binds it to its session_key; a turn of
		// another session is refused instead of interleaving its indices.
		var idx int64
		err := tx.QueryRow(ctx, `
INSERT INTO adapter.model_conversations AS c (conversation_id, session_key, next_turn_index, updated_at)
VALUES ($1, $2, 1, statement_timestamp())
ON CONFLICT (conversation_id) DO UPDATE SET next_turn_index = c.next_turn_index + 1, updated_at = statement_timestamp()
WHERE c.session_key = EXCLUDED.session_key
RETURNING next_turn_index - 1`, t.ConversationID, t.SessionKey).Scan(&idx)
		if errors.Is(err, pgx.ErrNoRows) {
			return &execute.AuxWriteError{Err: errors.New("conversation_id belongs to another session")}
		}
		if err != nil {
			return auxOrStore(err)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO adapter.model_turns (conversation_id, turn_index, session_key, action_id, raw_parts, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, statement_timestamp(), $6)`,
			t.ConversationID, idx, t.SessionKey, t.ActionID, []byte(t.RawParts), t.ExpiresAt.UTC().Truncate(time.Microsecond)); err != nil {
			return auxOrStore(err)
		}
		r, err := p.BuildResult(execute.AuxWriteResult{ModelTurn: &execute.ModelTurnKey{ConversationID: t.ConversationID, TurnIndex: idx}})
		if err != nil {
			return &execute.AuxWriteError{Err: err}
		}
		if r.AttemptID != p.AttemptID {
			return &execute.AuxWriteError{Err: errors.New("built result belongs to another attempt")}
		}
		res, err := json.Marshal(r)
		if err != nil {
			return &execute.AuxWriteError{Err: err}
		}
		_, err = tx.Exec(ctx, `
INSERT INTO adapter.pending_outcomes (decision_id, attempt_id, transition, reason_codes, observation, event, result, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, statement_timestamp())`, p.DecisionID, p.AttemptID, p.Transition, codes, obs, nullJSON(ev), res)
		return err
	})
}

// auxOrStore classifies a failed model_turns/model_conversations write: a
// value the table rejects (SQLSTATE class 22 data exception or 23 integrity
// violation) is the adapter's row; anything else is the store.
func auxOrStore(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code[:2] == "22" || pe.Code[:2] == "23") {
		return &execute.AuxWriteError{Err: fmt.Errorf("model turn rejected by the table (SQLSTATE %s)", pe.Code)}
	}
	return err
}

func raiseDataState(ctx context.Context, tx pgx.Tx, r execute.DataStateRaise) error {
	if (r.Key.WorkloadID == "") == (r.Key.ServiceSessionID == "") {
		return errors.New("store: workload_data_state needs exactly one of workload_id and service_session_id")
	}
	sources := []string{}
	if r.DataClass != "none" && r.Source != "" {
		sources = []string{r.Source}
	}
	conflict := "(workload_id) WHERE workload_id IS NOT NULL"
	if r.Key.ServiceSessionID != "" {
		conflict = "(service_session_id) WHERE service_session_id IS NOT NULL"
	}
	// SPEC-QUESTION: COMMON does not say what data_sources holds; the
	// adapter adds the canonical target_id of a response whose class ranks
	// above none. updated_by_attempt_id moves only when the class rises.
	_, err := tx.Exec(ctx, fmt.Sprintf(`
INSERT INTO adapter.workload_data_state AS w
    (workload_id, service_session_id, data_class_high_water, data_sources, updated_by_attempt_id, updated_at)
VALUES ($1, $2, $3::adapter.data_class, $4, $5, statement_timestamp())
ON CONFLICT %s DO UPDATE SET
    data_class_high_water = GREATEST(w.data_class_high_water, EXCLUDED.data_class_high_water),
    data_sources = ARRAY(SELECT DISTINCT unnest(w.data_sources || EXCLUDED.data_sources) ORDER BY 1),
    updated_by_attempt_id = CASE WHEN EXCLUDED.data_class_high_water > w.data_class_high_water
                                 THEN EXCLUDED.updated_by_attempt_id ELSE w.updated_by_attempt_id END,
    updated_at = statement_timestamp()`, conflict),
		nullable(r.Key.WorkloadID), nullable(r.Key.ServiceSessionID), r.DataClass, sources, nullable(r.AttemptID))
	return err
}

// Pending reads the recovery record.
func (s *PG) Pending(ctx context.Context, decisionID string) (execute.PendingOutcome, error) {
	var p execute.PendingOutcome
	var obs, ev, res []byte
	err := s.Pool.QueryRow(ctx, `
SELECT decision_id::text, attempt_id::text, transition, reason_codes, observation, event, result
FROM adapter.pending_outcomes WHERE decision_id = $1`, decisionID).
		Scan(&p.DecisionID, &p.AttemptID, &p.Transition, &p.ReasonCodes, &obs, &ev, &res)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, execute.ErrNotFound
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(obs, &p.Observation); err != nil {
		return p, err
	}
	if ev != nil {
		p.Event = &execute.Event{}
		if err := json.Unmarshal(ev, p.Event); err != nil {
			return p, err
		}
	}
	if res != nil {
		p.Result = &execute.ActionResult{}
		if err := json.Unmarshal(res, p.Result); err != nil {
			return p, err
		}
	}
	return p, nil
}

// EventID stores candidate as the row's event_id for eventType unless one is
// already stored, and returns the stored value.
func (s *PG) EventID(ctx context.Context, decisionID, eventType, candidate string) (string, error) {
	col := ""
	switch eventType {
	case "preflight_passed":
		col = "preflight_passed_event_id"
	case "preflight_rejected":
		col = "preflight_rejected_event_id"
	default:
		return "", fmt.Errorf("store: no event_id column for %q", eventType)
	}
	var id string
	err := s.Pool.QueryRow(ctx, fmt.Sprintf(`
UPDATE adapter.adapter_executions SET %[1]s = COALESCE(%[1]s, $2::uuid)
WHERE decision_id = $1 RETURNING %[1]s::text`, col), decisionID, candidate).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", execute.ErrNotFound
	}
	return id, err
}

// InsertResult is step ③. The attempt is the key, so a redo inserts nothing.
func (s *PG) InsertResult(ctx context.Context, r execute.ActionResult) error {
	body := []byte(r.ResultBody)
	if len(body) == 0 {
		body = []byte("null")
	}
	_, err := s.Pool.Exec(ctx, `
INSERT INTO adapter.action_results (attempt_id, action_id, execution_state, data_class, result_body,
    truncated, truncation_reason, evidence_level, result_digest, created_at)
VALUES ($1, $2, $3, $4::adapter.data_class, $5, $6, $7, $8, $9, $10)
ON CONFLICT (attempt_id) DO NOTHING`, r.AttemptID, r.ActionID, r.ExecutionState, r.DataClass, body,
		r.Truncated, r.TruncationReason, r.EvidenceLevel, r.ResultDigest, r.CreatedAt.UTC().Truncate(time.Microsecond))
	return err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullJSON(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}
