//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/store"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

// Model turns (TASK-05 3.1) written by SavePending with the recovery record.

const thoughtSig = "SECRET-THOUGHT-SIGNATURE"

// turnPending is a response_received record with a model turn whose result
// body carries the allocated {conversation_id, turn_index}.
func turnPending(d, at, a, conv, session string) execute.PendingOutcome {
	now := time.Now()
	return execute.PendingOutcome{DecisionID: d, AttemptID: at, Transition: execute.TransitionResponseReceived, ReasonCodes: []string{},
		Observation: transport.Observation{AttemptID: at, ResponseAt: &now},
		Event:       &execute.Event{Type: "response_received", ActionID: a, AttemptID: at, Payload: map[string]any{"status_code": 200}},
		ModelTurn: &execute.ModelTurnWrite{ConversationID: conv, SessionKey: session, ActionID: a,
			RawParts: json.RawMessage(`[{"text":"hi","thoughtSignature":"` + thoughtSig + `"}]`), ExpiresAt: now.Add(time.Hour)},
		BuildResult: func(aux execute.AuxWriteResult) (execute.ActionResult, error) {
			if aux.ModelTurn == nil || aux.ModelTurn.ConversationID != conv {
				return execute.ActionResult{}, fmt.Errorf("aux %+v", aux)
			}
			body := fmt.Sprintf(`{"conversation_id":%q,"turn_index":%d,"text":"hi"}`, conv, aux.ModelTurn.TurnIndex)
			return execute.ActionResult{ActionID: a, AttemptID: at, ExecutionState: "accepted", DataClass: "internal",
				ResultBody: json.RawMessage(body), EvidenceLevel: "accepted", ResultDigest: strings.Repeat("c", 64), CreatedAt: now}, nil
		},
	}
}

func turnIndex(t *testing.T, p execute.PendingOutcome) int64 {
	t.Helper()
	if p.Result == nil {
		t.Fatal("record without result")
	}
	var b struct {
		TurnIndex *int64 `json:"turn_index"`
	}
	if err := json.Unmarshal(p.Result.ResultBody, &b); err != nil || b.TurnIndex == nil {
		t.Fatalf("result body %s: %v", p.Result.ResultBody, err)
	}
	return *b.TurnIndex
}

func turnCount(t *testing.T, p *pgxpool.Pool, conv string) int {
	t.Helper()
	var n int
	if err := p.QueryRow(context.Background(), `SELECT count(*) FROM adapter.model_turns WHERE conversation_id = $1`, conv).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func begin(t *testing.T, s *store.PG) (d, a string) {
	t.Helper()
	d, a = uuid(), uuid()
	if _, _, err := s.Begin(context.Background(), d, a, "model"); err != nil {
		t.Fatal(err)
	}
	return d, a
}

// Every failure inside the transaction leaves nothing: no recovery record, no
// turn, no counter, no raise.
func TestModelTurnSameTransaction(t *testing.T) {
	p := pool(t)
	s := &store.PG{Pool: p}
	ctx := context.Background()
	session := uuid()
	raise := func() *execute.DataStateRaise {
		return &execute.DataStateRaise{Key: execute.DataStateKey{ServiceSessionID: session}, DataClass: "internal", Source: "agent-platform"}
	}
	nothing := func(name, d, conv string) {
		t.Helper()
		if _, err := s.Pending(ctx, d); err != execute.ErrNotFound {
			t.Fatalf("%s: recovery record kept: %v", name, err)
		}
		if n := turnCount(t, p, conv); n != 0 {
			t.Fatalf("%s: %d model turns kept", name, n)
		}
		var n int
		if err := p.QueryRow(ctx, `SELECT count(*) FROM adapter.model_conversations WHERE conversation_id = $1`, conv).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: conversation counter kept (%d, %v)", name, n, err)
		}
		if err := p.QueryRow(ctx, `SELECT count(*) FROM adapter.workload_data_state WHERE service_session_id = $1`, session).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: step 1 kept (%d, %v)", name, n, err)
		}
	}
	var aux *execute.AuxWriteError

	// BuildResult fails after the turn was inserted.
	d, a := begin(t, s)
	conv := uuid()
	po := turnPending(d, uuid(), a, conv, session)
	po.BuildResult = func(execute.AuxWriteResult) (execute.ActionResult, error) {
		return execute.ActionResult{}, errors.New("unparseable")
	}
	if err := s.SavePending(ctx, po, raise()); !errors.As(err, &aux) {
		t.Fatalf("builder failure: %v", err)
	}
	nothing("builder failure", d, conv)

	// The table refuses the row (expires_at not after created_at).
	po = turnPending(d, uuid(), a, conv, session)
	po.ModelTurn.ExpiresAt = time.Now().Add(-time.Hour)
	if err := s.SavePending(ctx, po, raise()); !errors.As(err, &aux) {
		t.Fatalf("expired turn: %v", err)
	}
	nothing("expired turn", d, conv)

	// The recovery record insert fails after the turn and the result (an
	// attempt_id that is not a UUID); this is a store error, not the
	// adapter's.
	po = turnPending(d, "not-a-uuid", a, conv, session)
	if err := s.SavePending(ctx, po, raise()); err == nil || errors.As(err, &aux) {
		t.Fatalf("pending insert failure: %v", err)
	}
	nothing("pending insert failure", d, conv)

	// Step 1 fails before anything else.
	po = turnPending(d, uuid(), a, conv, session)
	if err := s.SavePending(ctx, po, &execute.DataStateRaise{DataClass: "internal"}); err == nil || errors.As(err, &aux) {
		t.Fatalf("raise failure: %v", err)
	}
	nothing("raise failure", d, conv)

	// The engine's contract: a record with a turn has no Result and needs
	// BuildResult.
	po = turnPending(d, uuid(), a, conv, session)
	po.BuildResult = nil
	if err := s.SavePending(ctx, po, nil); err == nil {
		t.Fatal("model turn without BuildResult accepted")
	}
	po = turnPending(d, uuid(), a, conv, session)
	po.Result = &execute.ActionResult{}
	if err := s.SavePending(ctx, po, nil); err == nil {
		t.Fatal("model turn with a prebuilt Result accepted")
	}
	nothing("contract", d, conv)

	// The same record succeeds and writes everything together.
	if err := s.SavePending(ctx, turnPending(d, uuid(), a, conv, session), raise()); err != nil {
		t.Fatal(err)
	}
	got, err := s.Pending(ctx, d)
	if err != nil || turnIndex(t, got) != 0 || got.ModelTurn != nil || got.BuildResult != nil {
		t.Fatalf("%+v %v", got, err)
	}
	var sk, act, raw string
	if err := p.QueryRow(ctx, `SELECT session_key::text, action_id::text, raw_parts::text FROM adapter.model_turns WHERE conversation_id = $1 AND turn_index = 0`, conv).
		Scan(&sk, &act, &raw); err != nil || sk != session || act != a || !strings.Contains(raw, thoughtSig) {
		t.Fatalf("model turn %s %s %s %v", sk, act, raw, err)
	}
	if c, _, _ := dataClass(t, p, "service_session_id::text", session); c != "internal" {
		t.Fatalf("step 1 class %s", c)
	}

	// A conversation is bound to the session of its first turn.
	d2, a2 := begin(t, s)
	if err := s.SavePending(ctx, turnPending(d2, uuid(), a2, conv, uuid()), nil); !errors.As(err, &aux) {
		t.Fatalf("other session's turn: %v", err)
	}
	if n := turnCount(t, p, conv); n != 1 {
		t.Fatalf("turns after the refused session: %d", n)
	}
	if _, err := s.Pending(ctx, d2); err != execute.ErrNotFound {
		t.Fatalf("recovery record of the refused turn: %v", err)
	}
}

// Concurrent turns of one conversation get 0..n-1, each once.
func TestModelTurnConcurrentAllocation(t *testing.T) {
	p := pool(t)
	s := &store.PG{Pool: p}
	ctx := context.Background()
	conv, session := uuid(), uuid()
	const n = 20
	decisions := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		d, a := begin(t, s)
		decisions[i] = d
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.SavePending(ctx, turnPending(d, uuid(), a, conv, session), nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	seen := map[int64]bool{}
	for _, d := range decisions {
		got, err := s.Pending(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		idx := turnIndex(t, got)
		if seen[idx] {
			t.Fatalf("turn_index %d allocated twice", idx)
		}
		seen[idx] = true
	}
	for i := int64(0); i < n; i++ {
		if !seen[i] {
			t.Fatalf("turn_index %d missing: %v", i, seen)
		}
	}
	var next int64
	if err := p.QueryRow(ctx, `SELECT next_turn_index FROM adapter.model_conversations WHERE conversation_id = $1`, conv).Scan(&next); err != nil || next != n {
		t.Fatalf("next_turn_index %d %v", next, err)
	}
	if c := turnCount(t, p, conv); c != n {
		t.Fatalf("%d model turns", c)
	}
	// Every result's turn_index names the turn of its own action.
	var bad int
	if err := p.QueryRow(ctx, `
SELECT count(*) FROM adapter.pending_outcomes po
JOIN adapter.model_turns mt ON mt.conversation_id = $1 AND mt.turn_index = (po.result->'result_body'->>'turn_index')::bigint
WHERE po.decision_id = ANY($2::uuid[]) AND mt.action_id::text <> po.result->>'action_id'`, conv, decisions).Scan(&bad); err != nil || bad != 0 {
		t.Fatalf("%d results point at another action's turn (%v)", bad, err)
	}
}

// A second SavePending of the decision, also concurrent ones, keeps the first
// record and writes no second turn; a restarted store reads the same result.
func TestModelTurnIdempotentAndRestart(t *testing.T) {
	p := pool(t)
	s := &store.PG{Pool: p}
	ctx := context.Background()
	conv, session := uuid(), uuid()
	d, a := begin(t, s)
	at := uuid()
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.SavePending(ctx, turnPending(d, at, a, conv, session), nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	again := turnPending(d, at, a, conv, session)
	again.BuildResult = func(execute.AuxWriteResult) (execute.ActionResult, error) {
		t.Error("BuildResult called for a decision that has a record")
		return execute.ActionResult{}, errors.New("called")
	}
	if err := s.SavePending(ctx, again, nil); err != nil {
		t.Fatal(err)
	}
	// A record without a turn (restart unknown path) also keeps the first.
	unk := pending(d, at)
	unk.Transition = execute.TransitionUnknown
	if err := s.SavePending(ctx, unk, nil); err != nil {
		t.Fatal(err)
	}
	if c := turnCount(t, p, conv); c != 1 {
		t.Fatalf("%d model turns for one decision", c)
	}

	// Restart: a new store over a new pool reads the stored record.
	p2, err := pgxpool.NewWithConfig(ctx, p.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2 := &store.PG{Pool: p2}
	got, err := s2.Pending(ctx, d)
	if err != nil || got.Transition != execute.TransitionResponseReceived || turnIndex(t, got) != 0 || got.ModelTurn != nil {
		t.Fatalf("%+v %v", got, err)
	}
	// Step 3 from the record; the raw parts never left model_turns.
	if err := s2.InsertResult(ctx, *got.Result); err != nil {
		t.Fatal(err)
	}
	var rec, res string
	if err := p2.QueryRow(ctx, `SELECT row_to_json(po)::text FROM adapter.pending_outcomes po WHERE decision_id = $1`, d).Scan(&rec); err != nil {
		t.Fatal(err)
	}
	if err := p2.QueryRow(ctx, `SELECT row_to_json(ar)::text FROM adapter.action_results ar WHERE attempt_id = $1`, at).Scan(&res); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec, thoughtSig) || strings.Contains(res, thoughtSig) || strings.Contains(rec, "raw_parts") {
		t.Fatalf("raw parts outside model_turns:\n%s\n%s", rec, res)
	}
	// The counter survives the restart: the next turn is 1.
	d2, a2 := begin(t, s2)
	if err := s2.SavePending(ctx, turnPending(d2, uuid(), a2, conv, session), nil); err != nil {
		t.Fatal(err)
	}
	if got, err := s2.Pending(ctx, d2); err != nil || turnIndex(t, got) != 1 {
		t.Fatalf("next turn after restart: %v", err)
	}
}
