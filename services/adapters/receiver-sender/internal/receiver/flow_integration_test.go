//go:build integration

package receiver_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/store"
)

// End to end with the Postgres store (DATABASE_URL, empty database; the test
// applies migrations/*.up.sql when the adapter schema is missing).

var migrateOnce sync.Once

func pgStore(t *testing.T) (*store.PG, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	migrateOnce.Do(func() {
		// Test packages run in parallel against one database: serialize.
		conn, err := p.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(20261016110000)`); err != nil {
			t.Fatal(err)
		}
		defer conn.Exec(ctx, `SELECT pg_advisory_unlock(20261016110000)`)
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT to_regclass('adapter.adapter_executions') IS NOT NULL`).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			return
		}
		files, _ := filepath.Glob("../../../../../migrations/*.up.sql")
		sort.Strings(files)
		for _, f := range files {
			b, _ := os.ReadFile(f)
			if _, err := conn.Exec(ctx, string(b)); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	})
	return &store.PG{Pool: p}, p
}

func state(t *testing.T, p *pgxpool.Pool, d string) (st, attempt string) {
	t.Helper()
	var a *string
	if err := p.QueryRow(context.Background(), `SELECT state, attempt_id::text FROM adapter.adapter_executions WHERE decision_id = $1`, d).Scan(&st, &a); err != nil {
		t.Fatal(err)
	}
	if a != nil {
		attempt = *a
	}
	return st, attempt
}

func TestPGAcceptedAndDataClass(t *testing.T) {
	s, p := pgStore(t)
	h := newHarness(t, withResponseClass("internal"))
	h.useStore(s)
	d, a := h.action(okPayload)
	if _, _, err := h.engine.Submit(context.Background(), d, a); err != nil {
		t.Fatal(err)
	}
	h.engine.Wait()
	st, attempt := state(t, p, d)
	if st != execute.StateCompleted || h.recv.count.Load() != 1 {
		t.Fatalf("state %s sends %d", st, h.recv.count.Load())
	}
	var es, ev, dc string
	if err := p.QueryRow(context.Background(), `SELECT execution_state, evidence_level, data_class::text FROM adapter.action_results WHERE attempt_id = $1`, attempt).Scan(&es, &ev, &dc); err != nil {
		t.Fatal(err)
	}
	if es != "accepted" || ev != "accepted" || dc != "internal" {
		t.Fatalf("result %s %s %s", es, ev, dc)
	}
	var hw string
	if err := p.QueryRow(context.Background(), `SELECT data_class_high_water::text FROM adapter.workload_data_state WHERE workload_id = 'agent-runtime-0'`).Scan(&hw); err != nil {
		t.Fatal(err)
	}
	if hw != "internal" && hw != "confidential" {
		t.Fatalf("high-water %s", hw)
	}
}

func TestPGConcurrentExecuteOneSend(t *testing.T) {
	s, p := pgStore(t)
	h := newHarness(t)
	h.useStore(s)
	d, a := h.action(okPayload)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := h.engine.Submit(context.Background(), d, a); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	h.engine.Wait()
	if st, _ := state(t, p, d); st != execute.StateCompleted || h.coord.reservations != 1 || h.recv.count.Load() != 1 {
		t.Fatalf("state %s reservations %d sends %d", st, h.coord.reservations, h.recv.count.Load())
	}
}

// Crash between ① and ②: the outcome is not delivered; after restart the
// recovery record finishes ②–④ once, with one result and one send.
func TestPGRestartAfterRaise(t *testing.T) {
	s, p := pgStore(t)
	h := newHarness(t, withResponseClass("synthetic"))
	h.useStore(s)
	h.coord.mu.Lock()
	h.coord.failOutcome["response_received"] = 100
	h.coord.mu.Unlock()
	d, a := h.action(okPayload)
	if _, _, err := h.engine.Submit(context.Background(), d, a); err != nil {
		t.Fatal(err)
	}
	h.engine.Wait()
	st, attempt := state(t, p, d)
	if st != execute.StateReserved {
		t.Fatalf("state %s", st)
	}
	h.coord.mu.Lock()
	h.coord.failOutcome["response_received"] = 0
	h.coord.mu.Unlock()
	h.useStore(s) // a new process
	if err := h.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ := state(t, p, d); st != execute.StateCompleted {
		t.Fatalf("after restart: %s", st)
	}
	var n int
	if err := p.QueryRow(context.Background(), `SELECT count(*) FROM adapter.action_results WHERE action_id = $1`, a).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 || h.recv.count.Load() != 1 || !slices.Equal(h.coord.transitions(), []string{"dispatched", "response_received"}) {
		t.Fatalf("results %d sends %d transitions %v attempt %s", n, h.recv.count.Load(), h.coord.transitions(), attempt)
	}
}

func TestPGPreflightRejected(t *testing.T) {
	s, p := pgStore(t)
	h := newHarness(t)
	h.useStore(s)
	d, a := h.action(okPayload)
	h.mutate(d, func(in *execute.Inputs) { in.Content.ContentBytes = []byte(`{"email":null,"summary":"changed"}`) })
	if _, _, err := h.engine.Submit(context.Background(), d, a); err != nil {
		t.Fatal(err)
	}
	h.engine.Wait()
	if st, _ := state(t, p, d); st != execute.StatePreflightRejected || h.recv.count.Load() != 0 || h.coord.reservations != 0 {
		t.Fatalf("state %s", st)
	}
}

// flakyResults fails the first InsertResult: a crash after the audit append
// and before ③.
type flakyResults struct {
	*store.PG
	fail int
}

func (f *flakyResults) InsertResult(ctx context.Context, r execute.ActionResult) error {
	if f.fail > 0 {
		f.fail--
		return context.DeadlineExceeded
	}
	return f.PG.InsertResult(ctx, r)
}

// The recovery record round-trips through jsonb: the replayed outcome is
// byte-identical (the coordinator answers 2xx) and the event keeps its ID.
func TestPGReplayKeepsEventID(t *testing.T) {
	s, p := pgStore(t)
	h := newHarness(t)
	h.useStore(&flakyResults{PG: s, fail: 1})
	d, a := h.action(okPayload)
	if _, _, err := h.engine.Submit(context.Background(), d, a); err != nil {
		t.Fatal(err)
	}
	h.engine.Wait()
	if st, _ := state(t, p, d); st != execute.StateReserved {
		t.Fatalf("state %s", st)
	}
	var stored string
	if err := p.QueryRow(context.Background(), `SELECT event->>'EventID' FROM adapter.pending_outcomes WHERE decision_id = $1`, d).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	h.useStore(s) // a new process
	if err := h.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ := state(t, p, d); st != execute.StateCompleted || h.recv.count.Load() != 1 {
		t.Fatalf("state %s sends %d", st, h.recv.count.Load())
	}
	var ids []string
	for _, ev := range h.audit.events {
		if ev.Type == "response_received" {
			ids = append(ids, ev.EventID)
		}
	}
	if len(ids) != 2 || ids[0] != stored || ids[1] != stored {
		t.Fatalf("event ids %v, stored %s", ids, stored)
	}
}
