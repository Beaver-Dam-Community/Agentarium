//go:build integration

package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/store"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

// Run against an empty database; the test applies migrations/*.up.sql:
//
//	DATABASE_URL=postgres://... go test -tags integration ./packages/adapters/store/

var migrated sync.Once

func pool(t *testing.T) *pgxpool.Pool {
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
	migrated.Do(func() { migrate(t, p) })
	return p
}

// migrate applies every up migration once to an empty database.
func migrate(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
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
	files, _ := filepath.Glob("../../../migrations/*.up.sql")
	sort.Strings(files)
	if len(files) == 0 {
		t.Fatal("no migrations found")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func TestBeginIsIdempotentUnderConcurrency(t *testing.T) {
	s := &store.PG{Pool: pool(t)}
	d, a := uuid(), uuid()
	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			row, c, err := s.Begin(context.Background(), d, a, "evidence-reader")
			if err != nil {
				t.Error(err)
				return
			}
			if row.State != execute.StateReceived || row.ActionID != a {
				t.Errorf("row %+v", row)
			}
			if c {
				mu.Lock()
				created++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if created != 1 {
		t.Fatalf("created %d rows", created)
	}
}

func TestSetStateCompareAndSet(t *testing.T) {
	s := &store.PG{Pool: pool(t)}
	ctx := context.Background()
	d, a, at := uuid(), uuid(), uuid()
	if _, _, err := s.Begin(ctx, d, a, "evidence-reader"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetState(ctx, d, []string{execute.StateReceived}, execute.StateReserved, ""); err == nil {
		t.Fatal("reserved without attempt_id accepted")
	}
	if ok, err := s.SetState(ctx, d, []string{execute.StateReceived}, execute.StateReserved, at); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, _ := s.SetState(ctx, d, []string{execute.StateReceived}, execute.StatePreflightRejected, ""); ok {
		t.Fatal("CAS from a stale state succeeded")
	}
	rows, err := s.Unfinished(ctx, "evidence-reader")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.DecisionID == d {
			found = r.State == execute.StateReserved && r.AttemptID == at
		}
	}
	if !found {
		t.Fatal("reserved row not listed as unfinished")
	}
	if _, err := s.SetState(ctx, d, []string{execute.StateReserved}, "done", ""); err == nil {
		t.Fatal("state outside the enum accepted")
	}
}

func dataClass(t *testing.T, p *pgxpool.Pool, where string, arg string) (string, []string, *string) {
	t.Helper()
	var c string
	var src []string
	var by *string
	if err := p.QueryRow(context.Background(), `SELECT data_class_high_water::text, data_sources, updated_by_attempt_id::text FROM adapter.workload_data_state WHERE `+where+` = $1`, arg).Scan(&c, &src, &by); err != nil {
		t.Fatal(err)
	}
	return c, src, by
}

func pending(d, at string) execute.PendingOutcome {
	return execute.PendingOutcome{DecisionID: d, AttemptID: at, Transition: execute.TransitionFailed, ReasonCodes: []string{"TARGET_UNAVAILABLE"},
		Observation: transport.Observation{AttemptID: at}}
}

func TestWorkloadDataStateNeverLowers(t *testing.T) {
	p := pool(t)
	s := &store.PG{Pool: p}
	ctx := context.Background()
	w := "workload-" + uuid()
	raise := func(class string) string {
		d, at := uuid(), uuid()
		if _, _, err := s.Begin(ctx, d, uuid(), "evidence-reader"); err != nil {
			t.Fatal(err)
		}
		if err := s.SavePending(ctx, pending(d, at), &execute.DataStateRaise{Key: execute.DataStateKey{WorkloadID: w}, DataClass: class, Source: "receiver-primary", AttemptID: at}); err != nil {
			t.Fatal(err)
		}
		return at
	}
	a1 := raise("internal")
	raise("synthetic")
	raise("none")
	c, src, by := dataClass(t, p, "workload_id", w)
	if c != "internal" || len(src) != 1 || src[0] != "receiver-primary" || by == nil || *by != a1 {
		t.Fatalf("class %s sources %v by %v", c, src, by)
	}
	a4 := raise("confidential")
	if c, _, by = dataClass(t, p, "workload_id", w); c != "confidential" || *by != a4 {
		t.Fatalf("class %s by %v", c, *by)
	}
	if _, err := p.Exec(ctx, `UPDATE adapter.workload_data_state SET data_class_high_water = 'none' WHERE workload_id = $1`, w); err == nil {
		t.Fatal("lowering accepted")
	}
	// Service session key is separate from workload keys.
	ss := uuid()
	d := uuid()
	if _, _, err := s.Begin(ctx, d, uuid(), "evidence-reader"); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePending(ctx, pending(d, uuid()), &execute.DataStateRaise{Key: execute.DataStateKey{ServiceSessionID: ss}, DataClass: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := dataClass(t, p, "service_session_id::text", ss); c != "synthetic" {
		t.Fatalf("service session class %s", c)
	}
	// A failed raise rolls the recovery record back with it.
	d2 := uuid()
	if _, _, err := s.Begin(ctx, d2, uuid(), "evidence-reader"); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePending(ctx, pending(d2, uuid()), &execute.DataStateRaise{DataClass: "internal"}); err == nil {
		t.Fatal("raise without key accepted")
	}
	if _, err := s.Pending(ctx, d2); err != execute.ErrNotFound {
		t.Fatalf("recovery record kept after a failed ①: %v", err)
	}
}

func TestPendingAndResult(t *testing.T) {
	p := pool(t)
	s := &store.PG{Pool: p}
	ctx := context.Background()
	d, a, at := uuid(), uuid(), uuid()
	if _, _, err := s.Begin(ctx, d, a, "evidence-reader"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	res := &execute.ActionResult{ActionID: a, AttemptID: at, ExecutionState: "accepted", DataClass: "none",
		ResultBody: json.RawMessage(`{"effect_id":"e1"}`), EvidenceLevel: "accepted", ResultDigest: strings.Repeat("b", 64), CreatedAt: now}
	po := execute.PendingOutcome{DecisionID: d, AttemptID: at, Transition: execute.TransitionResponseReceived, ReasonCodes: []string{},
		Observation: transport.Observation{AttemptID: at, ResponseAt: &now}, Result: res,
		Event: &execute.Event{Type: "response_received", ActionID: a, AttemptID: at, Payload: map[string]any{"status_code": 201}}}
	if err := s.SavePending(ctx, po, nil); err != nil {
		t.Fatal(err)
	}
	// A second record for the same decision keeps the first.
	other := po
	other.Transition, other.Result = execute.TransitionUnknown, nil
	if err := s.SavePending(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.Pending(ctx, d)
	if err != nil || got.Transition != execute.TransitionResponseReceived || got.Result == nil || got.Result.ExecutionState != "accepted" ||
		got.Event == nil || got.Event.Type != "response_received" || got.Observation.ResponseAt == nil {
		t.Fatalf("%+v %v", got, err)
	}
	for i := 0; i < 2; i++ {
		if err := s.InsertResult(ctx, *got.Result); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	var body string
	if err := p.QueryRow(ctx, `SELECT count(*), max(result_body::text) FROM adapter.action_results WHERE action_id = $1`, a).Scan(&n, &body); err != nil {
		t.Fatal(err)
	}
	if n != 1 || !strings.Contains(body, "e1") {
		t.Fatalf("results %d body %s", n, body)
	}
	if _, err := s.Pending(ctx, uuid()); err != execute.ErrNotFound {
		t.Fatalf("missing record: %v", err)
	}
	// response_received requires a result.
	d3 := uuid()
	if _, _, err := s.Begin(ctx, d3, uuid(), "evidence-reader"); err != nil {
		t.Fatal(err)
	}
	bad := po
	bad.DecisionID, bad.Result = d3, nil
	if err := s.SavePending(ctx, bad, nil); err == nil {
		t.Fatal("response_received record without result accepted")
	}
}

// Down then up again leaves a working schema. It runs in a database of its
// own so that tests of other packages sharing DATABASE_URL are not disturbed.
func TestMigrationDownUp(t *testing.T) {
	admin := pool(t)
	ctx := context.Background()
	name := "adapter_downup_" + strings.ReplaceAll(uuid()[:8], "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.Database = name
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	migrate(t, p)
	// The adapter migrations, newest first for down.
	versions := []string{"20261018115000_adapter_model_turns", "20261016110000_adapter_results"}
	read := func(name string) string {
		b, err := os.ReadFile("../../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, v := range versions {
		if _, err := p.Exec(ctx, read(v+".down.sql")); err != nil {
			t.Fatalf("%s down: %v", v, err)
		}
	}
	var exists bool
	if err := p.QueryRow(ctx, `SELECT to_regnamespace('adapter') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("schema still exists after down: %v", err)
	}
	for i := len(versions) - 1; i >= 0; i-- {
		if _, err := p.Exec(ctx, read(versions[i]+".up.sql")); err != nil {
			t.Fatalf("%s up: %v", versions[i], err)
		}
	}
	s := &store.PG{Pool: p}
	d := uuid()
	if _, created, err := s.Begin(ctx, d, uuid(), "model"); err != nil || !created {
		t.Fatalf("schema after down/up: %v", err)
	}
	if err := s.SavePending(ctx, turnPending(d, uuid(), uuid(), uuid(), uuid()), nil); err != nil {
		t.Fatalf("model turn after down/up: %v", err)
	}
}

func TestEventIDStoredOnce(t *testing.T) {
	s := &store.PG{Pool: pool(t)}
	ctx := context.Background()
	d := uuid()
	if _, _, err := s.Begin(ctx, d, uuid(), "evidence-reader"); err != nil {
		t.Fatal(err)
	}
	first, second := uuid(), uuid()
	for i, typ := range []string{"preflight_passed", "preflight_rejected"} {
		got, err := s.EventID(ctx, d, typ, first)
		if err != nil || got != first {
			t.Fatalf("%d: %s %v", i, got, err)
		}
		if got, err = s.EventID(ctx, d, typ, second); err != nil || got != first {
			t.Fatalf("%d: second call returned %s %v", i, got, err)
		}
	}
	if _, err := s.EventID(ctx, uuid(), "preflight_passed", first); err != execute.ErrNotFound {
		t.Fatalf("missing row: %v", err)
	}
	if _, err := s.EventID(ctx, d, "dispatch_started", first); err == nil {
		t.Fatal("unknown event type accepted")
	}
}
