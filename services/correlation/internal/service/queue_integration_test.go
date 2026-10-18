//go:build integration

package service

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real PostgreSQL exercises commit visibility and restart behavior. Source
// tables contain only the columns consumed by the scheduler; the full receiver
// suite separately installs every migration and validates real evidence writes.
func TestPendingInputsPostgres(t *testing.T) {
	dsn := os.Getenv("NETPOL_TEST_DSN")
	if dsn == "" {
		t.Skip("set disposable NETPOL_TEST_DSN")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	name := "queue_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE SCHEMA audit; CREATE SCHEMA correlation;
 CREATE TABLE audit.kernel_events(source_event_id uuid PRIMARY KEY,node_uid uuid NOT NULL,source_time timestamptz NOT NULL,received_at timestamptz NOT NULL);
 CREATE TABLE correlation.network_policy_records(record_id uuid PRIMARY KEY,node_uid uuid NOT NULL,source_time timestamptz NOT NULL,received_at timestamptz NOT NULL);
 DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='correlation_writer') THEN CREATE ROLE correlation_writer NOLOGIN; END IF; END $$;
 DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='audit_owner') THEN CREATE ROLE audit_owner NOLOGIN; END IF; END $$;
 GRANT USAGE ON SCHEMA audit,correlation TO correlation_writer;
 GRANT SELECT ON audit.kernel_events,correlation.network_policy_records TO correlation_writer;
 GRANT USAGE ON SCHEMA audit TO audit_owner;
 ALTER TABLE audit.kernel_events OWNER TO audit_owner;`)
	migration, err := os.ReadFile("../../../../migrations/20261018102001_correlation_pending_inputs.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	// Retained evidence predates trigger installation and must be backfilled.
	preexisting := uuid.New()
	exec(`INSERT INTO audit.kernel_events VALUES($1,$2,now()-interval '2 days',now()-interval '1 day')`, preexisting, uuid.New())
	exec(string(migration))
	backfill, err := os.ReadFile("../../../../migrations/20261018102002_correlation_pending_backfill.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(backfill))
	// The scheduler has only the runtime role's table grants.
	cfg.ConnConfig.RuntimeParams["role"] = "correlation_writer"
	runtime, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	now := time.Now().UTC().Truncate(time.Second)
	node, id := uuid.New(), uuid.New()
	insert := func(id uuid.UUID, at, received time.Time) {
		t.Helper()
		exec(`INSERT INTO audit.kernel_events VALUES($1,$2,$3,$4)`, id, node, at, received)
	}
	// Replayed spool input predates the former five-minute source-time window.
	txOwner, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = txOwner.Exec(ctx, "SET LOCAL ROLE audit_owner"); err != nil {
		t.Fatal(err)
	}
	if _, err = txOwner.Exec(ctx, `INSERT INTO audit.kernel_events VALUES($1,$2,$3,$4)`, id, node, now.Add(-10*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err = txOwner.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Another input was received during a service outage longer than --lookback.
	old := uuid.New()
	insert(old, now.Add(-24*time.Hour), now.Add(-23*time.Hour))
	q := &PoolQueue{Pool: runtime}
	pending, err := q.Pending(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	found := map[uuid.UUID]bool{}
	for _, e := range pending {
		if e.To.Sub(e.From) > time.Minute+2*Rewind {
			t.Fatalf("unbounded window %+v", e)
		}
		for _, i := range e.Inputs {
			found[i.ID] = true
		}
		if err := q.Complete(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if !found[id] || !found[old] || !found[preexisting] {
		t.Fatalf("lost replay or outage input %v", found)
	}
	// An old received_at is not a commit-order cursor: commit after an empty
	// scan must still make this input eligible.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	late := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO audit.kernel_events VALUES($1,$2,$3,$4)`, late, node, now.Add(-time.Hour), now.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	q = &PoolQueue{Pool: runtime}
	if rows, err := q.Pending(ctx, now); err != nil || len(rows) != 0 {
		t.Fatalf("uncommitted input %v %v", rows, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	q = &PoolQueue{Pool: runtime} // process restart, pending work remains durable
	pending, err = q.Pending(ctx, now)
	if err != nil || len(pending) != 1 || pending[0].Inputs[0].ID != late {
		t.Fatalf("late commit %v %v", pending, err)
	}
	// Leave the failed input unacknowledged; successful input stays excluded.
	q = &PoolQueue{Pool: runtime}
	pending, err = q.Pending(ctx, now)
	if err != nil || len(pending) != 1 {
		t.Fatalf("restart retry %v %v", pending, err)
	}
	if err := q.Complete(ctx, pending[0]); err != nil {
		t.Fatal(err)
	}
	// Completed nodes never consume a page of pending inputs.
	for i := 1; i <= queueNodes+2; i++ {
		n := uuid.UUID{}
		n[14] = byte(i >> 8)
		n[15] = byte(i)
		rid := uuid.New()
		exec(`INSERT INTO correlation.network_policy_records VALUES($1,$2,$3,$4)`, rid, n, now.Add(-time.Hour), now)
		if i <= queueNodes {
			exec(`DELETE FROM correlation.pending_inputs WHERE input_kind='netpol' AND input_id=$1`, rid)
		}
	}
	q = &PoolQueue{Pool: runtime}
	if rows, err := q.Pending(ctx, now); err != nil || len(rows) != 2 {
		t.Fatalf("starved later nodes %v %v", rows, err)
	}
	// Same queue instance revisits a failed short page without an empty tick.
	if rows, err := q.Pending(ctx, now); err != nil || len(rows) != 2 {
		t.Fatalf("empty tick after short page %v %v", rows, err)
	}
	if rows := os.Getenv("CORRELATION_QUEUE_LOAD_ROWS"); rows != "" {
		n, err := strconv.Atoi(rows)
		if err != nil || n < 1 {
			t.Fatal("invalid CORRELATION_QUEUE_LOAD_ROWS")
		}
		// Populate completed raw history without queue entries, as if its evaluations
		// had already succeeded. Only test setup disables the trigger.
		exec(`ALTER TABLE audit.kernel_events DISABLE TRIGGER correlation_enqueue`)
		exec(`INSERT INTO audit.kernel_events
   SELECT md5('history-'||i)::uuid, md5('node-'||(i%40))::uuid,
    now()-interval '1 day',now()-interval '1 day'
   FROM generate_series(1,$1::int) i`, n)
		exec(`ALTER TABLE audit.kernel_events ENABLE TRIGGER correlation_enqueue`)
		exec(`DELETE FROM correlation.pending_inputs`)
		for i := 0; i < 5; i++ {
			insert(uuid.New(), now.Add(-48*time.Hour), now.Add(-time.Hour))
		}
		exec(`ANALYZE audit.kernel_events; ANALYZE correlation.pending_inputs`)
		deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
		start := time.Now()
		got, err := (&PoolQueue{Pool: runtime}).Pending(deadline, now)
		cancel()
		if err != nil {
			t.Fatalf("pending with %d completed events: %v", n, err)
		}
		count := 0
		for _, e := range got {
			count += len(e.Inputs)
		}
		if count != 5 {
			t.Fatalf("expected five delayed inputs, got %d", count)
		}
		t.Logf("Pending: %d completed events, 40 nodes, 5 pending inputs: %s", n, time.Since(start))
	}

}
