//go:build integration

package sessions

import (
	"context"
	"os"
	"testing"
)

// TASK-03 work-start gate: identity.work_readiness_session_view.budget_available
// is true for a session without session_budgets rows (no budget limit), and
// for a session with rows only while at least one row is unexpired and
// unexhausted (migration 20261018090000_identity_readiness_budget_available).
func TestReadinessViewBudgetAvailable(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	cr, err := s.Create(ctx, alice, k8sRequest())
	if err != nil {
		t.Fatal(err)
	}
	available := func() bool {
		t.Helper()
		var b bool
		if err := pool.QueryRow(ctx, `SELECT budget_available FROM identity.work_readiness_session_view
WHERE session_id = $1`, cr.SessionID).Scan(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, cr.SessionID); err != nil {
			t.Fatal(err)
		}
	}

	// One valid row (written by Create from standing.k8s_read.v1).
	if !available() {
		t.Fatal("one valid row: budget_available false")
	}
	// A second row that is exhausted does not hide the valid one.
	exec(`INSERT INTO identity.session_budgets (session_id, standing_rule_id, max_actions, used_actions, expires_at)
VALUES ($1, 'standing.model_synthetic.v1', 1, 1, statement_timestamp() + interval '1 hour')`)
	if !available() {
		t.Fatal("valid and exhausted rows: budget_available false")
	}
	// Every row exhausted or expired.
	exec(`UPDATE identity.session_budgets SET expires_at = statement_timestamp() - interval '1 second'
WHERE session_id = $1 AND standing_rule_id = 'standing.k8s_read.v1'`)
	if available() {
		t.Fatal("expired and exhausted rows: budget_available true")
	}
	// No rows: the session has no budget limit.
	exec(`DELETE FROM identity.session_budgets WHERE session_id = $1`)
	if !available() {
		t.Fatal("no rows: budget_available false")
	}

	// The replaced view keeps its columns, reader grant and options.
	var cols string
	var granted bool
	var opts *string
	if err := pool.QueryRow(ctx, `
SELECT (SELECT string_agg(attname || ':' || format_type(atttypid, atttypmod), ',' ORDER BY attnum)
        FROM pg_attribute WHERE attrelid = c.oid AND attnum > 0 AND NOT attisdropped),
    has_table_privilege('control_health_writer', c.oid, 'SELECT'),
    array_to_string(c.reloptions, ',')
FROM pg_class c WHERE c.oid = 'identity.work_readiness_session_view'::regclass`).Scan(&cols, &granted, &opts); err != nil {
		t.Fatal(err)
	}
	const want = "session_id:uuid,tenant:text,claimed_workload_identity:text,workload_id:text,state:text," +
		"expires_at:timestamp with time zone,allowed_operation_ids:text[],budget_available:boolean"
	if cols != want || !granted || opts != nil {
		t.Fatalf("columns %s, control_health_writer SELECT %v, reloptions %v", cols, granted, opts)
	}

	// The down migration restores the original rule (no rows → false).
	down, err := os.ReadFile("../../../../migrations/20261018090000_identity_readiness_budget_available.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	var b bool
	if err := tx.QueryRow(ctx, `SELECT budget_available FROM identity.work_readiness_session_view
WHERE session_id = $1`, cr.SessionID).Scan(&b); err != nil {
		t.Fatal(err)
	}
	if b {
		t.Fatal("down migration: no rows still true")
	}
}
