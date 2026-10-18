package dispatch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// queryTx is a pgx.Tx whose Query records its arguments and answers with
// rows or err. Every other method is nil and panics if called.
type queryTx struct {
	pgx.Tx
	sql   string
	args  []any
	calls int
	rows  [][]any
	err   error
}

func (q *queryTx) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.calls++
	q.sql, q.args = sql, args
	if q.err != nil {
		return nil, q.err
	}
	return &fakeRows{rows: q.rows, i: -1}, nil
}

type fakeRows struct {
	pgx.Rows
	rows [][]any
	i    int
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT") }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Next() bool                                   { r.i++; return r.i < len(r.rows) }

func (r *fakeRows) Scan(dest ...any) error {
	row := r.rows[r.i]
	if len(dest) != len(row) {
		return fmt.Errorf("scan %d into %d", len(row), len(dest))
	}
	for i, d := range dest {
		switch d := d.(type) {
		case *string:
			*d = row[i].(string)
		case *int64:
			*d = row[i].(int64)
		default:
			return fmt.Errorf("dest %T", d)
		}
	}
	return nil
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code || e.Status != http.StatusServiceUnavailable {
		t.Fatalf("want 503 %s, got %v", code, err)
	}
}

func TestPGHealthLockHoldsNullsEmptyFields(t *testing.T) {
	const node, sess = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	for name, c := range map[string]struct {
		scope HoldScope
		want  []any
	}{
		"user": {HoldScope{NodeUID: node, WorkloadID: "agent-exec/agent-runtime", TargetID: "t1", SessionID: sess},
			[]any{node, "agent-exec/agent-runtime", "t1", sess, nil}},
		"service, no target": {HoldScope{NodeUID: node, ServiceSessionID: sess},
			[]any{node, nil, nil, nil, sess}},
		"all empty": {HoldScope{}, []any{nil, nil, nil, nil, nil}},
	} {
		tx := &queryTx{rows: [][]any{{"h1", "policy_activation"}, {"h2", "operator_stop"}}}
		holds, err := PGHealth{}.LockHolds(context.Background(), tx, c.scope)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fmt.Sprint(tx.args) != fmt.Sprint(c.want) {
			t.Errorf("%s: args %v, want %v", name, tx.args, c.want)
		}
		for i, a := range tx.args {
			if (c.want[i] == nil) != (a == nil) {
				t.Errorf("%s: arg %d is %#v", name, i, a)
			}
		}
		if !strings.Contains(tx.sql, "health.lock_dispatch_holds($1::uuid, $2::text, $3::text, $4::uuid, $5::uuid)") {
			t.Errorf("%s: sql %s", name, tx.sql)
		}
		if len(holds) != 2 || holds[0] != (Hold{"h1", "policy_activation"}) || holds[1] != (Hold{"h2", "operator_stop"}) {
			t.Errorf("%s: holds %+v", name, holds)
		}
	}
}

func TestPGHealthLockNodeBootRows(t *testing.T) {
	const node = "11111111-1111-4111-8111-111111111111"
	one := []any{"boot-1", int64(3), int64(4), "ready"}
	two := []any{"boot-2", int64(1), int64(1), "preparing"}

	tx := &queryTx{rows: [][]any{one}}
	nb, err := PGHealth{}.LockNodeBoot(context.Background(), tx, node)
	if err != nil || nb != (NodeBoot{BootID: "boot-1", SensorGeneration: 3, GuardGeneration: 4, State: "ready"}) {
		t.Fatalf("one row: %+v %v", nb, err)
	}
	if len(tx.args) != 1 || tx.args[0] != node || !strings.Contains(tx.sql, "health.lock_dispatch_node($1::uuid)") {
		t.Fatalf("one row: %s %v", tx.sql, tx.args)
	}

	if _, err := (PGHealth{}).LockNodeBoot(context.Background(), &queryTx{}, node); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no row: %v", err)
	}

	_, err = PGHealth{}.LockNodeBoot(context.Background(), &queryTx{rows: [][]any{one, two}}, node)
	wantCode(t, err, "CONTROL_HEALTH_UNAVAILABLE")

	tx = &queryTx{}
	_, err = PGHealth{}.LockNodeBoot(context.Background(), tx, "")
	wantCode(t, err, "CONTROL_HEALTH_UNAVAILABLE")
	if tx.calls != 0 {
		t.Fatal("empty node UID reached the database")
	}
}

func TestPGHealthErrors(t *testing.T) {
	ctx := context.Background()
	invalid := &pgconn.PgError{Code: "22023", Message: "empty hold selector"}
	_, err := PGHealth{}.LockHolds(ctx, &queryTx{err: invalid}, HoldScope{})
	wantCode(t, err, "CONTROL_HEALTH_UNAVAILABLE")
	_, err = PGHealth{}.LockNodeBoot(ctx, &queryTx{err: invalid}, "n")
	wantCode(t, err, "CONTROL_HEALTH_UNAVAILABLE")

	// A lock timeout inside a function survives the adapter and depErr, so
	// that inTx answers LOCK_TIMEOUT rather than CONTROL_HEALTH_UNAVAILABLE.
	timeout := &pgconn.PgError{Code: "55P03", Message: "canceling statement due to lock timeout"}
	_, err = PGHealth{}.LockHolds(ctx, &queryTx{err: timeout}, HoldScope{})
	var pgErr *pgconn.PgError
	if !errors.As(depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "holds"), &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("holds lock timeout: %v", err)
	}
	_, err = PGHealth{}.LockNodeBoot(ctx, &queryTx{err: timeout}, "n")
	if !errors.As(depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "node_boot_generation"), &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("node lock timeout: %v", err)
	}

	// Any other failure is CONTROL_HEALTH_UNAVAILABLE through depErr.
	_, err = PGHealth{}.LockHolds(ctx, &queryTx{err: &pgconn.PgError{Code: "42501"}}, HoldScope{})
	wantCode(t, depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "holds"), "CONTROL_HEALTH_UNAVAILABLE")

	if err := (PGHealth{}).CheckLeases(ctx, &queryTx{err: invalid}, "op", "t"); err == nil {
		t.Fatal("leases: query error ignored")
	}
	_, err = PGHealth{}.LockActivationHold(ctx, &queryTx{err: timeout}, "c")
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("activation hold lock timeout: %v", err)
	}
}

func TestPGHealthCheckLeases(t *testing.T) {
	ctx := context.Background()
	tx := &queryTx{}
	if err := (PGHealth{}).CheckLeases(ctx, tx, "receiver.submit", "receiver-primary"); err != nil {
		t.Fatalf("all live: %v", err)
	}
	if fmt.Sprint(tx.args) != fmt.Sprint([]any{DefaultRequiredGlobal, DefaultRequiredTarget, "receiver-primary"}) {
		t.Fatalf("default sets: %v", tx.args)
	}
	if !strings.Contains(tx.sql, "health.control_health_leases") || !strings.Contains(tx.sql, "l.lease_until > statement_timestamp()") ||
		!strings.Contains(tx.sql, "l.scope_id = r.scope_id") {
		t.Fatalf("sql %s", tx.sql)
	}

	// No target: no per-target component is required.
	tx = &queryTx{}
	if err := (PGHealth{}).CheckLeases(ctx, tx, "model.generate", ""); err != nil {
		t.Fatal(err)
	}
	if got := tx.args[1].([]string); len(got) != 0 {
		t.Fatalf("no target: per-target %v", got)
	}

	// Every missing lease is named; the reservation answers 503.
	tx = &queryTx{rows: [][]any{{"coordinator", "global"}, {"destination-evidence", "target"}}}
	err := PGHealth{}.CheckLeases(ctx, tx, "receiver.submit", "receiver-primary")
	wantCode(t, err, "CONTROL_HEALTH_UNAVAILABLE")
	if !strings.Contains(err.Error(), "global/coordinator, target/destination-evidence") {
		t.Fatalf("missing: %v", err)
	}

	// An installed profile's own sets replace the defaults.
	tx = &queryTx{}
	if err := (PGHealth{RequiredGlobal: []string{"gateway"}, RequiredTarget: []string{}}).CheckLeases(ctx, tx, "op", "t"); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(tx.args) != fmt.Sprint([]any{[]string{"gateway"}, []string{}, "t"}) {
		t.Fatalf("profile sets: %v", tx.args)
	}
}

func TestPGHealthLockActivationHold(t *testing.T) {
	ctx := context.Background()
	tx := &queryTx{rows: [][]any{{"h1", "operator_stop"}, {"h2", "policy_activation"}}}
	h, err := PGHealth{}.LockActivationHold(ctx, tx, "change-1")
	if err != nil || h != (Hold{"h2", "policy_activation"}) {
		t.Fatalf("open hold: %+v %v", h, err)
	}
	if len(tx.args) != 0 || !strings.Contains(tx.sql, "health.lock_dispatch_holds(NULL::uuid, NULL::text, NULL::text, NULL::uuid, NULL::uuid)") {
		t.Fatalf("global holds only: %s %v", tx.sql, tx.args)
	}
	if _, err := (PGHealth{}).LockActivationHold(ctx, &queryTx{rows: [][]any{{"h1", "operator_stop"}}}, "c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no activation hold: %v", err)
	}
}
