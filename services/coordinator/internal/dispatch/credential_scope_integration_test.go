//go:build integration

package dispatch

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// brokerQuery returns the named query from the TASK-06 broker's sqlc file,
// with sqlc.arg(name) replaced by $n in the order of args, so the test runs
// the broker's own SQL text.
func brokerQuery(t *testing.T, name string, args ...string) string {
	t.Helper()
	b, err := os.ReadFile("../../../credential-broker/sql/queries.sql")
	if err != nil {
		t.Fatal(err)
	}
	var q string
	for _, part := range strings.Split(string(b), "-- name: ")[1:] {
		head, body, _ := strings.Cut(part, "\n")
		if strings.Fields(head)[0] == name {
			q = strings.TrimSpace(body)
		}
	}
	if q == "" {
		t.Fatalf("query %s not found", name)
	}
	for i, a := range args {
		q = regexp.MustCompile(`sqlc\.arg\(`+a+`\)`).ReplaceAllString(q, "$$"+string(rune('1'+i)))
	}
	if strings.Contains(q, "sqlc.") {
		t.Fatalf("query %s has unreplaced arguments: %s", name, q)
	}
	return q
}

// brokerLogin creates a LOGIN role that is a member of broker_reader, the way
// the broker's Cloud SQL IAM user is, and connects as it.
func brokerLogin(t *testing.T, e *env) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	role, password := "broker_login_"+randHex(4), randHex(16)
	if _, err := e.admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+password+"' IN ROLE broker_reader"); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = role, password
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Close(context.Background())
		if _, err := e.admin.Exec(context.Background(), "DROP ROLE "+role); err != nil {
			t.Errorf("drop %s: %v", role, err)
		}
	})
	return conn
}

func applyMigration(t *testing.T, e *env, pattern string) {
	t.Helper()
	files, err := filepath.Glob("../../../../migrations/" + pattern)
	if err != nil || len(files) != 1 {
		t.Fatalf("migration %s: %v %v", pattern, files, err)
	}
	b, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(context.Background(), string(b)); err != nil {
		t.Fatalf("%s: %v", files[0], err)
	}
}

func TestAttemptCredentialScope(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	d := e.approval(t)
	p, err := e.svc.Reserve(ctx, e.adapter, reqFor(d))
	if err != nil {
		t.Fatal(err)
	}
	putAction(t, e, p.ActionID, "user", e.session, ptr("agent-exec/agent-runtime"))
	// Besides setup's agent-adapters/receiver-adapter: a second enabled KSA
	// for the same adapter, a disabled one, and a non-adapter workload.
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id, service_principal, enabled) VALUES
    ('agent-adapters', 'receiver-alias', 'adapter', 'receiver', NULL, true),
    ('other-ns', 'receiver-adapter', 'adapter', 'receiver', NULL, false),
    ('agent-adapters', 'receiver-service', 'service', NULL, 'receiver', true)`); err != nil {
		t.Fatal(err)
	}
	binding := "receiver-api-key-" + randHex(4)
	if _, err := e.admin.Exec(ctx, `INSERT INTO broker.credential_bindings VALUES
    ($1, 'receiver', 'receiver.submit', 'projects/123/secrets/synthetic', '7', 'Authorization', 'bearer', true, now(), 'fixture')`, binding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = e.admin.Exec(context.Background(), `DELETE FROM broker.credential_bindings WHERE credential_binding = $1`, binding)
	})
	broker := brokerLogin(t, e)

	checkPermissions := brokerQuery(t, "CheckPermissions")
	resolveBinding := brokerQuery(t, "ResolveBinding", "attempt_id", "namespace", "ksa", "binding", "adapter_id")
	ready := func() bool {
		t.Helper()
		var ok bool
		if err := broker.QueryRow(ctx, checkPermissions).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	resolve := func(ns, ksa string) error {
		var res, ver, header, format string
		return broker.QueryRow(ctx, resolveBinding, p.AttemptID, ns, ksa, binding, "receiver").Scan(&res, &ver, &header, &format)
	}
	// scope reads the view as the broker login and returns its rows as
	// "adapter_id/operation_id/state/namespace/ksa", checking the columns.
	scope := func() []string {
		t.Helper()
		rows, err := broker.Query(ctx, `SELECT * FROM coordinator.attempt_credential_scope WHERE attempt_id = $1
ORDER BY adapter_namespace, adapter_ksa`, p.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var cols []string
		for _, f := range rows.FieldDescriptions() {
			cols = append(cols, f.Name)
		}
		if got := strings.Join(cols, ","); got != "attempt_id,adapter_id,operation_id,state,adapter_namespace,adapter_ksa" {
			t.Fatalf("columns %s", got)
		}
		var out []string
		for rows.Next() {
			var id uuid.UUID
			var adapter, op, state, ns, ksa string
			if err := rows.Scan(&id, &adapter, &op, &state, &ns, &ksa); err != nil {
				t.Fatal(err)
			}
			if id.String() != p.AttemptID {
				t.Fatalf("attempt %s", id)
			}
			out = append(out, strings.Join([]string{adapter, op, state, ns, ksa}, "/"))
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	both := "receiver/receiver.submit/planned/agent-adapters/receiver-adapter,receiver/receiver.submit/planned/agent-adapters/receiver-alias"
	expect := func(want string) {
		t.Helper()
		if got := strings.Join(scope(), ","); got != want {
			t.Fatalf("scope:\n got %s\nwant %s", got, want)
		}
	}
	admin := func(sql string) {
		t.Helper()
		if _, err := e.admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}

	if !ready() {
		t.Fatal("CheckPermissions is false for the broker login")
	}
	expect(both)
	if err := resolve("agent-adapters", "receiver-adapter"); err != nil {
		t.Fatalf("ResolveBinding: %v", err)
	}
	if err := resolve("other-ns", "receiver-adapter"); err != pgx.ErrNoRows {
		t.Fatalf("ResolveBinding for a disabled registration: %v", err)
	}

	// Registration changes show on the next query.
	for _, change := range []struct{ name, apply string }{
		{"disabled", `UPDATE identity.registered_workloads SET enabled = false WHERE ksa = 'receiver-alias'`},
		{"role", `UPDATE identity.registered_workloads SET role = 'service', adapter_id = NULL, service_principal = 'x' WHERE ksa = 'receiver-alias'`},
		{"adapter_id", `UPDATE identity.registered_workloads SET adapter_id = 'model' WHERE ksa = 'receiver-alias'`},
	} {
		admin(change.apply)
		expect("receiver/receiver.submit/planned/agent-adapters/receiver-adapter")
		admin(`UPDATE identity.registered_workloads SET role = 'adapter', adapter_id = 'receiver', service_principal = NULL, enabled = true
WHERE ksa = 'receiver-alias'`)
		expect(both)
	}
	admin(`UPDATE identity.registered_workloads SET enabled = false WHERE namespace = 'agent-adapters' AND ksa = 'receiver-adapter'`)
	if err := resolve("agent-adapters", "receiver-adapter"); err != pgx.ErrNoRows {
		t.Fatalf("ResolveBinding after disabling the caller: %v", err)
	}
	admin(`UPDATE identity.registered_workloads SET enabled = true WHERE namespace = 'agent-adapters' AND ksa = 'receiver-adapter'`)

	// The broker reads only the view.
	for _, q := range []string{
		`SELECT 1 FROM coordinator.attempts LIMIT 1`,
		`SELECT 1 FROM coordinator.reservations LIMIT 1`,
		`SELECT 1 FROM decisions.actions LIMIT 1`,
		`SELECT 1 FROM identity.registered_workloads LIMIT 1`,
	} {
		var n int
		if err := broker.QueryRow(ctx, q).Scan(&n); pgCode(err) != "42501" {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := e.execRole(t, "gateway_app", `SELECT state FROM coordinator.attempt_credential_scope LIMIT 1`); pgCode(err) != "42501" {
		t.Fatalf("gateway_app reads the view: %v", err)
	}

	// down → up → down → up. After down the view and the coordinator USAGE
	// are gone; after up both are back without any conditional grant.
	for i := 0; i < 2; i++ {
		applyMigration(t, e, "*_coordinator_credential_scope.down.sql")
		var view, usage bool
		if err := e.admin.QueryRow(ctx, `SELECT to_regclass('coordinator.attempt_credential_scope') IS NOT NULL,
    has_schema_privilege('broker_reader', 'coordinator', 'USAGE')`).Scan(&view, &usage); err != nil || view || usage {
			t.Fatalf("after down: view=%v usage=%v %v", view, usage, err)
		}
		if err := resolve("agent-adapters", "receiver-adapter"); pgCode(err) != "42P01" && pgCode(err) != "42501" {
			t.Fatalf("ResolveBinding without the view: %v", err)
		}
		applyMigration(t, e, "*_coordinator_credential_scope.up.sql")
		if !ready() {
			t.Fatal("CheckPermissions is false after up")
		}
		expect(both)
		if err := resolve("agent-adapters", "receiver-adapter"); err != nil {
			t.Fatalf("ResolveBinding after up: %v", err)
		}
	}
}
