package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func testDispatchLocks(t *testing.T, ctx context.Context, migrator, admin *pgx.Conn, cfg *pgx.ConnConfig, root string) {
	t.Helper()
	run := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, direction := range []string{"up", "down", "up"} {
		raw, err := os.ReadFile(filepath.Join(root, "migrations/20261017073602_health_dispatch_locks."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		run(migrator, string(raw))
		var elevated bool
		if err := migrator.QueryRow(ctx, "SELECT pg_has_role(current_user,'health_owner','USAGE') OR pg_has_role(current_user,'health_owner','SET')").Scan(&elevated); err != nil || elevated {
			t.Fatalf("migration leaked owner: %v %v", elevated, err)
		}
	}
	login := "dispatch_lock_" + uuid.NewString()[:8]
	run(admin, "CREATE ROLE "+login+" LOGIN")
	defer func() {
		// The test creates a TEMP shadow table owned by this login. Explicitly
		// remove test-owned objects/grants after its connection has closed.
		if _, err := admin.Exec(ctx, "DROP OWNED BY "+login); err != nil {
			t.Errorf("cleanup owned objects: %v", err)
		}
		if _, err := admin.Exec(ctx, "DROP ROLE "+login); err != nil {
			t.Errorf("cleanup reader role: %v", err)
		}
	}()
	run(admin, "GRANT coordinator_reader TO "+login)
	readerCfg := cfg.Copy()
	readerCfg.User = login
	reader, err := pgx.ConnectConfig(ctx, readerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close(ctx)
	expectCode := func(err error, code string) {
		t.Helper()
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != code {
			t.Fatalf("want %s, got %v", code, err)
		}
	}
	node, other, session, service := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	ids := []string{}
	for _, row := range [][3]string{{"global", "*", "open"}, {"node", node, "open"}, {"workload", "locks-workload", "open"}, {"target", "locks-target", "open"}, {"session", session, "open"}, {"session", service, "open"}, {"node", other, "open"}, {"node", node, "released"}} {
		id := uuid.NewString()
		ids = append(ids, id)
		run(admin, "INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by,released_at,release_ref) VALUES($1,$2,$3,'sensor_degraded','control-health','test',CASE WHEN $4='released' THEN now() END,CASE WHEN $4='released' THEN 'test' END)", id, row[0], row[1], row[2])
	}
	defer func() {
		_, _ = admin.Exec(ctx, "DELETE FROM health.holds WHERE hold_id=ANY($1::uuid[])", ids)
		_, _ = admin.Exec(ctx, "DELETE FROM health.node_boot_generation WHERE node_uid=ANY($1::uuid[])", []string{node, other})
	}()
	run(admin, "INSERT INTO health.node_boot_generation VALUES($1,'current',2,3,'unsupported','ready',now(),'not_measured'),($1,'old',1,1,'unsupported','retired',now(),'not_measured')", node)
	// SELECT alone cannot take row locks or modify tables; functions remain the only locking path.
	_, err = reader.Exec(ctx, "SELECT * FROM health.holds FOR SHARE")
	expectCode(err, "42501")
	_, err = reader.Exec(ctx, "UPDATE health.holds SET reason='db_unavailable' WHERE false")
	expectCode(err, "42501")
	_, err = reader.Exec(ctx, "UPDATE health.node_boot_generation SET state='ready' WHERE false")
	expectCode(err, "42501")
	tx, err := reader.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT * FROM health.lock_dispatch_holds($1,$2,$3,$4,$5)", node, "locks-workload", "locks-target", session, service)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for rows.Next() {
		var id, reason string
		if err := rows.Scan(&id, &reason); err != nil {
			t.Fatal(err)
		}
		got[id] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 {
		t.Fatalf("matched %d holds", len(got))
	}
	for _, id := range ids[:6] {
		if !got[id] {
			t.Fatalf("missing %s", id)
		}
	}
	var boot, state string
	var sensor, guard int64
	if err := tx.QueryRow(ctx, "SELECT * FROM health.lock_dispatch_node($1)", node).Scan(&boot, &sensor, &guard, &state); err != nil || boot != "current" || sensor != 2 || guard != 3 || state != "ready" {
		t.Fatalf("node result %s %d %d %s %v", boot, sensor, guard, state, err)
	}
	run(admin, "SET lock_timeout='100ms'")
	_, err = admin.Exec(ctx, "UPDATE health.holds SET released_at=now(),release_ref='release' WHERE hold_id=$1", ids[0])
	expectCode(err, "55P03")
	_, err = admin.Exec(ctx, "UPDATE health.node_boot_generation SET state='held' WHERE node_uid=$1 AND boot_id='current'", node)
	expectCode(err, "55P03")
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	run(admin, "UPDATE health.holds SET released_at=now(),release_ref='release' WHERE hold_id=$1", ids[0])
	run(admin, "UPDATE health.node_boot_generation SET state='held' WHERE node_uid=$1 AND boot_id='current'", node)
	run(admin, "RESET lock_timeout")
	_, err = reader.Exec(ctx, "SELECT * FROM health.lock_dispatch_holds(NULL,'',NULL,NULL,NULL)")
	expectCode(err, "22023")
	_, err = reader.Exec(ctx, "SELECT * FROM health.lock_dispatch_node(NULL)")
	expectCode(err, "22023")
	var count int
	if err := reader.QueryRow(ctx, "SELECT count(*) FROM health.lock_dispatch_node($1)", other).Scan(&count); err != nil || count != 0 {
		t.Fatalf("missing node=%d %v", count, err)
	}
	run(admin, "INSERT INTO health.node_boot_generation VALUES($1,'ambiguous',1,1,'unsupported','preparing',now(),'not_measured')", node)
	if err := reader.QueryRow(ctx, "SELECT count(*) FROM health.lock_dispatch_node($1)", node).Scan(&count); err != nil || count != 2 {
		t.Fatalf("must expose ambiguity to caller: %d %v", count, err)
	}
	// Writer can read health data but is not a function caller. TEMP objects cannot shadow the source.
	run(admin, "REVOKE coordinator_reader FROM "+login)
	run(admin, "GRANT control_health_writer TO "+login)
	_, err = reader.Exec(ctx, "SELECT * FROM health.lock_dispatch_node($1)", node)
	expectCode(err, "42501")
	run(admin, "REVOKE control_health_writer FROM "+login)
	run(admin, "GRANT coordinator_reader TO "+login)
	run(reader, "CREATE TEMP TABLE node_boot_generation(node_uid uuid,boot_id text,sensor_generation bigint,guard_generation bigint,state text)")
	run(reader, "INSERT INTO node_boot_generation VALUES('"+other+"','forged',1,1,'ready')")
	if err := reader.QueryRow(ctx, "SELECT count(*) FROM health.lock_dispatch_node($1)", other).Scan(&count); err != nil || count != 0 {
		t.Fatalf("temp object shadowed health: %d %v", count, err)
	}
}
