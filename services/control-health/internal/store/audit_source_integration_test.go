//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAuditSourceCurrentBootPostgres(t *testing.T) {
	dsn := os.Getenv("HEALTH_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable HEALTH_TEST_ADMIN_DSN")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	suffix := uuid.NewString()[:8]
	dbName, installer, writer, owner, outsider := "healthsrc_"+suffix, "hsrcinst_"+suffix, "hsrcwriter_"+suffix, "hsrcowner_"+suffix, "hsrcdeny_"+suffix
	exec := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []string{installer, writer, owner, outsider} {
		exec(admin, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	}
	exec(admin, "ALTER ROLE "+pgx.Identifier{installer}.Sanitize()+" CREATEROLE")
	// Repeated runs may find owner group roles from a prior disposable DB.
	// Supply only their installation-time ADMIN option, with no runtime SET or
	// inherited ownership. Each migration must still grant/revoke its own SET.
	for _, role := range []string{"audit_owner", "audit_producer", "health_owner"} {
		var exists bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)", role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			exec(admin, "GRANT "+pgx.Identifier{role}.Sanitize()+" TO "+pgx.Identifier{installer}.Sanitize()+" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
		}
	}
	exec(admin, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()+" OWNER "+pgx.Identifier{installer}.Sanitize())
	defer func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
		_, _ = admin.Exec(ctx, "REVOKE audit_producer FROM audit_writer GRANTED BY "+pgx.Identifier{installer}.Sanitize())
		for _, role := range []string{writer, owner, outsider, installer} {
			if _, err := admin.Exec(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Errorf("cleanup role %s: %v", role, err)
			}
		}
	}()
	connect := func(user string) *pgx.Conn {
		t.Helper()
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Database, cfg.User = dbName, user
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	db := connect(installer)
	migration := func(name string) {
		t.Helper()
		raw, err := os.ReadFile("../../../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		exec(db, string(raw))
	}
	migration("20261016132230_audit_store.up.sql")
	migration("20261016132231_health_control_health.up.sql")
	up, down := "20261017002500_health_audit_source_current_boot.up.sql", "20261017002500_health_audit_source_current_boot.down.sql"
	assertInstaller := func() {
		t.Helper()
		var set, inherit, super bool
		var current string
		if err := db.QueryRow(ctx, `SELECT pg_has_role(current_user,'health_owner','SET'),pg_has_role(current_user,'health_owner','USAGE'),rolsuper,current_user FROM pg_roles WHERE rolname=current_user`).Scan(&set, &inherit, &super, &current); err != nil {
			t.Fatal(err)
		}
		if set || inherit || super || current != installer {
			t.Fatalf("installer privileges leaked: %v %v %v %s", set, inherit, super, current)
		}
	}
	assertInstaller()
	migration(up)
	assertInstaller()
	fixture := connect(admin.Config().User)
	exec(fixture, "GRANT audit_writer TO "+pgx.Identifier{writer}.Sanitize())
	exec(fixture, "GRANT audit_owner TO "+pgx.Identifier{owner}.Sanitize())
	// Give the denied caller schema visibility so rejection proves EXECUTE isolation.
	exec(fixture, "GRANT USAGE ON SCHEMA health TO "+pgx.Identifier{outsider}.Sanitize())
	caller, ownerCaller, denied := connect(writer), connect(owner), connect(outsider)
	node, other := uuid.NewString(), uuid.NewString()
	exec(fixture, `INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,state,updated_at) VALUES ($1,'current','unsupported','preparing',now()),($1,'old','unsupported','retired',now()),($2,'other','guarded','held',now())`, node, other)
	hold := uuid.NewString()
	exec(fixture, `INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by) VALUES ($1,'node',$2,'sensor_degraded','control-health','fixture')`, hold, node)
	read := func(c *pgx.Conn, uid, boot any) bool {
		t.Helper()
		var got bool
		if err := c.QueryRow(ctx, `SELECT health.audit_source_current_boot($1,$2)`, uid, boot).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, state := range []string{"preparing", "ready", "held"} {
		exec(fixture, `UPDATE health.node_boot_generation SET state=$2 WHERE node_uid=$1 AND boot_id='current'`, node, state)
		for _, c := range []*pgx.Conn{caller, ownerCaller} {
			if !read(c, node, "current") {
				t.Fatalf("%s rejected", state)
			}
		}
	}
	for _, in := range []struct{ node, boot any }{{node, "old"}, {node, "other"}, {other, "current"}, {uuid.NewString(), "current"}, {nil, "current"}, {node, nil}, {node, ""}} {
		if read(caller, in.node, in.boot) {
			t.Fatalf("unknown or historical boot accepted: %+v", in)
		}
	}
	exec(fixture, `INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,state,updated_at) VALUES ($1,'ambiguous','unsupported','preparing',now())`, node)
	if read(caller, node, "current") || read(caller, node, "ambiguous") {
		t.Fatal("ambiguous current boot accepted")
	}
	exec(fixture, `UPDATE health.node_boot_generation SET state='retired' WHERE node_uid=$1 AND boot_id='ambiguous'`, node)
	if !read(caller, node, "current") {
		t.Fatal("unique current boot rejected")
	}
	exec(fixture, `UPDATE health.node_boot_generation SET state='retired' WHERE node_uid=$1 AND boot_id='current'`, node)
	if read(caller, node, "current") {
		t.Fatal("retired current accepted")
	}
	var released, unchanged bool
	if err := fixture.QueryRow(ctx, `SELECT released_at IS NOT NULL FROM health.holds WHERE hold_id=$1`, hold).Scan(&released); err != nil || released {
		t.Fatalf("hold changed: %v", err)
	}
	if err := fixture.QueryRow(ctx, `SELECT count(*)=4 FROM health.node_boot_generation`).Scan(&unchanged); err != nil || !unchanged {
		t.Fatalf("boot history changed: %v", err)
	}
	permissionDenied := func(c *pgx.Conn, q string) {
		t.Helper()
		_, err := c.Exec(ctx, q)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatalf("wanted permission denied for %s: %v", q, err)
		}
	}
	for _, c := range []*pgx.Conn{caller, ownerCaller} {
		for _, q := range []string{`SELECT * FROM health.node_boot_generation`, `SELECT * FROM health.holds`, `UPDATE health.holds SET released_at=now()`, `DELETE FROM health.node_boot_generation`, `CREATE TABLE health.forbidden(x int)`, `SET ROLE health_owner`} {
			permissionDenied(c, q)
		}
		exec(c, `CREATE TEMP TABLE node_boot_generation(node_uid uuid,boot_id text,state text)`)
		if !read(c, other, "other") {
			t.Fatal("temporary table changed qualified lookup")
		}
	}
	permissionDenied(denied, `SELECT health.audit_source_current_boot(NULL,NULL)`)
	var functionOwner string
	var definer bool
	var searchPath []string
	if err := fixture.QueryRow(ctx, `SELECT pg_get_userbyid(proowner),prosecdef,proconfig FROM pg_proc WHERE oid='health.audit_source_current_boot(uuid,text)'::regprocedure`).Scan(&functionOwner, &definer, &searchPath); err != nil {
		t.Fatal(err)
	}
	if functionOwner != "health_owner" || !definer || len(searchPath) != 1 || searchPath[0] != "search_path=pg_catalog, health, pg_temp" {
		t.Fatalf("unexpected function boundary: %s %v %v", functionOwner, definer, searchPath)
	}
	migration(down)
	assertInstaller()
	migration(up)
	assertInstaller()
	if !read(caller, other, "other") || read(caller, node, "current") {
		t.Fatal("down/up changed retained boot state")
	}
}
