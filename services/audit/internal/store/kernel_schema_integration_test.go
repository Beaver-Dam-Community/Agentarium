package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Real PostgreSQL migration compatibility test; never use a shared database.
func TestKernelWireSchemaPostgres(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable AUDIT_TEST_ADMIN_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	dbname, installer, writer := "kernelwire_"+suffix, "kwinstall_"+suffix, "kwwriter_"+suffix
	exec := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatalf("SQL: %v\n%s", err, q)
		}
	}
	createdGroups := []string{}
	for _, role := range []string{"audit_owner", "audit_producer", "audit_writer", "audit_exporter", "gateway_app"} {
		var exists bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			createdGroups = append(createdGroups, role)
		}
	}
	exec(admin, "CREATE ROLE "+installer+" LOGIN NOSUPERUSER NOCREATEDB CREATEROLE")
	exec(admin, "CREATE ROLE "+writer+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	exec(admin, "CREATE DATABASE "+dbname+" OWNER "+installer)
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+dbname+" WITH (FORCE)")
		_, _ = admin.Exec(context.Background(), "DROP ROLE "+writer)
		for _, role := range createdGroups {
			_, _ = admin.Exec(context.Background(), "DROP ROLE "+role)
		}
		_, _ = admin.Exec(context.Background(), "DROP ROLE "+installer)
	}()
	// Existing group roles belong to other fixture installations. Give only the
	// installer ADMIN option required by the merged migration's temporary grants.
	for _, role := range []string{"audit_owner", "audit_producer"} {
		var exists bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			exec(admin, "GRANT "+role+" TO "+installer+" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
		}
	}
	connect := func(user string) *pgx.Conn {
		t.Helper()
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Database, cfg.User = dbname, user
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	install, fixture := connect(installer), connect(admin.Config().User)
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("../../../../migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	exec(install, read("20261016132230_audit_store.up.sql"))
	exec(fixture, "GRANT audit_writer TO "+writer)
	runtime := connect(writer)
	var super, ownerSet bool
	if err := install.QueryRow(ctx, `SELECT rolsuper,pg_has_role(current_user,'audit_owner','SET') FROM pg_roles WHERE rolname=current_user`).Scan(&super, &ownerSet); err != nil || super || ownerSet {
		t.Fatalf("installer privilege leaked: %v %v %v", super, ownerSet, err)
	}
	node := uuid.New()
	stamp := time.Date(2026, 10, 17, 1, 2, 3, 456789000, time.UTC)
	insert := `INSERT INTO audit.kernel_events(source_event_id,source_id,sensor_id,source_epoch,source_sequence,exporter_instance_id,sensor_generation,node_uid,boot_id,source_time,spooled_at,received_at,event_type,process_exec_id,sock_ptr,tcp_new_state,metadata_status,normalization_version,rule_hash,coverage,safe_attributes,record_digest)
 VALUES($1,'source-test','source-test','epoch-test',$2,'exporter-test',1,$3,'boot-test',$4,$4,$4,$5,$6,$7,1,'complete','v1',repeat('a',64),'test','{"original":true}',repeat('b',64))`
	nullID := uuid.New()
	exec(fixture, insert, nullID, 1, node, stamp, "process_exec", "exec-id", nil)
	for i, value := range []int64{0, 1, -1, -9223372036854775808, 9223372036854775807} {
		exec(fixture, insert, uuid.New(), i+2, node, stamp, "tcp_state", "legacy-exec", value)
	}
	snapshot := func() string {
		t.Helper()
		var v string
		if err := fixture.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(k) ORDER BY source_sequence)::text FROM audit.kernel_events k`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	metadata := func() (string, string) {
		t.Helper()
		var indexes, grants string
		if err := fixture.QueryRow(ctx, `SELECT string_agg(indexname||':'||indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='audit' AND tablename='kernel_events'`).Scan(&indexes); err != nil {
			t.Fatal(err)
		}
		if err := fixture.QueryRow(ctx, `SELECT relowner::text||':'||coalesce(relacl::text,'') FROM pg_class WHERE oid='audit.kernel_events'::regclass`).Scan(&grants); err != nil {
			t.Fatal(err)
		}
		return indexes, grants
	}
	checkTypes := func(want string, wantNotNull bool) {
		t.Helper()
		var typ string
		var notNull bool
		if err := fixture.QueryRow(ctx, `SELECT format_type(a.atttypid,a.atttypmod),b.attnotnull FROM pg_attribute a JOIN pg_attribute b ON b.attrelid=a.attrelid AND b.attname='process_exec_id' WHERE a.attrelid='audit.kernel_events'::regclass AND a.attname='sock_ptr'`).Scan(&typ, &notNull); err != nil || typ != want || notNull != wantNotNull {
			t.Fatalf("schema type=%s notnull=%v err=%v", typ, notNull, err)
		}
	}
	before := snapshot()
	indexes, grants := metadata()
	checkTypes("bigint", true)
	up := read("20261017103710_audit_kernel_wire.up.sql")
	blocker, err := fixture.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `LOCK TABLE audit.kernel_events IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = install.Exec(ctx, up)
	elapsed := time.Since(started)
	var lockErr *pgconn.PgError
	if !errors.As(err, &lockErr) || lockErr.Code != "55P03" {
		t.Fatalf("expected bounded migration lock refusal: %v", err)
	}
	if elapsed < 1800*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("migration lock timeout took %s, want approximately 2s", elapsed)
	}
	exec(install, "ROLLBACK")
	if snapshot() != before {
		t.Fatal("lock timeout changed original rows or digests")
	}
	checkTypes("bigint", true)
	if i, g := metadata(); i != indexes || g != grants {
		t.Fatal("lock timeout changed indexes or grants")
	}
	if err := install.QueryRow(ctx, `SELECT pg_has_role(current_user,'audit_owner','SET')`).Scan(&ownerSet); err != nil || ownerSet {
		t.Fatalf("lock timeout retained owner SET: %v %v", ownerSet, err)
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = install.Exec(ctx, up)
	var legacyErr *pgconn.PgError
	if !errors.As(err, &legacyErr) || legacyErr.Code != "55000" {
		t.Fatalf("expected explicit legacy-pointer refusal: %v", err)
	}
	exec(install, "ROLLBACK")
	if after := snapshot(); after != before {
		t.Fatal("failed migration changed original rows or digests")
	}
	checkTypes("bigint", true)
	if i, g := metadata(); i != indexes || g != grants {
		t.Fatal("failed migration changed indexes or grants")
	}
	// Test-only removal models a new/empty deployment. Production legacy rows
	// require their own preservation plan; the migration never deletes them.
	exec(fixture, `DELETE FROM audit.kernel_events WHERE sock_ptr IS NOT NULL`)
	legacyNull := snapshot()
	exec(install, up)
	// The fixture seeded bigint through a cached prepared statement before DDL.
	// A restarted consumer discovers the new text type; refresh that metadata.
	if err := fixture.DeallocateAll(ctx); err != nil {
		t.Fatal(err)
	}
	checkTypes("text", false)
	if after := snapshot(); after != legacyNull {
		t.Fatal("NULL-pointer legacy row, IDs, timestamps or digest changed")
	}
	if i, g := metadata(); i != indexes || g != grants {
		t.Fatal("migration changed index definitions, owner or grants")
	}
	if err := install.QueryRow(ctx, `SELECT pg_has_role(current_user,'audit_owner','SET')`).Scan(&ownerSet); err != nil || ownerSet {
		t.Fatalf("migration retained owner SET: %v %v", ownerSet, err)
	}
	for i, value := range []any{nil, "0000000000000000", "0000000000000001", "7fffffffffffffff", "8000000000000000", "ffffffffffffffff"} {
		exec(fixture, insert, uuid.New(), i+100, node, stamp, "tcp_state", nil, value)
	}
	exec(fixture, insert, uuid.New(), 200, node, stamp, "process_exec", "exec-new", nil)
	for i, kind := range []string{"process_exec", "process_exit", "tcp_connect", "file_open", "openat"} {
		_, err := fixture.Exec(ctx, insert, uuid.New(), i+300, node, stamp, kind, nil, nil)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "23514" {
			t.Fatalf("null %s process accepted: %v", kind, err)
		}
	}
	for i, value := range []string{"0", "FFFFFFFFFFFFFFFF", "0xffffffffffffffff", "gggggggggggggggg", "fffffffffffffffff", ""} {
		_, err := fixture.Exec(ctx, insert, uuid.New(), i+400, node, stamp, "tcp_state", nil, value)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "23514" {
			t.Fatalf("invalid pointer %q: %v", value, err)
		}
	}
	var match int
	if err := fixture.QueryRow(ctx, `SELECT count(*) FROM audit.kernel_events WHERE node_uid=$1 AND boot_id='boot-test' AND sock_ptr='ffffffffffffffff' AND source_time=$2 AND process_exec_id IS NULL`, node, stamp).Scan(&match); err != nil || match != 1 {
		t.Fatalf("high-bit pointer lookup: %d %v", match, err)
	}
	exec(fixture, `SET enable_seqscan=off`)
	var plan string
	if err := fixture.QueryRow(ctx, `EXPLAIN (FORMAT JSON) SELECT source_event_id FROM audit.kernel_events WHERE node_uid=$1 AND boot_id='boot-test' AND sock_ptr='ffffffffffffffff' AND source_time=$2`, node, stamp).Scan(&plan); err != nil || !strings.Contains(plan, "kernel_events_sock") {
		t.Fatalf("socket index unavailable: %s %v", plan, err)
	}
	for _, q := range []string{`INSERT INTO audit.kernel_events(source_event_id) VALUES(gen_random_uuid())`, `UPDATE audit.kernel_events SET process_exec_id='tampered'`, `DELETE FROM audit.kernel_events`, `CREATE TABLE audit.forbidden(n integer)`} {
		_, err := runtime.Exec(ctx, q)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("runtime privilege denial missing: %s %v", q, err)
		}
	}
	durable := snapshot()
	if _, err := install.Exec(ctx, read("20261017103710_audit_kernel_wire.down.sql")); err == nil {
		t.Fatal("down truncated nullable/full-width pointer evidence")
	}
	exec(install, "ROLLBACK")
	if snapshot() != durable {
		t.Fatal("down changed persisted evidence")
	}
	checkTypes("text", false)
	if i, g := metadata(); i != indexes || g != grants {
		t.Fatal("down changed indexes or grants")
	}
	t.Run("required_tcp_state", func(t *testing.T) {
		up := read("20261017113838_audit_kernel_tcp_state.up.sql")
		down := read("20261017113838_audit_kernel_tcp_state.down.sql")
		stateInsert := strings.Replace(insert, "$7,1,", "$7,$8,", 1)
		legacyID := uuid.New()
		exec(fixture, stateInsert, legacyID, 1000, node, stamp, "tcp_state", nil, nil, nil)
		before := snapshot()
		checkPreserved := func() {
			t.Helper()
			if snapshot() != before {
				t.Fatal("constraint migration changed original records or digests")
			}
			if i, g := metadata(); i != indexes || g != grants {
				t.Fatal("constraint migration changed indexes, ownership or grants")
			}
			if err := install.QueryRow(ctx, `SELECT pg_has_role(current_user,'audit_owner','SET')`).Scan(&ownerSet); err != nil || ownerSet {
				t.Fatalf("constraint migration retained owner SET: %v %v", ownerSet, err)
			}
		}
		checkConstraint := func(want bool) {
			t.Helper()
			var present bool
			if err := fixture.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_constraint WHERE conrelid='audit.kernel_events'::regclass AND conname='kernel_events_tcp_state_required' AND convalidated)`).Scan(&present); err != nil || present != want {
				t.Fatalf("validated TCP state constraint=%v want %v: %v", present, want, err)
			}
		}
		// A blocked installation must fail promptly and leave data/ACLs unchanged.
		blocker, err := fixture.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(context.Background())
		if _, err := blocker.Exec(ctx, `LOCK TABLE audit.kernel_events IN ACCESS SHARE MODE`); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, err = install.Exec(ctx, up)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55P03" {
			t.Fatalf("expected lock timeout: %v", err)
		}
		if elapsed := time.Since(start); elapsed < 1800*time.Millisecond || elapsed > 5*time.Second {
			t.Fatalf("unexpected lock wait: %v", elapsed)
		}
		exec(install, "ROLLBACK")
		checkPreserved()
		checkConstraint(false)
		if err := blocker.Rollback(ctx); err != nil {
			t.Fatal(err)
		}

		// Preexisting malformed evidence is not silently repaired or deleted.
		_, err = install.Exec(ctx, up)
		if !errors.As(err, &pe) || pe.Code != "55000" {
			t.Fatalf("expected legacy state refusal: %v", err)
		}
		exec(install, "ROLLBACK")
		checkPreserved()
		checkConstraint(false)
		// Test-only cleanup models an installation with no malformed legacy evidence.
		exec(fixture, `DELETE FROM audit.kernel_events WHERE source_event_id=$1`, legacyID)
		before = snapshot()
		exec(install, up)
		checkPreserved()
		checkConstraint(true)

		for i, state := range []int16{1, 7} {
			exec(fixture, stateInsert, uuid.New(), 1100+i, node, stamp, "tcp_state", nil, "ffffffffffffffff", state)
		}
		for i, kind := range []string{"process_exec", "process_exit", "tcp_connect", "file_open", "openat"} {
			exec(fixture, stateInsert, uuid.New(), 1200+i, node, stamp, kind, "exec-id", nil, nil)
		}
		before = snapshot()
		for _, q := range []string{
			`UPDATE audit.kernel_events SET tcp_new_state=NULL WHERE event_type='tcp_state'`,
			`UPDATE audit.kernel_events SET event_type='tcp_state' WHERE source_sequence=1200`,
		} {
			_, err := fixture.Exec(ctx, q)
			if !errors.As(err, &pe) || pe.Code != "23514" || pe.ConstraintName != "kernel_events_tcp_state_required" {
				t.Fatalf("invalid state update accepted: %v", err)
			}
		}
		_, err = fixture.Exec(ctx, stateInsert, uuid.New(), 1300, node, stamp, "tcp_state", nil, nil, nil)
		if !errors.As(err, &pe) || pe.Code != "23514" || pe.ConstraintName != "kernel_events_tcp_state_required" {
			t.Fatalf("null TCP state insert accepted: %v", err)
		}
		checkPreserved()

		// Down removes only this constraint. Reapplying up validates retained rows.
		exec(install, down)
		checkPreserved()
		checkConstraint(false)
		exec(install, up)
		checkPreserved()
		checkConstraint(true)
	})

}
