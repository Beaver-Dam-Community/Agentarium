package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	export "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/export"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestExportAcknowledgementPostgres(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx := context.Background()
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close(ctx)
	name := "export_verify_" + uuid.NewString()[:8]
	run := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, e := c.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	run(admin, "CREATE DATABASE "+name)
	cfg, e := pgx.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.Database = name
	db, e := pgx.ConnectConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { db.Close(ctx); _, _ = admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)") }()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../../../..")
	paths, e := filepath.Glob(filepath.Join(root, "migrations/*_audit_store.up.sql"))
	if e != nil || len(paths) != 1 {
		t.Fatal("missing audit migration")
	}
	migration, e := os.ReadFile(paths[0])
	if e != nil {
		t.Fatal(e)
	}
	run(db, string(migration))
	id := "61041562-9572-4f87-a24c-f4842fe35177"
	object := "abcd/business/2026-10-16/" + id + ".ndjson"
	ref := object + "#123"
	run(db, "INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state) VALUES ('audit_event','event-a','gcs','business',20,'pending'),('audit_event','event-b','gcs','business',20,'pending')")
	run(db, "INSERT INTO audit.export_batches(batch_id,destination,source_class,object_key) VALUES ($1,'gcs','business',$2)", id, object)
	run(db, "INSERT INTO audit.export_batch_members(batch_id,ordinal,record_kind,record_id,destination) VALUES ($1,1,'audit_event','event-a','gcs'),($1,2,'audit_event','event-b','gcs')", id)
	run(db, "SET ROLE audit_exporter")
	checker := export.PGAcks{Queries: auditdb.New(db), Destination: "gcs"}
	if e = checker.Check(ctx, id, ref, 2); e == nil {
		t.Fatal("pending rows passed")
	}
	run(db, "UPDATE audit.audit_outbox SET state='acked',ack_ref=$1 WHERE record_id='event-a'", ref)
	if e = checker.Check(ctx, id, ref, 2); e == nil {
		t.Fatal("partial batch passed")
	}
	run(db, "UPDATE audit.audit_outbox SET state='acked',ack_ref=$1", ref)
	if e = checker.Check(ctx, id, ref, 2); e != nil {
		t.Fatal(e)
	}
	if e = checker.Check(ctx, id, object+"#124", 2); e == nil {
		t.Fatal("wrong generation passed")
	}
	if e = checker.Check(ctx, id, ref, 1); e == nil {
		t.Fatal("missing member passed")
	}
	if e = (export.PGAcks{Queries: auditdb.New(db), Destination: "gcs_decision_inputs"}).Check(ctx, id, ref, 2); e == nil {
		t.Fatal("wrong chain passed")
	}
	if e = checker.Check(ctx, uuid.NewString(), ref, 2); e == nil {
		t.Fatal("missing batch passed")
	}
}
