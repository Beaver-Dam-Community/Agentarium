package export

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 20261018091801: manifest and intent created_at are DB-assigned
// and immutable, and the exporter cannot name the column at all.
func TestManifestTimesAreDBAssignedPostgres(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx := context.Background()
	db, cfg := installAllMigrations(t, ctx, dsn)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("SQL: %v", err)
		}
	}
	login := "mt_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	exec("CREATE ROLE " + login + " LOGIN INHERIT NOSUPERUSER")
	exec("GRANT audit_exporter TO " + login)
	pc, err := pgxpool.ParseConfig(cfg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.Database, pc.ConnConfig.User = cfg.Database, login
	exporter, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	lease := &PGLease{Pool: exporter, Holder: "time-test"}
	token, err := lease.Acquire(ctx, "gcs")
	if err != nil {
		t.Fatal(err)
	}
	batch := uuid.NewString()
	exec("INSERT INTO audit.export_batches(batch_id,destination,source_class,object_key) VALUES($1,'gcs','business',$2)", batch, "k/"+batch)
	forged := []string{
		"INSERT INTO audit.manifest_intents(chain_id,manifest_seq,batch_id,fencing_token,created_at) VALUES('gcs',1,$1,$2,now()-interval '40 days')",
		"INSERT INTO audit.export_manifests(chain_id,manifest_seq,object_generation,batch_digest,manifest_digest,kms_key_version,signature,manifest_object_key,fencing_token,created_at) VALUES('gcs',1,1,repeat('a',64),repeat('b',64),'k','\\x01','manifests/1.json',$2,now()-interval '40 days')",
	}
	for _, q := range forged {
		if _, err := exporter.Exec(ctx, q, batch, token); err == nil {
			t.Fatalf("exporter supplied created_at: %s", q)
		}
	}
	if _, err := exporter.Exec(ctx, "INSERT INTO audit.manifest_intents(chain_id,manifest_seq,batch_id,fencing_token) VALUES('gcs',1,$1,$2)", batch, token); err != nil {
		t.Fatal(err)
	}
	if _, err := exporter.Exec(ctx, "UPDATE audit.manifest_intents SET created_at=now()-interval '40 days'"); err == nil {
		t.Fatal("exporter updated created_at")
	}
	// Even a superuser INSERT gets the DB time, and an UPDATE is refused.
	exec("INSERT INTO audit.export_manifests(chain_id,manifest_seq,object_generation,batch_digest,manifest_digest,kms_key_version,signature,manifest_object_key,fencing_token,created_at) VALUES('gcs',1,1,repeat('a',64),repeat('b',64),'k','\\x01','manifests/1.json',$1,now()-interval '40 days')", token)
	var age time.Duration
	var intentAge time.Duration
	if err := db.QueryRow(ctx, `SELECT extract(epoch FROM clock_timestamp()-m.created_at)*interval '1 second', extract(epoch FROM clock_timestamp()-i.created_at)*interval '1 second'
		FROM audit.export_manifests m JOIN audit.manifest_intents i USING(chain_id,manifest_seq)`).Scan(&age, &intentAge); err != nil || age > time.Minute || intentAge > time.Minute {
		t.Fatalf("forged created_at stored: manifest %s intent %s %v", age, intentAge, err)
	}
	for _, q := range []string{"UPDATE audit.export_manifests SET created_at=now()-interval '40 days'", "UPDATE audit.manifest_intents SET created_at=now()-interval '40 days'"} {
		if _, err := db.Exec(ctx, q); err == nil {
			t.Fatalf("created_at changed: %s", q)
		}
	}
}
