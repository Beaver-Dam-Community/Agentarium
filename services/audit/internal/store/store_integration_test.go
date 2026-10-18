package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The supplied admin DSN MUST point at a disposable local test cluster.
func TestPostgres(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_TEST_ADMIN_DSN for real PostgreSQL integration")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	suffix := uuid.NewString()[:8]
	dbname := "audit_test_" + suffix
	writer := "audit_writer_" + suffix
	producer := "audit_producer_" + suffix
	other := "audit_other_" + suffix
	gateway := "audit_gateway_" + suffix
	migrator := "audit_migrator_" + suffix
	exec := func(c *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("SQL failed: %v", err)
		}
	}
	exec(admin, "CREATE ROLE "+migrator+" LOGIN CREATEROLE NOSUPERUSER")

	// PostgreSQL roles are cluster-wide; another integration database may have
	// created them first. Grant only installer ADMIN, not runtime SET/inheritance.
	for _, role := range []string{"audit_owner", "audit_producer"} {
		var exists bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)", role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			exec(admin, "GRANT "+role+" TO "+migrator+" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
		}
	}
	exec(admin, "CREATE DATABASE "+dbname+" OWNER "+migrator)
	cfg, _ := pgx.ParseConfig(dsn)
	cfg.Database = dbname
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close(ctx)
		_, _ = admin.Exec(ctx, "DROP DATABASE "+dbname+" WITH (FORCE)")
		_, _ = admin.Exec(ctx, "REVOKE audit_producer FROM audit_writer GRANTED BY "+migrator)
		for _, role := range []string{writer, producer, other, gateway, migrator} {
			_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+role)
		}
	}()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../../../..")
	paths, err := filepath.Glob(filepath.Join(root, "migrations/*_audit_store.up.sql"))
	if err != nil || len(paths) != 1 {
		t.Fatal("migration not found")
	}
	migration, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	migrationCfg := cfg.Copy()
	migrationCfg.User = migrator
	migrationDB, err := pgx.ConnectConfig(ctx, migrationCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationDB.Close(ctx)
	exec(migrationDB, string(migration))
	var canSet, superuser bool
	if err := migrationDB.QueryRow(ctx, "SELECT pg_has_role(current_user,'audit_owner','SET'), rolsuper FROM pg_roles WHERE rolname=current_user").Scan(&canSet, &superuser); err != nil || canSet || superuser {
		t.Fatalf("migration left owner privilege: set=%v superuser=%v err=%v", canSet, superuser, err)
	}
	for _, role := range []string{writer, producer, other, gateway} {
		exec(admin, "CREATE ROLE "+role+" LOGIN")
	}
	exec(db, "GRANT audit_writer TO "+writer)
	exec(db, "GRANT audit_producer TO "+producer)
	exec(db, "GRANT audit_producer TO "+other)
	exec(db, "GRANT gateway_app TO "+gateway)
	exec(db, "INSERT INTO audit.db_role_sources VALUES ($1,NULL,true),($2,'source-a',false),($3,'source-b',false)", writer, producer, other)
	exec(db, "INSERT INTO audit.producer_event_grants VALUES ('source-a','approval_revoked','tenant-a'),('source-b','approval_revoked','tenant-a')")
	userPool := func(user string) *pgxpool.Pool {
		t.Helper()
		pc, _ := pgxpool.ParseConfig(dsn)
		pc.ConnConfig.Database = dbname
		pc.ConnConfig.User = user
		p, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	wp := userPool(writer)
	pp := userPool(producer)
	op := userPool(other)
	gp := userPool(gateway)
	s := Store{Pool: wp}
	event := func() ([]byte, ingest.Event) {
		t.Helper()
		e := ingest.Event{EventID: uuid.NewString(), EventType: "approval_revoked", Tenant: "tenant-a", SourceID: "source-a", SourceVersion: "v1", SourceEpoch: "epoch-1", SourceTime: "2026-10-15T00:00:00Z", SchemaVersion: 1, EvidenceRefs: []json.RawMessage{}, SafePayload: map[string]json.RawMessage{"approval_id": json.RawMessage(`"approval-1"`), "revoke_reason": json.RawMessage(`"user"`)}}
		return signed(t, e)
	}

	t.Run("decision_input_outbox", func(t *testing.T) {
		digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		query := "SELECT audit.enqueue_decision_input($1::char(64),$2::integer)"
		tx, err := gp.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, query, digest, 123); err != nil {
			t.Fatal(err)
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var count, size int
		if err = db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_outbox WHERE record_id=$1", digest).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rollback count=%d err=%v", count, err)
		}
		for range 2 {
			if _, err = gp.Exec(ctx, query, digest, 123); err != nil {
				t.Fatal(err)
			}
		}
		if err = db.QueryRow(ctx, "SELECT count(*),max(record_bytes) FROM audit.audit_outbox WHERE record_kind='decision_input' AND destination='gcs_decision_inputs' AND source_class='decision_input' AND state='pending' AND record_id=$1", digest).Scan(&count, &size); err != nil || count != 1 || size != 123 {
			t.Fatalf("outbox count=%d size=%d err=%v", count, size, err)
		}
		for _, p := range []*pgxpool.Pool{pp, wp, op} {
			if _, err = p.Exec(ctx, query, digest, 123); !errors.Is(classify(err), ingest.ErrForbidden) {
				t.Fatalf("non-gateway execute: %v", err)
			}
		}
		for _, q := range []string{"SELECT * FROM audit.audit_outbox", "INSERT INTO audit.audit_outbox(record_id) VALUES('x')", "SELECT audit._authorize_source('source-a')"} {
			if _, err = gp.Exec(ctx, q); !errors.Is(classify(err), ingest.ErrForbidden) {
				t.Fatalf("gateway base/private access: %v", err)
			}
		}
		for _, args := range [][]any{{nil, 123}, {"bad", 123}, {digest, nil}, {digest, 0}, {digest, -1}} {
			if _, err = gp.Exec(ctx, query, args...); !errors.Is(classify(err), ingest.ErrSchema) {
				t.Fatalf("invalid input accepted: %v", err)
			}
		}
	})
	t.Run("nul_is_schema_error", func(t *testing.T) {
		_, e := event()
		e.SafePayload["revoke_reason"] = json.RawMessage(`"nul\u0000value"`)
		raw, e := signed(t, e)
		if _, err := s.Append(ctx, e, raw); !errors.Is(err, ingest.ErrSchema) {
			t.Fatalf("NUL error: %v", err)
		}
	})
	t.Run("commit_duplicate_conflict", func(t *testing.T) {
		raw, e := event()
		ack, err := s.Append(ctx, e, raw)
		if err != nil || ack.Result != "created" {
			t.Fatalf("%+v %v", ack, err)
		}
		again, err := s.Append(ctx, e, raw)
		if err != nil || again.Result != "duplicate" || !again.ReceivedAt.Equal(ack.ReceivedAt) {
			t.Fatalf("%+v %v", again, err)
		}
		e.SafePayload["revoke_reason"] = json.RawMessage(`"changed"`)
		raw, e = signed(t, e)
		conflict, err := s.Append(ctx, e, raw)
		if err != nil || conflict.Result != "conflict" {
			t.Fatalf("%+v %v", conflict, err)
		}
		var count int
		_ = db.QueryRow(ctx, "SELECT count(*) FROM audit.event_conflicts WHERE record_id=$1", e.EventID).Scan(&count)
		if count != 1 {
			t.Fatal("conflict not durable")
		}
		_ = db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_outbox WHERE record_id=$1", e.EventID).Scan(&count)
		if count != 1 {
			t.Fatal("outbox not exactly once")
		}
	})
	t.Run("permissions_and_spoofing", func(t *testing.T) {
		raw, e := event()
		var result string
		if err := pp.QueryRow(ctx, "SELECT audit.audit_append($1::jsonb,ARRAY['gcs'])", raw).Scan(&result); err != nil || result != "created" {
			t.Fatalf("direct producer %s %v", result, err)
		}
		if _, err := op.Exec(ctx, "SELECT audit.audit_append($1::jsonb,ARRAY['gcs'])", raw); err == nil {
			t.Fatal("source spoof allowed")
		}
		for _, query := range []string{"SELECT * FROM audit.audit_events", "UPDATE audit.audit_events SET tenant='x'", "DELETE FROM audit.audit_events", "CREATE TABLE audit.evil(x int)", "SELECT audit._authorize_source('source-a')", "SELECT audit.audit_event_ack('" + e.EventID + "','source-a','tenant-a')"} {
			if _, err := pp.Exec(ctx, query); err == nil {
				t.Fatalf("producer allowed %s", query)
			}
		}
		if _, err := wp.Exec(ctx, "SELECT * FROM audit.audit_events"); err == nil {
			t.Fatal("writer base SELECT allowed")
		}
		if _, err := wp.Exec(ctx, "SELECT audit.audit_event_ack($1,'source-a','other-tenant')", e.EventID); err == nil {
			t.Fatal("ack crossed tenant")
		}
		if _, err := pp.Exec(ctx, "INSERT INTO audit.audit_events(event_id) VALUES(gen_random_uuid())"); err == nil {
			t.Fatal("direct insert allowed")
		}
	})
	t.Run("atomic_rollback", func(t *testing.T) {
		raw, e := event()
		tx, err := pp.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, "SELECT audit.audit_append($1::jsonb,ARRAY['gcs'])", raw); err != nil {
			t.Fatal(err)
		}
		_ = tx.Rollback(ctx)
		var count int
		_ = db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE event_id=$1", e.EventID).Scan(&count)
		if count != 0 {
			t.Fatal("event survived rollback")
		}
		_ = db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_outbox WHERE record_id=$1", e.EventID).Scan(&count)
		if count != 0 {
			t.Fatal("outbox survived rollback")
		}
	})
	t.Run("parallel_retry", func(t *testing.T) {
		raw, e := event()
		results := make(chan string, 16)
		errs := make(chan error, 16)
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() { ack, err := s.Append(ctx, e, raw); errs <- err; results <- ack.Result })
		}
		wg.Wait()
		close(results)
		close(errs)
		created := 0
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		for result := range results {
			if result == "created" {
				created++
			} else if result != "duplicate" {
				t.Fatal(result)
			}
		}
		if created != 1 {
			t.Fatalf("created=%d", created)
		}
	})
	t.Run("invalid_and_ungranted", func(t *testing.T) {
		for _, kind := range []string{"digest", "missing_payload", "registry", "storage_table", "tenant", "server_time", "destinations"} {
			t.Run(kind, func(t *testing.T) {
				_, e := event()
				switch kind {
				case "missing_payload":
					delete(e.SafePayload, "approval_id")
				case "registry":
					e.EventType = "unknown"
				case "storage_table":
					e.EventType = "kernel_event_observed"
				case "tenant":
					e.Tenant = "tenant-b"
				}
				raw, e := signed(t, e)
				if kind == "digest" {
					raw = bytes.Replace(raw, []byte(`"source_version":"v1"`), []byte(`"source_version":"v2"`), 1)
				}
				if kind == "server_time" {
					raw = bytes.Replace(raw, []byte(`"tenant"`), []byte(`"received_at":"2020-01-01T00:00:00Z","tenant"`), 1)
				}
				dest := "gcs"
				if kind == "destinations" {
					dest = "gcs_decision_inputs"
				}
				if _, err := pp.Exec(ctx, "SELECT audit.audit_append($1::jsonb,ARRAY[$2]::text[])", raw, dest); err == nil {
					t.Fatal("accepted invalid input")
				}
				var count int
				_ = db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE event_id=$1", e.EventID).Scan(&count)
				if count != 0 {
					t.Fatal("invalid event persisted")
				}
			})
		}
	})
	t.Run("cross_source_id_collision", func(t *testing.T) {
		raw, e := event()
		if _, err := s.Append(ctx, e, raw); err != nil {
			t.Fatal(err)
		}
		e.SourceID = "source-b"
		raw, e = signed(t, e)
		_, err := s.Append(ctx, e, raw)
		if !errors.Is(err, ingest.ErrForbidden) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("canonical_crosscheck", func(t *testing.T) {
		for _, raw := range []string{`{"\ue000":0,"😀":1,"a":"x\n\t\b\f\r\"\\","n":-9007199254740991}`, `{"z":[null,true,false,{},[]],"a":9007199254740991}`, `{"한글":"값","x":-0}`} {
			want, err := canonical.JCS([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			var got string
			if err := db.QueryRow(ctx, "SELECT audit._canonical_json($1::jsonb)", raw).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("SQL %s Go %s", got, want)
			}
		}
	})
	t.Run("live_registration", func(t *testing.T) {
		exec(db, "DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$")
		identity, err := os.ReadFile(filepath.Join(root, "migrations/20261014144500_identity_workload_pki.up.sql"))
		if err != nil {
			t.Fatal(err)
		}
		exec(db, string(identity))
		exec(db, "GRANT USAGE ON SCHEMA identity TO audit_writer; GRANT SELECT ON identity.registered_workloads TO audit_writer")
		exec(db, "INSERT INTO identity.registered_workloads(namespace,ksa,role,service_principal,enabled) VALUES ('agent-control','coordinator','service','coordinator',true)")
		auth, err := NewAuthorizer(wp, []SourceBinding{{SourceID: "source-a", Namespace: "agent-control", KSA: "coordinator", Principal: "coordinator"}})
		if err != nil {
			t.Fatal(err)
		}
		san := "spiffe://agentarium.internal/ns/agent-control/sa/coordinator"
		if err := auth.Authorize(ctx, san, "source-a"); err != nil {
			t.Fatal(err)
		}
		if err := auth.Authorize(ctx, san, "source-b"); !errors.Is(err, ingest.ErrForbidden) {
			t.Fatal("unbound source allowed")
		}
		t.Run("mutual_tls_to_committed_event", func(t *testing.T) {
			testMutualTLSPostgres(t, s, auth, db, event)
		})
		t.Run("work_events_mutual_tls", func(t *testing.T) {
			testWorkEventsPostgres(t, s, db)
		})
		exec(db, "UPDATE identity.registered_workloads SET enabled=false")
		if err := auth.Authorize(ctx, san, "source-a"); !errors.Is(err, ingest.ErrForbidden) {
			t.Fatal("disabled source allowed")
		}
	})
	t.Run("down_up", func(t *testing.T) {
		down, err := os.ReadFile(paths[0][:len(paths[0])-6] + "down.sql")
		if err != nil {
			t.Fatal(err)
		}
		exec(migrationDB, string(down))
		exec(migrationDB, string(migration))
	})
}
func signed(t *testing.T, e ingest.Event) ([]byte, ingest.Event) {
	t.Helper()
	raw, _ := json.Marshal(e)
	digest, err := canonical.PayloadDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	e.PayloadDigest = digest
	raw, _ = json.Marshal(e)
	return raw, e
}
