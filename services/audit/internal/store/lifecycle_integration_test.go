package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/netip"
	"net/url"
	"os"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This is a transaction-boundary fixture, NOT the lifecycle ingest SQL
// implementation. It deliberately creates no production lifecycle tables or
// grants and cannot establish watermark/gap/checkpoint correctness.
func TestLifecycleTransactionFixturePostgres(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable PostgreSQL admin DSN")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	suffix := uuid.NewString()[:8]
	name := "lifecycle_tx_" + suffix
	role := "lifecycle_writer_" + suffix
	exec := func(c *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(admin, "CREATE DATABASE "+name)
	exec(admin, "CREATE ROLE "+role+" LOGIN")
	defer func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		_, _ = admin.Exec(ctx, "DROP ROLE "+role)
	}()
	cfg, _ := pgx.ParseConfig(dsn)
	cfg.Database = name
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	exec(db, `CREATE SCHEMA audit; CREATE TABLE audit.tx_fixture (source text, marker int, UNIQUE(source,marker) DEFERRABLE INITIALLY DEFERRED);
 CREATE FUNCTION audit.ingest_lifecycle_batch(source_id text,batch jsonb,certificate_serial text,exact_san text,writer_version text,writer_epoch text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,audit AS $$
 BEGIN
   IF certificate_serial <> 'f' OR exact_san <> source_id OR writer_version <> 'fixture' OR writer_epoch <> 'fixture-receiver-epoch' THEN RAISE EXCEPTION 'wrong authentication arguments'; END IF;
   IF source_id='forbidden' THEN RAISE EXCEPTION 'forbidden' USING ERRCODE='42501'; END IF;
   INSERT INTO audit.tx_fixture VALUES(source_id,1);
   IF source_id='commit_failure' THEN INSERT INTO audit.tx_fixture VALUES(source_id,1); END IF;
   IF source_id='sql_failure' THEN RAISE EXCEPTION 'fixture failure'; END IF;
   IF source_id='constraint_failure' THEN RAISE EXCEPTION 'fixture constraint failure' USING ERRCODE='23514'; END IF;
   IF source_id='malformed_result' THEN RETURN '{}'::jsonb; END IF;
   RETURN jsonb_build_object('batch_id',batch->>'batch_id','accepted_ids',jsonb_build_array(batch->'records'->0->>'lifecycle_event_id'),
     'duplicate_ids','[]'::jsonb,'rejected','[]'::jsonb,'watermarks',jsonb_build_array(jsonb_build_object('source_epoch',batch->>'source_epoch','acked_through',1)), 'checkpoint',NULL);
 END $$;
 REVOKE ALL ON ALL TABLES IN SCHEMA audit FROM PUBLIC;
 REVOKE ALL ON FUNCTION audit.ingest_lifecycle_batch(text,jsonb,text,text,text,text) FROM PUBLIC;`)
	exec(db, "GRANT USAGE ON SCHEMA audit TO "+role)
	exec(db, "GRANT EXECUTE ON FUNCTION audit.ingest_lifecycle_batch(text,jsonb,text,text,text,text) TO "+role)
	pc, _ := pgxpool.ParseConfig(dsn)
	pc.ConnConfig.Database = name
	pc.ConnConfig.User = role
	pc.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := Store{Pool: pool, WriterVersion: "fixture", WriterEpoch: "fixture-receiver-epoch"}
	recordID, _ := canonical.LifecycleEventID("fixture-source", "epoch", 1)
	b := map[string]any{"batch_id": uuid.NewString(), "source_epoch": "epoch", "records": []any{map[string]any{"lifecycle_event_id": recordID, "source_id": "fixture-source", "source_epoch": "epoch", "source_sequence": 1}}, "sequence_range_abandoned": []any{}}
	digest, _ := canonical.CanonicalDigest(b)
	b["batch_digest"] = digest
	raw, _ := json.Marshal(b)
	envelope, err := ingest.DecodeLifecycleEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"success", "commit_failure", "sql_failure", "constraint_failure", "malformed_result", "forbidden"} {
		t.Run(source, func(t *testing.T) {
			ack, err := store.IngestLifecycle(ctx, ingest.LifecycleSource{SourceID: source, ExactSAN: source, CertificateSerial: "f"}, raw)
			if source == "success" {
				if err != nil || ingest.ValidateLifecycleAck(ack, envelope) != nil {
					t.Fatalf("ack: %s %v", ack, err)
				}
			} else if err == nil || ack != nil {
				t.Fatalf("failure acknowledged: %s %v", ack, err)
			}
			if source == "constraint_failure" && errors.Is(err, ingest.ErrSchema) {
				t.Fatal("storage constraint failure mislabeled as caller schema")
			}
			var count int
			if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.tx_fixture WHERE source=$1", source).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if source == "success" {
				want = 1
			}
			if count != want {
				t.Fatalf("committed rows=%d, want %d", count, want)
			}
		})
	}
	if _, err := pool.Exec(ctx, "SELECT * FROM audit.tx_fixture"); err == nil {
		t.Fatal("fixture writer unexpectedly has direct SELECT")
	}
	if _, err := pool.Exec(ctx, "INSERT INTO audit.tx_fixture VALUES('bypass',1)"); err == nil {
		t.Fatal("fixture writer unexpectedly has direct INSERT")
	}
	// Restricted helper fixtures exercise the Go adapter and NULL watcher node
	// behavior, not production certificate issuance or current-boot semantics.
	exec(db, `CREATE SCHEMA identity; CREATE SCHEMA health;
 CREATE TABLE identity.registered_workloads(namespace text,ksa text,role text,service_principal text,enabled boolean);
 INSERT INTO identity.registered_workloads VALUES ('agent-observe','pod-watcher','service','watcher',true),('agent-sensors','lifecycle-recorder','service','recorder',true);
 CREATE TABLE health.boot_fixture(active boolean); INSERT INTO health.boot_fixture VALUES(true);
 CREATE FUNCTION identity.audit_source_certificate(certificate_serial text, exact_san text,requested_boot_hash text)
 RETURNS TABLE(namespace text,ksa text,node_uid uuid,certificate_boot_id text,historical_boot_id text)
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT 'agent-observe'::text,'pod-watcher'::text,NULL::uuid,NULL::text,NULL::text WHERE certificate_serial='03' AND exact_san='spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher'
  UNION ALL SELECT 'agent-sensors','lifecycle-recorder','17d3e81e-65f8-462e-b681-670a14d57f88'::uuid,'boot',NULL WHERE certificate_serial='05' AND exact_san='spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder'
 $$;
 CREATE FUNCTION health.audit_source_current_boot(node_uid uuid,certificate_boot_id text) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT active AND node_uid='17d3e81e-65f8-462e-b681-670a14d57f88'::uuid AND certificate_boot_id='boot' FROM health.boot_fixture $$;
 CREATE FUNCTION audit.lifecycle_checkpoint(source_id text,scope text) RETURNS TABLE(scope text,resource_version text,committed_at timestamptz,checkpoint_revision bigint)
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT $2,'opaque-rv'::text,'2026-10-16T00:00:00Z'::timestamptz,7::bigint WHERE $1='spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher' AND $2='namespace/agent-exec' $$;
 REVOKE ALL ON ALL FUNCTIONS IN SCHEMA identity,health FROM PUBLIC;
 REVOKE ALL ON FUNCTION audit.lifecycle_checkpoint(text,text) FROM PUBLIC;`)
	exec(db, "GRANT USAGE ON SCHEMA identity,health TO "+role)
	exec(db, "GRANT SELECT ON identity.registered_workloads TO "+role)
	exec(db, "GRANT EXECUTE ON FUNCTION identity.audit_source_certificate(text,text,text),health.audit_source_current_boot(uuid,text),audit.lifecycle_checkpoint(text,text) TO "+role)
	auth, err := NewAuthorizer(pool, []SourceBinding{{SourceID: podWatcher, Namespace: "agent-observe", KSA: "pod-watcher", Principal: "watcher", Scopes: []string{"namespace/agent-exec"}}, {SourceID: lifecycleRecorder, Namespace: "agent-sensors", KSA: "lifecycle-recorder", Principal: "recorder"}})
	if err != nil {
		t.Fatal(err)
	}
	cert := func(serial int64, san string) *x509.Certificate {
		uri, _ := url.Parse(san)
		return &x509.Certificate{SerialNumber: big.NewInt(serial), URIs: []*url.URL{uri}}
	}
	watcher, err := auth.ResolveLifecycle(ctx, cert(3, podWatcher), netip.MustParseAddr("127.0.0.1"))
	if err != nil || watcher.Kind != "pod_watcher" || watcher.NodeUID != "" || watcher.BootID != "" {
		t.Fatalf("NULL-node watcher: %+v %v", watcher, err)
	}
	if _, err := auth.ResolveLifecycle(ctx, cert(9, podWatcher), netip.MustParseAddr("127.0.0.1")); !errors.Is(err, ingest.ErrForbidden) {
		t.Fatalf("unknown serial: %v", err)
	}
	if _, err := auth.ResolveLifecycle(ctx, cert(5, lifecycleRecorder), netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	exec(db, "UPDATE health.boot_fixture SET active=false")
	if _, err := auth.ResolveLifecycle(ctx, cert(5, lifecycleRecorder), netip.MustParseAddr("127.0.0.1")); !errors.Is(err, ingest.ErrForbidden) {
		t.Fatalf("stale boot: %v", err)
	}
	if _, err := auth.ResolveLifecycle(ctx, cert(3, podWatcher), netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatalf("watcher must not need host boot: %v", err)
	}
	result, err := store.LifecycleCheckpoint(ctx, podWatcher, "namespace/agent-exec")
	if err != nil || result.Revision != 7 || result.ResourceVersion != "opaque-rv" || result.CommittedAt.IsZero() {
		t.Fatalf("checkpoint: %+v %v", result, err)
	}
	if _, err := store.LifecycleCheckpoint(ctx, podWatcher, "namespace/missing"); !errors.Is(err, ingest.ErrLifecycleCheckpointNotFound) {
		t.Fatalf("missing checkpoint: %v", err)
	}
	exec(db, "UPDATE identity.registered_workloads SET enabled=false WHERE ksa='pod-watcher'")
	if _, err := auth.ResolveLifecycle(ctx, cert(3, podWatcher), netip.MustParseAddr("127.0.0.1")); !errors.Is(err, ingest.ErrForbidden) {
		t.Fatalf("disabled source: %v", err)
	}
	if _, err := pool.Exec(ctx, "SELECT * FROM health.boot_fixture"); err == nil {
		t.Fatal("writer can read helper base table")
	}
	exec(db, "DROP FUNCTION audit.ingest_lifecycle_batch(text,jsonb,text,text,text,text)")
	if ack, err := store.IngestLifecycle(ctx, ingest.LifecycleSource{SourceID: "absent_function", ExactSAN: "absent_function", CertificateSerial: "f"}, raw); err == nil || ack != nil {
		t.Fatal("missing production function acknowledged")
	}
}
