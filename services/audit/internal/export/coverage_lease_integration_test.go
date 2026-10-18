package export

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TASK-07 3.2.1 on PostgreSQL 16 with every merged migration installed and
// restricted logins: fencing-token lease, unsequenced outbox_range coverage,
// audit_verifier privileges and the audit_retention purge job.
func TestCoverageLeaseRetentionPostgres(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx := context.Background()
	db, cfg := installAllMigrations(t, ctx, dsn)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("SQL failed: %v", err)
		}
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	loginPool := func(name, group string) *pgxpool.Pool {
		t.Helper()
		exec("CREATE ROLE " + name + "_" + suffix + " LOGIN INHERIT NOSUPERUSER")
		exec("GRANT " + group + " TO " + name + "_" + suffix)
		pc, err := pgxpool.ParseConfig(cfg.ConnString())
		if err != nil {
			t.Fatal(err)
		}
		pc.ConnConfig.User = name + "_" + suffix
		pc.ConnConfig.Database = cfg.Database
		p, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	exporterA := loginPool("exp_a", "audit_exporter")
	exporterB := loginPool("exp_b", "audit_exporter")
	verifier := loginPool("verifier", "audit_verifier")
	retention := loginPool("retention", "audit_retention")
	writer := loginPool("writer", "audit_writer")
	denied := func(p *pgxpool.Pool, sql string, args ...any) {
		t.Helper()
		if _, err := p.Exec(ctx, sql, args...); err == nil {
			t.Fatalf("privilege unexpectedly allowed: %s", sql)
		}
	}
	insertEvent := func(sequence *int64, age time.Duration) string {
		t.Helper()
		id := uuid.NewString()
		exec(`INSERT INTO audit.audit_events(event_id,event_type,tenant,source_id,source_version,source_epoch,source_sequence,source_time,received_at,schema_version,payload_digest,safe_payload)
			VALUES($1,'approval_revoked','t','producer','v1','epoch',$2,statement_timestamp(),statement_timestamp()-$3::interval,1,$4,'{}')`, id, sequence, age.String(), strings.Repeat("a", 64))
		exec(`INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state,enqueued_at) VALUES('audit_event',$1,'gcs','business',50,'pending',statement_timestamp()-$2::interval)`, id, age.String())
		return id
	}
	seq := func(n int64) *int64 { return &n }
	newPublisher := func(pool *pgxpool.Pool, lease LeaderLease, cloud *publisherCloud) ManifestPublisher {
		return ManifestPublisher{Pool: pool, Objects: cloud.Objects, Signer: cloud.Signer, KeyVersion: cloud.Version, Keys: map[string]*ecdsa.PublicKey{cloud.Version: cloud.Key}, Leader: lease}
	}
	cloud := newPublisherCloud(t)

	var tokenB int64
	a := &PGLease{Pool: exporterA, Holder: "exporter-a"}
	b := &PGLease{Pool: exporterB, Holder: "exporter-b"}
	t.Run("lease fencing", func(t *testing.T) {
		t1, err := a.Acquire(ctx, "gcs")
		if err != nil || t1 < 1 {
			t.Fatalf("acquire: %d %v", t1, err)
		}
		if _, err = b.Acquire(ctx, "gcs"); !errors.Is(err, ErrLeaseHeld) {
			t.Fatalf("second holder acquired live lease: %v", err)
		}
		if renewed, err := a.Acquire(ctx, "gcs"); err != nil || renewed != t1 {
			t.Fatalf("renew changed token: %d %v", renewed, err)
		}
		for _, sql := range []string{"SELECT * FROM audit.manifest_leases", "UPDATE audit.manifest_leases SET fencing_token=fencing_token+1"} {
			denied(exporterA, sql)
		}
		for _, p := range []*pgxpool.Pool{verifier, retention, writer} {
			denied(p, "SELECT * FROM audit.acquire_manifest_lease('gcs','x')")
		}
		batch := uuid.NewString()
		exec("INSERT INTO audit.export_batches(batch_id,destination,source_class,object_key) VALUES($1,'gcs','business',$2)", batch, "x/"+batch)
		denied(exporterA, "INSERT INTO audit.manifest_intents(chain_id,manifest_seq,batch_id) VALUES('gcs',900,$1)", batch)
		denied(exporterA, "INSERT INTO audit.manifest_intents(chain_id,manifest_seq,batch_id,fencing_token) VALUES('gcs',900,$1,$2)", batch, t1+7)

		// The fenced INSERT keeps the lease row share-locked: a takeover after
		// expiry waits for that transaction and then receives token + 1.
		exec("UPDATE audit.manifest_leases SET lease_until=clock_timestamp()+interval '1 second' WHERE chain_id='gcs'")
		tx, err := exporterA.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "INSERT INTO audit.manifest_intents(chain_id,manifest_seq,batch_id,fencing_token) VALUES('gcs',900,$1,$2)", batch, t1); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1200 * time.Millisecond)
		type result struct {
			token int64
			err   error
		}
		done := make(chan result, 1)
		go func() { tok, err := b.Acquire(ctx, "gcs"); done <- result{tok, err} }()
		select {
		case r := <-done:
			t.Fatalf("takeover did not wait for fenced transaction: %+v", r)
		case <-time.After(300 * time.Millisecond):
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		r := <-done
		if r.err != nil || r.token != t1+1 {
			t.Fatalf("takeover token %d %v", r.token, r.err)
		}
		tokenB = r.token
		denied(exporterA, "INSERT INTO audit.manifest_intents(chain_id,manifest_seq,batch_id,fencing_token) VALUES('gcs',901,$1,$2)", batch, t1)
		exec("DELETE FROM audit.manifest_intents WHERE batch_id=$1", batch)
		exec("DELETE FROM audit.export_batches WHERE batch_id=$1", batch)
	})

	out := Outbox{Pool: exporterB}
	var manifest Manifest
	t.Run("stale holder cannot publish and unsequenced coverage verifies", func(t *testing.T) {
		ids := []string{insertEvent(nil, 0), insertEvent(seq(1), 0), insertEvent(seq(2), 0), insertEvent(nil, 0)}
		// a still believes its local lease is valid; only the DB fence stops it.
		if _, err := a.Check(ctx, "gcs"); err != nil {
			t.Fatalf("stale holder lost local lease too early: %v", err)
		}
		stale := Worker{Outbox: Outbox{Pool: exporterA}, Publisher: newPublisher(exporterA, a, cloud)}
		if worked, err := stale.Once(ctx); !worked || !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("stale holder published: %v %v", worked, err)
		}
		var manifests, pending int
		if err := db.QueryRow(ctx, "SELECT (SELECT count(*) FROM audit.export_manifests),(SELECT count(*) FROM audit.audit_outbox WHERE state='pending')").Scan(&manifests, &pending); err != nil || manifests != 0 || pending != 4 {
			t.Fatalf("stale publication changed state: manifests=%d pending=%d %v", manifests, pending, err)
		}
		exec("UPDATE audit.audit_outbox SET next_retry_at=statement_timestamp()-interval '1 second'")
		current := Worker{Outbox: out, Publisher: newPublisher(exporterB, b, cloud)}
		if worked, err := current.Once(ctx); !worked || err != nil {
			t.Fatalf("current holder: %v %v", worked, err)
		}
		var token int64
		if err := db.QueryRow(ctx, "SELECT m.fencing_token FROM audit.export_manifests m JOIN audit.manifest_intents i USING(chain_id,manifest_seq) WHERE i.fencing_token=m.fencing_token").Scan(&token); err != nil || token != tokenB {
			t.Fatalf("manifest fencing token %d %v", token, err)
		}
		raw, err := cloud.Objects.ReadManifest(ctx, "manifests/1.json")
		if err != nil {
			t.Fatal(err)
		}
		env, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		manifest = env.Manifest
		var first, last int64
		if err := db.QueryRow(ctx, "SELECT min(outbox_id),max(outbox_id) FROM audit.audit_outbox WHERE record_id = ANY($1)", ids).Scan(&first, &last); err != nil {
			t.Fatal(err)
		}
		if manifest.OutboxRange != (OutboxRange{first, last}) || manifest.RecordCount != 4 || len(manifest.Sources) != 1 || manifest.Sources[0] != (Source{"producer", "epoch", 1, 2}) {
			t.Fatalf("manifest coverage: %+v range DB %d..%d", manifest, first, last)
		}
		acks := PGAcks{Queries: auditdb.New(verifier), Destination: "gcs"}
		keys := map[string]*ecdsa.PublicKey{cloud.Version: cloud.Key}
		if _, err = Verify(ctx, raw, 1, nil, keys, cloud.Objects, acks); err != nil {
			t.Fatalf("verifier role rejected intact batch: %v", err)
		}
		// A DB administrator swapping one fixed member is a coverage incident.
		other := insertEvent(seq(3), 0)
		var ordinal int
		var original string
		if err := db.QueryRow(ctx, "SELECT ordinal,record_id FROM audit.export_batch_members WHERE batch_id=$1 ORDER BY ordinal DESC LIMIT 1", manifest.BatchID).Scan(&ordinal, &original); err != nil {
			t.Fatal(err)
		}
		exec("UPDATE audit.export_batch_members SET record_id=$1 WHERE batch_id=$2 AND ordinal=$3", other, manifest.BatchID, ordinal)
		if _, err = Verify(ctx, raw, 1, nil, keys, cloud.Objects, acks); FailureCode(err) != FailCoverageMismatch {
			t.Fatalf("swapped member: %v", err)
		}
		exec("UPDATE audit.export_batch_members SET record_id=$1 WHERE batch_id=$2 AND ordinal=$3", original, manifest.BatchID, ordinal)
		exec("DELETE FROM audit.audit_outbox WHERE record_id=$1", other)
		exec("DELETE FROM audit.audit_events WHERE event_id=$1", other)
		if _, err = Verify(ctx, raw, 1, nil, keys, cloud.Objects, acks); err != nil {
			t.Fatal(err)
		}
		denied(exporterA, "UPDATE audit.audit_outbox SET outbox_id=1")
	})

	t.Run("verifier role is read-only and minimal", func(t *testing.T) {
		for _, sql := range []string{
			"SELECT * FROM audit.audit_events", "SELECT record_bytes FROM audit.audit_outbox", "SELECT * FROM decisions.decision_inputs",
			"UPDATE audit.audit_outbox SET state='pending'", "INSERT INTO audit.export_batches(batch_id) VALUES (gen_random_uuid())",
			"DELETE FROM audit.export_manifests", "SELECT * FROM audit.purge_expired_records(1)",
		} {
			denied(verifier, sql)
		}
		var n int
		if err := verifier.QueryRow(ctx, "SELECT count(*) FROM audit.export_manifests").Scan(&n); err != nil || n != 1 {
			t.Fatalf("verifier cannot read manifests: %d %v", n, err)
		}
	})

	t.Run("retention purges only expired acknowledged batches", func(t *testing.T) {
		current := Worker{Outbox: out, Publisher: newPublisher(exporterB, b, cloud)}
		if _, err := b.Acquire(ctx, "gcs"); err != nil {
			t.Fatal(err)
		}
		expired := []string{insertEvent(seq(10), 40*24*time.Hour), insertEvent(nil, 40*24*time.Hour)}
		if worked, err := current.Once(ctx); !worked || err != nil {
			t.Fatalf("export expired batch: %v %v", worked, err)
		}
		referenced := insertEvent(seq(11), 40*24*time.Hour)
		if worked, err := current.Once(ctx); !worked || err != nil {
			t.Fatalf("export referenced batch: %v %v", worked, err)
		}
		exec(`INSERT INTO audit.abandoned_ranges(source_id,stream,source_epoch,from_seq,to_seq,reason,range_digest,gap_id,received_at,sequence_event_id,gap_event_id)
			VALUES('producer','lifecycle','epoch',1,1,'test',$1,gen_random_uuid(),statement_timestamp(),$2,$2)`, strings.Repeat("b", 64), referenced)
		unacked := insertEvent(seq(12), 40*24*time.Hour)
		var recent int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events").Scan(&recent); err != nil {
			t.Fatal(err)
		}
		for _, p := range []*pgxpool.Pool{exporterA, verifier, writer} {
			denied(p, "SELECT * FROM audit.purge_expired_records(10)")
		}
		denied(retention, "DELETE FROM audit.audit_events")
		denied(retention, "DELETE FROM audit.audit_outbox")
		denied(retention, "SELECT * FROM audit.purge_expired_records(0)")
		var purged, skipped int64
		// Old records exported late: their manifests were committed just now
		// and are inside the 30-day verification window, so nothing is purged.
		if err := retention.QueryRow(ctx, "SELECT purged_batches,skipped_batches FROM audit.purge_expired_records(100)").Scan(&purged, &skipped); err != nil || purged != 0 || skipped != 0 {
			t.Fatalf("purge inside verification window %d/%d %v", purged, skipped, err)
		}
		acks := PGAcks{Queries: auditdb.New(verifier), Destination: "gcs"}
		raw, err := cloud.Objects.ReadManifest(ctx, "manifests/2.json")
		if err != nil {
			t.Fatal(err)
		}
		prev, err := auditdb.New(verifier).ManifestForSequence(ctx, auditdb.ManifestForSequenceParams{ChainID: "gcs", ManifestSeq: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Verify(ctx, raw, 2, &prev.ManifestDigest, map[string]*ecdsa.PublicKey{cloud.Version: cloud.Key}, cloud.Objects, acks); err != nil {
			t.Fatalf("late-exported batch inside window failed verification: %v", err)
		}
		// 30 days later the manifests are outside the verification window; a
		// one-day margin (31 days) applies before rows are purged.
		// Simulate elapsed time: created_at is DB-assigned and immutable, so the
		// fixture (a superuser) bypasses that trigger explicitly.
		exec("ALTER TABLE audit.export_manifests DISABLE TRIGGER export_manifests_db_time")
		exec("UPDATE audit.export_manifests SET created_at=created_at-interval '30 days 12 hours' WHERE manifest_seq IN (2,3)")
		exec("ALTER TABLE audit.export_manifests ENABLE TRIGGER export_manifests_db_time")
		if err := retention.QueryRow(ctx, "SELECT purged_batches,skipped_batches FROM audit.purge_expired_records(100)").Scan(&purged, &skipped); err != nil || purged != 0 || skipped != 0 {
			t.Fatalf("purge inside one-day margin %d/%d %v", purged, skipped, err)
		}
		// Simulate elapsed time: created_at is DB-assigned and immutable, so the
		// fixture (a superuser) bypasses that trigger explicitly.
		exec("ALTER TABLE audit.export_manifests DISABLE TRIGGER export_manifests_db_time")
		exec("UPDATE audit.export_manifests SET created_at=created_at-interval '1 day' WHERE manifest_seq IN (2,3)")
		exec("ALTER TABLE audit.export_manifests ENABLE TRIGGER export_manifests_db_time")
		if err := retention.QueryRow(ctx, "SELECT purged_batches,skipped_batches FROM audit.purge_expired_records(100)").Scan(&purged, &skipped); err != nil || purged != 1 || skipped != 1 {
			t.Fatalf("purge result %d/%d %v", purged, skipped, err)
		}
		var events, outbox, members, manifests int
		if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.audit_events),
			(SELECT count(*) FROM audit.audit_outbox WHERE record_id = ANY($1)),
			(SELECT count(*) FROM audit.export_batch_members WHERE record_id = ANY($1)),
			(SELECT count(*) FROM audit.export_manifests)`, expired).Scan(&events, &outbox, &members, &manifests); err != nil {
			t.Fatal(err)
		}
		if events != recent-2 || outbox != 0 || members != 0 || manifests != 3 {
			t.Fatalf("purge removed wrong rows: events %d/%d outbox %d members %d manifests %d", events, recent, outbox, members, manifests)
		}
		for _, id := range []string{referenced, unacked} {
			var n int
			if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE event_id=$1", id).Scan(&n); err != nil || n != 1 {
				t.Fatalf("protected record %s purged: %d %v", id, n, err)
			}
		}
		// Only manifests outside the window lose their rows; cmd/verify stops at
		// the window boundary before reaching them (TASK-07 3.2.1).
		var oldest time.Time
		if err := db.QueryRow(ctx, `SELECT max(em.created_at) FROM audit.export_manifests em JOIN audit.manifest_intents i USING(chain_id,manifest_seq)
			WHERE NOT EXISTS (SELECT FROM audit.export_batch_members m WHERE m.batch_id=i.batch_id)`).Scan(&oldest); err != nil || time.Since(oldest) < 31*24*time.Hour {
			t.Fatalf("purged a batch whose manifest is in the window: %s %v", oldest, err)
		}
	})
}

// installAllMigrations creates a disposable database with every up migration
// in version order and drops only the cluster roles this test introduced.
func installAllMigrations(t *testing.T, ctx context.Context, dsn string) (*pgx.Conn, *pgx.ConnConfig) {
	t.Helper()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	roles := func() map[string]bool {
		rows, err := admin.Query(ctx, "SELECT rolname FROM pg_roles")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		set := map[string]bool{}
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				t.Fatal(err)
			}
			set[r] = true
		}
		return set
	}
	existing := roles()
	name := "audit_cov_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = name
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		db.Close(ctx)
		_, _ = admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		var added []string
		for r := range roles() {
			if !existing[r] {
				added = append(added, r)
			}
		}
		sort.Strings(added)
		for _, r := range added {
			if _, err := admin.Exec(ctx, "DROP ROLE "+pgx.Identifier{r}.Sanitize()); err != nil {
				t.Errorf("drop role %s: %v", r, err)
			}
		}
	})
	if _, err := db.Exec(ctx, "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$"); err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	files, err := filepath.Glob(filepath.Join(filepath.Dir(file), "../../../../migrations/*.up.sql"))
	if err != nil || len(files) == 0 {
		t.Fatal("migrations not found")
	}
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
	}
	return db, cfg
}
