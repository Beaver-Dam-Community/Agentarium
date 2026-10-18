//go:build integration

package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Installs real migrations, including the merged identity/health helpers.
// The local runner supplies their paths; no function fixture replaces ingest.
func TestLifecycleSQLPostgres(t *testing.T) {
	dsn := os.Getenv("AUDIT_LIFECYCLE_TEST_DSN")
	identityMigration := os.Getenv("LIFECYCLE_IDENTITY_MIGRATION")
	healthMigration := os.Getenv("LIFECYCLE_HEALTH_MIGRATION")
	if dsn == "" || identityMigration == "" || healthMigration == "" {
		t.Skip("set disposable DB and actual source-helper migration paths")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	suffix := uuid.NewString()[:8]
	dbName, installer, writer, denied := "lcdb_"+suffix, "lcinst_"+suffix, "lcwriter_"+suffix, "lcdeny_"+suffix
	exec := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, e := c.Exec(ctx, q, args...); e != nil {
			t.Fatalf("SQL: %v\n%s", e, q)
		}
	}
	for _, role := range []string{installer, writer, denied} {
		exec(admin, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	}
	exec(admin, "ALTER ROLE "+pgx.Identifier{installer}.Sanitize()+" CREATEROLE")
	exec(admin, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()+" OWNER "+pgx.Identifier{installer}.Sanitize())
	defer func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
		_, _ = admin.Exec(ctx, "REVOKE audit_producer FROM audit_writer GRANTED BY "+pgx.Identifier{installer}.Sanitize())
		for _, r := range []string{writer, denied, installer} {
			_, _ = admin.Exec(ctx, "DROP ROLE "+pgx.Identifier{r}.Sanitize())
		}
	}()
	for _, role := range []string{"audit_owner", "audit_producer", "health_owner"} {
		var exists bool
		if e := admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)", role).Scan(&exists); e != nil {
			t.Fatal(e)
		}
		if exists {
			exec(admin, "GRANT "+role+" TO "+pgx.Identifier{installer}.Sanitize()+" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
		}
	}
	connect := func(user string) *pgx.Conn {
		t.Helper()
		cfg, e := pgx.ParseConfig(dsn)
		if e != nil {
			t.Fatal(e)
		}
		cfg.Database = dbName
		cfg.User = user
		c, e := pgx.ConnectConfig(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	install := connect(installer)
	migration := func(path string) {
		t.Helper()
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		exec(install, string(raw))
	}
	base := "../../../../migrations"
	for _, name := range []string{"20261016132230_audit_store.up.sql", "20261016132231_health_control_health.up.sql", "20261014144500_identity_workload_pki.up.sql"} {
		migration(filepath.Join(base, name))
	}
	migration(identityMigration)
	migration(healthMigration)
	migration(filepath.Join(base, "20261017114903_health_audit_gap_writer.up.sql"))
	fixture := connect(admin.Config().User)
	lifecycleUp, err := os.ReadFile(filepath.Join(base, "20261017114904_audit_lifecycle_ingest.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("migration lock acquisition is bounded and atomic", func(t *testing.T) {
		blocker, err := fixture.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(ctx)
		if _, err := blocker.Exec(ctx, "LOCK TABLE audit.abandoned_ranges IN ACCESS SHARE MODE"); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		_, err = install.Exec(ctx, string(lifecycleUp))
		elapsed := time.Since(started)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "55P03" || elapsed < 1500*time.Millisecond || elapsed > 10*time.Second {
			t.Fatalf("DDL lock timeout: %s %v", elapsed, err)
		}
		exec(install, "ROLLBACK")
		var unchanged bool
		if err := fixture.QueryRow(ctx, `SELECT
 NOT EXISTS(SELECT FROM pg_attribute WHERE attrelid='audit.abandoned_ranges'::regclass AND attname='sequence_event_id' AND NOT attisdropped)
 AND NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='audit.db_role_sources'::regclass AND conname='db_role_sources_proxy_receiver_source')`).Scan(&unchanged); err != nil || !unchanged {
			t.Fatalf("lock failure left migration changes: %v %v", unchanged, err)
		}
	})
	for _, stream := range []string{"lifecycle", "kernel"} {
		t.Run("migration rejects unlinked legacy "+stream+" range", func(t *testing.T) {
			exec(fixture, `INSERT INTO audit.abandoned_ranges(source_id,stream,source_epoch,from_seq,to_seq,reason,range_digest,gap_id,received_at)
 VALUES('legacy',$1,'legacy-epoch',1,2,'record_rejected',repeat('a',64),$2,'2026-10-16T00:00:00Z')`, stream, uuid.NewString())
			var before, after string
			if err := fixture.QueryRow(ctx, `SELECT to_jsonb(r)::text FROM audit.abandoned_ranges r WHERE source_id='legacy'`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			_, err := install.Exec(ctx, string(lifecycleUp))
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "55000" {
				t.Fatalf("legacy range migrated: %v", err)
			}
			exec(install, "ROLLBACK")
			if err := fixture.QueryRow(ctx, `SELECT to_jsonb(r)::text FROM audit.abandoned_ranges r WHERE source_id='legacy'`).Scan(&after); err != nil || after != before {
				t.Fatalf("legacy evidence changed: %s %s %v", before, after, err)
			}
			var unchanged bool
			if err := fixture.QueryRow(ctx, `SELECT
 NOT EXISTS(SELECT FROM pg_attribute WHERE attrelid='audit.abandoned_ranges'::regclass AND attname IN ('sequence_event_id','gap_event_id') AND NOT attisdropped)
 AND NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='audit.db_role_sources'::regclass AND conname='db_role_sources_proxy_receiver_source')
 AND EXISTS(SELECT FROM audit.event_types WHERE event_type='sequence_range_abandoned' AND producer_task='TASK-09' AND NOT(required_payload_fields ? 'source_id'))`).Scan(&unchanged); err != nil || !unchanged {
				t.Fatalf("failed migration left schema/registry changes: %v %v", unchanged, err)
			}
			var who string
			if err := install.QueryRow(ctx, "SELECT current_user").Scan(&who); err != nil || who != installer {
				t.Fatalf("failed migration retained SET ROLE: %s %v", who, err)
			}
			// Disposable fixture cleanup only; an actual installation needs a
			// separately reviewed preservation/provenance plan, never this DELETE.
			exec(fixture, "DELETE FROM audit.abandoned_ranges WHERE source_id='legacy'")
		})
	}
	migration(filepath.Join(base, "20261017114904_audit_lifecycle_ingest.up.sql"))
	assertGapSchema := func() {
		t.Helper()
		var valid bool
		if err := fixture.QueryRow(ctx, `SELECT
 (SELECT count(*)=2 FROM pg_attribute WHERE attrelid='audit.abandoned_ranges'::regclass AND attname IN ('sequence_event_id','gap_event_id') AND attnotnull AND NOT attisdropped)
 AND EXISTS(SELECT FROM audit.event_types WHERE event_type='sequence_range_abandoned' AND producer_task='TASK-07' AND required_payload_fields='["source_id","stream","source_epoch","range","reason","range_digest"]'::jsonb)
 AND has_schema_privilege('audit_owner','health','USAGE')
 AND has_column_privilege('audit_owner','health.observation_gaps','gap_id','INSERT')
 AND NOT has_column_privilege('audit_owner','health.observation_gaps','created_at','INSERT')
 AND NOT has_table_privilege('audit_owner','health.observation_gaps','SELECT,INSERT,UPDATE')
 AND NOT has_table_privilege('audit_writer','health.observation_gaps','SELECT,INSERT,UPDATE')`).Scan(&valid); err != nil || !valid {
			t.Fatalf("#95 target schema missing: %v %v", valid, err)
		}
	}
	t.Run("required range audit links and receiver registry", func(t *testing.T) {
		assertGapSchema()
		_, err := fixture.Exec(ctx, `INSERT INTO audit.abandoned_ranges(source_id,stream,source_epoch,from_seq,to_seq,reason,range_digest,gap_id,received_at) VALUES('unlinked','lifecycle','epoch',1,1,'record_rejected',repeat('a',64),$1,now())`, uuid.NewString())
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23502" {
			t.Fatalf("unlinked range allowed: %v", err)
		}
	})
	exec(fixture, "GRANT audit_writer TO "+pgx.Identifier{writer}.Sanitize())
	exec(fixture, "GRANT USAGE ON SCHEMA audit TO "+pgx.Identifier{denied}.Sanitize())
	caller, outsider := connect(writer), connect(denied)
	runtimeSAN := "spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder"
	watcherSAN := "spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher"
	receiver := "audit-writer-test"
	node, foreign := uuid.NewString(), uuid.NewString()
	exec(fixture, `INSERT INTO identity.registered_workloads(namespace,ksa,role,service_principal) VALUES
 ('agent-sensors','lifecycle-recorder','service','lifecycle-recorder'),('agent-observe','pod-watcher','service','pod-watcher')`)
	exec(fixture, `INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,node_uid,boot_id,issued_at,expires_at,revoked_at) VALUES
 ('0a',$1,'agent-sensors','lifecycle-recorder',$3,'boot-current',now()-interval '1 minute',now()+interval '1 hour',NULL),
 ('0b',$1,'agent-sensors','lifecycle-recorder',$3,'boot-old',now()-interval '2 days',now()-interval '1 day',now()-interval '1 day'),
 ('0c',$1,'agent-sensors','lifecycle-recorder',$4,'boot-foreign',now()-interval '2 days',now()-interval '1 day',NULL),
 ('0d',$2,'agent-observe','pod-watcher',NULL,NULL,now()-interval '1 minute',now()+interval '1 hour',NULL)`, runtimeSAN, watcherSAN, node, foreign)
	exec(fixture, `INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,state,updated_at) VALUES ($1,'boot-current','unsupported','held',now())`, node)
	for _, invalidSource := range []any{nil, ""} {
		_, e := fixture.Exec(ctx, `INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES ($1,$2,true)`, writer, invalidSource)
		var pgerr *pgconn.PgError
		if !errors.As(e, &pgerr) || pgerr.Code != "23514" {
			t.Fatalf("proxy source constraint: %v", e)
		}
	}
	exec(fixture, `INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES ($1,$2,true)`, writer, receiver)
	exec(fixture, `INSERT INTO audit.producer_event_grants(source_id,event_type,tenant) VALUES ($1,'lifecycle_recorded','*'),($2,'lifecycle_recorded','*'),($3,'sequence_range_abandoned','*'),($3,'observation_gap_recorded','*')`, runtimeSAN, watcherSAN, receiver)
	hash := func(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
	epoch := func(boot string) string {
		return strings.ReplaceAll(node, "-", "") + hash(boot) + strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	watcherEpoch := func() string { return strings.ReplaceAll(uuid.NewString(), "-", "") + "_1" }
	record := func(source, ep string, seq int64, boot string) map[string]any {
		id, e := canonical.LifecycleEventID(source, ep, seq)
		if e != nil {
			t.Fatal(e)
		}
		r := map[string]any{"lifecycle_event_id": id, "source_id": source, "source_epoch": ep, "source_sequence": seq, "cluster_uid": uuid.NewString(), "pod_uid": uuid.NewString(), "namespace": "agent-exec", "pod_name": "test-pod", "transition": "test_observed", "mapping_version": 1, "evidence_refs": []any{}}
		if source == runtimeSAN {
			r["node_uid"] = node
			r["boot_id"] = boot
		}
		d, e := canonical.CanonicalDigest(r)
		if e != nil {
			t.Fatal(e)
		}
		r["record_digest"] = d
		return r
	}
	envelope := func(ep string, records []any, ranges []any, scope string, cursor any) map[string]any {
		b := map[string]any{"batch_id": uuid.NewString(), "source_epoch": ep, "records": records, "sequence_range_abandoned": ranges}
		if scope != "" {
			b["scope"] = scope
		}
		if cursor != nil {
			b["cursor"] = cursor
		}
		return b
	}
	rawBatch := func(b map[string]any) []byte {
		t.Helper()
		delete(b, "batch_digest")
		d, e := canonical.CanonicalDigest(b)
		if e != nil {
			t.Fatal(e)
		}
		b["batch_digest"] = d
		raw, e := json.Marshal(b)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	call := func(c *pgx.Conn, source, serial string, b map[string]any) (map[string]any, error) {
		t.Helper()
		var raw []byte
		e := c.QueryRow(ctx, `SELECT audit.ingest_lifecycle_batch($1,$2,$3,$1,'test-v1','writer-instance_1')`, source, rawBatch(b), serial).Scan(&raw)
		if e != nil {
			return nil, e
		}
		var out map[string]any
		e = json.Unmarshal(raw, &out)
		return out, e
	}
	must := func(source, serial string, b map[string]any) map[string]any {
		t.Helper()
		out, e := call(caller, source, serial, b)
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	through := func(a map[string]any) float64 {
		return a["watermarks"].([]any)[0].(map[string]any)["acked_through"].(float64)
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if e := fixture.QueryRow(ctx, q, args...).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	expectCode := func(e error, code string) {
		t.Helper()
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != code {
			t.Fatalf("want %s: %v", code, e)
		}
	}
	ep := epoch("boot-current")
	r2 := record(runtimeSAN, ep, 2, "boot-current")
	b2 := envelope(ep, []any{r2}, []any{}, "", nil)
	a := must(runtimeSAN, "0a", b2)
	if through(a) != 0 || len(a["accepted_ids"].([]any)) != 1 {
		t.Fatalf("out of order: %v", a)
	}
	if count(`SELECT count(*) FROM audit.audit_outbox WHERE record_kind='lifecycle_event'`) != 1 {
		t.Fatal("missing raw outbox")
	}
	a = must(runtimeSAN, "0a", b2)
	if len(a["duplicate_ids"].([]any)) != 1 || through(a) != 0 {
		t.Fatalf("retry: %v", a)
	}
	r1 := record(runtimeSAN, ep, 1, "boot-current")
	a = must(runtimeSAN, "0a", envelope(ep, []any{r1}, []any{}, "", nil))
	if through(a) != 2 {
		t.Fatalf("contiguous: %v", a)
	}
	conflict := map[string]any{}
	for k, v := range r2 {
		conflict[k] = v
	}
	conflict["pod_name"] = "changed"
	delete(conflict, "record_digest")
	d, _ := canonical.CanonicalDigest(conflict)
	conflict["record_digest"] = d
	a = must(runtimeSAN, "0a", envelope(ep, []any{conflict}, []any{}, "", nil))
	if a["rejected"].([]any)[0].(map[string]any)["reason_codes"].([]any)[0] != "EVENT_ID_CONFLICT" {
		t.Fatalf("conflict: %v", a)
	}
	bad := record(runtimeSAN, ep, 3, "boot-current")
	bad["record_digest"] = strings.Repeat("0", 64)
	good := record(runtimeSAN, ep, 4, "boot-current")
	a = must(runtimeSAN, "0a", envelope(ep, []any{bad, good}, []any{}, "", nil))
	if through(a) != 2 || len(a["rejected"].([]any)) != 1 || len(a["accepted_ids"].([]any)) != 1 {
		t.Fatalf("partial: %v", a)
	}
	digest, _ := canonical.AbandonedRangeDigest(runtimeSAN, "lifecycle", ep, 3, 3, "record_rejected")
	abandoned := map[string]any{"from_seq": 3, "to_seq": 3, "reason": "record_rejected", "range_digest": digest}
	gapBatch := envelope(ep, []any{}, []any{abandoned}, "", nil)
	a = must(runtimeSAN, "0a", gapBatch)
	if through(a) != 4 {
		t.Fatalf("gap: %v", a)
	}
	if count(`SELECT count(*) FROM health.observation_gaps`) != 1 || count(`SELECT count(*) FROM audit.audit_events`) != 2 || count(`SELECT count(*) FROM audit.audit_outbox WHERE record_kind='audit_event'`) != 2 {
		t.Fatal("gap+two audits+outboxes incomplete")
	}
	a = must(runtimeSAN, "0a", gapBatch)
	if len(a["duplicate_ids"].([]any)) != 1 || count(`SELECT count(*) FROM audit.audit_events`) != 2 {
		t.Fatalf("range duplicate: %v", a)
	}
	// A missing receiver grant must roll back records, gap, both events/outboxes and watermark together.
	rollbackEpoch := epoch("boot-current")
	rd, _ := canonical.AbandonedRangeDigest(runtimeSAN, "lifecycle", rollbackEpoch, 2, 2, "wal_segment_corrupt")
	rb := envelope(rollbackEpoch, []any{record(runtimeSAN, rollbackEpoch, 1, "boot-current")}, []any{map[string]any{"from_seq": 2, "to_seq": 2, "reason": "wal_segment_corrupt", "range_digest": rd}}, "", nil)
	exec(fixture, `DELETE FROM audit.producer_event_grants WHERE source_id=$1 AND event_type='observation_gap_recorded'`, receiver)
	_, e := call(caller, runtimeSAN, "0a", rb)
	expectCode(e, "42501")
	if count(`SELECT count(*) FROM audit.lifecycle_events WHERE source_epoch=$1`, rollbackEpoch) != 0 || count(`SELECT count(*) FROM audit.ingest_watermarks WHERE source_epoch=$1`, rollbackEpoch) != 0 || count(`SELECT count(*) FROM health.observation_gaps`) != 1 {
		t.Fatal("failed audit partially committed")
	}
	exec(fixture, `INSERT INTO audit.producer_event_grants VALUES ($1,'observation_gap_recorded','*')`, receiver)
	must(runtimeSAN, "0a", rb)
	// Current cert may replay unseen historical boot with retained prior issuance evidence.
	oldEpoch := epoch("boot-old")
	must(runtimeSAN, "0a", envelope(oldEpoch, []any{record(runtimeSAN, oldEpoch, 1, "boot-old")}, []any{}, "", nil))
	unknownEpoch := epoch("not-issued")
	_, e = call(caller, runtimeSAN, "0a", envelope(unknownEpoch, []any{}, []any{}, "", nil))
	expectCode(e, "42501")
	_, e = call(caller, runtimeSAN, "0b", b2)
	expectCode(e, "42501")
	exec(fixture, `UPDATE health.node_boot_generation SET state='retired' WHERE node_uid=$1`, node)
	_, e = call(caller, runtimeSAN, "0a", b2)
	expectCode(e, "42501")
	exec(fixture, `UPDATE health.node_boot_generation SET state='held' WHERE node_uid=$1`, node)
	// Watcher authenticates without node/boot and uses opaque RV + revision CAS.
	scope := "namespace/agent-exec"
	we := watcherEpoch()
	cursor := func(rv string, revision int) map[string]any {
		return map[string]any{"scope": scope, "resource_version": rv, "expected_checkpoint_revision": revision}
	}
	ca := envelope(we, []any{}, []any{}, scope, cursor("opaque-A", 0))
	a = must(watcherSAN, "0d", ca)
	if a["checkpoint"].(map[string]any)["checkpoint_revision"] != float64(1) || through(a) != 0 {
		t.Fatalf("empty cursor: %v", a)
	}
	a = must(watcherSAN, "0d", ca)
	if a["checkpoint"].(map[string]any)["checkpoint_revision"] != float64(1) {
		t.Fatalf("same current retry: %v", a)
	}
	cb := envelope(we, []any{}, []any{}, scope, cursor("opaque-B", 1))
	must(watcherSAN, "0d", cb)
	a = must(watcherSAN, "0d", ca)
	if a["checkpoint"] != nil {
		t.Fatalf("late A rewound B: %v", a)
	}
	stale := envelope(we, []any{record(watcherSAN, we, 1, "")}, []any{}, scope, cursor("stale-record", 0))
	a = must(watcherSAN, "0d", stale)
	if a["checkpoint"] != nil || through(a) != 1 || len(a["accepted_ids"].([]any)) != 1 {
		t.Fatalf("stale record commit: %v", a)
	}
	var rv string
	var revision int64
	if e = caller.QueryRow(ctx, `SELECT resource_version,checkpoint_revision FROM audit.lifecycle_checkpoint($1,$2)`, watcherSAN, scope).Scan(&rv, &revision); e != nil || rv != "opaque-B" || revision != 2 {
		t.Fatalf("checkpoint: %s %d %v", rv, revision, e)
	}
	// Another epoch's first INSERT cannot bypass the same scope lock.
	locker := connect(admin.Config().User)
	tx, e := locker.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('lifecycle/checkpoint/'||$1||'/'||$2,0))`, watcherSAN, scope); e != nil {
		t.Fatal(e)
	}
	started := time.Now()
	_, e = call(caller, watcherSAN, "0d", envelope(watcherEpoch(), []any{}, []any{}, scope, cursor("busy", 2)))
	expectCode(e, "55P03")
	if time.Since(started) > 3*time.Second {
		t.Fatal("lock wait unbounded")
	}
	_ = tx.Rollback(ctx)
	// Repeated IDs represent one acknowledgement identity, not duplicate results.
	repeatedEpoch := epoch("boot-current")
	repeated := record(runtimeSAN, repeatedEpoch, 1, "boot-current")
	repeatedBatch := envelope(repeatedEpoch, []any{repeated, repeated}, []any{}, "", nil)
	a = must(runtimeSAN, "0a", repeatedBatch)
	if len(a["accepted_ids"].([]any)) != 1 || len(a["duplicate_ids"].([]any)) != 0 {
		t.Fatalf("duplicate request IDs: %v", a)
	}
	a = must(runtimeSAN, "0a", repeatedBatch)
	if len(a["duplicate_ids"].([]any)) != 1 {
		t.Fatalf("duplicate retry IDs: %v", a)
	}
	malformedIDs := envelope(repeatedEpoch, []any{map[string]any{"lifecycle_event_id": 42}, map[string]any{"lifecycle_event_id": map[string]any{"x": true}}}, []any{}, "", nil)
	a = must(runtimeSAN, "0a", malformedIDs)
	if len(a["rejected"].([]any)) != 1 || a["rejected"].([]any)[0].(map[string]any)["id"] != "" {
		t.Fatalf("malformed rejection IDs: %v", a)
	}
	// Both cert and enabled workload are rechecked by the DB, not only HTTP.
	exec(fixture, `UPDATE identity.issued_certificates SET revoked_at=now() WHERE serial='0d'`)
	_, e = call(caller, watcherSAN, "0d", cb)
	expectCode(e, "42501")
	exec(fixture, `UPDATE identity.issued_certificates SET revoked_at=NULL WHERE serial='0d'`)
	exec(fixture, `UPDATE identity.registered_workloads SET enabled=false WHERE ksa='pod-watcher'`)
	_, e = call(caller, watcherSAN, "0d", cb)
	expectCode(e, "42501")
	exec(fixture, `UPDATE identity.registered_workloads SET enabled=true WHERE ksa='pod-watcher'`)
	// Scope is immutable even without a cursor; namespaced records must match it.
	_, e = call(caller, watcherSAN, "0d", envelope(we, []any{}, []any{}, "namespace/other", nil))
	expectCode(e, "42501")
	wrongNS := record(watcherSAN, we, 2, "")
	wrongNS["namespace"] = "other"
	delete(wrongNS, "record_digest")
	nsDigest, _ := canonical.CanonicalDigest(wrongNS)
	wrongNS["record_digest"] = nsDigest
	a = must(watcherSAN, "0d", envelope(we, []any{wrongNS}, []any{}, scope, nil))
	if len(a["rejected"].([]any)) != 1 || through(a) != 1 {
		t.Fatalf("namespace escape: %v", a)
	}
	// Unsupported envelope fields and bad whole-body digest create no state.
	malformedEpoch := watcherEpoch()
	malformed := envelope(malformedEpoch, []any{}, []any{}, scope, nil)
	malformed["unexpected"] = true
	_, e = call(caller, watcherSAN, "0d", malformed)
	expectCode(e, "22023")
	delete(malformed, "unexpected")
	rawBatch(malformed)
	malformed["batch_digest"] = strings.Repeat("0", 64)
	badWire, _ := json.Marshal(malformed)
	_, e = caller.Exec(ctx, `SELECT audit.ingest_lifecycle_batch($1,$2,'0d',$1,'v1','writer_1')`, watcherSAN, badWire)
	expectCode(e, "22023")
	if count(`SELECT count(*) FROM audit.ingest_watermarks WHERE source_epoch=$1`, malformedEpoch) != 0 {
		t.Fatal("invalid envelope mutated DB")
	}
	// A DB failure after INSERT must escape, not become an individual schema rejection.
	exec(fixture, `CREATE FUNCTION audit.test_outbox_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected outbox failure' USING ERRCODE='23514'; END $$; CREATE TRIGGER test_outbox_failure BEFORE INSERT ON audit.audit_outbox FOR EACH ROW EXECUTE FUNCTION audit.test_outbox_failure()`)
	failedEpoch := epoch("boot-current")
	_, e = call(caller, runtimeSAN, "0a", envelope(failedEpoch, []any{record(runtimeSAN, failedEpoch, 1, "boot-current")}, []any{}, "", nil))
	expectCode(e, "23514")
	if count(`SELECT count(*) FROM audit.lifecycle_events WHERE source_epoch=$1`, failedEpoch) != 0 || count(`SELECT count(*) FROM audit.ingest_watermarks WHERE source_epoch=$1`, failedEpoch) != 0 {
		t.Fatal("outbox failure partially committed")
	}
	exec(fixture, `DROP TRIGGER test_outbox_failure ON audit.audit_outbox; DROP FUNCTION audit.test_outbox_failure()`)
	// Huge ranges advance by interval, not one loop per sequence.
	hugeEpoch := epoch("boot-current")
	const high int64 = 9007199254740991
	hugeDigest, _ := canonical.AbandonedRangeDigest(runtimeSAN, "lifecycle", hugeEpoch, 1, high, "wal_segment_corrupt")
	started = time.Now()
	a = must(runtimeSAN, "0a", envelope(hugeEpoch, []any{}, []any{map[string]any{"from_seq": 1, "to_seq": high, "reason": "wal_segment_corrupt", "range_digest": hugeDigest}}, "", nil))
	if through(a) != float64(high) || time.Since(started) > 3*time.Second {
		t.Fatal("large range did not advance in bounded time")
	}
	// Revision overflow rolls back newly supplied records as well as the cursor.
	exec(fixture, `UPDATE audit.watch_checkpoints SET checkpoint_revision=9007199254740991 WHERE source_id=$1 AND scope=$2`, watcherSAN, scope)
	overflowEpoch := watcherEpoch()
	overCursor := cursor("overflow", 0)
	overCursor["expected_checkpoint_revision"] = high
	_, e = call(caller, watcherSAN, "0d", envelope(overflowEpoch, []any{record(watcherSAN, overflowEpoch, 1, "")}, []any{}, scope, overCursor))
	expectCode(e, "22003")
	if count(`SELECT count(*) FROM audit.lifecycle_events WHERE source_epoch=$1`, overflowEpoch) != 0 || count(`SELECT count(*) FROM audit.ingest_watermarks WHERE source_epoch=$1`, overflowEpoch) != 0 {
		t.Fatal("overflow partially committed")
	}
	exec(fixture, `UPDATE audit.watch_checkpoints SET checkpoint_revision=2 WHERE source_id=$1 AND scope=$2`, watcherSAN, scope)
	// Runtime callers cannot read/write base tables or invoke private helpers.
	for _, q := range []string{`SELECT * FROM audit.lifecycle_events`, `SELECT * FROM audit.watch_checkpoints`, `SELECT * FROM health.observation_gaps`, `INSERT INTO audit.ingest_watermarks(source_id,stream,source_epoch,updated_at) VALUES ('x','lifecycle','x',now())`, `SELECT audit._lifecycle_proxy('x')`} {
		_, e = caller.Exec(ctx, q)
		expectCode(e, "42501")
	}
	_, e = call(outsider, watcherSAN, "0d", ca)
	expectCode(e, "42501")
	migration(filepath.Join(base, "20261017114904_audit_lifecycle_ingest.down.sql"))
	assertGapSchema()
	migration(filepath.Join(base, "20261017114904_audit_lifecycle_ingest.up.sql"))
	a = must(watcherSAN, "0d", cb)
	if a["checkpoint"].(map[string]any)["checkpoint_revision"] != float64(2) {
		t.Fatal("down/up lost checkpoint")
	}
	// Full receive path: real TLS leaf -> live authorizer -> production SQL -> COMMIT.
	// The local CA replaces CAS issuance only; no identity/store function is mocked.
	exec(fixture, `GRANT USAGE ON SCHEMA identity TO audit_writer;
 GRANT SELECT(namespace,ksa,enabled,role,service_principal) ON identity.registered_workloads TO audit_writer`)
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.Database, poolConfig.ConnConfig.User = dbName, writer
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	authorizer, err := NewAuthorizer(pool, []SourceBinding{
		{SourceID: watcherSAN, Namespace: "agent-observe", KSA: "pod-watcher", Principal: "pod-watcher", Scopes: []string{scope}},
		{SourceID: runtimeSAN, Namespace: "agent-sensors", KSA: "lifecycle-recorder", Principal: "lifecycle-recorder"},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := Store{Pool: pool, WriterVersion: "integration-v1", WriterEpoch: strings.ReplaceAll(uuid.NewString(), "-", "") + "_1"}
	handler := ingest.LifecycleHandler{Identity: authorizer, Validator: authorizer, Store: store, NodeCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	server, clientFor := lifecycleSQLTLS(t, handler)
	request := func(client *http.Client, method, path string, body []byte, want int) []byte {
		t.Helper()
		req, e := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		raw, e := io.ReadAll(res.Body)
		if e != nil || res.StatusCode != want {
			t.Fatalf("HTTP %s: status=%d want=%d error=%v body=%s", path, res.StatusCode, want, e, raw)
		}
		return raw
	}
	watcherClient := clientFor(13, watcherSAN) // 0d is the issuer's byte-hex serial.
	runtimeClient := clientFor(10, runtimeSAN) // 0a, not the integer-text spelling a.
	get := "/internal/lifecycle/checkpoints?scope=" + url.QueryEscape(scope)
	var checkpoint ingest.LifecycleCheckpointResult
	if e := json.Unmarshal(request(watcherClient, http.MethodGet, get, nil, 200), &checkpoint); e != nil || checkpoint.Revision != 2 {
		t.Fatalf("GET checkpoint: %+v %v", checkpoint, e)
	}
	request(watcherClient, http.MethodGet, "/internal/lifecycle/checkpoints?scope=namespace/other", nil, 404)
	httpEpoch := watcherEpoch()
	httpBatch := envelope(httpEpoch, []any{record(watcherSAN, httpEpoch, 1, "")}, []any{}, scope, cursor("http-rv", 2))
	wire := rawBatch(httpBatch)
	decoded, e := ingest.DecodeLifecycleEnvelope(wire)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		ack := request(watcherClient, http.MethodPost, "/internal/lifecycle/events:batch", wire, 200)
		if e := ingest.ValidateLifecycleAck(ack, decoded); e != nil {
			t.Fatalf("production ACK: %v %s", e, ack)
		}
	}
	if count(`SELECT count(*) FROM audit.lifecycle_events WHERE source_epoch=$1`, httpEpoch) != 1 || count(`SELECT count(*) FROM audit.audit_outbox o JOIN audit.lifecycle_events l ON o.record_id=l.lifecycle_event_id::text WHERE l.source_epoch=$1 AND o.record_kind='lifecycle_event'`, httpEpoch) != 1 {
		t.Fatal("HTTP retry did not persist exactly one record/outbox")
	}
	if e := json.Unmarshal(request(watcherClient, http.MethodGet, get, nil, 200), &checkpoint); e != nil || checkpoint.Revision != 3 || checkpoint.ResourceVersion != "http-rv" {
		t.Fatalf("committed GET: %+v %v", checkpoint, e)
	}
	runtimeHTTPEpoch := epoch("boot-current")
	request(runtimeClient, http.MethodPost, "/internal/lifecycle/events:batch", rawBatch(envelope(runtimeHTTPEpoch, []any{record(runtimeSAN, runtimeHTTPEpoch, 1, "boot-current")}, []any{}, "", nil)), 200)
	if count(`SELECT count(*) FROM audit.lifecycle_events WHERE source_epoch=$1`, runtimeHTTPEpoch) != 1 {
		t.Fatal("runtime HTTP record missing")
	}
	exec(fixture, `UPDATE identity.issued_certificates SET revoked_at=now() WHERE serial='0d'`)
	request(watcherClient, http.MethodGet, get, nil, 403)
	exec(fixture, `UPDATE identity.issued_certificates SET revoked_at=NULL WHERE serial='0d'`)
	// A deferred trigger fails at COMMIT, after SQL returned a valid ACK. HTTP must
	// return 503 and all record/outbox/watermark writes must be absent.
	exec(fixture, `CREATE FUNCTION audit.test_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure' USING ERRCODE='23514'; END $$;
 CREATE CONSTRAINT TRIGGER test_commit_failure AFTER INSERT ON audit.audit_outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION audit.test_commit_failure()`)
	commitEpoch := watcherEpoch()
	commitWire := rawBatch(envelope(commitEpoch, []any{record(watcherSAN, commitEpoch, 1, "")}, []any{}, scope, nil))
	request(watcherClient, http.MethodPost, "/internal/lifecycle/events:batch", commitWire, 503)
	if count(`SELECT count(*) FROM audit.lifecycle_events WHERE source_epoch=$1`, commitEpoch) != 0 || count(`SELECT count(*) FROM audit.ingest_watermarks WHERE source_epoch=$1`, commitEpoch) != 0 {
		t.Fatal("failed COMMIT left lifecycle state")
	}
	exec(fixture, `DROP TRIGGER test_commit_failure ON audit.audit_outbox; DROP FUNCTION audit.test_commit_failure()`)
	request(watcherClient, http.MethodPost, "/internal/lifecycle/events:batch", commitWire, 200)

	// Issue #110: real HTTP and restricted SQL must commit incidents with the
	// accepted rows, and rejected input must never create phantom backlog.
	t.Run("batch_conflict_atomicity_and_watermark", func(t *testing.T) {
		conflictEpoch := watcherEpoch()
		original := record(watcherSAN, conflictEpoch, 1, "")
		request(watcherClient, http.MethodPost, "/internal/lifecycle/events:batch", rawBatch(envelope(conflictEpoch, []any{original}, []any{}, scope, nil)), 200)
		changed := make(map[string]any, len(original))
		for k, v := range original {
			changed[k] = v
		}
		changed["pod_name"] = "conflicting-pod"
		delete(changed, "record_digest")
		changed["record_digest"], e = canonical.CanonicalDigest(changed)
		if e != nil {
			t.Fatal(e)
		}
		incidents := func() int {
			return count(`SELECT count(*) FROM audit.event_conflicts WHERE record_id=$1 AND source_id=$2 AND existing_digest=$3 AND rejected_digest=$4`, original["lifecycle_event_id"], watcherSAN, original["record_digest"], changed["record_digest"])
		}
		state := func(wantRows, wantMax, wantAck, wantIncidents int) {
			t.Helper()
			if count(`SELECT count(*) FROM audit.lifecycle_events WHERE source_epoch=$1`, conflictEpoch) != wantRows ||
				count(`SELECT count(*) FROM audit.audit_outbox o JOIN audit.lifecycle_events l ON l.lifecycle_event_id::text=o.record_id WHERE o.record_kind='lifecycle_event' AND l.source_epoch=$1`, conflictEpoch) != wantRows ||
				count(`SELECT max_seen FROM audit.ingest_watermarks WHERE source_id=$1 AND source_epoch=$2`, watcherSAN, conflictEpoch) != wantMax ||
				count(`SELECT acked_through FROM audit.ingest_watermarks WHERE source_id=$1 AND source_epoch=$2`, watcherSAN, conflictEpoch) != wantAck || incidents() != wantIncidents {
				t.Fatalf("unexpected persisted state: rows=%d max=%d ack=%d incidents=%d", count(`SELECT count(*) FROM audit.lifecycle_events WHERE source_epoch=$1`, conflictEpoch), count(`SELECT max_seen FROM audit.ingest_watermarks WHERE source_id=$1 AND source_epoch=$2`, watcherSAN, conflictEpoch), count(`SELECT acked_through FROM audit.ingest_watermarks WHERE source_id=$1 AND source_epoch=$2`, watcherSAN, conflictEpoch), incidents())
			}
			if count(`SELECT count(*) FROM audit.lifecycle_events WHERE lifecycle_event_id=$1 AND record_digest=$2 AND pod_name='test-pod'`, original["lifecycle_event_id"], original["record_digest"]) != 1 {
				t.Fatal("conflict changed the original record")
			}
		}
		post := func(b map[string]any) map[string]any {
			t.Helper()
			wire := rawBatch(b)
			raw := request(watcherClient, http.MethodPost, "/internal/lifecycle/events:batch", wire, 200)
			decoded, err := ingest.DecodeLifecycleEnvelope(wire)
			if err != nil {
				t.Fatal(err)
			}
			if err := ingest.ValidateLifecycleAck(raw, decoded); err != nil {
				t.Fatal(err)
			}
			var ack map[string]any
			if err := json.Unmarshal(raw, &ack); err != nil {
				t.Fatal(err)
			}
			return ack
		}
		r2 := record(watcherSAN, conflictEpoch, 2, "")
		partial := post(envelope(conflictEpoch, []any{r2, changed}, []any{}, scope, cursor("partial", 3)))
		if through(partial) != 2 || partial["checkpoint"] != nil || len(partial["accepted_ids"].([]any)) != 1 || len(partial["rejected"].([]any)) != 1 {
			t.Fatalf("mixed conflict ACK: %v", partial)
		}
		state(2, 2, 2, 1)
		// Failure occurs after a good row/outbox has been inserted. No success ACK
		// or partial state may escape when the incident INSERT fails.
		exec(fixture, `CREATE FUNCTION audit.test_incident_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected incident failure' USING ERRCODE='23514'; END $$;
 CREATE TRIGGER test_incident_failure BEFORE INSERT ON audit.event_conflicts FOR EACH ROW EXECUTE FUNCTION audit.test_incident_failure()`)
		r3 := record(watcherSAN, conflictEpoch, 3, "")
		request(watcherClient, http.MethodPost, "/internal/lifecycle/events:batch", rawBatch(envelope(conflictEpoch, []any{r3, changed}, []any{}, scope, cursor("failed-incident", 3))), 503)
		state(2, 2, 2, 1)
		exec(fixture, `DROP TRIGGER test_incident_failure ON audit.event_conflicts; DROP FUNCTION audit.test_incident_failure()`)
		rangeInput := func(from, to int64) map[string]any {
			d, err := canonical.AbandonedRangeDigest(watcherSAN, "lifecycle", conflictEpoch, from, to, "record_rejected")
			if err != nil {
				t.Fatal(err)
			}
			return map[string]any{"from_seq": from, "to_seq": to, "reason": "record_rejected", "range_digest": d}
		}
		badHigh := record(watcherSAN, conflictEpoch, 1000, "")
		badHigh["record_digest"] = strings.Repeat("0", 64)
		// These rejected IDs have no existing same-source record for the helper.
		partial = post(envelope(conflictEpoch, []any{badHigh}, []any{rangeInput(1, 100)}, scope, cursor("rejected-high", 3)))
		if partial["checkpoint"] != nil || len(partial["rejected"].([]any)) != 2 {
			t.Fatalf("rejected high input: %v", partial)
		}
		state(2, 2, 2, 1)
		// Real pending sequence 4 still blocks a cursor-only request until 3 arrives.
		post(envelope(conflictEpoch, []any{record(watcherSAN, conflictEpoch, 4, "")}, []any{}, scope, nil))
		state(3, 4, 2, 1)
		if ack := post(envelope(conflictEpoch, []any{}, []any{}, scope, cursor("backlog", 3))); ack["checkpoint"] != nil {
			t.Fatalf("cursor passed pending record: %v", ack)
		}
		post(envelope(conflictEpoch, []any{r3}, []any{}, scope, nil))
		state(4, 4, 4, 1)
		bookmark := envelope(conflictEpoch, []any{}, []any{}, scope, cursor("after-rejections", 3))
		for i := 0; i < 2; i++ {
			ack := post(bookmark)
			if cp, ok := ack["checkpoint"].(map[string]any); !ok || cp["checkpoint_revision"] != float64(4) || cp["resource_version"] != "after-rejections" {
				t.Fatalf("cursor-only after rejection/retry: %v", ack)
			}
		}
		if ack := post(envelope(conflictEpoch, []any{}, []any{}, scope, cursor("stale", 3))); ack["checkpoint"] != nil {
			t.Fatalf("stale cursor bypassed CAS: %v", ack)
		}
		// Accepted and duplicate ranges update only real stored coverage. A record
		// inside an abandoned range has no original row and must not raise 42501.
		for i := 0; i < 2; i++ {
			post(envelope(conflictEpoch, []any{}, []any{rangeInput(5, 6)}, scope, nil))
			state(4, 6, 6, 1)
		}
		partial = post(envelope(conflictEpoch, []any{record(watcherSAN, conflictEpoch, 5, "")}, []any{rangeInput(6, 200)}, scope, cursor("abandoned-overlap", 4)))
		if partial["checkpoint"] != nil || len(partial["rejected"].([]any)) != 2 {
			t.Fatalf("abandoned conflict: %v", partial)
		}
		state(4, 6, 6, 1)
		ack := post(envelope(conflictEpoch, []any{}, []any{}, scope, cursor("after-abandoned", 4)))
		if cp, ok := ack["checkpoint"].(map[string]any); !ok || cp["checkpoint_revision"] != float64(5) {
			t.Fatalf("abandoned conflict poisoned bookmark: %v", ack)
		}
	})

}

func lifecycleSQLTLS(t *testing.T, handler http.Handler) (*httptest.Server, func(int64, string) *http.Client) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1000), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, san string, usage x509.ExtKeyUsage) tls.Certificate {
		t.Helper()
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		uri, err := url.Parse(san)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{issue(1001, "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer", x509.ExtKeyUsageServerAuth)}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, func(serial int64, san string) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{issue(serial, san, x509.ExtKeyUsageClientAuth)}}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}
}
