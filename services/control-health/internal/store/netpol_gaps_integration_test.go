package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNetpolGapPostgres applies every merged migration plus the M2-9 ones to a
// disposable PostgreSQL 16 database and checks that an expired netpol-collector
// lease opens exactly one NETPOL_COLLECTOR_STOPPED gap with its audit events,
// starting at the last acknowledged record, and never a hold.
func TestNetpolGapPostgres(t *testing.T) {
	dsn := os.Getenv("HEALTH_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set HEALTH_TEST_ADMIN_DSN for disposable PostgreSQL integration")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	roles := func() []string {
		rows, err := admin.Query(ctx, "SELECT rolname FROM pg_roles ORDER BY 1")
		if err != nil {
			t.Fatal(err)
		}
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return names
	}
	before := roles()
	suffix := uuid.NewString()[:8]
	database, login := "netpolgap_"+suffix, "netpolgap_login_"+suffix
	run := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%v: %.200s", err, q)
		}
	}
	run(admin, "CREATE DATABASE "+database)
	defer func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE "+database+" WITH(FORCE)")
		// Roles are cluster-wide: drop the ones created here so other suites in
		// the same cluster install with their own migrator.
		for _, role := range roles() {
			if !slices.Contains(before, role) {
				if _, err := admin.Exec(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
					t.Errorf("cleanup role %s: %v", role, err)
				}
			}
		}
	}()
	cfg, _ := pgx.ParseConfig(dsn)
	cfg.Database = database
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../../../..")
	run(db, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$`)
	files, _ := filepath.Glob(filepath.Join(root, "migrations/*.up.sql"))
	slices.Sort(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		run(db, string(raw))
	}
	run(admin, "CREATE ROLE "+login+" LOGIN")
	run(db, "GRANT control_health_writer,audit_producer TO "+login)
	run(db, "INSERT INTO audit.db_role_sources VALUES($1,'health-source',false)", login)
	run(db, "INSERT INTO audit.producer_event_grants VALUES ('health-source','source_health_changed','*'),('health-source','observation_gap_recorded','*')")
	pc, _ := pgxpool.ParseConfig(dsn)
	pc.ConnConfig.Database, pc.ConnConfig.User = database, login
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s, err := New(pool, Config{AuditSourceID: "health-source", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	s.Epoch = "1"
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	lease := func(node uuid.UUID, until string) {
		run(db, `INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,observed_state,details,lease_until,reported_at,first_reported_at)
			VALUES('netpol-'||$1::text,'netpol-collector','node',$1::text,$1::uuid,'boot-1','healthy','{}',now()+$2::interval,now()-interval '20 seconds',now()-interval '10 minutes')
			ON CONFLICT(source_id,component) DO UPDATE SET lease_until=excluded.lease_until`, node, until)
	}
	acked := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	node := uuid.New()
	run(db, `INSERT INTO correlation.network_policy_watermarks VALUES($1,'e1',7,$2,$2,NULL,NULL)`, node, acked)

	t.Run("live_lease_has_no_gap", func(t *testing.T) {
		lease(node, "10 seconds")
		if err := s.RecordNetpolGaps(ctx); err != nil {
			t.Fatal(err)
		}
		if count("SELECT count(*) FROM health.observation_gaps") != 0 {
			t.Fatal("gap for a live collector")
		}
	})
	t.Run("expired_lease_records_one_gap", func(t *testing.T) {
		lease(node, "-1 second")
		for i := 0; i < 2; i++ {
			if err := s.RecordNetpolGaps(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var start time.Time
		var state, quality, source string
		if err := db.QueryRow(ctx, "SELECT start_at,recovery_state,count_quality,source_id FROM health.observation_gaps WHERE stage='network_policy_log' AND reason='NETPOL_COLLECTOR_STOPPED' AND node_uid=$1", node).Scan(&start, &state, &quality, &source); err != nil {
			t.Fatal(err)
		}
		if !start.Equal(acked) || state != "open" || quality != "unknown" || source != "netpol-node/"+node.String() {
			t.Fatalf("gap start=%v state=%s quality=%s source=%s", start, state, quality, source)
		}
		if count("SELECT count(*) FROM health.observation_gaps") != 1 || count("SELECT count(*) FROM audit.audit_events WHERE event_type='observation_gap_recorded'") != 1 || count("SELECT count(*) FROM audit.audit_events WHERE event_type='source_health_changed'") != 1 {
			t.Fatal("gap or audit not recorded once")
		}
		if count("SELECT count(*) FROM health.holds") != 0 {
			t.Fatal("netpol collector outage created a hold")
		}
	})
	t.Run("final_flush_waits_for_grace", func(t *testing.T) {
		flushed := uuid.New()
		at := time.Now().UTC().Add(-150 * time.Second).Truncate(time.Microsecond)
		run(db, `INSERT INTO correlation.network_policy_watermarks VALUES($1,'e1',3,$2,$2,3,$2)`, flushed, at)
		lease(flushed, "-1 second")
		if err := s.RecordNetpolGaps(ctx); err != nil {
			t.Fatal(err)
		}
		if count("SELECT count(*) FROM health.observation_gaps WHERE node_uid=$1", flushed) != 0 {
			t.Fatal("gap opened inside the final flush grace")
		}
		lease(flushed, "-121 seconds")
		if err := s.RecordNetpolGaps(ctx); err != nil {
			t.Fatal(err)
		}
		var start time.Time
		if err := db.QueryRow(ctx, "SELECT start_at FROM health.observation_gaps WHERE node_uid=$1", flushed).Scan(&start); err != nil || !start.Equal(at) {
			t.Fatalf("final flush gap start %v %v", start, err)
		}
	})
	t.Run("never_acked_starts_at_first_lease", func(t *testing.T) {
		fresh := uuid.New()
		lease(fresh, "-1 second")
		if err := s.RecordNetpolGaps(ctx); err != nil {
			t.Fatal(err)
		}
		var start, first time.Time
		if err := db.QueryRow(ctx, "SELECT g.start_at,l.first_reported_at FROM health.observation_gaps g JOIN health.control_health_leases l ON l.node_uid=g.node_uid AND l.component='netpol-collector' WHERE g.node_uid=$1", fresh).Scan(&start, &first); err != nil || !start.Equal(first) {
			t.Fatalf("gap start %v first lease %v %v", start, first, err)
		}
	})
	t.Run("replaced_collector_pod_keeps_node_open", func(t *testing.T) {
		// A replaced collector leaves an expired row beside the live one.
		replaced := uuid.New()
		lease(replaced, "10 seconds")
		run(db, `INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,observed_state,details,lease_until,reported_at,first_reported_at)
			VALUES('netpol-old-'||$1::text,'netpol-collector','node',$1::text,$1::uuid,'boot-1','healthy','{}',now()-interval '1 hour',now()-interval '61 minutes',now()-interval '2 hours')`, replaced)
		if err := s.RecordNetpolGaps(ctx); err != nil {
			t.Fatal(err)
		}
		if count("SELECT count(*) FROM health.observation_gaps WHERE node_uid=$1", replaced) != 0 {
			t.Fatal("expired row of a replaced Pod opened a gap for a live collector")
		}
	})
	t.Run("closed_gap_not_reopened_while_delivering", func(t *testing.T) {
		delivering := uuid.New()
		lease(delivering, "-3 seconds")
		run(db, `INSERT INTO correlation.network_policy_watermarks VALUES($1,'e1',5,now()-interval '1 minute',now(),NULL,NULL)`, delivering)
		before := count("SELECT count(*) FROM audit.audit_events WHERE event_type='observation_gap_recorded'")
		for i := 0; i < 4; i++ {
			if err := s.RecordNetpolGaps(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if count("SELECT count(*) FROM health.observation_gaps WHERE node_uid=$1", delivering) != 0 || count("SELECT count(*) FROM audit.audit_events WHERE event_type='observation_gap_recorded'") != before {
			t.Fatal("a collector that acked after its lease ended got a gap")
		}
	})
	t.Run("stale_late_ack_does_not_suppress_gap", func(t *testing.T) {
		stale := uuid.New()
		run(db, `INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,observed_state,details,lease_until,reported_at,first_reported_at)
			VALUES('netpol-'||$1::text,'netpol-collector','node',$1::text,$1::uuid,'boot-1','healthy','{}',now()-interval '10 minutes',now()-interval '11 minutes',now()-interval '1 hour')`, stale)
		run(db, `INSERT INTO correlation.network_policy_watermarks VALUES($1,'e1',4,now()-interval '20 minutes',now()-interval '5 minutes',NULL,NULL)`, stale)
		if err := s.RecordNetpolGaps(ctx); err != nil {
			t.Fatal(err)
		}
		if count("SELECT count(*) FROM health.observation_gaps WHERE node_uid=$1", stale) != 1 {
			t.Fatal("one late acknowledgement suppressed the gap forever")
		}
	})
	t.Run("final_flush_grace_wins_over_late_ack", func(t *testing.T) {
		flushed := uuid.New()
		run(db, `INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,observed_state,details,lease_until,reported_at,first_reported_at)
			VALUES('netpol-'||$1::text,'netpol-collector','node',$1::text,$1::uuid,'boot-1','healthy','{}',now()-interval '130 seconds',now()-interval '140 seconds',now()-interval '1 hour')`, flushed)
		run(db, `INSERT INTO correlation.network_policy_watermarks VALUES($1,'e1',3,now()-interval '3 minutes',now()-interval '1 second',3,now()-interval '3 minutes')`, flushed)
		if err := s.RecordNetpolGaps(ctx); err != nil {
			t.Fatal(err)
		}
		if count("SELECT count(*) FROM health.observation_gaps WHERE node_uid=$1", flushed) != 1 {
			t.Fatal("a recent ack kept the gap closed after the final flush grace")
		}
	})
	t.Run("never_acked_restart_keeps_conservative_start", func(t *testing.T) {
		restarted := uuid.New()
		run(db, `INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,observed_state,details,lease_until,reported_at,first_reported_at) VALUES
			('netpol-a-'||$1::text,'netpol-collector','node',$1::text,$1::uuid,'boot-1','healthy','{}',now()-interval '30 minutes',now()-interval '31 minutes',now()-interval '2 hours'),
			('netpol-b-'||$1::text,'netpol-collector','node',$1::text,$1::uuid,'boot-1','healthy','{}',now()-interval '1 minute',now()-interval '70 seconds',now()-interval '20 minutes')`, restarted)
		if err := s.RecordNetpolGaps(ctx); err != nil {
			t.Fatal(err)
		}
		var start, oldest time.Time
		if err := db.QueryRow(ctx, "SELECT g.start_at,(SELECT min(first_reported_at) FROM health.control_health_leases WHERE node_uid=$1) FROM health.observation_gaps g WHERE g.node_uid=$1", restarted).Scan(&start, &oldest); err != nil || !start.Equal(oldest) {
			t.Fatalf("restart shortened the gap: start %v oldest first lease %v %v", start, oldest, err)
		}
	})
	t.Run("writer_has_no_direct_gap_insert", func(t *testing.T) {
		for name, sql := range map[string]string{
			"collector gap":      `INSERT INTO health.observation_gaps(gap_id,stage,reason,node_uid,source_id,start_at,count_quality,evidence_refs,recovery_state,created_by) VALUES(gen_random_uuid(),'network_policy_log','NETPOL_COLLECTOR_STOPPED',gen_random_uuid(),'netpol-node/x',now(),'unknown','[]','open','TASK-10')`,
			"created_by TASK-07": `INSERT INTO health.observation_gaps(gap_id,stage,reason,start_at,count_quality,recovery_state,created_by) VALUES(gen_random_uuid(),'lifecycle_capture','SEQUENCE_RANGE_ABANDONED',now(),'exact','unrecoverable','TASK-07')`,
		} {
			if _, err := pool.Exec(ctx, sql); err == nil {
				t.Fatalf("control_health_writer inserted a gap directly: %s", name)
			}
		}
		if _, err := pool.Exec(ctx, "SELECT health.record_netpol_collector_gap(NULL,'b',now(),'[]')"); err == nil {
			t.Fatal("definer function accepted a NULL node")
		}
		var source, createdBy string
		fresh := uuid.New()
		var gap string
		if err := pool.QueryRow(ctx, "SELECT health.record_netpol_collector_gap($1,'b',now(),'[]')::text", fresh).Scan(&gap); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(ctx, "SELECT source_id,created_by FROM health.observation_gaps WHERE gap_id=$1::uuid", gap).Scan(&source, &createdBy); err != nil || source != "netpol-node/"+fresh.String() || createdBy != "TASK-10" {
			t.Fatalf("definer fixed values %s %s %v", source, createdBy, err)
		}
	})
	t.Run("writer_cannot_set_created_at", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `INSERT INTO health.observation_gaps(gap_id,stage,reason,node_uid,source_id,start_at,count_quality,evidence_refs,recovery_state,created_by,created_at)
			VALUES(gen_random_uuid(),'network_policy_log','NETPOL_COLLECTOR_STOPPED',gen_random_uuid(),'netpol-node/x',now(),'unknown','[]','open','TASK-10',now()-interval '1 day')`); err == nil {
			t.Fatal("control_health_writer set created_at on a gap")
		}
	})
	t.Run("audit_failure_rolls_back_gap", func(t *testing.T) {
		other := uuid.New()
		lease(other, "-1 second")
		run(db, "DELETE FROM audit.producer_event_grants WHERE event_type='observation_gap_recorded'")
		if err := s.RecordNetpolGaps(ctx); err == nil {
			t.Fatal("gap committed without its audit event")
		}
		if count("SELECT count(*) FROM health.observation_gaps WHERE node_uid=$1", other) != 0 {
			t.Fatal("partial gap commit")
		}
	})
}
