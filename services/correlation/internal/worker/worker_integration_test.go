//go:build integration

package worker

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/results"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestWorkerPostgres goes from inserted audit, lifecycle and TASK-03 rows to
// stored correlation revisions on a disposable PostgreSQL 16 database with
// every merged migration, using a login that holds only correlation_writer
// and audit_producer.
func TestWorkerPostgres(t *testing.T) {
	dsn := os.Getenv("CORRELATION_WORKER_TEST_DSN")
	if dsn == "" {
		t.Skip("set disposable CORRELATION_WORKER_TEST_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	dbName, writer := "corrworker_"+suffix, "corrworker_login_"+suffix
	run := func(c *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("SQL: %v\n%.300s", err, sql)
		}
	}
	run(admin, "CREATE DATABASE "+dbName)
	run(admin, "CREATE ROLE "+writer+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+dbName+" WITH (FORCE)")
		_, _ = admin.Exec(context.Background(), "DROP ROLE "+writer)
	}()
	cfg, _ := pgx.ParseConfig(dsn)
	cfg.Database = dbName
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())
	run(db, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$`)
	files, _ := filepath.Glob("../../../../migrations/*.up.sql")
	slices.Sort(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		run(db, string(raw))
	}
	// Stand-in for the TASK-03 grant TASK-10 3.1 requested (attempt_observations
	// and the attempt -> action relation). The audit reads come from the real
	// TASK-07 migration.
	run(db, "GRANT USAGE ON SCHEMA coordinator TO correlation_reader")
	run(db, "GRANT SELECT ON coordinator.attempt_observations TO correlation_reader")
	run(db, "GRANT SELECT (attempt_id, action_id, adapter_node_uid) ON coordinator.attempts TO correlation_reader")
	source := "correlation-worker-" + suffix
	run(db, "GRANT correlation_writer, audit_producer TO "+writer)
	run(db, `INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES($1,$2,false)`, writer, source)
	run(db, `INSERT INTO audit.producer_event_grants(source_id,event_type,tenant) VALUES($1,'kernel_correlation_checked','*')`, source)
	pc, _ := pgxpool.ParseConfig(dsn)
	pc.ConnConfig.Database, pc.ConnConfig.User = dbName, writer
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	cluster, node := uuid.New(), uuid.New()
	adapterPod, execPod := uuid.New(), uuid.New()
	adapterContainer, execContainer := strings.Repeat("a", 64), strings.Repeat("b", 64)
	workloads := map[uuid.UUID]string{adapterPod: "agent-adapters/receiver-sender", execPod: "agent-exec/runtime"}
	resolve := func(p uuid.UUID) *string {
		if w, ok := workloads[p]; ok {
			return &w
		}
		return nil
	}
	w := Worker{Pool: pool, Results: results.Store{Pool: pool, Config: results.Config{SourceID: source, Version: "test", Epoch: "1", Tenant: "*"}},
		ClusterUID: cluster, AlgorithmVersion: "tuple-v1", Workloads: resolve}
	base := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Millisecond)
	for pod, container := range map[uuid.UUID]string{adapterPod: adapterContainer, execPod: execContainer} {
		run(db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,started_at,end_quality,mapping_version,source_event_ids)
			VALUES(gen_random_uuid(),$1,$2,$3,'boot-1',$4,$5,'open',1,ARRAY[gen_random_uuid()])`, cluster, pod, node, container, base.Add(-time.Hour))
	}
	run(db, `INSERT INTO correlation.tuple_normalization_rules VALUES('tuple-v1','10.96.0.20',443,'10.0.2.0/24',8443,'vip','vip','q0-run-1')`)
	const netns = 4026531992
	sequence := int64(0)
	kernel := func(kind, container string, at time.Time, sport int, dest string, sock string) uuid.UUID {
		t.Helper()
		sequence++
		id := uuid.New()
		var state, process any = nil, "exec-" + container[:4]
		if kind == "tcp_state" {
			state, process = 1, nil
		}
		run(db, `INSERT INTO audit.kernel_events(source_event_id,source_id,sensor_id,source_epoch,source_sequence,exporter_instance_id,sensor_generation,node_uid,boot_id,source_time,spooled_at,received_at,event_type,process_exec_id,container_id,netns_inode,saddr,sport,daddr,dport,sock_ptr,tcp_new_state,metadata_status,normalization_version,rule_hash,coverage,safe_attributes,record_digest)
			VALUES($1,'sensor','sensor-1','1',$2,'exp-1',1,$3,'boot-1',$4,$4,$4,$5,$6,$7,$8,'10.0.1.5',$9,$10::inet,443,$11,$12,'resolved','v1',$13,'full','{}',$13)`,
			id, sequence, node, at, kind, process, container, netns, sport, dest, sock, state, strings.Repeat("e", 64))
		return id
	}
	observe := func(at time.Time, sport int) (uuid.UUID, uuid.UUID) {
		t.Helper()
		attempt, action := uuid.New(), uuid.New()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		// TASK-03 owns the reservation chain; fixture rows skip its FK triggers.
		if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO coordinator.attempts(attempt_id,action_id,reservation_id,adapter_id,adapter_node_uid,state,created_at,updated_at) VALUES($1,$2,gen_random_uuid(),'receiver-sender',$3,'dispatched',now(),now())`, attempt, action, node); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO coordinator.attempt_observations(attempt_id,local_addr,local_port,peer_addr,peer_port,netns_inode,pod_uid,connect_started_at,send_started_at,recorded_at) VALUES($1,'10.0.1.5',$2,'10.96.0.20',443,4026531992,$3,$4,$4::timestamptz+interval '100 milliseconds',now())`, attempt, sport, adapterPod, at); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return attempt, action
	}
	latest := func(kernel uuid.UUID) results.Result {
		t.Helper()
		r, err := w.Results.Latest(ctx, kernel)
		if err != nil {
			t.Fatalf("latest %s: %v", kernel, err)
		}
		return r
	}

	confirmedAttempt, confirmedAction := observe(base, 40001)
	confirmed := kernel("tcp_connect", adapterContainer, base.Add(10*time.Millisecond), 40001, "10.96.0.20", "00000000000000aa")
	kernel("tcp_state", adapterContainer, base.Add(20*time.Millisecond), 40001, "10.96.0.20", "00000000000000aa")
	observe(base.Add(time.Second), 40002)
	stateMissing := kernel("tcp_connect", adapterContainer, base.Add(time.Second+10*time.Millisecond), 40002, "10.96.0.20", "00000000000000ab")
	execConnect := kernel("tcp_connect", execContainer, base.Add(2*time.Second), 40003, "10.96.0.20", "00000000000000ac")
	unknown := kernel("tcp_connect", strings.Repeat("c", 64), base.Add(3*time.Second), 40004, "10.96.0.20", "00000000000000ad")
	// No measured rule for this destination: never confirmed.
	observe(base.Add(4*time.Second), 40005)
	run(db, `UPDATE coordinator.attempt_observations SET peer_addr='198.51.100.7' WHERE local_port=40005`)
	unmeasured := kernel("tcp_connect", adapterContainer, base.Add(4*time.Second+10*time.Millisecond), 40005, "198.51.100.7", "00000000000000ae")
	kernel("tcp_state", adapterContainer, base.Add(4*time.Second+20*time.Millisecond), 40005, "198.51.100.7", "00000000000000ae")

	t.Run("stored_rows_become_correlations", func(t *testing.T) {
		n, err := w.Run(ctx, node, base.Add(-time.Minute), base.Add(time.Minute), time.Now())
		if err != nil || n != 5 {
			t.Fatalf("written %d %v", n, err)
		}
		c := latest(confirmed)
		if c.Confidence != "confirmed" || c.AttemptID == nil || *c.AttemptID != confirmedAttempt || c.ActionID == nil || *c.ActionID != confirmedAction || c.CandidateCount != 1 || c.Method != Method ||
			!slices.Contains(c.EvidenceRefs, "q0_run:q0-run-1") || !slices.Contains(c.EvidenceRefs, "attempt:"+confirmedAttempt.String()) || !slices.Contains(c.EvidenceRefs, "process_exec:exec-aaaa") {
			t.Fatalf("confirmed %+v", c)
		}
		if r := latest(stateMissing); r.Confidence != "workload_inferred" || r.Reason != "state_event_missing" || r.AttemptID != nil {
			t.Fatalf("state missing %+v", r)
		}
		if r := latest(execConnect); r.Confidence != "workload_inferred" || r.WorkloadID == nil || *r.WorkloadID != "agent-exec/runtime" || r.AttemptID != nil {
			t.Fatalf("exec %+v", r)
		}
		if r := latest(unknown); r.Confidence != "unlinked" || r.WorkloadID != nil {
			t.Fatalf("unknown container %+v", r)
		}
		if r := latest(unmeasured); r.Confidence != "workload_inferred" || r.AttemptID != nil {
			t.Fatalf("unmeasured destination %+v", r)
		}
		var events int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM audit.audit_events WHERE event_type='kernel_correlation_checked'`).Scan(&events); err != nil || events != 5 {
			t.Fatalf("audit events %d %v", events, err)
		}
	})
	t.Run("rerun_is_idempotent", func(t *testing.T) {
		if n, err := w.Run(ctx, node, base.Add(-time.Minute), base.Add(time.Minute), time.Now()); err != nil || n != 0 {
			t.Fatalf("rerun wrote %d %v", n, err)
		}
	})
	t.Run("late_ambiguity_appends_revision", func(t *testing.T) {
		// A second observation of the same socket arrives later: the pair is no
		// longer unique, so a new revision lowers confidence and keeps revision 1.
		observe(base, 40001)
		if n, err := w.Run(ctx, node, base.Add(-time.Minute), base.Add(time.Minute), time.Now()); err != nil || n != 1 {
			t.Fatalf("late rerun wrote %d %v", n, err)
		}
		r := latest(confirmed)
		if r.Revision != 2 || r.Confidence != "workload_inferred" || r.CandidateCount != 2 || r.AttemptID != nil {
			t.Fatalf("revision %+v", r)
		}
		var kept string
		if err := db.QueryRow(ctx, `SELECT confidence FROM correlation.correlations WHERE kernel_event_id=$1 AND revision=1`, confirmed).Scan(&kept); err != nil || kept != "confirmed" {
			t.Fatalf("revision 1 %s %v", kept, err)
		}
	})
	t.Run("newer_mapping_version_keeps_confirmed", func(t *testing.T) {
		// The lifecycle store appends a second version (netns filled); only the
		// latest version is read, so the mapping stays unique.
		run(db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,netns_inode,started_at,end_quality,mapping_version,source_event_ids)
			VALUES(gen_random_uuid(),$1,$2,$3,'boot-1',$4,4026531992,$5,'open',2,ARRAY[gen_random_uuid()])`, cluster, adapterPod, node, adapterContainer, base.Add(-time.Hour))
		later := base.Add(20 * time.Second)
		attempt, _ := observe(later, 40011)
		id := kernel("tcp_connect", adapterContainer, later.Add(10*time.Millisecond), 40011, "10.96.0.20", "00000000000000b1")
		kernel("tcp_state", adapterContainer, later.Add(20*time.Millisecond), 40011, "10.96.0.20", "00000000000000b1")
		if _, err := w.Run(ctx, node, later.Add(-time.Second), later.Add(time.Second), time.Now()); err != nil {
			t.Fatal(err)
		}
		if r := latest(id); r.Confidence != "confirmed" || r.AttemptID == nil || *r.AttemptID != attempt {
			t.Fatalf("second mapping version broke the unique mapping: %+v", r)
		}
	})
	t.Run("bad_observation_row_does_not_fail_the_run", func(t *testing.T) {
		at := base.Add(40 * time.Second)
		observe(at, 40021)
		run(db, `UPDATE coordinator.attempt_observations SET local_addr='0.0.0.0' WHERE local_port=40021`)
		id := kernel("tcp_connect", adapterContainer, at.Add(10*time.Millisecond), 40022, "10.96.0.20", "00000000000000b2")
		if _, err := w.Run(ctx, node, at.Add(-time.Second), at.Add(time.Second), time.Now()); err != nil {
			t.Fatalf("one unspecified-address observation failed the run: %v", err)
		}
		if r := latest(id); r.Confidence != "workload_inferred" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("unresolved_metadata_is_recorded", func(t *testing.T) {
		at := base.Add(50 * time.Second)
		id := kernel("tcp_connect", adapterContainer, at, 40031, "10.96.0.20", "00000000000000b3")
		run(db, `UPDATE audit.kernel_events SET container_id=NULL WHERE source_event_id=$1`, id)
		if _, err := w.Run(ctx, node, at.Add(-time.Second), at.Add(time.Second), time.Now()); err != nil {
			t.Fatal(err)
		}
		if r := latest(id); r.Confidence != "unlinked" || !slices.Contains(r.Limitations, "metadata_unresolved") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("recent_window_waits_for_ingest", func(t *testing.T) {
		if n, err := w.Run(ctx, node, time.Now().Add(-30*time.Second), time.Now(), time.Now()); err != nil || n != 0 {
			t.Fatalf("a window younger than MinDelay was correlated: %d %v", n, err)
		}
	})
	t.Run("writer_reads_only_granted_sources", func(t *testing.T) {
		for _, sql := range []string{"SELECT * FROM audit.audit_events LIMIT 1", "UPDATE correlation.correlations SET reason='x'", "DELETE FROM audit.kernel_events"} {
			if _, err := pool.Exec(ctx, sql); err == nil {
				t.Fatalf("writer allowed %s", sql)
			}
		}
	})
}
