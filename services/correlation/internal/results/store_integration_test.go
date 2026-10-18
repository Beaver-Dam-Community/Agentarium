//go:build integration

package results

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A disposable cluster is required: installation uses an actual non-superuser
// database owner and calls run through a separate restricted producer login.
func TestResultsPostgres(t *testing.T) {
	dsn := os.Getenv("CORRELATION_RESULTS_TEST_DSN")
	if dsn == "" {
		t.Skip("set disposable CORRELATION_RESULTS_TEST_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	dbName, installer, writer := "corrdb_"+suffix, "corrinst_"+suffix, "corrwriter_"+suffix
	exec := func(c *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("SQL: %v\n%s", err, sql)
		}
	}
	exec(admin, "CREATE ROLE "+installer+" LOGIN NOSUPERUSER NOCREATEDB CREATEROLE")
	exec(admin, "CREATE ROLE "+writer+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	exec(admin, "CREATE DATABASE "+dbName+" OWNER "+installer)
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+dbName+" WITH (FORCE)")
		_, _ = admin.Exec(context.Background(), "DROP ROLE "+writer)
		// The disposable cluster owns any group-role memberships left by migrations.
		_, _ = admin.Exec(context.Background(), "DROP ROLE "+installer)
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
	install := connect(installer)
	for _, name := range []string{"20261016132230_audit_store.up.sql", "20261016132231_health_control_health.up.sql", "20261016143437_correlation_lifecycle_intervals.up.sql", "20261017114452_correlation_results.up.sql"} {
		raw, err := os.ReadFile(filepath.Join("../../../../migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		exec(install, string(raw))
	}
	fixture := connect(admin.Config().User)
	source := "correlation-test-" + suffix
	exec(fixture, "GRANT correlation_writer TO "+writer)
	exec(fixture, `INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES($1,$2,false)`, writer, source)
	exec(fixture, `INSERT INTO audit.producer_event_grants(source_id,event_type,tenant) VALUES($1,'kernel_correlation_checked','*')`, source)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database, cfg.ConnConfig.User, cfg.MaxConns = dbName, writer, 16
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := Store{Pool: pool, Config: Config{SourceID: source, Version: "test-v1", Epoch: "instance-1", Tenant: "*"}}
	var who string
	var super, createrole bool
	if err := pool.QueryRow(ctx, `SELECT current_user,rolsuper,rolcreaterole FROM pg_roles WHERE rolname=current_user`).Scan(&who, &super, &createrole); err != nil || who != writer || super || createrole {
		t.Fatalf("runtime identity: %s %v %v %v", who, super, createrole, err)
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := fixture.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	checkCounts := func(kernel uuid.UUID, want int) {
		t.Helper()
		for label, sql := range map[string]string{
			"results": `SELECT count(*) FROM correlation.correlations WHERE kernel_event_id=$1`,
			"audit":   `SELECT count(*) FROM audit.audit_events WHERE event_type='kernel_correlation_checked' AND safe_payload->>'kernel_event_id'=$1::text`,
			"outbox":  `SELECT count(*) FROM audit.audit_outbox o JOIN audit.audit_events a ON a.event_id::text=o.record_id WHERE o.record_kind='audit_event' AND a.event_type='kernel_correlation_checked' AND a.safe_payload->>'kernel_event_id'=$1::text`,
		} {
			if n := count(sql, kernel); n != want {
				t.Fatalf("%s count=%d want=%d", label, n, want)
			}
		}
	}
	makeResult := func() Result {
		action, attempt := uuid.New(), uuid.New()
		workload := "workload-test"
		return Result{KernelEventID: uuid.New(), ActionID: &action, AttemptID: &attempt, WorkloadID: &workload, Confidence: "confirmed", Method: "tuple_interval", AlgorithmVersion: "test-v1", Reason: "single matching attempt", EvidenceRefs: []string{"fixture:kernel", "fixture:attempt"}, CandidateCount: 1, Limitations: []string{}}
	}
	t.Run("concurrent_duplicate_revision_and_reload", func(t *testing.T) {
		in := makeResult()
		var created atomic.Int32
		var wg sync.WaitGroup
		got := make(chan Result, 12)
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v, new, err := s.Append(ctx, in, 0)
				if err != nil {
					t.Error(err)
					return
				}
				if new {
					created.Add(1)
				}
				got <- v
			}()
		}
		wg.Wait()
		close(got)
		if created.Load() != 1 {
			t.Fatalf("created %d duplicate revisions", created.Load())
		}
		var first Result
		for v := range got {
			if v.ID == uuid.Nil || v.Revision != 1 || v.CreatedAt.IsZero() {
				t.Fatalf("invalid allocated result: %+v", v)
			}
			if first.ID == uuid.Nil {
				first = v
			}
			if !samePersistedResult(v, first) {
				t.Fatalf("duplicate differs: %+v vs %+v", v, first)
			}
		}
		checkCounts(in.KernelEventID, 1)
		if count(`SELECT count(*) FROM audit.audit_events WHERE event_type='kernel_correlation_checked' AND safe_payload->>'correlation_id'=$1 AND safe_payload->>'kernel_event_id'=$2 AND safe_payload->>'confidence'='confirmed' AND safe_payload->>'algorithm_version'='test-v1' AND (safe_payload->>'revision')::integer=1`, first.ID.String(), in.KernelEventID.String()) != 1 {
			t.Fatal("audit payload does not bind the stored result")
		}
		late := in
		late.Confidence = "workload_inferred"
		late.AttemptID = nil
		late.ActionID = nil
		late.CandidateCount = 2
		late.Reason = "late evidence introduced ambiguity"
		late.Limitations = []string{"multiple attempt candidates"}
		late.EvidenceRefs = append(append([]string(nil), in.EvidenceRefs...), "fixture:late")
		v, new, err := s.Append(ctx, late, 1)
		if err != nil || !new || v.Revision != 2 || v.ID == first.ID {
			t.Fatalf("late downgrade: %+v %v %v", v, new, err)
		}
		checkCounts(in.KernelEventID, 2)
		if count(`SELECT count(*) FROM correlation.correlations WHERE correlation_id=$1 AND revision=1 AND confidence='confirmed' AND attempt_id=$2`, first.ID, *in.AttemptID) != 1 {
			t.Fatal("old revision changed")
		}
		retry, new, err := s.Append(ctx, late, 1)
		if err != nil || new || !samePersistedResult(retry, v) {
			t.Fatalf("ack-loss retry: %+v %v %v", retry, new, err)
		}
		stale := late
		stale.Reason = "different stale evaluation"
		if _, new, err := s.Append(ctx, stale, 1); !errors.Is(err, ErrStaleRevision) || new {
			t.Fatalf("stale overwrite accepted: %v %v", new, err)
		}
		checkCounts(in.KernelEventID, 2)
		restarted, err := pgxpool.NewWithConfig(ctx, cfg.Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer restarted.Close()
		latest, err := (Store{Pool: restarted, Config: s.Config}).Latest(ctx, in.KernelEventID)
		if err != nil || !samePersistedResult(latest, v) {
			t.Fatalf("reload lost result: %+v %v", latest, err)
		}
	})
	t.Run("different_evaluations_compete_by_revision", func(t *testing.T) {
		in := makeResult()
		if _, _, err := s.Append(ctx, in, 0); err != nil {
			t.Fatal(err)
		}
		var created, stale atomic.Int32
		var wg sync.WaitGroup
		for _, reason := range []string{"new-evidence-a", "new-evidence-b"} {
			wg.Add(1)
			go func(reason string) {
				defer wg.Done()
				next := in
				next.Reason = reason
				_, new, err := s.Append(ctx, next, 1)
				if errors.Is(err, ErrStaleRevision) && !new {
					stale.Add(1)
					return
				}
				if err != nil || !new {
					t.Errorf("competing revision: %v %v", new, err)
					return
				}
				created.Add(1)
			}(reason)
		}
		wg.Wait()
		if created.Load() != 1 || stale.Load() != 1 {
			t.Fatalf("created=%d stale=%d", created.Load(), stale.Load())
		}
		checkCounts(in.KernelEventID, 2)
	})
	t.Run("bounded_lock_wait_rolls_back", func(t *testing.T) {
		in := makeResult()
		tx, err := fixture.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('correlation/result/'||$1,0))`, in.KernelEventID.String()); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		_, new, err := s.Append(ctx, in, 0)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55P03" || new {
			t.Fatalf("expected lock timeout: %v %v", new, err)
		}
		if elapsed := time.Since(started); elapsed < time.Second || elapsed > 6*time.Second {
			t.Fatalf("unbounded wait: %v", elapsed)
		}
		checkCounts(in.KernelEventID, 0)
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if _, new, err := s.Append(ctx, in, 0); err != nil || !new {
			t.Fatalf("pool failed after rollback: %v %v", new, err)
		}
	})
	t.Run("audit_grant_failure_and_atomic_rollback", func(t *testing.T) {
		in := makeResult()
		exec(fixture, `DELETE FROM audit.producer_event_grants WHERE source_id=$1`, source)
		_, new, err := s.Append(ctx, in, 0)
		if err == nil || new {
			t.Fatalf("missing audit grant accepted: %v %v", new, err)
		}
		checkCounts(in.KernelEventID, 0)
		exec(fixture, `INSERT INTO audit.producer_event_grants VALUES($1,'kernel_correlation_checked','*')`, source)
		for _, mode := range []string{"audit_insert", "deferred_commit"} {
			t.Run(mode, func(t *testing.T) {
				failed := makeResult()
				exec(fixture, `CREATE FUNCTION audit.test_results_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected correlation audit failure' USING ERRCODE='23514'; END $$`)
				if mode == "audit_insert" {
					exec(fixture, `CREATE TRIGGER test_results_failure BEFORE INSERT ON audit.audit_events FOR EACH ROW EXECUTE FUNCTION audit.test_results_failure()`)
				} else {
					exec(fixture, `CREATE CONSTRAINT TRIGGER test_results_failure AFTER INSERT ON audit.audit_outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION audit.test_results_failure()`)
				}
				_, new, err := s.Append(ctx, failed, 0)
				if err == nil || new {
					t.Fatalf("audit failure returned success: %v %v", new, err)
				}
				checkCounts(failed.KernelEventID, 0)
				table := "audit.audit_events"
				if mode == "deferred_commit" {
					table = "audit.audit_outbox"
				}
				exec(fixture, "DROP TRIGGER test_results_failure ON "+table)
				exec(fixture, "DROP FUNCTION audit.test_results_failure()")
				if _, new, err := s.Append(ctx, failed, 0); err != nil || !new {
					t.Fatalf("retry after failure: %v %v", new, err)
				}
				checkCounts(failed.KernelEventID, 1)
			})
		}
		spoof := s
		spoof.Config.SourceID = "another-source"
		other := makeResult()
		if _, new, err := spoof.Append(ctx, other, 0); err == nil || new {
			t.Fatal("source impersonation accepted")
		}
		checkCounts(other.KernelEventID, 0)
	})
	t.Run("caller_allocated_fields_and_mutation_privileges_denied", func(t *testing.T) {
		for _, field := range []string{"id", "revision", "created_at"} {
			in := makeResult()
			switch field {
			case "id":
				in.ID = uuid.New()
			case "revision":
				in.Revision = 7
			case "created_at":
				in.CreatedAt = time.Now()
			}
			if _, new, err := s.Append(ctx, in, 0); err == nil || new {
				t.Fatalf("caller %s accepted", field)
			}
			checkCounts(in.KernelEventID, 0)
		}
		for _, sql := range []string{`UPDATE correlation.correlations SET confidence='unlinked'`, `DELETE FROM correlation.correlations`, `TRUNCATE correlation.correlations`, `CREATE TABLE correlation.forbidden(n int)`, `SELECT * FROM audit.audit_events`, `INSERT INTO audit.audit_events(event_id) VALUES(gen_random_uuid())`} {
			_, err := pool.Exec(ctx, sql)
			var denied *pgconn.PgError
			if !errors.As(err, &denied) || denied.Code != "42501" {
				t.Fatalf("expected privilege denial for %s: %v", sql, err)
			}
		}
	})
	t.Run("down_refuses_to_destroy_audited_history", func(t *testing.T) {
		in := makeResult()
		before, created, err := s.Append(ctx, in, 0)
		if err != nil || !created {
			t.Fatalf("create history: %v %v", created, err)
		}
		raw, err := os.ReadFile("../../../../migrations/20261017114452_correlation_results.down.sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := install.Exec(ctx, string(raw)); err == nil {
			t.Fatal("down destroyed audited relation")
		}
		after, err := s.Latest(ctx, in.KernelEventID)
		if err != nil || !samePersistedResult(before, after) {
			t.Fatalf("down changed history: %+v %v", after, err)
		}
		checkCounts(in.KernelEventID, 1)
	})

}

// PostgreSQL preserves the instant, not Go's local/UTC Location pointer.
func samePersistedResult(a, b Result) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return false
	}
	a.CreatedAt, b.CreatedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}
