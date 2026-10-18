//go:build integration

package feed

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCollectorReadsPostgres(t *testing.T) {
	dsn := os.Getenv("EVIDENCE_FEED_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable EVIDENCE_FEED_TEST_ADMIN_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	db, installer, login := "feeddb_"+suffix, "feedinst_"+suffix, "feedlogin_"+suffix
	execSQL := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var created []string
	for _, role := range []string{"control_health_writer", "coordinator_app", "identity_app", "gateway_app", "adapter_reader", "audit_owner", "audit_producer", "audit_writer", "audit_exporter", "evidence_collector"} {
		var exists bool
		if err = admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)", role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			created = append(created, role)
		}
	}
	execSQL(admin, "CREATE ROLE "+installer+" LOGIN NOSUPERUSER NOCREATEDB CREATEROLE")
	execSQL(admin, "CREATE ROLE "+login+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	execSQL(admin, "CREATE DATABASE "+db+" OWNER "+installer)
	defer func() {
		cleanup := context.Background()
		_, _ = admin.Exec(cleanup, "DROP DATABASE "+db+" WITH (FORCE)")
		for _, role := range append(append([]string{login}, created...), installer) {
			if _, err := admin.Exec(cleanup, "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Error("cleanup", err)
			}
		}
	}()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = db
	inspect, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer inspect.Close(context.Background())
	config = config.Copy()
	config.User = installer
	install, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer install.Close(context.Background())
	execSQL(install, "CREATE ROLE control_health_writer NOLOGIN; CREATE ROLE coordinator_app NOLOGIN")
	readMigration := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("../../../../migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, name := range []string{"20261014144500_identity_workload_pki.up.sql", "20261016120000_identity_sessions_tokens.up.sql", "20261016175130_identity_approvals.up.sql", "20261016132230_audit_store.up.sql", "20261016181826_gateway_decisions.up.sql"} {
		execSQL(install, readMigration(name))
	}
	up := readMigration("20261017121300_receiver_collector_reads.up.sql")
	down := readMigration("20261017121300_receiver_collector_reads.down.sql")
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.Database = db
	pc.ConnConfig.User = login
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reader, err := New(pool, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	pgCode := func(err error, want string) {
		t.Helper()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != want {
			t.Fatalf("want SQLSTATE %s got %v", want, err)
		}
	}
	_, err = reader.Page(ctx, nil, 2)
	pgCode(err, "42501")
	membership := func() string {
		t.Helper()
		var v string
		if err := admin.QueryRow(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_array(grantor,admin_option,inherit_option,set_option) ORDER BY grantor)::text,'[]') FROM pg_auth_members WHERE roleid='audit_owner'::regrole AND member=$1::regrole`, installer).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	beforeMembership := membership()
	t.Run("migration_failure_rolls_back_role_and_grants", func(t *testing.T) {
		execSQL(inspect, "ALTER SCHEMA decisions OWNER TO "+pgx.Identifier{admin.Config().User}.Sanitize())
		_, err := install.Exec(ctx, up)
		pgCode(err, "42501")
		execSQL(install, "ROLLBACK")
		var exists bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname='evidence_collector')").Scan(&exists); err != nil || exists {
			t.Fatal("failed migration left role", err)
		}
		if membership() != beforeMembership {
			t.Fatal("failed migration left audit owner access")
		}
		execSQL(inspect, "ALTER SCHEMA decisions OWNER TO "+installer)
	})
	execSQL(install, up)
	if membership() != beforeMembership {
		t.Fatal("successful migration changed installer owner grants")
	}
	execSQL(admin, "GRANT evidence_collector TO "+login)
	t.Run("existing_partial_owner_membership_preserved", func(t *testing.T) {
		execSQL(install, "GRANT audit_owner TO CURRENT_USER WITH INHERIT FALSE, SET FALSE")
		original := membership()
		execSQL(install, up)
		if membership() != original {
			t.Fatal("existing grant options changed")
		}
		execSQL(install, "REVOKE audit_owner FROM CURRENT_USER")
	})
	var super, createRole, owner, canLogin bool
	if err = pool.QueryRow(ctx, "SELECT rolsuper,rolcreaterole,pg_has_role(current_user,'audit_owner','MEMBER'),(SELECT rolcanlogin FROM pg_roles WHERE rolname='evidence_collector') FROM pg_roles WHERE rolname=current_user").Scan(&super, &createRole, &owner, &canLogin); err != nil || super || createRole || owner || canLogin {
		t.Fatal("runtime role boundary", err)
	}
	at := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	actionA, actionB := uuid.New(), uuid.New()
	attempt := uuid.New()
	insertEvent := func(c *pgx.Conn, id uuid.UUID, tenant, event string, when time.Time, action *uuid.UUID) {
		t.Helper()
		execSQL(c, `INSERT INTO audit.audit_events(event_id,event_type,tenant,source_id,source_version,source_epoch,source_time,received_at,schema_version,action_id,attempt_id,payload_digest,safe_payload) VALUES($1,$2,$3,'fixture','v1','epoch', $4,$4,1,$5,$6,repeat('a',64),'{}')`, id, event, tenant, when, action, attempt)
	}
	ids := []uuid.UUID{uuid.MustParse("00000000-0000-4000-8000-000000000001"), uuid.MustParse("00000000-0000-4000-8000-000000000003"), uuid.MustParse("00000000-0000-4000-8000-000000000005")}
	insertEvent(inspect, ids[2], "tenant-a", "attempt_failed", at, &actionA)
	insertEvent(inspect, ids[0], "tenant-a", "preflight_passed", at, &actionA)
	insertEvent(inspect, ids[1], "tenant-a", "response_received", at, nil)
	insertEvent(inspect, uuid.MustParse("00000000-0000-4000-8000-000000000002"), "tenant-b", "response_received", at, &actionB)
	insertEvent(inspect, uuid.New(), "tenant-a", "session_created", at, &actionA)
	insertAction := func(id uuid.UUID, tenant string) {
		execSQL(inspect, `INSERT INTO decisions.actions(action_id,request_id,authenticated_actor,session_kind,session_id,client_request_key,raw_body_digest,tenant,environment,operation_id,canonical_target,created_at) VALUES($1,$2,'service:fixture','service',$3,'request_1',repeat('a',64),$4,'test','receiver.submit','{"target_id":"receiver-primary","route_id":"submissions-v1"}',$5)`, id, uuid.New(), uuid.New(), tenant, at)
	}
	insertAction(actionA, "tenant-a")
	insertAction(actionB, "tenant-b")
	t.Run("tenant_filter_precedes_limit_and_cursor_tie_break", func(t *testing.T) {
		first, err := reader.Page(ctx, nil, 2)
		if err != nil || len(first) != 2 || first[0].EventID != ids[0] || first[1].EventID != ids[1] || first[1].ActionID != nil || first[0].AttemptID == nil || *first[0].AttemptID != attempt {
			t.Fatalf("page %+v %v", first, err)
		}
		after := Cursor{ReceivedAt: first[1].ReceivedAt, EventID: first[1].EventID}
		second, err := reader.Page(ctx, &after, 2)
		if err != nil || len(second) != 1 || second[0].EventID != ids[2] {
			t.Fatalf("next page %+v %v", second, err)
		}
		for _, e := range append(first, second...) {
			if e.Tenant != "tenant-a" || !e.ReceivedAt.Equal(at) || e.EventType == "session_created" {
				t.Fatal("view/tenant scope leak", e)
			}
		}
		for _, n := range []int{0, MaxPageSize + 1} {
			if _, err := reader.Page(ctx, nil, n); err == nil {
				t.Fatal("unbounded page accepted")
			}
		}
	})
	t.Run("target_tenant_exact", func(t *testing.T) {
		target, err := reader.Target(ctx, actionA)
		var value map[string]string
		_ = json.Unmarshal(target.CanonicalTarget, &value)
		if err != nil || target.Tenant != "tenant-a" || target.OperationID != "receiver.submit" || value["target_id"] != "receiver-primary" {
			t.Fatal(target, err)
		}
		if _, err = reader.Target(ctx, actionB); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("cross tenant action", err)
		}
	})
	t.Run("no_base_write_or_owner_grants", func(t *testing.T) {
		for _, query := range []string{"SELECT * FROM audit.audit_events", "SELECT * FROM decisions.actions", "SELECT * FROM decisions.action_contents", "UPDATE audit.collector_feed SET tenant='x'", "DELETE FROM decisions.actions_target_view", "SELECT audit.audit_append('{}'::jsonb,ARRAY['gcs'])", "SET ROLE audit_owner", "CREATE TABLE audit.unauthorized(id integer)"} {
			_, err := pool.Exec(ctx, query)
			pgCode(err, "42501")
		}
	})
	t.Run("rollback_reads_preserves_source_rows", func(t *testing.T) {
		execSQL(install, down)
		if membership() != beforeMembership {
			t.Fatal("down changed owner grants")
		}
		_, err := reader.Page(ctx, nil, 2)
		pgCode(err, "42501")
		_, err = reader.Target(ctx, actionA)
		pgCode(err, "42501")
		var count int
		if err = inspect.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events").Scan(&count); err != nil || count != 5 {
			t.Fatal("source history changed", err, count)
		}
		execSQL(install, up)
		if _, err = reader.Page(ctx, nil, 2); err != nil {
			t.Fatal(err)
		}
	})
}
