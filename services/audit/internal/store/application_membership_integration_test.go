package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// AUDIT_TEST_ADMIN_DSN must point to the runner's disposable PostgreSQL cluster.
func TestApplicationAuditMembershipPostgres(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable AUDIT_TEST_ADMIN_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	suffix := uuid.NewString()[:8]
	dbname, installer := "aam_"+suffix, "aam_install_"+suffix
	cases := []struct {
		role, event, payload, login string
		caller                      *pgx.Conn
		raw                         []byte
	}{
		{role: "identity_app", event: "approval_revoked", payload: `{"approval_id":"approval-1","revoke_reason":"user"}`},
		{role: "coordinator_app", event: "activation_probe_registered", payload: `{"activation_probe_id":"probe-1","change_id":"change-1","service_session_id":"session-1","client_request_key":"key-1","target_epoch":1}`},
		{role: "gateway_app", event: "policy_decided", payload: `{"decision_id":"decision-1","decision_stage":"normalize","verdict":"deny","reason_codes":["SCHEMA_INVALID"],"matched_rule_ids":["input.required_keys.v1"],"evaluated_rule_ids":["input.required_keys.v1"],"gateway_added_rule_ids":[],"policy_bundle_id":"bundle-1","policy_epoch":1,"catalog_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`},
	}
	grantInstaller := "cam_grant_" + suffix
	exec := func(t *testing.T, c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatalf("SQL failed: %v\n%s", err, q)
		}
	}
	wantCode := func(t *testing.T, err error, code string) {
		t.Helper()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != code {
			t.Fatalf("want SQLSTATE %s, got %v", code, err)
		}
	}
	for _, role := range []string{"identity_app", "coordinator_app"} {
		var exists bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil || exists {
			t.Fatalf("use isolated audit runner without %s: exists=%v err=%v", role, exists, err)
		}
	}
	groups := []string{}
	for _, role := range []string{"audit_owner", "audit_producer", "audit_writer", "audit_exporter", "gateway_app"} {
		var exists bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			groups = append(groups, role)
		}
	}
	// Other packages can leave reusable group roles and memberships in this
	// disposable cluster. This fixture must restore their exact prior state.
	membershipSnapshot := func(ctx context.Context) (string, error) {
		var value string
		err := admin.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY roleid,member,grantor),'[]'::jsonb)::text FROM pg_auth_members m`).Scan(&value)
		return value, err
	}
	membershipsBefore, err := membershipSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exec(t, admin, "CREATE ROLE "+installer+" LOGIN NOSUPERUSER CREATEROLE")
	exec(t, admin, "CREATE ROLE "+grantInstaller+" LOGIN NOSUPERUSER CREATEROLE")
	for i := range cases {
		cases[i].login = cases[i].role + "_" + suffix
		exec(t, admin, "CREATE ROLE "+cases[i].login+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	}
	exec(t, admin, "CREATE DATABASE "+dbname+" OWNER "+installer)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+dbname+" WITH (FORCE)"); err != nil {
			t.Errorf("drop fixture database: %v", err)
		}
		// PostgreSQL 16 tracks membership grantors as role dependencies. The
		// installer may have added a second audit_producer -> audit_writer grant
		// alongside an existing admin grant; revoke only this fixture's grantors.
		// No CASCADE or broad role revoke may remove another fixture's grant.
		rows, err := admin.Query(cleanup, `SELECT format('REVOKE %I FROM %I GRANTED BY %I',r.rolname,m.rolname,g.rolname)
		 FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid
		 JOIN pg_roles m ON m.oid=a.member JOIN pg_roles g ON g.oid=a.grantor
		 WHERE g.rolname=ANY($1::text[]) ORDER BY r.rolname,m.rolname,g.rolname`, []string{installer, grantInstaller})
		if err != nil {
			t.Errorf("list fixture membership grants: %v", err)
		} else {
			var revokes []string
			for rows.Next() {
				var revoke string
				if err := rows.Scan(&revoke); err != nil {
					t.Errorf("read fixture membership grant: %v", err)
					break
				}
				revokes = append(revokes, revoke)
			}
			if err := rows.Err(); err != nil {
				t.Errorf("read fixture membership grants: %v", err)
			}
			rows.Close()
			for _, revoke := range revokes {
				if _, err := admin.Exec(cleanup, revoke); err != nil {
					t.Errorf("revoke fixture membership: %v", err)
				}
			}
		}
		roles := []string{}
		for _, c := range cases {
			roles = append(roles, c.login)
		}
		roles = append(roles, "identity_app", "coordinator_app")
		roles = append(roles, groups...)
		roles = append(roles, installer, grantInstaller)
		for _, role := range roles {
			if _, err := admin.Exec(cleanup, "DROP ROLE IF EXISTS "+role); err != nil {
				t.Errorf("drop fixture role %s: %v", role, err)
			}
		}
		var remaining int
		if err := admin.QueryRow(cleanup, `SELECT count(*) FROM pg_roles WHERE rolname=ANY($1::text[])`, roles).Scan(&remaining); err != nil || remaining != 0 {
			t.Errorf("fixture roles remain: count=%d err=%v", remaining, err)
		}
		if after, err := membershipSnapshot(cleanup); err != nil || after != membershipsBefore {
			t.Errorf("fixture cleanup changed pre-existing memberships: err=%v", err)
		}
	}()
	for _, role := range []string{"audit_owner", "audit_producer"} {
		var exists bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			exec(t, admin, "GRANT "+role+" TO "+installer+" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
		}
	}
	connect := func(user string) *pgx.Conn {
		t.Helper()
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Database, cfg.User = dbname, user
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	install, fixture := connect(installer), connect(admin.Config().User)
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("../../../../migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	up := read("20261017105252_audit_application_membership.up.sql")
	down := read("20261017105252_audit_application_membership.down.sql")
	exec(t, install, read("20261016132230_audit_store.up.sql"))
	for _, missing := range []string{"identity_app", "coordinator_app"} {
		_, err = install.Exec(ctx, up)
		wantCode(t, err, "42704")
		exec(t, install, "ROLLBACK")
		var partialGrant bool
		if err := fixture.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles a ON a.oid=m.member WHERE r.rolname='audit_producer' AND a.rolname IN ('identity_app','coordinator_app','gateway_app'))`).Scan(&partialGrant); err != nil || partialGrant {
			t.Fatalf("missing %s left partial membership: %v %v", missing, partialGrant, err)
		}
		// TASK-03 owns these groups; fixtures reproduce only the prerequisites.
		exec(t, fixture, "CREATE ROLE "+missing+" NOLOGIN")
	}
	for i := range cases {
		c := &cases[i]
		exec(t, fixture, "GRANT "+c.role+" TO "+c.login)
		c.caller = connect(c.login)
	}
	// CREATEROLE is insufficient when the producer role already exists.
	install = connect(grantInstaller)
	_, err = install.Exec(ctx, up)
	wantCode(t, err, "42501")
	exec(t, install, "ROLLBACK")
	exec(t, fixture, "GRANT audit_producer TO "+grantInstaller+" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
	query := `SELECT audit.audit_append($1::jsonb,ARRAY['gcs'])`
	makeEvent := func(t *testing.T, event, payload, source, tenant string) []byte {
		t.Helper()
		e := ingest.Event{EventID: uuid.NewString(), EventType: event, Tenant: tenant, SourceID: source, SourceVersion: "v1", SourceEpoch: "epoch-1", SourceTime: "2026-10-17T00:00:00Z", SchemaVersion: 1, EvidenceRefs: []json.RawMessage{}}
		if err := json.Unmarshal([]byte(payload), &e.SafePayload); err != nil {
			t.Fatal(err)
		}
		raw, _ := signed(t, e)
		return raw
	}
	for i := range cases {
		c := &cases[i]
		c.raw = makeEvent(t, c.event, c.payload, c.role, "tenant-test")
		_, err = c.caller.Exec(ctx, query, c.raw)
		wantCode(t, err, "42501")
	}
	exec(t, install, up)
	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			// Function membership does not bypass session_user/source or event grants.
			_, err := c.caller.Exec(ctx, query, c.raw)
			wantCode(t, err, "42501")
			exec(t, fixture, `INSERT INTO audit.db_role_sources VALUES ($1,$2,false)`, c.login, c.role)
			_, err = c.caller.Exec(ctx, query, c.raw)
			wantCode(t, err, "42501")
			exec(t, fixture, `INSERT INTO audit.producer_event_grants VALUES ($1,$2,'tenant-test')`, c.role, c.event)
			var result string
			if err := c.caller.QueryRow(ctx, query, c.raw).Scan(&result); err != nil || result != "created" {
				t.Fatalf("append result=%q err=%v", result, err)
			}
			if err := c.caller.QueryRow(ctx, query, c.raw).Scan(&result); err != nil || result != "duplicate" {
				t.Fatalf("retry result=%q err=%v", result, err)
			}
			_, err = c.caller.Exec(ctx, query, makeEvent(t, c.event, c.payload, c.role, "other-tenant"))
			wantCode(t, err, "42501")
			for _, q := range []string{
				`SELECT * FROM audit.audit_events`, `INSERT INTO audit.audit_events(event_id) VALUES(gen_random_uuid())`,
				`UPDATE audit.audit_events SET tenant='other'`, `DELETE FROM audit.audit_events`,
				`SELECT * FROM audit.audit_outbox`, `UPDATE audit.audit_outbox SET state='acked'`,
				`UPDATE audit.db_role_sources SET proxy=true`, `CREATE TABLE audit.forbidden(n int)`,
				`SELECT audit.audit_event_ack(gen_random_uuid(),'source-test','tenant-test')`,
				`GRANT audit_producer TO gateway_app`, `SET ROLE audit_owner`,
			} {
				_, err := c.caller.Exec(ctx, q)
				wantCode(t, err, "42501")
			}
			var member bool
			if err := c.caller.QueryRow(ctx, `SELECT pg_has_role(current_user,'audit_producer','USAGE')`).Scan(&member); err != nil || !member {
				t.Fatalf("caller does not inherit producer: %v %v", member, err)
			}
		})
	}
	// Even a different source with valid event and tenant grants remains forbidden.
	for i, c := range cases {
		_, err := c.caller.Exec(ctx, query, cases[(i+1)%len(cases)].raw)
		wantCode(t, err, "42501")
	}
	var super, ownerSet, member bool
	if err := install.QueryRow(ctx, `SELECT rolsuper,pg_has_role(current_user,'audit_owner','SET') FROM pg_roles WHERE rolname=current_user`).Scan(&super, &ownerSet); err != nil || super || ownerSet {
		t.Fatalf("installer privilege leaked: super=%v owner=%v err=%v", super, ownerSet, err)
	}
	snapshot := func() string {
		t.Helper()
		var v string
		if err := fixture.QueryRow(ctx, `SELECT jsonb_build_object('events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id) FROM audit.audit_events e),'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY record_kind,record_id,destination) FROM audit.audit_outbox o),'sources',(SELECT jsonb_agg(to_jsonb(s) ORDER BY db_role) FROM audit.db_role_sources s),'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY source_id,event_type,tenant) FROM audit.producer_event_grants g))::text`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := snapshot()
	for _, c := range cases {
		tx, err := c.caller.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, query, makeEvent(t, c.event, c.payload, c.role, "tenant-test")); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if snapshot() != before {
		t.Fatal("caller rollback left an audit event or outbox entry")
	}
	exec(t, install, down)
	for _, c := range cases {
		_, err = c.caller.Exec(ctx, query, c.raw)
		wantCode(t, err, "42501")
	}
	if snapshot() != before {
		t.Fatal("down changed audit history, outbox or source registration")
	}
	if err := fixture.QueryRow(ctx, `SELECT pg_has_role('audit_writer','audit_producer','USAGE')`).Scan(&member); err != nil || !member {
		t.Fatalf("down removed unrelated writer membership: %v %v", member, err)
	}
	exec(t, install, up)
	for _, c := range cases {
		var result string
		if err := c.caller.QueryRow(ctx, query, c.raw).Scan(&result); err != nil || result != "duplicate" {
			t.Fatalf("reinstall lost %s history: %q %v", c.role, result, err)
		}
	}
}
