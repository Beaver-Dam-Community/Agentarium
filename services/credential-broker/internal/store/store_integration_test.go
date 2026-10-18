package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/broker"
	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/store/brokerdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestBrokerPostgres(t *testing.T) {
	dsn := os.Getenv("BROKER_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx := context.Background()
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close(ctx)
	name := "broker_test_" + uuid.NewString()[:8]
	role := "broker_login_" + uuid.NewString()[:8]
	migratorRole := "broker_migrator_" + uuid.NewString()[:8]
	exec := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, e := c.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(admin, "CREATE DATABASE "+name)
	exec(admin, "CREATE ROLE "+role+" LOGIN")
	exec(admin, "CREATE ROLE "+migratorRole+" LOGIN NOSUPERUSER CREATEROLE")
	exec(admin, "GRANT CREATE ON DATABASE "+name+" TO "+migratorRole)
	cfg, e := pgx.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.Database = name
	db, e := pgx.ConnectConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		db.Close(ctx)
		_, _ = admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		_, _ = admin.Exec(ctx, "DROP ROLE "+role)
		_, _ = admin.Exec(ctx, "DROP ROLE "+migratorRole)
	}()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../../../..")
	apply := func(conn *pgx.Conn, pattern string) {
		t.Helper()
		paths, e := filepath.Glob(filepath.Join(root, pattern))
		if e != nil || len(paths) != 1 {
			t.Fatal("missing migration", pattern)
		}
		b, e := os.ReadFile(paths[0])
		if e != nil {
			t.Fatal(e)
		}
		exec(conn, string(b))
	}
	exec(db, "DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$")
	apply(db, "migrations/*_identity_workload_pki.up.sql")
	migratorConfig := cfg.Copy()
	migratorConfig.User = migratorRole
	migrator, err := pgx.ConnectConfig(ctx, migratorConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer migrator.Close(ctx)
	var super bool
	var version int
	if err = migrator.QueryRow(ctx, "SELECT rolsuper,current_setting('server_version_num')::int FROM pg_roles WHERE rolname=current_user").Scan(&super, &version); err != nil || super || version < 170000 || version >= 180000 {
		t.Fatalf("requires PostgreSQL 17 non-superuser migrator: super=%v version=%d err=%v", super, version, err)
	}
	apply(migrator, "migrations/*_broker_credential_bindings.up.sql")
	assertOwnerRevoked := func() {
		t.Helper()
		var inherit, set bool
		var current string
		if err := migrator.QueryRow(ctx, "SELECT pg_has_role(current_user,'broker_owner','USAGE'),pg_has_role(current_user,'broker_owner','SET'),current_user").Scan(&inherit, &set, &current); err != nil || inherit || set || current != migratorRole {
			t.Fatalf("temporary ownership leaked: inherit=%v set=%v current=%s err=%v", inherit, set, current, err)
		}
	}
	assertOwnerRevoked()
	if _, err := migrator.Exec(ctx, "SELECT * FROM broker.credential_bindings"); err == nil {
		t.Fatal("migrator retained broker access")
	}
	var schemaOwner, tableOwner string
	if err := db.QueryRow(ctx, "SELECT pg_get_userbyid(n.nspowner),pg_get_userbyid(c.relowner) FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid WHERE n.nspname='broker' AND c.relname='credential_bindings'").Scan(&schemaOwner, &tableOwner); err != nil || schemaOwner != "broker_owner" || tableOwner != "broker_owner" {
		t.Fatalf("unexpected ownership: %s/%s %v", schemaOwner, tableOwner, err)
	}
	// Proposed adapter-scope contract fixture, pending its separate contract PR.
	// The broker receives view SELECT without identity schema/base-table access.
	exec(db, "CREATE SCHEMA coordinator; CREATE SCHEMA decisions; CREATE TABLE coordinator.test_attempts(attempt_id uuid PRIMARY KEY,reservation_id uuid,adapter_id text,state text); CREATE TABLE coordinator.test_reservations(reservation_id uuid PRIMARY KEY,action_id uuid); CREATE TABLE decisions.test_actions(action_id uuid PRIMARY KEY,operation_id text)")
	const viewSQL = `CREATE VIEW coordinator.attempt_credential_scope AS
 SELECT a.attempt_id,a.adapter_id,action.operation_id,a.state,
 w.namespace AS adapter_namespace,w.ksa AS adapter_ksa
 FROM coordinator.test_attempts a
 JOIN coordinator.test_reservations r USING (reservation_id)
 JOIN decisions.test_actions action ON action.action_id=r.action_id
 JOIN identity.registered_workloads w ON w.adapter_id=a.adapter_id AND w.role='adapter' AND w.enabled`
	exec(db, viewSQL)
	exec(db, "GRANT broker_reader TO "+role)
	exec(db, "GRANT USAGE ON SCHEMA coordinator TO broker_reader; GRANT SELECT ON coordinator.attempt_credential_scope TO broker_reader")
	exec(db, "INSERT INTO identity.registered_workloads(namespace,ksa,role,adapter_id,enabled) VALUES ('agent-adapters','receiver-sender','adapter','receiver-sender',true),('agent-adapters','model-adapter','adapter','model-adapter',true)")
	id := "61041562-9572-4f87-a24c-f4842fe35177"
	exec(db, "INSERT INTO decisions.test_actions VALUES ($1,'receiver.submit');", id)
	exec(db, "INSERT INTO coordinator.test_reservations VALUES ($1,$1)", id)
	exec(db, "INSERT INTO coordinator.test_attempts VALUES ($1,$1,'receiver-sender','planned')", id)
	exec(db, "INSERT INTO broker.credential_bindings VALUES ('receiver-api-key','receiver-sender','receiver.submit','projects/123/secrets/synthetic','7','Authorization','bearer',true,now(),'fixture')")
	cfg.User = role
	reader, e := pgx.ConnectConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close(ctx)
	queries := brokerdb.New(reader)
	store := Store{Queries: queries}
	ready := func() bool { allowed, err := queries.CheckPermissions(ctx); return err == nil && allowed }
	if !ready() {
		t.Fatal("view-only runtime role not ready")
	}
	q := broker.Request{AttemptID: id, AdapterID: "receiver-sender", Binding: "receiver-api-key"}
	resolve := func() error { _, e := store.Resolve(ctx, "agent-adapters", "receiver-sender", q); return e }
	if e = resolve(); e != nil {
		t.Fatal(e)
	}
	if _, e = store.Resolve(ctx, "agent-adapters", "model-adapter", q); e == nil {
		t.Fatal("other adapter read secret binding")
	}
	exec(db, "UPDATE coordinator.test_attempts SET state='claimed'")
	if resolve() == nil {
		t.Fatal("claimed attempt accepted")
	}
	exec(db, "UPDATE coordinator.test_attempts SET state='planned'")
	exec(db, "UPDATE decisions.test_actions SET operation_id='other'")
	if resolve() == nil {
		t.Fatal("other operation accepted")
	}
	exec(db, "UPDATE decisions.test_actions SET operation_id='receiver.submit'")
	exec(db, "UPDATE broker.credential_bindings SET enabled=false")
	if resolve() == nil {
		t.Fatal("disabled binding accepted")
	}
	exec(db, "UPDATE broker.credential_bindings SET enabled=true")
	exec(db, "UPDATE identity.registered_workloads SET enabled=false WHERE ksa='receiver-sender'")
	if resolve() == nil {
		t.Fatal("disabled identity accepted")
	}
	exec(db, "UPDATE identity.registered_workloads SET enabled=true WHERE ksa='receiver-sender'")
	for _, change := range []string{
		"UPDATE identity.registered_workloads SET role='service',adapter_id=NULL WHERE ksa='receiver-sender'",
		"UPDATE identity.registered_workloads SET adapter_id='other' WHERE ksa='receiver-sender'",
	} {
		exec(db, change)
		if resolve() == nil {
			t.Fatal("changed identity accepted", change)
		}
		exec(db, "UPDATE identity.registered_workloads SET role='adapter',adapter_id='receiver-sender' WHERE ksa='receiver-sender'")
	}
	// Multiple registered KSAs for an adapter cannot make a request ambiguous.
	exec(db, "INSERT INTO identity.registered_workloads(namespace,ksa,role,adapter_id,enabled) VALUES ('agent-adapters','sender-alias','adapter','receiver-sender',true),('other-ns','receiver-sender','adapter','receiver-sender',false)")
	if resolve() != nil {
		t.Fatal("second registered KSA made the original ambiguous")
	}
	if _, err := store.Resolve(ctx, "agent-adapters", "sender-alias", q); err != nil {
		t.Fatal("active alias rejected")
	}
	exec(db, "UPDATE identity.registered_workloads SET enabled=false WHERE ksa='receiver-sender' AND namespace='agent-adapters'")
	if resolve() == nil {
		t.Fatal("active alias bypassed caller revocation")
	}
	exec(db, "UPDATE identity.registered_workloads SET enabled=true WHERE ksa='receiver-sender' AND namespace='agent-adapters'")
	if _, err := store.Resolve(ctx, "other-ns", "receiver-sender", q); err == nil {
		t.Fatal("disabled namespace accepted")
	}
	for _, privilege := range []struct{ revoke, restore string }{
		{"REVOKE USAGE ON SCHEMA broker FROM broker_reader", "GRANT USAGE ON SCHEMA broker TO broker_reader"},
		{"REVOKE USAGE ON SCHEMA coordinator FROM broker_reader", "GRANT USAGE ON SCHEMA coordinator TO broker_reader"},
		{"REVOKE SELECT ON coordinator.attempt_credential_scope FROM broker_reader", "GRANT SELECT ON coordinator.attempt_credential_scope TO broker_reader"},
	} {
		exec(db, privilege.revoke)
		if ready() || resolve() == nil {
			t.Fatal("missing privilege accepted", privilege.revoke)
		}
		exec(db, privilege.restore)
		if !ready() || resolve() != nil {
			t.Fatal("restored privilege rejected")
		}
	}
	for _, query := range []string{"UPDATE broker.credential_bindings SET secret_version='8'", "DELETE FROM broker.credential_bindings", "SELECT * FROM identity.registered_workloads", "SELECT * FROM coordinator.test_attempts", "SELECT * FROM coordinator.test_reservations", "SELECT * FROM decisions.test_actions"} {
		if _, e = reader.Exec(ctx, query); e == nil {
			t.Fatal("excess privilege", query)
		}
	}
	for _, missing := range []string{"operation_id", "adapter_namespace", "adapter_ksa"} {
		exec(db, "DROP VIEW coordinator.attempt_credential_scope")
		columns := []string{}
		for _, column := range []string{"attempt_id", "adapter_id", "operation_id", "state", "adapter_namespace", "adapter_ksa"} {
			if column != missing {
				columns = append(columns, column)
			}
		}
		exec(db, "CREATE VIEW coordinator.attempt_credential_scope AS SELECT "+strings.Join(columns, ",")+" FROM ("+strings.TrimPrefix(viewSQL, "CREATE VIEW coordinator.attempt_credential_scope AS")+") scoped")
		exec(db, "GRANT SELECT ON coordinator.attempt_credential_scope TO broker_reader")
		if ready() || resolve() == nil {
			t.Fatal("missing contract column accepted", missing)
		}
		exec(db, "DROP VIEW coordinator.attempt_credential_scope")
		exec(db, viewSQL)
	}

	apply(migrator, "migrations/*_broker_credential_bindings.down.sql")
	assertOwnerRevoked()
	apply(migrator, "migrations/*_broker_credential_bindings.up.sql")
	assertOwnerRevoked()
	// A pre-existing full membership is not removed by this migration.
	exec(admin, "GRANT broker_owner TO "+migratorRole+" WITH INHERIT TRUE, SET TRUE")
	apply(migrator, "migrations/*_broker_credential_bindings.down.sql")
	apply(migrator, "migrations/*_broker_credential_bindings.up.sql")
	var retained bool
	if err := migrator.QueryRow(ctx, "SELECT pg_has_role(current_user,'broker_owner','USAGE') AND pg_has_role(current_user,'broker_owner','SET')").Scan(&retained); err != nil || !retained {
		t.Fatal("existing ownership membership removed", err)
	}
	t.Logf("PostgreSQL %d: non-superuser CREATEROLE up/down/up passed; temporary ownership revoked; pre-existing full membership retained", version)
}
