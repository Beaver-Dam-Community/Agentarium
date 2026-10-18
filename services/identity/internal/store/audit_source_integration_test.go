//go:build integration

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A real non-superuser owns the identity objects and installs the function.
// Separate LOGINs exercise the granted writer/owner roles and a denied caller.
func TestAuditSourceCertificatePostgres(t *testing.T) {
	dsn := os.Getenv("IDENTITY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set disposable IDENTITY_TEST_DATABASE_URL")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	suffix := uuid.NewString()[:8]
	dbName, installer, writer, owner, outsider := "certdb_"+suffix, "certinst_"+suffix, "certwriter_"+suffix, "certowner_"+suffix, "certdeny_"+suffix
	exec := func(c *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []string{installer, writer, owner, outsider} {
		exec(admin, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	}
	exec(admin, "ALTER ROLE "+pgx.Identifier{installer}.Sanitize()+" CREATEROLE")
	exec(admin, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()+" OWNER "+pgx.Identifier{installer}.Sanitize())
	defer func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
		for _, role := range []string{writer, owner, outsider, installer} {
			_, _ = admin.Exec(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize())
		}
	}()
	exec(admin, `DO $$ BEGIN
      IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF;
      IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='audit_writer') THEN CREATE ROLE audit_writer NOLOGIN; END IF;
      IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='audit_owner') THEN CREATE ROLE audit_owner NOLOGIN; END IF;
    END $$`)
	exec(admin, "GRANT audit_writer TO "+pgx.Identifier{writer}.Sanitize())
	exec(admin, "GRANT audit_owner TO "+pgx.Identifier{owner}.Sanitize())
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
	db := connect(installer)
	migration := func(name string) {
		t.Helper()
		raw, err := os.ReadFile("../../../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		exec(db, string(raw))
	}
	migration("20261014144500_identity_workload_pki.up.sql")
	up, down := "20261017074056_identity_audit_source_certificate.up.sql", "20261017074056_identity_audit_source_certificate.down.sql"
	migration(up)
	caller, ownerCaller, denied := connect(writer), connect(owner), connect(outsider)
	runtimeSAN := "spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder"
	watcherSAN := "spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher"
	node, otherNode := uuid.NewString(), uuid.NewString()
	exec(db, `INSERT INTO identity.registered_workloads(namespace,ksa,role,service_principal) VALUES
      ('agent-sensors','lifecycle-recorder','service','lifecycle-recorder'),
      ('agent-observe','pod-watcher','service','pod-watcher')`)
	exec(db, `INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,node_uid,boot_id,issued_at,expires_at,revoked_at) VALUES
      ('0a',$1,'agent-sensors','lifecycle-recorder',$3,'current-boot',now()-interval '1 minute',now()+interval '1 hour',NULL),
      ('0b',$1,'agent-sensors','lifecycle-recorder',$3,'old-boot',now()-interval '2 days',now()-interval '1 day',now()-interval '1 day'),
      ('0c',$1,'agent-sensors','lifecycle-recorder',$4,'foreign-boot',now()-interval '2 days',now()-interval '1 day',NULL),
      ('0d',$2,'agent-observe','pod-watcher',NULL,NULL,now()-interval '1 minute',now()+interval '1 hour',NULL),
      ('0e',$1,'agent-sensors','lifecycle-recorder',$3,'future-boot',now()+interval '1 day',now()+interval '2 days',NULL),
      ('0f',$2,'agent-observe','pod-watcher',$3,'watcher-boot',now()-interval '2 days',now()-interval '1 day',NULL)`, runtimeSAN, watcherSAN, node, otherNode)
	hash := func(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
	type facts struct {
		Namespace, KSA         string
		Node, Boot, Historical *string
	}
	read := func(c *pgx.Conn, serial, san string, h any) []facts {
		t.Helper()
		rows, err := c.Query(ctx, `SELECT namespace,ksa,node_uid::text,certificate_boot_id,historical_boot_id FROM identity.audit_source_certificate($1,$2,$3)`, serial, san, h)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []facts
		for rows.Next() {
			var f facts
			if err := rows.Scan(&f.Namespace, &f.KSA, &f.Node, &f.Boot, &f.Historical); err != nil {
				t.Fatal(err)
			}
			out = append(out, f)
		}
		if rows.Err() != nil {
			t.Fatal(rows.Err())
		}
		return out
	}
	current := read(caller, "0a", runtimeSAN, nil)
	if len(current) != 1 || current[0].Node == nil || *current[0].Node != node || current[0].Boot == nil || *current[0].Boot != "current-boot" || current[0].Historical != nil {
		t.Fatalf("current: %+v", current)
	}
	historical := read(caller, "0a", runtimeSAN, hash("old-boot"))
	if len(historical) != 1 || historical[0].Historical == nil || *historical[0].Historical != "old-boot" {
		t.Fatalf("historical: %+v", historical)
	}
	for _, boot := range []string{"foreign-boot", "watcher-boot", "future-boot", "unknown"} {
		got := read(caller, "0a", runtimeSAN, hash(boot))
		if len(got) != 1 || got[0].Historical != nil {
			t.Fatalf("untrusted history %s: %+v", boot, got)
		}
	}
	watcher := read(caller, "0d", watcherSAN, nil)
	if len(watcher) != 1 || watcher[0].Node != nil || watcher[0].Boot != nil {
		t.Fatalf("node-less watcher: %+v", watcher)
	}
	if len(read(ownerCaller, "0a", runtimeSAN, nil)) != 1 {
		t.Fatal("audit_owner cannot use restricted function")
	}
	for _, tc := range []struct {
		serial, san string
		hash        any
	}{
		{"0b", runtimeSAN, nil}, {"0c", runtimeSAN, nil}, {"0e", runtimeSAN, nil}, {"0a", watcherSAN, nil}, {"0A", runtimeSAN, nil},
		{"a", runtimeSAN, nil}, {"00", runtimeSAN, nil}, {"0a", runtimeSAN, "bad"},
		{"0a", runtimeSAN + "/pod/" + uuid.NewString(), nil},
	} {
		if got := read(caller, tc.serial, tc.san, tc.hash); len(got) != 0 {
			t.Fatalf("unauthorized lookup: %+v", tc)
		}
	}
	for _, change := range []string{"enabled=false", "service_principal='different'", "role='probe'"} {
		exec(db, "UPDATE identity.registered_workloads SET "+change+" WHERE ksa='lifecycle-recorder'")
		if len(read(caller, "0a", runtimeSAN, nil)) != 0 {
			t.Fatal("disabled or mismatched registration accepted")
		}
		exec(db, "UPDATE identity.registered_workloads SET enabled=true,service_principal=ksa,role='service' WHERE ksa='lifecycle-recorder'")
	}
	exec(db, "UPDATE identity.issued_certificates SET revoked_at=now() WHERE serial='0a'")
	if len(read(caller, "0a", runtimeSAN, nil)) != 0 {
		t.Fatal("revoked current certificate accepted")
	}
	exec(db, "UPDATE identity.issued_certificates SET revoked_at=NULL WHERE serial='0a'")
	for _, c := range []*pgx.Conn{caller, ownerCaller} {
		for _, query := range []string{"SELECT * FROM identity.issued_certificates", "SELECT * FROM identity.registered_workloads", "SELECT * FROM identity.sessions", "UPDATE identity.issued_certificates SET revoked_at=NULL"} {
			if _, err := c.Exec(ctx, query); err == nil {
				t.Fatal("base table access granted:", query)
			}
		}
	}
	if _, err := denied.Exec(ctx, `SELECT * FROM identity.audit_source_certificate('0a',$1,NULL)`, runtimeSAN); err == nil {
		t.Fatal("ungranted caller executed function")
	}
	// Temp relation names cannot shadow the fully qualified identity tables.
	exec(caller, `CREATE TEMP TABLE issued_certificates(serial text); CREATE TEMP TABLE registered_workloads(enabled boolean)`)
	if len(read(caller, "0a", runtimeSAN, nil)) != 1 {
		t.Fatal("temporary table shadowing changed result")
	}
	var actualOwner string
	var super, createRole bool
	if err := db.QueryRow(ctx, `SELECT pg_get_userbyid(p.proowner),r.rolsuper,r.rolcreaterole FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid='identity.audit_source_certificate(text,text,text)'::regprocedure`).Scan(&actualOwner, &super, &createRole); err != nil {
		t.Fatal(err)
	}
	if actualOwner != installer || super || !createRole {
		t.Fatalf("owner=%s super=%v createrole=%v", actualOwner, super, createRole)
	}
	migration(down)
	migration(up)
	if len(read(caller, "0a", runtimeSAN, hash("old-boot"))) != 1 {
		t.Fatal("up/down/up changed retained data")
	}
}
