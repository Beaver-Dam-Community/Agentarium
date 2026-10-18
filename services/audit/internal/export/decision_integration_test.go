package export

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Uses the parent fixture's isolated database, installing real producer tables
// and grants. Both gateway enqueue and exporter access use restricted logins.
func testDecisionPublication(t *testing.T, ctx context.Context, db *pgx.Conn, cfg *pgx.ConnConfig, root string) {
	t.Helper()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Roles are cluster-wide even though the database is disposable. Remove
	// only roles introduced by this fixture so later packages see their original
	// prerequisites; preserve every role that was already installed.
	originalRoles := map[string]bool{}
	roleRows, err := db.Query(ctx, "SELECT rolname FROM pg_roles")
	if err != nil {
		t.Fatal(err)
	}
	for roleRows.Next() {
		var role string
		if err := roleRows.Scan(&role); err != nil {
			t.Fatal(err)
		}
		originalRoles[role] = true
	}
	roleRows.Close()
	t.Cleanup(func() {
		rows, err := db.Query(ctx, "SELECT rolname FROM pg_roles ORDER BY rolname")
		if err != nil {
			t.Fatal(err)
		}
		var added []string
		for rows.Next() {
			var role string
			if err := rows.Scan(&role); err != nil {
				t.Fatal(err)
			}
			if !originalRoles[role] {
				added = append(added, role)
			}
		}
		rows.Close()
		for _, role := range added {
			exec("DROP OWNED BY " + pgx.Identifier{role}.Sanitize() + " CASCADE")
		}
		for _, role := range added {
			exec("DROP ROLE " + pgx.Identifier{role}.Sanitize())
		}
	})
	if !originalRoles["coordinator_app"] {
		exec("CREATE ROLE coordinator_app NOLOGIN")
	}
	for _, pattern := range []string{"*_health.up.sql", "*_identity_workload_pki.up.sql", "*_identity_sessions_tokens.up.sql", "*_identity_approvals.up.sql", "*_gateway_decisions.up.sql"} {
		paths, err := filepath.Glob(filepath.Join(root, "migrations", pattern))
		if err != nil || len(paths) != 1 {
			t.Fatalf("migration %s: %v", pattern, err)
		}
		raw, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		exec(string(raw))
	}
	loginPool := func(group string) *pgxpool.Pool {
		t.Helper()
		name := "di_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		exec("CREATE ROLE " + name + " LOGIN INHERIT")
		exec("GRANT " + group + " TO " + name)
		pc, err := pgxpool.ParseConfig(cfg.ConnString())
		if err != nil {
			t.Fatal(err)
		}
		pc.ConnConfig.Database = cfg.Database
		pc.ConnConfig.User = name
		p, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close(); exec("DROP ROLE " + name) })
		var super bool
		var current string
		if err := p.QueryRow(ctx, "SELECT current_user,rolsuper FROM pg_roles WHERE rolname=session_user").Scan(&current, &super); err != nil || super || current != name {
			t.Fatalf("restricted login %s: %s %v %v", name, current, super, err)
		}
		return p
	}
	writer := loginPool("gateway_app")
	pool := loginPool("audit_exporter")
	out := Outbox{Pool: pool}
	seed := func(digest, tenant string, commit bool) {
		t.Helper()
		tx, err := writer.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO decisions.decision_inputs VALUES($1,$2,'{"tenant":"different-input-tenant"}','bundle','2026-10-16T12:34:56.123456+09:00')`, digest, tenant)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `SELECT audit.enqueue_decision_input($1,200)`, digest)
		if err != nil {
			t.Fatal(err)
		}
		if commit {
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	count := func(state string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_outbox WHERE destination='gcs_decision_inputs' AND state=$1", state).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	cloud := newPublisherCloudBucket(t, "decision-input-exports")
	checks := 0
	live := liveLease(pool)
	pub := ManifestPublisher{Chain: "gcs_decision_inputs", Pool: pool, Objects: cloud.Objects, Signer: cloud.Signer, KeyVersion: cloud.Version, Keys: map[string]*ecdsa.PublicKey{cloud.Version: cloud.Key}, Leader: leaseFunc(func(ctx context.Context, chain string) (int64, error) {
		checks++
		if chain != "gcs_decision_inputs" {
			return 0, errors.New("wrong lease chain")
		}
		return live(ctx, chain)
	})}
	worker := Worker{Outbox: out, Publisher: pub, SourceClass: "decision_input"}
	t.Run("producer rollback is not exported", func(t *testing.T) {
		seed(strings.Repeat("0", 64), "rollback", false)
		if worked, err := worker.Once(ctx); err != nil || worked {
			t.Fatalf("rolled back input exported: %v %v", worked, err)
		}
	})
	seed(strings.Repeat("a", 64), "tenant/한글", true)
	seed(strings.Repeat("b", 64), "tenant-b", true)
	t.Run("wrong publisher chain cannot claim", func(t *testing.T) {
		wrong := pub
		wrong.Chain = "gcs"
		if worked, err := (Worker{Outbox: out, Publisher: wrong, SourceClass: "decision_input"}).Once(ctx); err == nil || worked || count("pending") != 2 {
			t.Fatalf("wrong chain claimed: %v %v", worked, err)
		}
	})
	var firstDigest string
	t.Run("fixed rows crash recovery tenant and signed independent chain", func(t *testing.T) {
		// A separate gcs chain can already have sequence 1 without affecting this
		// bucket's sequence, object names, or predecessor.
		gcs := newPublisherCloudBucket(t, "audit-exports")
		gp := pub
		gp.Chain = "gcs"
		gp.Objects = gcs.Objects
		gp.Leader = leaseFunc(func(ctx context.Context, c string) (int64, error) {
			if c != "gcs" {
				return 0, errors.New("wrong chain")
			}
			return live(ctx, c)
		})
		if worked, err := (Worker{Outbox: out, Publisher: gp}).Once(ctx); err != nil || !worked {
			t.Fatalf("business publication: %v %v", worked, err)
		}
		exec(`CREATE FUNCTION audit.test_di_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.chain_id='gcs_decision_inputs' THEN RAISE EXCEPTION 'crash after upload'; END IF; RETURN NEW; END $$`)
		exec(`CREATE TRIGGER test_di_failure BEFORE INSERT ON audit.export_manifests FOR EACH ROW EXECUTE FUNCTION audit.test_di_failure()`)
		if worked, err := worker.Once(ctx); err == nil || !worked || count("pending") != 2 || count("acked") != 0 {
			t.Fatalf("crash acked: %v %v", worked, err)
		}
		if n, s := cloud.counts(); n != 2 || s != 2 {
			t.Fatalf("crash artifacts/signs: %d %d", n, s)
		}
		raw, err := cloud.Objects.ReadManifest(ctx, "manifests/1.json")
		if err != nil {
			t.Fatal(err)
		}
		env, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if env.Manifest.Previous != nil || len(env.Manifest.Sources) != 0 || env.Manifest.RecordCount != 2 {
			t.Fatalf("invented source/predecessor: %+v", env.Manifest)
		}
		data, err := cloud.Objects.Read(ctx, env.Manifest.ObjectKey, env.Manifest.Generation)
		if err != nil {
			t.Fatal(err)
		}
		rows := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
		tenants := map[string]bool{}
		for _, row := range rows {
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(row, &fields); err != nil || len(fields) != 5 {
				t.Fatalf("row: %s %v", row, err)
			}
			var tenant, created string
			_ = json.Unmarshal(fields["tenant"], &tenant)
			_ = json.Unmarshal(fields["created_at"], &created)
			tenants[tenant] = true
			if created != "2026-10-16T03:34:56.123456Z" {
				t.Fatalf("timestamp changed: %s", created)
			}
		}
		if !tenants["tenant/한글"] || !tenants["tenant-b"] {
			t.Fatalf("tenant overwritten: %v", tenants)
		}
		exec("DROP TRIGGER test_di_failure ON audit.export_manifests")
		exec("DROP FUNCTION audit.test_di_failure()")
		exec("UPDATE audit.audit_outbox SET next_retry_at=statement_timestamp()-interval '1 second' WHERE destination='gcs_decision_inputs'")
		if worked, err := worker.Once(ctx); err != nil || !worked || count("acked") != 2 {
			t.Fatalf("retry: %v %v", worked, err)
		}
		recovered, err := cloud.Objects.ReadManifest(ctx, "manifests/1.json")
		if err != nil || !bytes.Equal(raw, recovered) {
			t.Fatal("retry changed manifest", err)
		}
		if n, s := cloud.counts(); n != 2 || s != 2 {
			t.Fatalf("retry re-signed: %d %d", n, s)
		}
		firstDigest, err = Verify(ctx, raw, 1, nil, pub.Keys, cloud.Objects, PGAcks{Queries: auditdb.New(pool), Destination: "gcs_decision_inputs"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Verify(ctx, raw, 1, nil, pub.Keys, cloud.Objects, PGAcks{Queries: auditdb.New(pool), Destination: "gcs"}); err == nil {
			t.Fatal("wrong-chain ACK verified")
		}
		if checks == 0 {
			t.Fatal("lease not checked")
		}
	})
	t.Run("second batch false claim and fixed source checks", func(t *testing.T) {
		seed(strings.Repeat("c", 64), "tenant-c", true)
		c, err := out.Claim(ctx, "gcs_decision_inputs", "decision_input")
		if err != nil || c == nil {
			t.Fatal(c, err)
		}
		data, sources, err := out.Records(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		wrong := *c
		wrong.Destination = "gcs"
		if _, err = pub.Publish(ctx, &wrong, data, sources); err == nil {
			t.Fatal("wrong destination accepted")
		}
		wrong = *c
		wrong.ObjectKey = strings.Replace(c.ObjectKey, "/decision_input/", "/business/", 1)
		if _, err = pub.Publish(ctx, &wrong, data, sources); err == nil {
			t.Fatal("forged object key accepted")
		}
		if _, err = pub.Publish(ctx, c, data, []Source{{ID: "invented", Epoch: "invented", First: 1, Last: 1}}); err == nil {
			t.Fatal("invented source accepted")
		}
		exec("UPDATE audit.audit_outbox SET lease_until=statement_timestamp()-interval '1 second',next_retry_at=statement_timestamp()-interval '1 second' WHERE state='claimed'")
		if worked, err := worker.Once(ctx); err != nil || !worked || count("acked") != 3 {
			t.Fatalf("second batch: %v %v", worked, err)
		}
		raw, err := cloud.Objects.ReadManifest(ctx, "manifests/2.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Verify(ctx, raw, 2, &firstDigest, pub.Keys, cloud.Objects, PGAcks{Queries: auditdb.New(pool), Destination: "gcs_decision_inputs"}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("exporter cannot mutate source rows", func(t *testing.T) {
		for _, sql := range []string{"UPDATE decisions.decision_inputs SET tenant='changed'", "DELETE FROM decisions.decision_inputs", "SELECT * FROM decisions.actions", "SELECT audit.enqueue_decision_input(repeat('d',64)::char(64),200)"} {
			if _, err := pool.Exec(ctx, sql); err == nil {
				t.Fatalf("exporter privilege unexpectedly allowed: %s", sql)
			}
		}
	})
	t.Run("missing immutable row remains pending", func(t *testing.T) {
		if _, err := writer.Exec(ctx, "SELECT audit.enqueue_decision_input($1,200)", strings.Repeat("d", 64)); err != nil {
			t.Fatal(err)
		}
		beforeObjects, beforeSigns := cloud.counts()
		if worked, err := worker.Once(ctx); !worked || !errors.Is(err, pgx.ErrNoRows) || count("pending") != 1 || count("acked") != 3 {
			t.Fatalf("missing row acknowledged or dropped: %v %v", worked, err)
		}
		if objects, signs := cloud.counts(); objects != beforeObjects || signs != beforeSigns {
			t.Fatal("missing row published")
		}
	})

}
