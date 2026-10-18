//go:build integration

package m31

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	dbName    = "agentarium"
	installer = "db-installer"
)

// logins are the per-service DB logins (Cloud SQL IAM users in GKE).
var logins = map[string]string{
	"identity":           "m31_identity",
	"gateway":            "m31_gateway",
	"coordinator":        "m31_coordinator",
	"receiver-sender":    "m31_adapter",
	"receiver":           "m31_receiver",
	"evidence-collector": "m31_collector",
	"control-health":     "m31_health",
	"credential-broker":  "m31_broker",
	"audit-writer":       "m31_audit_writer",
	"audit-exporter":     "m31_audit_exporter",
}

func (e env) dsn(user string) string {
	return fmt.Sprintf("postgres://%s@127.0.0.1:%s/%s?sslmode=disable", user, e.pgPort, dbName)
}

// installDB creates the Cloud SQL stand-in roles, applies every migration as
// the non-superuser installer (as the #156 installer Job does) and runs the
// install SQL: the repo's deploy/gcp/base/installer/m3-1-action-path.sql and
// tests/m3-1/local-install.sql for the inputs no repo file installs yet.
func installDB(t *testing.T, e env, receiverKeySecret string) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(bg(), 5*time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, fmt.Sprintf("postgres://postgres@127.0.0.1:%s/postgres?sslmode=disable", e.pgPort))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(bg())
	stmts := []string{
		"CREATE ROLE cloudsqlsuperuser NOLOGIN CREATEROLE CREATEDB",
		`CREATE ROLE "` + installer + `" LOGIN CREATEROLE CREATEDB IN ROLE cloudsqlsuperuser`,
		"CREATE DATABASE " + dbName + " OWNER cloudsqlsuperuser",
	}
	for _, l := range sortedValues(logins) {
		stmts = append(stmts, "CREATE ROLE "+l+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	}
	for _, s := range stmts {
		if _, err := admin.Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	inst, err := pgx.Connect(ctx, e.dsn(installer))
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close(bg())
	// render-db-installer-job.py BOOTSTRAP_SQL, then every migration in order.
	if _, err := inst.Exec(ctx, "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$;"); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(e.repo, "migrations", "*.up.sql"))
	if err != nil || len(files) == 0 {
		t.Fatal("no migrations", err)
	}
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inst.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("migration %s: %v", filepath.Base(f), err)
		}
	}
	info("%d migrations applied as %s (latest %s)", len(files), installer, strings.SplitN(filepath.Base(files[len(files)-1]), "_", 2)[0])

	installFile(t, e, filepath.Join(e.repo, "deploy/gcp/base/installer/m3-1-action-path.sql"), map[string]string{
		"tenant": tenant, "identity_login": logins["identity"], "gateway_login": logins["gateway"],
		"coordinator_login": logins["coordinator"], "adapter_login": logins["receiver-sender"],
		"receiver_login": logins["receiver"], "collector_login": logins["evidence-collector"],
		"health_login": logins["control-health"], "health_audit_source_id": "control-health",
		"receiver_api_key_secret": receiverKeySecret, "receiver_api_key_version": "1",
	})
	// Local inputs for components outside the repo install files; applied as
	// the superuser because the installer has no schema-owner membership
	// after the migrations (see installFile).
	if err := psqlFile(e, "postgres", filepath.Join(e.repo, "tests/m3-1/local-install.sql"), map[string]string{
		"broker_login": logins["credential-broker"], "writer_login": logins["audit-writer"],
		"exporter_login": logins["audit-exporter"], "health_audit_source_id": "control-health",
	}); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(bg(), e.dsn("postgres"))
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

// installFile applies a repository install SQL file as the documented
// login, the migration installer. If that fails, the failure is recorded as
// an install gap (printed, written to $M31_E2E_WORK/gaps, and the run can
// no longer pass) and the file is applied as the superuser so the later
// stages still run.
func installFile(t *testing.T, e env, file string, vars map[string]string) {
	t.Helper()
	err := psqlFile(e, installer, file, vars)
	if err == nil {
		return
	}
	gap := fmt.Sprintf("%s fails as %s: %s", strings.TrimPrefix(file, e.repo+"/"), installer, firstLine(err.Error()))
	info("INSTALL GAP: %s", gap)
	f, ferr := os.OpenFile(e.path("gaps"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if ferr != nil {
		t.Fatal(ferr)
	}
	_, _ = fmt.Fprintln(f, gap)
	_ = f.Close()
	if err := psqlFile(e, "postgres", file, vars); err != nil {
		t.Fatal(err)
	}
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "ERROR:") {
			return strings.TrimSpace(l)
		}
	}
	return strings.SplitN(s, "\n", 2)[0]
}

// psqlFile runs an install SQL file with psql inside the PostgreSQL
// container as user, with -v variables.
func psqlFile(e env, user, file string, vars map[string]string) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	args := []string{"exec", "-i", e.pgContainer, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", dbName}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-v", k+"="+vars[k])
	}
	cmd := exec.Command("docker", args...)
	cmd.Stdin = bytes.NewReader(raw)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("psql %s as %s: %v\n%s", filepath.Base(file), user, err, out)
	}
	info("%s applied as %s", strings.TrimPrefix(file, e.repo+"/"), user)
	return nil
}

func sortedValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func count(t *testing.T, db *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(bg(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func exec1(t *testing.T, db *pgxpool.Pool, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(bg(), q, args...); err != nil {
		t.Fatalf("%.100s: %v", q, err)
	}
}
