// Package testfixture holds local stand-ins shared by TASK-07 process-level
// integration tests: disposable PostgreSQL install, a local PKI, a GCS/KMS
// contract fixture, a TASK-10 control-health contract fake, and helpers to
// build and run the real binaries. It is imported only from _test.go files.
// None of these fixtures is Google infrastructure or the TASK-10 service.
package testfixture

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RepoRoot is the repository root, resolved from this source file.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "../../../..")
}

func MustExec(t *testing.T, ctx context.Context, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := c.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("SQL failed: %v", err)
	}
}

// InstallDatabase applies every merged up migration in version order to a new
// database, as the installer does, and removes only the cluster-wide roles it
// added when the test ends.
func InstallDatabase(t *testing.T, ctx context.Context, dsn string) (*pgx.Conn, *pgx.ConnConfig) {
	t.Helper()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	existing := roleSet(t, ctx, admin)
	name := "audit_proc_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	MustExec(t, ctx, admin, "CREATE DATABASE "+name)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = name
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		db.Close(ctx)
		_, _ = admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		var added []string
		for role := range roleSet(t, ctx, admin) {
			if !existing[role] {
				added = append(added, role)
			}
		}
		sort.Strings(added)
		for _, role := range added {
			// Roles are cluster-wide and another package may still use one.
			// Preserve the base branch cleanup behavior.
			if _, err := admin.Exec(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Logf("left cluster role %s: %v", role, err)
			}
		}
	})
	// Installer prerequisite: TASK-10 owns this NOLOGIN role, and the identity
	// migration refuses to run before it exists.
	MustExec(t, ctx, db, "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$")
	files, err := filepath.Glob(filepath.Join(RepoRoot(), "migrations", "*.up.sql"))
	if err != nil || len(files) == 0 {
		t.Fatal("migrations not found")
	}
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
	}
	return db, cfg
}

func roleSet(t *testing.T, ctx context.Context, c *pgx.Conn) map[string]bool {
	t.Helper()
	rows, err := c.Query(ctx, "SELECT rolname FROM pg_roles")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			t.Fatal(err)
		}
		set[role] = true
	}
	return set
}

// Login creates a restricted LOGIN role that is a member of group.
func Login(t *testing.T, ctx context.Context, db *pgx.Conn, name, group string) string {
	t.Helper()
	MustExec(t, ctx, db, "CREATE ROLE "+name+" LOGIN INHERIT NOSUPERUSER")
	MustExec(t, ctx, db, "GRANT "+group+" TO "+name)
	return name
}

func DSN(cfg *pgx.ConnConfig, user string) string {
	u := url.URL{Scheme: "postgres", User: url.User(user), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}
	return u.String()
}

// Pool opens a pool for a restricted login and checks it is not a superuser.
func Pool(t *testing.T, ctx context.Context, cfg *pgx.ConnConfig, user string) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(ctx, DSN(cfg, user))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var super bool
	if err := p.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname=session_user").Scan(&super); err != nil || super {
		t.Fatalf("restricted login %s: super=%v err=%v", user, super, err)
	}
	return p
}
