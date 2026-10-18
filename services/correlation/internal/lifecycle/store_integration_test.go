//go:build integration

package lifecycle

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Use a dedicated disposable PostgreSQL cluster. This test creates a database
// and group/login roles; it never drops an existing database or schema.
func TestPostgresHistory(t *testing.T) {
	raw := os.Getenv("LIFECYCLE_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("LIFECYCLE_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := "lifecycle_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	role := name + "_writer"
	for _, sql := range []string{`CREATE DATABASE ` + name, `CREATE ROLE ` + role + ` LOGIN`,
		`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$`} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE `+name+` WITH (FORCE)`)
		_, _ = admin.Exec(context.Background(), `DROP ROLE `+role)
	}()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	migrate := func(direction string) {
		t.Helper()
		b, err := os.ReadFile("../../../../migrations/20261016143437_correlation_lifecycle_intervals." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, string(b)); err != nil {
			t.Fatal(err)
		}
	}
	migrate("up")
	if _, err := db.Exec(ctx, `GRANT correlation_writer TO `+role); err != nil {
		t.Fatal(err)
	}
	u.User = url.User(role)
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := Store{Pool: pool}
	var who string
	var super, createRole bool
	if err := pool.QueryRow(ctx, `SELECT current_user,rolsuper,rolcreaterole FROM pg_roles WHERE rolname=current_user`).Scan(&who, &super, &createRole); err != nil || who != role || super || createRole {
		t.Fatalf("runtime role invalid: %s %v %v %v", who, super, createRole, err)
	}
	h := fixture()
	in, err := Derive(h)
	if err != nil {
		t.Fatal(err)
	}
	// A different transaction holds the container lock. Append must return a
	// database lock timeout (not wait indefinitely) and leave no partial revision.
	blocker, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, in.Identity.Container); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, didCreate, err := s.Append(ctx, in)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" || didCreate {
		t.Fatalf("expected lock timeout rollback: %v %v", didCreate, err)
	}
	if elapsed := time.Since(started); elapsed < time.Second || elapsed > 6*time.Second {
		t.Fatalf("unbounded lock wait: %v", elapsed)
	}
	var afterTimeout int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM correlation.lifecycle_intervals`).Scan(&afterTimeout); err != nil || afterTimeout != 0 {
		t.Fatalf("timeout committed partial revision: %d %v", afterTimeout, err)
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// Success immediately after timeout also proves the failed transaction was
	// rolled back before its pool connection became reusable.
	var created atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, new, err := s.Append(ctx, in)
			if err != nil {
				t.Error(err)
				return
			}
			if v.Version != 1 {
				t.Errorf("duplicate version %d", v.Version)
			}
			if new {
				created.Add(1)
			}
		}()
	}
	wg.Wait()
	if created.Load() != 1 {
		t.Fatalf("created %d copies", created.Load())
	}
	add(&h, Watcher, Deleted, ptr(h.Events[1].SourceTime.Add(10*time.Second)))
	unknown, _ := Derive(h)
	v, new, err := s.Append(ctx, unknown)
	if err != nil || !new || v.Version != 2 || v.EndQuality != "unknown" {
		t.Fatalf("tombstone: %+v %v %v", v, new, err)
	}
	add(&h, Runtime, RuntimeExit, ptr(h.Events[1].SourceTime.Add(time.Second)))
	closed, _ := Derive(h)
	v, new, err = s.Append(ctx, closed)
	if err != nil || !new || v.Version != 3 || v.EndQuality != "observed" {
		t.Fatalf("late exit: %+v %v %v", v, new, err)
	}
	if _, _, err = s.Append(ctx, in); err == nil {
		t.Fatal("stale snapshot discarded retained evidence")
	}
	changed := closed
	changed.EndedAt = ptr(closed.EndedAt.Add(time.Second))
	if _, _, err = s.Append(ctx, changed); err == nil {
		t.Fatal("observed exit overwritten")
	}
	other := fixture()
	other.Identity.Boot = "boot-b"
	other.Identity.Pod = uuid.New()
	other.Identity.Restart = ptr(int32(1))
	for i := range other.Events {
		other.Events[i].ID = uuid.New()
		other.Events[i].Identity = other.Identity
	}
	b, _ := Derive(other)
	v, new, err = s.Append(ctx, b)
	if err != nil || !new || v.Version != 4 {
		t.Fatalf("boot isolation: %+v %v %v", v, new, err)
	}
	// Simulate process/cache restart by constructing a fresh pool and store.
	restarted, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	latest, err := (Store{Pool: restarted}).Latest(ctx, h.Identity.Cluster, h.Identity.Container)
	if err != nil || len(latest) != 2 || latest[0].Version != 3 || latest[1].Version != 4 || latest[0].Identity.Boot == latest[1].Identity.Boot {
		t.Fatalf("durable history: %+v %v", latest, err)
	}
	var count int
	var originalQuality string
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM correlation.lifecycle_intervals`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("revisions %d %v", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT end_quality FROM correlation.lifecycle_intervals WHERE mapping_version=1`).Scan(&originalQuality); err != nil || originalQuality != "open" {
		t.Fatalf("original changed: %s %v", originalQuality, err)
	}
	for _, sql := range []string{`UPDATE correlation.lifecycle_intervals SET end_quality='unknown'`, `DELETE FROM correlation.lifecycle_intervals`, `TRUNCATE correlation.lifecycle_intervals`, `CREATE TABLE correlation.not_allowed (n int)`} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatalf("runtime privilege leaked: %s", sql)
		}
	}
	var read, write bool
	if err := db.QueryRow(ctx, `SELECT has_table_privilege('control_health_writer','correlation.lifecycle_intervals','SELECT'),has_table_privilege('control_health_writer','correlation.lifecycle_intervals','INSERT')`).Scan(&read, &write); err != nil || !read || write {
		t.Fatalf("health rights %v %v %v", read, write, err)
	}
	migrate("down")
	migrate("up")
}
