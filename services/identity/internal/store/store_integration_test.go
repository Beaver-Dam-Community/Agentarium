//go:build integration

package store

// Runs against a throwaway PostgreSQL given by IDENTITY_TEST_DATABASE_URL.
// The test creates the TASK-10 prerequisite role and applies the identity
// migration itself, then drops the schema.
//
//	IDENTITY_TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55432/postgres \
//	  go test -tags integration ./services/identity/internal/store/

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/bootstrap"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/pki"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/revoker"
)

func migrate(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) {
	t.Helper()
	sql, err := os.ReadFile("../../../../migrations/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func TestStore(t *testing.T) {
	url := os.Getenv("IDENTITY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("IDENTITY_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close) // runs after the migration-down cleanup below
	_, _ = pool.Exec(ctx, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$`)
	_, _ = pool.Exec(ctx, `DROP SCHEMA IF EXISTS identity CASCADE`)
	migrate(t, ctx, pool, "20261014144500_identity_workload_pki.up.sql")
	t.Cleanup(func() { migrate(t, ctx, pool, "20261014144500_identity_workload_pki.down.sql") })

	s := Store{Pool: pool}
	ins, upd, err := s.UpsertRegistrations(ctx, []Registration{
		{Namespace: "agent-exec", KSA: "agent-runtime", Role: pki.RoleRuntime},
		{Namespace: "agent-control", KSA: "policy-gateway", Role: pki.RoleService, ServicePrincipal: "policy-gateway"},
	})
	if err != nil || ins != 2 || upd != 0 {
		t.Fatalf("upsert: %d %d %v", ins, upd, err)
	}
	// Idempotent: the same input updates, never duplicates.
	if ins, upd, err = s.UpsertRegistrations(ctx, []Registration{{Namespace: "agent-exec", KSA: "agent-runtime", Role: pki.RoleRuntime}}); err != nil || ins != 0 || upd != 1 {
		t.Fatalf("re-upsert: %d %d %v", ins, upd, err)
	}
	// An adapter row without adapter_id violates the DDL CHECK and rolls back.
	if _, _, err = s.UpsertRegistrations(ctx, []Registration{
		{Namespace: "agent-targets", KSA: "receiver", Role: pki.RoleService, ServicePrincipal: "receiver"},
		{Namespace: "agent-adapters", KSA: "model-adapter", Role: pki.RoleAdapter},
	}); err == nil {
		t.Fatal("adapter without adapter_id accepted")
	}
	if _, found, _ := s.Workload(ctx, "agent-targets", "receiver"); found {
		t.Fatal("partial upsert was committed")
	}

	w, found, err := s.Workload(ctx, "agent-exec", "agent-runtime")
	if err != nil || !found || w.Role != pki.RoleRuntime || !w.Enabled {
		t.Fatalf("workload: %+v %v %v", w, found, err)
	}
	if _, found, _ = s.Workload(ctx, "agent-exec", "nobody"); found {
		t.Fatal("unregistered workload found")
	}

	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	pod := "11111111-2222-3333-4444-555555555555"
	node := "99999999-8888-7777-6666-555555555555"
	for i, rec := range []bootstrap.IssuedRecord{
		{Serial: "01", SAN: "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/" + pod, Namespace: "agent-exec", KSA: "agent-runtime", PodUID: pod, NodeUID: node, BootID: "b1", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)},
		{Serial: "02", SAN: "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway", Namespace: "agent-control", KSA: "policy-gateway", NodeUID: node, BootID: "b1", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)},
	} {
		if err := s.RecordIssued(ctx, rec); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	// A certificate for an unregistered workload violates the foreign key.
	if err := s.RecordIssued(ctx, bootstrap.IssuedRecord{Serial: "03", SAN: "x", Namespace: "agent-exec", KSA: "nobody", IssuedAt: now, ExpiresAt: now}); err == nil {
		t.Fatal("certificate for unregistered workload recorded")
	}

	pods, err := s.UnrevokedPods(ctx, now)
	if err != nil || len(pods) != 1 || pods[0] != (revoker.PodRef{Namespace: "agent-exec", UID: pod}) {
		t.Fatalf("unrevoked: %v %v", pods, err)
	}
	if n, err := s.RevokePod(ctx, pod, now); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if n, _ := s.RevokePod(ctx, pod, now); n != 0 {
		t.Fatal("second revoke changed rows")
	}
	if pods, _ = s.UnrevokedPods(ctx, now); len(pods) != 0 {
		t.Fatalf("still unrevoked: %v", pods)
	}
}
