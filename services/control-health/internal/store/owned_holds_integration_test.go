package store

import (
	"context"
	"errors"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/jackc/pgx/v5"
)

// testOwnedHolds checks #177 on real PostgreSQL: a component lists only its
// own open holds whose reason it may release, never another component's,
// released or security holds, and only for its own component name.
func testOwnedHolds(t *testing.T, s *Store, db *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	owner := "spiffe://agentarium.internal/ns/agent-observe/sa/owned-exporter"
	plain := "spiffe://agentarium.internal/ns/agent-observe/sa/owned-plain"
	exec("INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES ('agent-observe','owned-exporter','service',true),('agent-observe','owned-plain','service',true)")
	exec("INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,issued_at,expires_at) VALUES ('o1',$1,'agent-observe','owned-exporter',now()-interval '1 minute',now()+interval '1 hour'),('o2',$2,'agent-observe','owned-plain',now()-interval '1 minute',now()+interval '1 hour')", owner, plain)
	exec("INSERT INTO health.component_principals VALUES ($1,'owned-export',ARRAY['global','node'],ARRAY['export_lag'],ARRAY['export_lag','control_drift']),($2,'owned-plain',ARRAY['global'],ARRAY['export_lag'],ARRAY[]::text[])", owner, plain)
	var want string
	if err := db.QueryRow(ctx, "INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by) VALUES(gen_random_uuid(),'target','owned-t1','export_lag','owned-export','test') RETURNING hold_id::text").Scan(&want); err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by,released_at,release_ref) VALUES(gen_random_uuid(),'target','owned-t2','export_lag','owned-export','test',now(),'auto:x:y')")
	exec("INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by) VALUES(gen_random_uuid(),'target','owned-t3','export_lag','other-component','test')")
	exec("INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by) VALUES(gen_random_uuid(),'target','owned-t4','control_drift','owned-export','test')")
	peer := health.Peer{SAN: owner, Serial: "o1"}
	got, err := s.OwnedHolds(ctx, peer, "owned-export")
	if err != nil || len(got.Holds) != 1 || got.Holds[0].HoldID != want || got.Holds[0].OwnerComponent != "owned-export" {
		t.Fatalf("owned holds %+v %v", got, err)
	}
	if _, err := s.OwnedHolds(ctx, peer, "other-component"); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("another component's holds: %v", err)
	}
	if _, err := s.OwnedHolds(ctx, health.Peer{SAN: plain, Serial: "o2"}, "owned-plain"); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("component without releasable reasons: %v", err)
	}
	if _, err := s.OwnedHolds(ctx, health.Peer{SAN: owner, Serial: "unknown"}, "owned-export"); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("unknown certificate: %v", err)
	}
}
