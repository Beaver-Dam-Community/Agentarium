package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type nodeFactsFunc func(context.Context, string) (NodeFacts, error)

func (f nodeFactsFunc) Current(ctx context.Context, uid string) (NodeFacts, error) {
	return f(ctx, uid)
}

// PostgreSQL, authorization, lease persistence and rollback are real. Current
// Kubernetes/Q0 observations are injected fixtures, not live runtime evidence.
func testPostgresNodeBootstrap(t *testing.T, base *Store, db *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	node := uuid.NewString()
	san := "spiffe://agentarium.internal/ns/agent-sensors/sa/sensor-exporter"
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	issue := func(serial, boot string) health.Peer {
		t.Helper()
		exec("INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,node_uid,boot_id,issued_at,expires_at) VALUES($1,$2,'agent-sensors','sensor-exporter',$3,$4,now()-interval '1 minute',now()+interval '1 hour')", serial, san, node, boot)
		return health.Peer{SAN: san, Serial: serial}
	}
	peer := issue("b001", "bootstrap-1")
	freshLease := func(_ string) health.Lease { // the label names the case; the node source is fixed
		now := time.Now().UTC()
		gen := int64(1)
		return health.Lease{SourceID: "sensors-node/" + node, Component: "node-sensors", Scope: "node", ScopeID: node, SensorGeneration: &gen, ReportedAt: now, LeaseUntil: now.Add(15 * time.Second), ObservedState: "healthy"}
	}
	s := *base
	countBoot := func() int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM health.node_boot_generation WHERE node_uid=$1", node).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := s.Put(ctx, peer, freshLease("bootstrap-disabled")); !errors.Is(err, health.ErrForbidden) || countBoot() != 0 {
		t.Fatalf("unwired bootstrap: %v", err)
	}
	for _, mode := range []string{"unknown_q0", "wrong_uid", "stale_boot", "provider_unavailable", "wrong_generation", "expired_lease"} {
		t.Run(mode, func(t *testing.T) {
			s.NodeFacts = nodeFactsFunc(func(context.Context, string) (NodeFacts, error) {
				facts := NodeFacts{NodeUID: node, BootID: "bootstrap-1", StartupCapture: "unsupported", StartupMeasurement: NotMeasured}
				switch mode {
				case "unknown_q0":
					facts.StartupCapture = ""
				case "wrong_uid":
					facts.NodeUID = uuid.NewString()
				case "stale_boot":
					facts.BootID = "other-boot"
				case "provider_unavailable":
					return NodeFacts{}, errors.New("unavailable")
				}
				return facts, nil
			})
			l := freshLease("bootstrap-" + mode)
			if mode == "wrong_generation" {
				*l.SensorGeneration = 2
			}
			if mode == "expired_lease" {
				l.ReportedAt = l.ReportedAt.Add(-time.Hour)
				l.LeaseUntil = l.LeaseUntil.Add(-time.Hour)
			}
			if _, err := s.Put(ctx, peer, l); err == nil || countBoot() != 0 {
				t.Fatalf("invalid bootstrap committed: mode=%s err=%v", mode, err)
			}
		})
	}
	// A different node component cannot establish node readiness facts.
	otherSAN := "spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder"
	exec("INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES ('agent-sensors','lifecycle-recorder','service',true) ON CONFLICT DO NOTHING")
	exec("INSERT INTO health.component_principals VALUES($1,'lifecycle-recorder',ARRAY['node'],ARRAY[]::text[],ARRAY[]::text[]) ON CONFLICT DO NOTHING", otherSAN)
	exec("INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,node_uid,boot_id,issued_at,expires_at) VALUES('b003',$1,'agent-sensors','lifecycle-recorder',$2,'bootstrap-1',now()-interval '1 minute',now()+interval '1 hour')", otherSAN, node)
	s.NodeFacts = nodeFactsFunc(func(context.Context, string) (NodeFacts, error) {
		t.Error("non-sensor reached bootstrap facts")
		return NodeFacts{node, "bootstrap-1", "unsupported", NotMeasured}, nil
	})
	otherLease := freshLease("bootstrap-other-component")
	otherLease.Component = "lifecycle-recorder"
	otherLease.SourceID = "lifecycle-node/" + node
	if _, err := s.Put(ctx, health.Peer{SAN: otherSAN, Serial: "b003"}, otherLease); !errors.Is(err, health.ErrForbidden) || countBoot() != 0 {
		t.Fatalf("non-sensor bootstrapped node: %v", err)
	}
	s.NodeFacts = nodeFactsFunc(func(context.Context, string) (NodeFacts, error) {
		return NodeFacts{node, "bootstrap-1", "unsupported", NotMeasured}, nil
	})
	t.Run("advisory_lock_timeout_rolls_back", func(t *testing.T) {
		blocker, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(ctx)
		if _, err = blocker.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('health.node_boot_generation:' || $1::text,0))", node); err != nil {
			t.Fatal(err)
		}
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		started := time.Now()
		_, err = s.Put(call, peer, freshLease("bootstrap-locked"))
		elapsed := time.Since(started)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
			t.Fatalf("want PostgreSQL lock timeout, got %v", err)
		}
		if elapsed < 1500*time.Millisecond || elapsed > 4500*time.Millisecond {
			t.Fatalf("lock waited %v, expected approximately 2s", elapsed)
		}
		if countBoot() != 0 {
			t.Fatal("timed-out bootstrap wrote a boot row")
		}
		var leaseCount int
		if err = db.QueryRow(ctx, "SELECT count(*) FROM health.control_health_leases WHERE node_uid=$1", node).Scan(&leaseCount); err != nil || leaseCount != 0 {
			t.Fatalf("timed-out bootstrap wrote lease: %d %v", leaseCount, err)
		}
		if err = blocker.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var timeout string
		if err = s.Pool.QueryRow(ctx, "SHOW lock_timeout").Scan(&timeout); err != nil || timeout != "0" {
			t.Fatalf("transaction setting leaked: %s %v", timeout, err)
		}
	})
	var wg sync.WaitGroup
	failures := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Put(ctx, peer, freshLease(fmt.Sprintf("bootstrap-race-%d", i)))
			failures <- err
		}(i)
	}
	wg.Wait()
	close(failures)
	// All reports share the node's single source row; a report that commits
	// after a newer one is stale (ErrInvalid), not a second bootstrap.
	accepted := 0
	for err := range failures {
		switch {
		case err == nil:
			accepted++
		case !errors.Is(err, health.ErrInvalid):
			t.Fatal(err)
		}
	}
	if accepted == 0 || countBoot() != 1 {
		t.Fatal("concurrent first reports created multiple boot rows")
	}
	var leases int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM health.control_health_leases WHERE node_uid=$1", node).Scan(&leases); err != nil || leases != 1 { // one per-node source row
		t.Fatalf("committed first leases=%d err=%v", leases, err)
	}
	var state, capture string
	var generation, guard int64
	if err := db.QueryRow(ctx, "SELECT state,startup_capture,sensor_generation,guard_generation FROM health.node_boot_generation WHERE node_uid=$1", node).Scan(&state, &capture, &generation, &guard); err != nil || state != "preparing" || capture != "unsupported" || generation != 1 || guard != 1 {
		t.Fatalf("bootstrap state=%s capture=%s generation=%d/%d err=%v", state, capture, generation, guard, err)
	}
	// Changing boots and the corresponding first lease commit together. An invalid
	// lease must not retire the previous current row or leave a new row behind.
	newer := issue("b002", "bootstrap-2")
	s.NodeFacts = nodeFactsFunc(func(context.Context, string) (NodeFacts, error) {
		return NodeFacts{node, "bootstrap-2", "guarded", Measured}, nil
	})
	bad := freshLease("bootstrap-new-boot")
	bad.ReportedAt = bad.ReportedAt.Add(-time.Hour)
	bad.LeaseUntil = bad.LeaseUntil.Add(-time.Hour)
	if _, err := s.Put(ctx, newer, bad); err == nil {
		t.Fatal("expired first lease accepted")
	}
	if countBoot() != 1 {
		t.Fatal("failed lease left new boot row")
	}
	if err := db.QueryRow(ctx, "SELECT state FROM health.node_boot_generation WHERE node_uid=$1 AND boot_id='bootstrap-1'", node).Scan(&state); err != nil || state != "preparing" {
		t.Fatalf("failed lease retired old boot: %s %v", state, err)
	}
	if _, err := s.Put(ctx, newer, freshLease("bootstrap-new-boot")); err != nil {
		t.Fatal(err)
	}
	if countBoot() != 2 {
		t.Fatal("boot history lost")
	}
	if err := db.QueryRow(ctx, "SELECT state FROM health.node_boot_generation WHERE node_uid=$1 AND boot_id='bootstrap-1'", node).Scan(&state); err != nil || state != "retired" {
		t.Fatalf("old boot not retired: %s %v", state, err)
	}
	if _, err := s.Put(ctx, peer, freshLease("bootstrap-old-cert")); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("old cert revived old boot: %v", err)
	}
	s.NodeFacts = nodeFactsFunc(func(context.Context, string) (NodeFacts, error) {
		return NodeFacts{node, "bootstrap-1", "unsupported", NotMeasured}, nil
	})
	if _, err := s.Put(ctx, peer, freshLease("bootstrap-stale-facts")); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("historical boot resurrected: %v", err)
	}
	if err := db.QueryRow(ctx, "SELECT state FROM health.node_boot_generation WHERE node_uid=$1 AND boot_id='bootstrap-2'", node).Scan(&state); err != nil || state != "preparing" {
		t.Fatalf("new boot overwritten: %s %v", state, err)
	}
	// The runtime login cannot modify principal registration or release a hold;
	// this path uses only the node INSERT/UPDATE grant already required by TASK-10.
}
