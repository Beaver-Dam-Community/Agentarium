package store

import (
	"context"
	"sync"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/jackc/pgx/v5"
)

// No node row serializes these calls: the partial unique index and OpenHold
// lookup must converge on one ID while every accepted request is audited.
func testGlobalHoldRequests(t *testing.T, s *Store, db *pgx.Conn) {
	ctx := context.Background()
	san := "spiffe://agentarium.internal/ns/agent-observe/sa/audit-export"
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES('agent-observe','audit-export','service',true)")
	exec("INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,issued_at,expires_at) VALUES('09',$1,'agent-observe','audit-export',now()-interval '1 minute',now()+interval '1 hour')", san)
	exec("INSERT INTO health.component_principals VALUES($1,'audit-export',ARRAY['global'],ARRAY['export_lag'],ARRAY[]::text[])", san)
	const calls = 24
	results := make(chan health.HoldAck, calls)
	failures := make(chan error, calls)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ack, err := s.RequestHold(ctx, health.Peer{SAN: san, Serial: "09"}, health.HoldRequest{Scope: "global", ScopeID: "*", Reason: "export_lag", EvidenceRefs: []string{"export:test"}})
			if err != nil {
				failures <- err
			} else {
				results <- ack
			}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	created, existing := 0, 0
	id := ""
	for ack := range results {
		if ack.HoldID == nil {
			t.Fatal(ack)
		}
		if id != "" && id != *ack.HoldID {
			t.Fatal("different hold IDs")
		}
		id = *ack.HoldID
		switch ack.Decision {
		case "created":
			created++
		case "existing":
			existing++
		default:
			t.Fatal(ack)
		}
	}
	if created != 1 || existing != calls-1 {
		t.Fatalf("created=%d existing=%d", created, existing)
	}
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"SELECT count(*) FROM health.holds WHERE scope='global' AND scope_id='*' AND reason='export_lag' AND released_at IS NULL", 1},
		{"SELECT count(*) FROM audit.audit_events WHERE event_type='hold_requested' AND safe_payload->>'reason'='export_lag'", calls},
		{"SELECT count(*) FROM audit.audit_events WHERE event_type='execution_held' AND safe_payload->>'reason'='export_lag'", 1},
		{"SELECT count(*) FROM audit.audit_outbox o JOIN audit.audit_events e ON e.event_id::text=o.record_id WHERE e.safe_payload->>'reason'='export_lag'", calls + 1},
	} {
		var got int
		if err := db.QueryRow(ctx, tc.query).Scan(&got); err != nil || got != tc.want {
			t.Fatalf("count %d want %d: %v", got, tc.want, err)
		}
	}
}
