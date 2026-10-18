package store

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/jackc/pgx/v5"
)

func testHoldRequests(t *testing.T, s *Store, db *pgx.Conn, sensor health.Peer, node, otherNode string) {
	t.Helper()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, q, node).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	request := health.HoldRequest{Scope: "node", ScopeID: node, Reason: "sensor_degraded", EvidenceRefs: []string{"wal:durable-evidence"}}
	exec("UPDATE health.component_principals SET allowed_hold_reasons=ARRAY['sensor_degraded'] WHERE principal_san=$1", sensor.SAN)
	// Previous tests retired boot-1. A trusted but old certificate still cannot
	// hold the node's new boot, including when a hold already exists later.
	if _, err := s.RequestHold(ctx, sensor, request); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("old boot: %v", err)
	}
	exec("UPDATE identity.issued_certificates SET boot_id='boot-2' WHERE serial='02'")
	exec("INSERT INTO health.node_boot_generation VALUES($1,'other',1,1,'unsupported','preparing',now(),'not_measured')", otherNode)
	for _, tc := range []struct{ name, change, restore string }{
		{"grant", "UPDATE health.component_principals SET allowed_hold_reasons='{}' WHERE component='node-sensors'", "UPDATE health.component_principals SET allowed_hold_reasons=ARRAY['sensor_degraded'] WHERE component='node-sensors'"},
		{"scope", "UPDATE health.component_principals SET allowed_scopes='{}' WHERE component='node-sensors'", "UPDATE health.component_principals SET allowed_scopes=ARRAY['node'] WHERE component='node-sensors'"},
		{"revoked", "UPDATE identity.issued_certificates SET revoked_at=now() WHERE serial='02'", "UPDATE identity.issued_certificates SET revoked_at=NULL WHERE serial='02'"},
		{"disabled", "UPDATE identity.registered_workloads SET enabled=false WHERE ksa='sensor-exporter'", "UPDATE identity.registered_workloads SET enabled=true WHERE ksa='sensor-exporter'"},
		{"expired", "UPDATE identity.issued_certificates SET expires_at=now()-interval '1 second' WHERE serial='02'", "UPDATE identity.issued_certificates SET expires_at=now()+interval '1 hour' WHERE serial='02'"},
	} {
		exec(tc.change)
		_, err := s.RequestHold(ctx, sensor, request)
		exec(tc.restore)
		if !errors.Is(err, health.ErrForbidden) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	other := request
	other.ScopeID = otherNode
	if _, err := s.RequestHold(ctx, sensor, other); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("other node: %v", err)
	}
	if _, err := s.RequestHold(ctx, health.Peer{SAN: sensor.SAN, Serial: "unregistered"}, request); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("unknown serial: %v", err)
	}
	// Earlier subtests leave released lease_expired holds (and their audit rows) on this
	// node, so these checks count only the reason this test requests.
	if count("SELECT count(*) FROM health.holds WHERE scope_id=$1 AND reason='sensor_degraded'") != 0 {
		t.Fatal("denied request wrote a hold")
	}

	// Missing either audit grant or the state-column grant must roll back all
	// rows, including the first audit event when the second append fails.
	for _, phase := range []string{"request_audit", "execution_audit", "node_state"} {
		if phase != "request_audit" {
			exec("INSERT INTO audit.producer_event_grants VALUES('health-source','hold_requested','*') ON CONFLICT DO NOTHING")
		}
		if phase == "execution_audit" {
			exec("DELETE FROM audit.producer_event_grants WHERE source_id='health-source' AND event_type='execution_held'")
		}
		if phase == "node_state" {
			exec("REVOKE UPDATE ON health.node_boot_generation FROM control_health_writer")
		}
		if _, err := s.RequestHold(ctx, sensor, request); err == nil {
			t.Fatalf("accepted missing %s", phase)
		}
		if phase == "execution_audit" {
			exec("INSERT INTO audit.producer_event_grants VALUES('health-source','execution_held','*')")
		}
		if phase == "node_state" {
			exec("GRANT UPDATE ON health.node_boot_generation TO control_health_writer")
		}
		if count("SELECT count(*) FROM health.holds WHERE scope_id=$1 AND reason='sensor_degraded'") != 0 || count("SELECT count(*) FROM audit.audit_events WHERE safe_payload->>'scope_id'=$1 AND safe_payload->>'reason'='sensor_degraded'") != 0 {
			t.Fatalf("partial commit after %s", phase)
		}
	}

	const calls = 12
	results := make(chan health.HoldAck, calls)
	failures := make(chan error, calls)
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ack, err := s.RequestHold(ctx, sensor, request)
			if err != nil {
				failures <- err
			} else {
				results <- ack
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	created := 0
	var id string
	for ack := range results {
		if ack.HoldID == nil {
			t.Fatal(ack)
		}
		if id != "" && id != *ack.HoldID {
			t.Fatal("duplicate hold IDs")
		}
		id = *ack.HoldID
		if ack.Decision == "created" {
			created++
		} else if ack.Decision != "existing" {
			t.Fatal(ack)
		}
	}
	if created != 1 || count("SELECT count(*) FROM health.holds WHERE scope_id=$1 AND reason='sensor_degraded'") != 1 || count("SELECT count(*) FROM audit.audit_events WHERE safe_payload->>'scope_id'=$1 AND safe_payload->>'reason'='sensor_degraded' AND event_type='hold_requested'") != calls || count("SELECT count(*) FROM audit.audit_events WHERE safe_payload->>'scope_id'=$1 AND safe_payload->>'reason'='sensor_degraded' AND event_type='execution_held'") != 1 {
		t.Fatal("concurrent hold/audit counts")
	}
	if count("SELECT count(*) FROM audit.audit_outbox o JOIN audit.audit_events e ON e.event_id::text=o.record_id WHERE e.safe_payload->>'scope_id'=$1 AND e.safe_payload->>'reason'='sensor_degraded'") != calls+1 {
		t.Fatal("outbox not atomic")
	}
	var state, owner, requester string
	if err := db.QueryRow(ctx, "SELECT state FROM health.node_boot_generation WHERE node_uid=$1 AND boot_id='boot-2'", node).Scan(&state); err != nil || state != "held" {
		t.Fatalf("node state %s %v", state, err)
	}
	if err := db.QueryRow(ctx, "SELECT owner_component,requested_by FROM health.holds WHERE hold_id=$1", id).Scan(&owner, &requester); err != nil || owner != "node-sensors" || requester != sensor.SAN {
		t.Fatalf("owner/requester %s %s %v", owner, requester, err)
	}
	var payload, refs []byte
	if err := db.QueryRow(ctx, "SELECT safe_payload,evidence_refs FROM audit.audit_events WHERE event_type='hold_requested' AND safe_payload->>'scope_id'=$1 LIMIT 1", node).Scan(&payload, &refs); err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	if event["requester"] != sensor.SAN || string(refs) != `["wal:durable-evidence"]` {
		t.Fatalf("lost attribution/evidence %s %s", payload, refs)
	}
	// Block the hold INSERT before it can obtain its table lock. RequestHold
	// must not take the node row lock ahead of the hold write.
	blocker, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(ctx)
	if _, err := blocker.Exec(ctx, "LOCK TABLE health.holds IN SHARE MODE"); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() { _, err := s.RequestHold(ctx, sensor, request); completed <- err }()
	deadline := time.Now().Add(time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		if _, err := blocker.Exec(ctx, "SELECT pg_stat_clear_snapshot()"); err != nil {
			t.Fatal(err)
		}
		if err := blocker.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%-- name: CreateHold%')").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("request did not wait for the hold INSERT")
	}
	if _, err := blocker.Exec(ctx, "SET LOCAL lock_timeout='500ms'"); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(ctx, "UPDATE health.node_boot_generation SET updated_at=statement_timestamp() WHERE node_uid=$1 AND boot_id='boot-2'", node); err != nil {
		t.Fatalf("holds -> node lock order: %v", err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}

	// A competing bootstrap is bounded by the same two-second lock timeout.
	bootTx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer bootTx.Rollback(ctx)
	if _, err := bootTx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('health.node_boot_generation:' || $1::text,0))", node); err != nil {
		t.Fatal(err)
	}
	before := count("SELECT count(*) FROM audit.audit_events WHERE safe_payload->>'scope_id'=$1")
	if _, err := s.RequestHold(ctx, sensor, request); err == nil || errors.Is(err, health.ErrForbidden) {
		t.Fatalf("bootstrap wait must be retryable: %v", err)
	}
	if err := bootTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got := count("SELECT count(*) FROM audit.audit_events WHERE safe_payload->>'scope_id'=$1"); got != before {
		t.Fatal("bootstrap timeout committed audit")
	}
	// Missing and ambiguous current boots are unavailable, not auth denials.
	exec("UPDATE health.node_boot_generation SET state='retired' WHERE node_uid=$1 AND boot_id='boot-2'", node)
	if _, err := s.RequestHold(ctx, sensor, request); err == nil || errors.Is(err, health.ErrForbidden) {
		t.Fatalf("missing current boot: %v", err)
	}
	exec("UPDATE health.node_boot_generation SET state='held' WHERE node_uid=$1 AND boot_id='boot-2'", node)
	exec("INSERT INTO health.node_boot_generation VALUES($1,'ambiguous',1,1,'unsupported','preparing',now(),'not_measured')", node)
	if _, err := s.RequestHold(ctx, sensor, request); err == nil || errors.Is(err, health.ErrForbidden) {
		t.Fatalf("ambiguous current boot: %v", err)
	}
	exec("DELETE FROM health.node_boot_generation WHERE node_uid=$1 AND boot_id='ambiguous'", node)

	// Even an existing hold retry needs a still-live certificate and audit grant.
	exec("UPDATE identity.issued_certificates SET revoked_at=now() WHERE serial='02'")
	if _, err := s.RequestHold(ctx, sensor, request); !errors.Is(err, health.ErrForbidden) {
		t.Fatal("existing bypassed revocation")
	}
	exec("UPDATE identity.issued_certificates SET revoked_at=NULL WHERE serial='02'")
	exec("DELETE FROM audit.producer_event_grants WHERE event_type='hold_requested'")
	if _, err := s.RequestHold(ctx, sensor, request); err == nil {
		t.Fatal("existing ack without request audit")
	}
	exec("INSERT INTO audit.producer_event_grants VALUES('health-source','hold_requested','*')")
	for _, q := range []string{"UPDATE health.holds SET owner_component='forged'"} {
		if _, err := s.Pool.Exec(ctx, q); err == nil {
			t.Fatalf("writer allowed %s", q)
		}
	}
}
