package store

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func testHoldHTTPPostgres(t *testing.T, store *Store, db *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	exec := func(q string) {
		t.Helper()
		if _, err := db.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	exec("UPDATE health.component_principals SET allowed_hold_reasons=ARRAY['control_drift'] WHERE component='gateway'")
	request, untrusted, origin := healthHTTPFixture(t, store)
	body := []byte(`{"scope":"global","scope_id":"*","reason":"control_drift","evidence_refs":["baseline:verified-difference"]}`)
	var created, existing health.HoldAck
	request("POST", "/internal/holds", body, 200, &created)
	request("POST", "/internal/holds", body, 200, &existing)
	if created.HoldID == nil || created.Decision != "created" || existing.HoldID == nil || existing.Decision != "existing" || *created.HoldID != *existing.HoldID {
		t.Fatalf("create/retry: %+v %+v", created, existing)
	}
	var holds, events int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM health.holds WHERE hold_id=$1", *created.HoldID).Scan(&holds); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE safe_payload->>'reason'='control_drift'").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if holds != 1 || events != 3 {
		t.Fatalf("holds=%d audit=%d", holds, events)
	}
	var snapshot health.Snapshot
	request("GET", "/internal/control-health?scope=global&scope_id=*", nil, 200, &snapshot)
	found := false
	for _, h := range snapshot.OpenHolds {
		if h.HoldID == *created.HoldID {
			found = h.OwnerComponent == "control-health"
		}
	}
	if !found || snapshot.State != "unhealthy" {
		t.Fatal("committed hold missing from health response")
	}
	var invalid map[string]any
	if err := json.Unmarshal(body, &invalid); err != nil {
		t.Fatal(err)
	}
	invalid["requester"] = "forged"
	raw, _ := json.Marshal(invalid)
	request("POST", "/internal/holds", raw, 422, nil)
	delete(invalid, "requester")
	invalid["reason"] = "db_unavailable"
	raw, _ = json.Marshal(invalid)
	var rejected health.HoldAck
	request("POST", "/internal/holds", raw, 403, &rejected)
	if rejected.Decision != "rejected" || rejected.HoldID != nil || len(rejected.ReasonCodes) != 1 || rejected.ReasonCodes[0] != health.CodeHoldRequestDenied {
		t.Fatal(rejected)
	}
	exec("DELETE FROM audit.producer_event_grants WHERE event_type='hold_requested'")
	request("POST", "/internal/holds", body, 503, nil)
	exec("INSERT INTO audit.producer_event_grants VALUES('health-source','hold_requested','*')")
	exec("UPDATE identity.issued_certificates SET revoked_at=now() WHERE serial='01'")
	request("POST", "/internal/holds", body, 403, &rejected)
	exec("UPDATE identity.issued_certificates SET revoked_at=NULL WHERE serial='01'")
	if len(rejected.ReasonCodes) != 1 || rejected.ReasonCodes[0] != health.CodeHoldRequestDenied {
		t.Fatalf("revoked certificate rejection: %+v", rejected)
	}
	probe := []byte(`{"scope":"global","scope_id":"*","reason":"probe_failed","evidence_refs":["probe:validated-result"]}`)
	// Even an accidental component grant does not authorize direct probe calls.
	// The certificate and HTTP path are real; registration changes are fixtures.
	exec("UPDATE health.component_principals SET allowed_hold_reasons=ARRAY['probe_failed'] WHERE component='gateway'")
	request("POST", "/internal/holds", probe, 403, &rejected)
	exec("UPDATE health.component_principals SET component='probe-runner' WHERE component='gateway'")
	request("POST", "/internal/holds", probe, 403, &rejected)
	if len(rejected.ReasonCodes) != 1 || rejected.ReasonCodes[0] != health.CodeHoldRequestDenied {
		t.Fatalf("direct probe rejection: %+v", rejected)
	}
	// A controller's registered identity can own the hold after validating a
	// probe result; this does not implement that separate validation pipeline.
	exec("UPDATE health.component_principals SET component='control-health' WHERE component='probe-runner'")
	var probeHold health.HoldAck
	request("POST", "/internal/holds", probe, 200, &probeHold)
	var owner string
	if probeHold.HoldID == nil || probeHold.Decision != "created" {
		t.Fatalf("controller probe hold: %+v", probeHold)
	}
	if err := db.QueryRow(ctx, "SELECT owner_component FROM health.holds WHERE hold_id=$1", *probeHold.HoldID).Scan(&owner); err != nil || owner != "control-health" {
		t.Fatalf("probe hold owner %q: %v", owner, err)
	}
	exec("UPDATE health.component_principals SET component='gateway',allowed_hold_reasons=ARRAY['control_drift'] WHERE component='control-health'")
	t.Run("ambiguous_current_boot", func(t *testing.T) {
		testHoldHTTPAmbiguousCurrentBoot(t, store, db)
	})

	if resp, err := untrusted.Post(origin+"/internal/holds", "application/json", bytes.NewReader(body)); err == nil {
		resp.Body.Close()
		t.Fatal("hold without client certificate accepted")
	}
}

func testHoldHTTPAmbiguousCurrentBoot(t *testing.T, store *Store, db *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	node := uuid.NewString()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Registration is a fixture. The production HTTP handler, mTLS identity
	// lookup and hold transaction all run against PostgreSQL.
	exec("UPDATE health.component_principals SET allowed_scopes=ARRAY['global','node'] WHERE component='gateway'")
	defer exec("UPDATE health.component_principals SET allowed_scopes=ARRAY['global'] WHERE component='gateway'")
	exec(`INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,state,updated_at,startup_capture_measurement) VALUES($1,'hold-a','unsupported','ready',now(),'not_measured'),($1,'hold-b','guarded','preparing',now()-interval '1 hour','measured')`, node)
	request, _, _ := healthHTTPFixture(t, store)
	body, err := json.Marshal(health.HoldRequest{Scope: "node", ScopeID: node, Reason: "control_drift", EvidenceRefs: []string{"boot:ambiguity"}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := db.QueryRow(ctx, `SELECT jsonb_build_object('holds',(SELECT jsonb_agg(to_jsonb(h) ORDER BY hold_id) FROM health.holds h),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY event_id) FROM audit.audit_events a),'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY record_kind,record_id,destination) FROM audit.audit_outbox o),'boots',(SELECT jsonb_agg(to_jsonb(b) ORDER BY boot_id) FROM health.node_boot_generation b WHERE node_uid=$1))::text`, node).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	for _, phase := range []string{"new", "existing"} {
		t.Run(phase, func(t *testing.T) {
			before := snapshot()
			request("POST", "/internal/holds", body, 503, nil)
			if snapshot() != before {
				t.Fatal("ambiguous hold request changed hold/audit/outbox/node state")
			}
		})
		if phase == "new" {
			// Removing ambiguity permits creation. Reintroducing it must reject
			// even a retry of the existing hold, regardless of updated_at order.
			exec("UPDATE health.node_boot_generation SET state='retired' WHERE node_uid=$1 AND boot_id='hold-b'", node)
			var ack health.HoldAck
			request("POST", "/internal/holds", body, 200, &ack)
			if ack.Decision != "created" || ack.HoldID == nil {
				t.Fatalf("single current boot hold: %+v", ack)
			}
			exec("UPDATE health.node_boot_generation SET state='preparing',updated_at=now()+interval '1 hour' WHERE node_uid=$1 AND boot_id='hold-b'", node)
		}
	}
}
