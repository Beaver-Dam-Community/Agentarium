package store

import (
	"context"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func testAmbiguousCurrentBoot(t *testing.T, base *Store, db *pgx.Conn) {
	ctx := context.Background()
	node := uuid.NewString()
	san := "spiffe://agentarium.internal/ns/agent-sensors/sa/sensor-exporter"
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,state,updated_at,startup_capture_measurement) VALUES($1,'ambiguous-a','unsupported','ready',now(),'not_measured'),($1,'ambiguous-b','guarded','ready',now()-interval '1 hour','measured')`, node)
	for i, boot := range []string{"ambiguous-a", "ambiguous-b"} {
		serial := []string{"c101", "c102"}[i]
		exec(`INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,node_uid,boot_id,issued_at,expires_at) VALUES($1,$2,'agent-sensors','sensor-exporter',$3,$4,now()-interval '1 minute',now()+interval '1 hour')`, serial, san, node, boot)
	}
	s := *base
	s.NodeFacts = nodeFactsFunc(func(context.Context, string) (NodeFacts, error) {
		t.Error("ambiguous persisted boots reached bootstrap")
		return NodeFacts{}, nil
	})
	gen := int64(1)
	lease := func() health.Lease {
		now := time.Now().UTC()
		return health.Lease{SourceID: "sensors-node/" + node, Component: "node-sensors", Scope: "node", ScopeID: node, SensorGeneration: &gen, ReportedAt: now, LeaseUntil: now.Add(15 * time.Second), ObservedState: "healthy"}
	}
	for _, serial := range []string{"c101", "c102"} {
		peer := health.Peer{SAN: san, Serial: serial}
		if _, err := s.Put(ctx, peer, lease()); err == nil {
			t.Fatal("accepted lease from arbitrarily selected current boot")
		}
		if _, err := s.Get(ctx, peer, "node", node); err == nil {
			t.Fatal("accepted node snapshot with two current boots")
		}
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM health.control_health_leases WHERE source_id='sensors-node/'||$1`, node).Scan(&count); err != nil || count != 0 {
		t.Fatalf("ambiguous lease persisted: %d %v", count, err)
	}
	exec(`INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,observed_state,details,reported_at,lease_until,first_reported_at) VALUES('ambiguous-expired','node-sensors','node',$1::text,$1::text::uuid,'ambiguous-a','healthy','{}',now()-interval '1 minute',now()-interval '45 seconds',now()-interval '1 minute')`, node)
	// This source sorts first, so Expire writes its hold and audit/outbox before
	// encountering the conflicting node. All of those writes must roll back.
	exec(`INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,observed_state,details,reported_at,lease_until,first_reported_at) VALUES('aaa-before-ambiguous','destination-evidence','target','ambiguity-test-target','healthy','{}',now()-interval '1 minute',now()-interval '45 seconds',now()-interval '1 minute')`)
	snapshot := func() string {
		t.Helper()
		var value string
		if err := db.QueryRow(ctx, `SELECT jsonb_build_object('holds',(SELECT jsonb_agg(to_jsonb(h) ORDER BY hold_id) FROM health.holds h),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY event_id) FROM audit.audit_events a),'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY record_kind,record_id,destination) FROM audit.audit_outbox o))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	if err := s.Expire(ctx); err == nil {
		t.Fatal("expiry created a hold using ambiguous current boot")
	}
	if snapshot() != before {
		t.Fatal("ambiguous expiry partially committed hold/audit/outbox")
	}
	exec(`DELETE FROM health.control_health_leases WHERE source_id IN ('ambiguous-expired','aaa-before-ambiguous')`)
	// Once the stale row is explicitly retired, normal reporting resumes.
	exec(`UPDATE health.node_boot_generation SET state='retired' WHERE node_uid=$1 AND boot_id='ambiguous-b'`, node)
	if _, err := s.Put(ctx, health.Peer{SAN: san, Serial: "c101"}, lease()); err != nil {
		t.Fatal(err)
	}
	snapshotHealth, err := s.Get(ctx, health.Peer{SAN: san, Serial: "c101"}, "node", node)
	if err != nil || snapshotHealth.StartupCapture == nil || *snapshotHealth.StartupCapture != "unsupported" {
		t.Fatalf("normal single boot rejected: %+v %v", snapshotHealth, err)
	}
}
