package store

import (
	"context"
	"errors"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/jackc/pgx/v5"
)

// testRiskEventHolds checks #172 on real PostgreSQL: only the correlation
// principal may request a workload risk_event hold, reason_detail is stored
// from the first request and never changed by later evidence, and every
// accepted request is audited.
func testRiskEventHolds(t *testing.T, s *Store, db *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	correlationSAN := "spiffe://agentarium.internal/ns/agent-observe/sa/correlation"
	impostorSAN := "spiffe://agentarium.internal/ns/agent-observe/sa/impostor"
	exec("INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES ('agent-observe','correlation','service',true),('agent-observe','impostor','service',true)")
	exec("INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,issued_at,expires_at) VALUES ('c1',$1,'agent-observe','correlation',now()-interval '1 minute',now()+interval '1 hour'),('c2',$2,'agent-observe','impostor',now()-interval '1 minute',now()+interval '1 hour')", correlationSAN, impostorSAN)
	exec("INSERT INTO health.component_principals VALUES ($1,'correlation',ARRAY['workload'],ARRAY['risk_event'],ARRAY[]::text[]),($2,'node-readiness',ARRAY['workload'],ARRAY['risk_event'],ARRAY[]::text[])", correlationSAN, impostorSAN)
	exec("INSERT INTO audit.producer_event_grants VALUES('health-source','hold_requested','*') ON CONFLICT DO NOTHING")
	correlation := health.Peer{SAN: correlationSAN, Serial: "c1"}
	detail := func(v string) *string { return &v }
	request := health.HoldRequest{Scope: "workload", ScopeID: "agent-exec/runtime", Reason: "risk_event", ReasonDetail: detail("unregistered_connect_established"), EvidenceRefs: []string{"kernel_event:11111111-1111-4111-8111-111111111111"}}
	if _, err := s.RequestHold(ctx, health.Peer{SAN: impostorSAN, Serial: "c2"}, request); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("non-correlation principal: %v", err)
	}
	first, err := s.RequestHold(ctx, correlation, request)
	if err != nil || first.Decision != "created" {
		t.Fatalf("first risk hold %+v %v", first, err)
	}
	later := request
	later.ReasonDetail = detail("unexpected_child_exec")
	later.EvidenceRefs = []string{"kernel_event:22222222-2222-4222-8222-222222222222"}
	second, err := s.RequestHold(ctx, correlation, later)
	if err != nil || second.Decision != "existing" || *second.HoldID != *first.HoldID {
		t.Fatalf("second risk hold %+v %v", second, err)
	}
	var stored, owner string
	var requests int
	if err := db.QueryRow(ctx, "SELECT reason_detail,owner_component FROM health.holds WHERE hold_id=$1::uuid", *first.HoldID).Scan(&stored, &owner); err != nil || stored != "unregistered_connect_established" || owner != "control-health" {
		t.Fatalf("stored detail %s owner %s %v", stored, owner, err)
	}
	if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE event_type='hold_requested' AND safe_payload->>'reason'='risk_event' AND evidence_refs ? 'kernel_event:22222222-2222-4222-8222-222222222222'").Scan(&requests); err != nil || requests != 1 {
		t.Fatalf("later evidence not audited: %d %v", requests, err)
	}
	missing := request
	missing.ReasonDetail = nil
	if missing.Valid() {
		t.Fatal("risk_event without reason_detail accepted")
	}
	wrongScope := request
	wrongScope.Scope, wrongScope.ScopeID = "global", "*"
	if wrongScope.Valid() {
		t.Fatal("risk_event outside workload scope accepted")
	}
	other := health.HoldRequest{Scope: "workload", ScopeID: "agent-exec/runtime", Reason: "alignment_mismatch", ReasonDetail: detail("protected_path_write"), EvidenceRefs: []string{}}
	if other.Valid() {
		t.Fatal("reason_detail accepted for another reason")
	}
}
