//go:build integration

package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Run against an empty database; the test applies migrations/*.up.sql:
//
//	DATABASE_URL=postgres://... go test -tags integration ./services/identity/internal/sessions/
func setup(t *testing.T) (*Service, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrateOnce(t, pool)
	if _, err := pool.Exec(ctx, `
TRUNCATE identity.issue_candidate_counters, identity.issue_candidates, identity.service_session_counters, identity.session_tokens,
    identity.service_sessions, identity.session_budgets, identity.sessions, identity.issued_certificates,
    identity.registered_workloads CASCADE;
INSERT INTO identity.registered_workloads (namespace, ksa, role, service_principal) VALUES
    ('agent-exec', 'agent-runtime', 'runtime', NULL),
    ('agent-exec', 'other-runtime', 'runtime', NULL),
    ('agent-observe', 'policy-proposer', 'service', 'policy-proposer'),
    ('agent-release', 'releaser', 'service', 'releaser'),
    ('agent-control', 'intent-checker', 'service', 'intent-checker');`); err != nil {
		t.Fatal(err)
	}
	cat, err := canonical.LoadCatalogDir("../../../../packages/canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	pol := Policy{Catalog: cat, StandingRules: map[string]StandingRule{
		"standing.k8s_read.v1": {StandingRuleID: "standing.k8s_read.v1", SessionKind: "user",
			OperationIDs: []string{"k8s.pods.list", "k8s.events.list", "k8s.pods.logs"}, TargetPattern: "k8s-agent-targets", SessionBudget: 100},
		"standing.model_synthetic.v1": {StandingRuleID: "standing.model_synthetic.v1", SessionKind: "user",
			OperationIDs: []string{"model.generate"}, TargetPattern: "agent-platform-gemini", SessionBudget: 50},
		"probe.activation.v1": {StandingRuleID: "probe.activation.v1", SessionKind: "service",
			OperationIDs: []string{"receiver.submit"}, TargetPattern: "receiver-probe", SessionBudget: 4},
	}}
	return &Service{Pool: pool, Policy: staticPolicy{pol}, Audit: &recorder{}, Environment: "test", ClaimKey: []byte("test-claim-key")}, pool
}

var migrated sync.Once

func migrateOnce(t *testing.T, pool *pgxpool.Pool) {
	migrated.Do(func() {
		ctx := context.Background()
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('identity.session_tokens') IS NOT NULL`).Scan(&exists); err != nil || exists {
			return
		}
		if _, err := pool.Exec(ctx, `DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF;
        END $$`); err != nil {
			t.Fatal(err)
		}
		files, _ := filepath.Glob("../../../../migrations/*.up.sql")
		sort.Strings(files)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, string(b)); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	})
}

type staticPolicy struct{ p Policy }

func (s staticPolicy) Policy(context.Context) (Policy, error) { return s.p, nil }

type recorder struct {
	mu     sync.Mutex
	events []Event
	fail   bool
}

func (r *recorder) Append(ctx context.Context, tx pgx.Tx, ev Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("audit down")
	}
	if err := checkRegistry(ctx, tx, ev); err != nil {
		return err
	}
	r.events = append(r.events, ev)
	return nil
}

// checkRegistry applies audit_append's required-field rule (TASK-07
// migration): every field in audit.event_types.required_payload_fields must
// be present in the payload and not JSON null.
func checkRegistry(ctx context.Context, tx pgx.Tx, ev Event) error {
	b, err := json.Marshal(ev.Payload)
	if err != nil {
		return err
	}
	var known bool
	var missing []string
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (SELECT FROM audit.event_types WHERE event_type = $1),
    coalesce((SELECT array_agg(f ORDER BY f) FROM audit.event_types r, jsonb_array_elements_text(r.required_payload_fields) f
        WHERE r.event_type = $1 AND (NOT ($2::jsonb ? f) OR $2::jsonb -> f = 'null'::jsonb)), '{}')`,
		ev.Type, string(b)).Scan(&known, &missing); err != nil {
		return err
	}
	if !known || len(missing) > 0 {
		return fmt.Errorf("SCHEMA_INVALID: %s (registered %v) missing or null %v", ev.Type, known, missing)
	}
	return nil
}

var (
	alice   = Actor{AuthenticatedActor: "google:alice", Tenant: "hackathon"}
	bob     = Actor{AuthenticatedActor: "google:bob", Tenant: "hackathon"}
	op      = Actor{AuthenticatedActor: "google:ops", Tenant: "hackathon", Roles: []string{"operator"}}
	podA    = RuntimePrincipal{SAN: "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/" + uuid.NewString(), Namespace: "agent-exec", KSA: "agent-runtime"}
	podB    = RuntimePrincipal{SAN: "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/" + uuid.NewString(), Namespace: "agent-exec", KSA: "agent-runtime"}
	otherWl = RuntimePrincipal{SAN: "spiffe://agentarium.internal/ns/agent-exec/sa/other-runtime/pod/" + uuid.NewString(), Namespace: "agent-exec", KSA: "other-runtime"}
)

func k8sRequest() CreateRequest {
	return CreateRequest{WorkloadID: "agent-exec/agent-runtime", TaskStatement: "list pods in agent-targets",
		RequestedScope: RequestedScope{OperationIDs: []string{"k8s.pods.list", "k8s.pods.logs"}, TargetIDs: []string{"k8s-agent-targets"}}}
}

func code(t *testing.T, err error) string {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	return e.Code
}

func TestCreateAssignClaim(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	cr, err := s.Create(ctx, alice, k8sRequest())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cr.AllowedOperationIDs, ",") != "k8s.pods.list,k8s.pods.logs" {
		t.Fatalf("allowed ops %v", cr.AllowedOperationIDs)
	}
	var budgets int
	var digestLen int
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.session_budgets WHERE session_id = $1`, cr.SessionID).Scan(&budgets)
	pool.QueryRow(ctx, `SELECT length(claim_code_digest) FROM identity.sessions WHERE session_id = $1`, cr.SessionID).Scan(&digestLen)
	if budgets != 1 || digestLen != 32 {
		t.Fatalf("budgets %d, claim digest %d bytes", budgets, digestLen)
	}

	as, err := s.Assignments(ctx, podA)
	if err != nil || len(as) != 1 || as[0].ClaimCode != cr.ClaimCode {
		t.Fatalf("assignments %+v %v", as, err)
	}
	if as2, _ := s.Assignments(ctx, otherWl); len(as2) != 0 {
		t.Fatal("other workload sees the session")
	}

	if _, err := s.Claim(ctx, otherWl, cr.SessionID, cr.ClaimCode); code(t, err) != "CLAIM_CODE_INVALID" {
		t.Fatal("other workload claimed")
	}
	if _, err := s.Claim(ctx, podA, cr.SessionID, "wrong"); code(t, err) != "CLAIM_CODE_INVALID" {
		t.Fatal("wrong code claimed")
	}
	tok, err := s.Claim(ctx, podA, cr.SessionID, cr.ClaimCode)
	if err != nil || tok.Token == "" {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, podB, cr.SessionID, cr.ClaimCode); code(t, err) != "CLAIM_CODE_INVALID" {
		t.Fatal("code reused")
	}
	var bound string
	pool.QueryRow(ctx, `SELECT claimed_workload_identity FROM identity.sessions WHERE session_id = $1`, cr.SessionID).Scan(&bound)
	if bound != podA.SAN {
		t.Fatalf("claimed identity %s", bound)
	}
	if as, _ := s.Assignments(ctx, podA); len(as) != 0 {
		t.Fatal("claimed session still assigned")
	}
	types := s.Audit.(*recorder).events
	for _, ev := range types {
		if ev.Tenant != alice.Tenant || ev.SessionID != cr.SessionID || ev.WorkloadID != podA.WorkloadID() {
			t.Fatalf("event query context %+v", ev)
		}
	}
	if len(types) != 2 || types[0].Type != "session_created" || types[1].Type != "session_claimed" {
		t.Fatalf("events %+v", types)
	}
}

func TestClaimExpiredCode(t *testing.T) {
	ctx := context.Background()
	s, _ := setup(t)
	s.Now = func() time.Time { return time.Now().Add(-2 * ClaimCodeTTL) }
	cr, err := s.Create(ctx, alice, k8sRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, podA, cr.SessionID, cr.ClaimCode); code(t, err) != "CLAIM_CODE_INVALID" {
		t.Fatal("expired code claimed")
	}
}

func TestConcurrentClaimOneWins(t *testing.T) {
	ctx := context.Background()
	s, _ := setup(t)
	cr, err := s.Create(ctx, alice, k8sRequest())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for _, p := range []RuntimePrincipal{podA, podB, podA, podB} {
		wg.Add(1)
		go func(p RuntimePrincipal) {
			defer wg.Done()
			if _, err := s.Claim(ctx, p, cr.SessionID, cr.ClaimCode); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d claims succeeded", wins)
	}
}

func claimed(t *testing.T, s *Service) (*CreateResponse, string) {
	t.Helper()
	cr, err := s.Create(context.Background(), alice, k8sRequest())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Claim(context.Background(), podA, cr.SessionID, cr.ClaimCode)
	if err != nil {
		t.Fatal(err)
	}
	return cr, tok.Token
}

func TestRefreshRotatesToken(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	cr, tok := claimed(t, s)
	if _, err := s.Refresh(ctx, podB, cr.SessionID, tok); code(t, err) != "AUTH_REQUIRED" {
		t.Fatal("refresh from another Pod accepted")
	}
	nt, err := s.Refresh(ctx, podA, cr.SessionID, tok)
	if err != nil || nt.Token == tok || !nt.ExpiresAt.After(cr.ExpiresAt) {
		t.Fatalf("refresh %+v %v", nt, err)
	}
	// COMMON registry: session_refreshed requires session_id and authenticated_actor.
	ev := lastEvent(t, s)
	if ev.Type != "session_refreshed" || ev.Tenant != alice.Tenant || ev.WorkloadID != podA.WorkloadID() || ev.Actor != "workload:"+podA.SAN || ev.SessionID != cr.SessionID ||
		ev.Payload["session_id"] != cr.SessionID || ev.Payload["authenticated_actor"] != ev.Actor {
		t.Fatalf("refresh event %+v", ev)
	}
	if exp, ok := ev.Payload["expires_at"].(time.Time); !ok || !exp.Equal(nt.ExpiresAt) {
		t.Fatalf("refresh event expires_at %v, response %v", ev.Payload["expires_at"], nt.ExpiresAt)
	}
	if _, err := s.Refresh(ctx, podA, cr.SessionID, tok); code(t, err) != "AUTH_REQUIRED" {
		t.Fatal("old token still refreshes")
	}
	var bexp time.Time
	pool.QueryRow(ctx, `SELECT expires_at FROM identity.session_budgets WHERE session_id = $1`, cr.SessionID).Scan(&bexp)
	if !bexp.Equal(nt.ExpiresAt) {
		t.Fatalf("budget expiry %v, session %v", bexp, nt.ExpiresAt)
	}

	// Concurrent refresh with the same token: exactly one succeeds.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Refresh(ctx, podA, cr.SessionID, nt.Token); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d refreshes succeeded", wins)
	}

	// At the 8 h cap no further refresh is possible.
	cr2, tok2 := claimed(t, s)
	pool.Exec(ctx, `UPDATE identity.sessions SET max_expires_at = expires_at WHERE session_id = $1`, cr2.SessionID)
	if _, err := s.Refresh(ctx, podA, cr2.SessionID, tok2); code(t, err) != "AUTH_REQUIRED" {
		t.Fatal("refresh past max_expires_at")
	}
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	cr, tok := claimed(t, s)
	if _, err := s.Revoke(ctx, bob, cr.SessionID, "x"); code(t, err) != "SESSION_BINDING_INVALID" {
		t.Fatal("another user revoked")
	}
	if _, err := s.Revoke(ctx, alice, cr.SessionID, "done"); err != nil {
		t.Fatal(err)
	}
	var live int
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.session_tokens WHERE session_id = $1 AND revoked_at IS NULL`, cr.SessionID).Scan(&live)
	if live != 0 {
		t.Fatal("token not revoked")
	}
	if _, err := s.Refresh(ctx, podA, cr.SessionID, tok); code(t, err) != "AUTH_REQUIRED" {
		t.Fatal("revoked session refreshed")
	}
	cr2, _ := claimed(t, s)
	if _, err := s.Revoke(ctx, op, cr2.SessionID, "ops"); err != nil {
		t.Fatalf("operator revoke: %v", err)
	}
	opOther := Actor{AuthenticatedActor: "google:ops2", Tenant: "other", Roles: []string{"operator"}}
	cr3, _ := claimed(t, s)
	if _, err := s.Revoke(ctx, opOther, cr3.SessionID, "x"); code(t, err) != "SESSION_BINDING_INVALID" {
		t.Fatal("operator of another tenant revoked")
	}
}

func TestScopeChecks(t *testing.T) {
	ctx := context.Background()
	s, _ := setup(t)
	cases := map[string]struct {
		mod  func(*CreateRequest)
		code string
	}{
		"unknown target":    {func(r *CreateRequest) { r.RequestedScope.TargetIDs = []string{"nope"} }, "ENDPOINT_NOT_REGISTERED"},
		"unknown operation": {func(r *CreateRequest) { r.RequestedScope.OperationIDs = []string{"x.y"} }, "ENDPOINT_NOT_REGISTERED"},
		"op not served":     {func(r *CreateRequest) { r.RequestedScope.OperationIDs = []string{"receiver.submit"} }, "TARGET_SCOPE_DENIED"},
		"not runtime":       {func(r *CreateRequest) { r.WorkloadID = "agent-release/releaser" }, "SCHEMA_INVALID"},
		"unregistered":      {func(r *CreateRequest) { r.WorkloadID = "agent-exec/ghost" }, "SCHEMA_INVALID"},
		"empty statement":   {func(r *CreateRequest) { r.TaskStatement = " " }, "SCHEMA_INVALID"},
		"long statement":    {func(r *CreateRequest) { r.TaskStatement = strings.Repeat("가", 4001) }, "SCHEMA_INVALID"},
		"no targets":        {func(r *CreateRequest) { r.RequestedScope.TargetIDs = nil }, "SCHEMA_INVALID"},
	}
	for name, c := range cases {
		req := k8sRequest()
		c.mod(&req)
		if _, err := s.Create(ctx, alice, req); code(t, err) != c.code {
			t.Errorf("%s: got %v, want %s", name, err, c.code)
		}
	}
	other := Actor{AuthenticatedActor: "google:eve", Tenant: "other"}
	if _, err := s.Create(ctx, other, k8sRequest()); code(t, err) != "TARGET_SCOPE_DENIED" {
		t.Error("other tenant created a session on hackathon targets")
	}
}

func TestAuditFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	s.Audit.(*recorder).fail = true
	if _, err := s.Create(ctx, alice, k8sRequest()); err == nil {
		t.Fatal("created without audit")
	}
	s.Audit = nil // unwired
	if _, err := s.Create(ctx, alice, k8sRequest()); !errors.Is(err, ErrAuditUnwired) {
		t.Fatalf("unwired auditor: %v", err)
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.sessions`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d sessions committed without audit", n)
	}
}

func TestRefreshAuditFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	cr, tok := claimed(t, s)
	state := func() (time.Time, time.Time, int, int) {
		var sexp, bexp time.Time
		var tokens, live int
		pool.QueryRow(ctx, `SELECT expires_at FROM identity.sessions WHERE session_id = $1`, cr.SessionID).Scan(&sexp)
		pool.QueryRow(ctx, `SELECT expires_at FROM identity.session_budgets WHERE session_id = $1 LIMIT 1`, cr.SessionID).Scan(&bexp)
		pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE revoked_at IS NULL) FROM identity.session_tokens WHERE session_id = $1`,
			cr.SessionID).Scan(&tokens, &live)
		return sexp, bexp, tokens, live
	}
	s1, b1, n1, l1 := state()
	rec := s.Audit.(*recorder)
	events := len(rec.events)
	rec.fail = true
	if _, err := s.Refresh(ctx, podA, cr.SessionID, tok); err == nil {
		t.Fatal("refreshed without audit")
	}
	s2, b2, n2, l2 := state()
	if !s2.Equal(s1) || !b2.Equal(b1) || n2 != n1 || l2 != l1 || len(rec.events) != events {
		t.Fatalf("refresh committed without audit: before %v %v %d %d, after %v %v %d %d", s1, b1, n1, l1, s2, b2, n2, l2)
	}
	// The old token was not rotated, so it still refreshes once audit is back.
	rec.fail = false
	if _, err := s.Refresh(ctx, podA, cr.SessionID, tok); err != nil {
		t.Fatalf("refresh after audit recovery: %v", err)
	}
	if ev := lastEvent(t, s); ev.Type != "session_refreshed" || ev.Payload["authenticated_actor"] != "workload:"+podA.SAN {
		t.Fatalf("refresh event %+v", ev)
	}
}

var proposer = RuntimePrincipal{SAN: "spiffe://agentarium.internal/ns/agent-observe/sa/policy-proposer", Namespace: "agent-observe", KSA: "policy-proposer"}

func proposalReq(issue, cand string) ServiceRequest {
	return ServiceRequest{Profile: "policy_proposal", IssueID: &issue, CandidateID: &cand, Tenant: "hackathon",
		ToolBudget: &ToolBudget{ModelCalls: &ModelCalls{PerCandidateMax: 100}, ReadToolCalls: &ReadToolCalls{PerCandidateMax: 2}}}
}

func TestServiceSessions(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue := uuid.NewString()
	out, err := s.CreateService(ctx, proposer, proposalReq(issue, uuid.NewString()))
	if err != nil {
		t.Fatal(err)
	}
	if b := out.ToolBudget; b.ModelCalls.PerCandidateMax != 8 || b.ModelCalls.TotalMax != 16 || b.ReadToolCalls.PerCandidateMax != 2 || b.Candidates.Max != 2 {
		t.Fatalf("budget not capped: %+v %+v %+v", b.ModelCalls, b.ReadToolCalls, b.Candidates)
	}
	var model, reads int
	pool.QueryRow(ctx, `SELECT max_value FROM identity.service_session_counters WHERE service_session_id = $1 AND counter = 'model'`, out.ServiceSessionID).Scan(&model)
	pool.QueryRow(ctx, `SELECT max_value FROM identity.service_session_counters WHERE service_session_id = $1 AND counter = 'read_tools'`, out.ServiceSessionID).Scan(&reads)
	if model != 8 || reads != 2 {
		t.Fatalf("counters model=%d read_tools=%d", model, reads)
	}
	var actor string
	pool.QueryRow(ctx, `SELECT authenticated_actor FROM identity.service_sessions WHERE service_session_id = $1`, out.ServiceSessionID).Scan(&actor)
	if actor != "service:agent-observe/policy-proposer" {
		t.Fatalf("actor %s", actor)
	}

	change := uuid.NewString()
	two := proposalReq(issue, uuid.NewString())
	two.ChangeID = &change
	if _, err := s.CreateService(ctx, proposer, two); code(t, err) != "SCHEMA_INVALID" {
		t.Fatal("two scopes accepted")
	}
	if _, err := s.CreateService(ctx, releaser, proposalReq(issue, uuid.NewString())); code(t, err) != "SERVICE_SCOPE_DENIED" {
		t.Fatal("releaser used policy_proposal")
	}
	if _, err := s.CreateService(ctx, proposer, ServiceRequest{Profile: "policy_proposal", IssueID: &issue, Tenant: "hackathon"}); code(t, err) != "SCHEMA_INVALID" {
		t.Fatal("policy_proposal without candidate accepted")
	}
	probe, err := s.CreateService(ctx, releaser, ServiceRequest{Profile: "activation_probe", ChangeID: &change, Tenant: "hackathon"})
	if err != nil || probe.ToolBudget == nil || probe.ToolBudget.ProbeActions == nil || probe.ToolBudget.ProbeActions.Max != 4 {
		t.Fatalf("probe session %+v %v", probe, err)
	}
	var probeMax int
	pool.QueryRow(ctx, `SELECT max_value FROM identity.service_session_counters WHERE service_session_id = $1 AND counter = 'probe_actions'`, probe.ServiceSessionID).Scan(&probeMax)
	if probeMax != 4 {
		t.Fatalf("probe_actions %d", probeMax)
	}
	if _, err := s.CreateService(ctx, proposer, proposalReq(issue, uuid.NewString())); err != nil {
		t.Fatalf("second candidate: %v", err)
	}
	if _, err := s.CreateService(ctx, proposer, proposalReq(issue, uuid.NewString())); code(t, err) != "TOOL_BUDGET_EXHAUSTED" {
		t.Fatal("third candidate accepted")
	}
}

var releaser = RuntimePrincipal{SAN: "spiffe://agentarium.internal/ns/agent-release/sa/releaser", Namespace: "agent-release", KSA: "releaser"}

func probeReq() ServiceRequest {
	change := uuid.NewString()
	return ServiceRequest{Profile: "activation_probe", ChangeID: &change, Tenant: "hackathon"}
}

// Every profile's service_session_created event carries the applied budget
// as a non-null tool_budget; the recorder rejects a null one as audit_append
// does.
func TestServiceSessionCreatedBudget(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	if _, err := pool.Exec(ctx, `
INSERT INTO identity.registered_workloads (namespace, ksa, role, service_principal) VALUES ('agent-observe', 'discovery', 'service', 'discovery')`); err != nil {
		t.Fatal(err)
	}
	checker := RuntimePrincipal{SAN: "spiffe://agentarium.internal/ns/agent-control/sa/intent-checker", Namespace: "agent-control", KSA: "intent-checker"}
	discoverer := RuntimePrincipal{SAN: "spiffe://agentarium.internal/ns/agent-observe/sa/discovery", Namespace: "agent-observe", KSA: "discovery"}
	action, snapshot := uuid.NewString(), uuid.NewString()
	cases := []struct {
		p   RuntimePrincipal
		req ServiceRequest
	}{
		{checker, ServiceRequest{Profile: "intent_check", ActionID: &action, Tenant: "hackathon"}},
		{proposer, proposalReq(uuid.NewString(), uuid.NewString())},
		{discoverer, ServiceRequest{Profile: "discovery", SnapshotID: &snapshot, Tenant: "hackathon"}},
		{releaser, probeReq()},
	}
	for _, c := range cases {
		out, err := s.CreateService(ctx, c.p, c.req)
		if err != nil {
			t.Fatalf("%s: %v", c.req.Profile, err)
		}
		ev := lastEvent(t, s)
		if ev.Type != "service_session_created" || ev.SessionID != out.ServiceSessionID {
			t.Fatalf("%s event %+v", c.req.Profile, ev)
		}
		got, _ := json.Marshal(ev.Payload["tool_budget"])
		// The response and the event carry the same applied budget.
		want, _ := json.Marshal(out.ToolBudget)
		if c.req.Profile == "activation_probe" {
			// It is the probe_actions counter maximum, with no other key.
			max := counters(t, pool, out.ServiceSessionID)["probe_actions"][1]
			if max != 4 || string(want) != `{"probe_actions":{"max":4,"used":0}}` {
				t.Fatalf("probe_actions counter %d, response %s", max, want)
			}
		}
		if string(got) != string(want) || string(got) == "null" {
			t.Fatalf("%s tool_budget %s, want %s", c.req.Profile, got, want)
		}
	}
	// The recorder rejects a null tool_budget, as audit_append would.
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return checkRegistry(ctx, tx, Event{Type: "service_session_created",
			Payload: map[string]any{"service_session_id": uuid.NewString(), "caller_principal": "releaser", "tool_budget": (*ToolBudget)(nil)}})
	})
	if err == nil || !strings.Contains(err.Error(), "tool_budget") {
		t.Fatalf("null tool_budget accepted: %v", err)
	}
}

// A failed audit append leaves no activation_probe session, token or counter.
func TestProbeSessionAuditRollback(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	s.Audit.(*recorder).fail = true
	if _, err := s.CreateService(ctx, releaser, probeReq()); err == nil {
		t.Fatal("probe session created without audit")
	}
	var n [3]int
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.service_sessions`).Scan(&n[0])
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.session_tokens WHERE service_session_id IS NOT NULL`).Scan(&n[1])
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.service_session_counters`).Scan(&n[2])
	if n != [3]int{} {
		t.Fatalf("rows left after a failed audit: sessions, tokens, counters = %v", n)
	}
}

func TestCandidateLimitUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue := uuid.NewString()
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.CreateService(ctx, proposer, proposalReq(issue, uuid.NewString()))
		}()
	}
	wg.Wait()
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.issue_candidates WHERE issue_id = $1`, issue).Scan(&n)
	if n != MaxCandidatesPerIssue {
		t.Fatalf("%d candidates recorded", n)
	}
}

func TestServiceBudgetRejects(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue := uuid.NewString()
	zero, neg := 0, -5
	cases := map[string]func(*ServiceRequest){
		"negative model":      func(r *ServiceRequest) { r.ToolBudget.ModelCalls.PerCandidateMax = -1 },
		"lower total_max":     func(r *ServiceRequest) { r.ToolBudget.ModelCalls.TotalMax = 1 },
		"lower candidates":    func(r *ServiceRequest) { r.ToolBudget.Candidates = &Candidates{Max: 1} },
		"used set":            func(r *ServiceRequest) { r.ToolBudget.ModelCalls.UsedTotal = 3 },
		"candidates used set": func(r *ServiceRequest) { r.ToolBudget.Candidates = &Candidates{Max: 2, Used: 1} },
		"zero ttl":            func(r *ServiceRequest) { r.TTLSeconds = &zero },
		"negative ttl":        func(r *ServiceRequest) { r.TTLSeconds = &neg },
	}
	for name, mod := range cases {
		r := proposalReq(issue, uuid.NewString())
		mod(&r)
		if _, err := s.CreateService(ctx, proposer, r); code(t, err) != "SCHEMA_INVALID" {
			t.Errorf("%s accepted", name)
		}
	}
	change := uuid.NewString()
	withBudget := ServiceRequest{Profile: "activation_probe", ChangeID: &change, Tenant: "hackathon", ToolBudget: &ToolBudget{ModelCalls: &ModelCalls{PerCandidateMax: 1}}}
	if _, err := s.CreateService(ctx, releaser, withBudget); code(t, err) != "SCHEMA_INVALID" {
		t.Error("activation_probe accepted a model budget")
	}
	// A caller's probe_actions.max is cut to 4; the response, the event and
	// the counter row carry the same applied value.
	for asked, want := range map[int]int{2: 2, 9: 4} {
		r := probeReq()
		r.ToolBudget = &ToolBudget{ProbeActions: &ProbeActions{Max: asked}}
		out, err := s.CreateService(ctx, releaser, r)
		if err != nil {
			t.Fatalf("probe_actions %d: %v", asked, err)
		}
		got, _ := json.Marshal(lastEvent(t, s).Payload["tool_budget"])
		resp, _ := json.Marshal(out.ToolBudget)
		if max := counters(t, pool, out.ServiceSessionID)["probe_actions"][1]; max != want || out.ToolBudget.ProbeActions.Max != want || string(got) != string(resp) {
			t.Fatalf("probe_actions %d: counter %d, response %s, event %s", asked, max, resp, got)
		}
	}
	// The caps themselves are accepted, and values above them are cut.
	for _, v := range [][2]int{{16, 2}, {100, 9}} {
		r := proposalReq(uuid.NewString(), uuid.NewString())
		r.ToolBudget.ModelCalls.TotalMax = v[0]
		r.ToolBudget.Candidates = &Candidates{Max: v[1]}
		out, err := s.CreateService(ctx, proposer, r)
		if err != nil {
			t.Fatalf("total_max %d candidates %d: %v", v[0], v[1], err)
		}
		if out.ToolBudget.ModelCalls.TotalMax != 16 || out.ToolBudget.Candidates.Max != 2 {
			t.Fatalf("not cut to the cap: %+v %+v", out.ToolBudget.ModelCalls, out.ToolBudget.Candidates)
		}
	}
	ttl := 60
	short := proposalReq(uuid.NewString(), uuid.NewString())
	short.TTLSeconds = &ttl
	out, err := s.CreateService(ctx, proposer, short)
	if err != nil || time.Until(out.ExpiresAt) > 70*time.Second {
		t.Fatalf("ttl not applied: %+v %v", out, err)
	}
}

func TestLockTimeout(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	cr, err := s.Create(ctx, alice, k8sRequest())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM identity.sessions WHERE session_id = $1 FOR UPDATE`, cr.SessionID); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = s.Claim(ctx, podA, cr.SessionID, cr.ClaimCode)
	if code(t, err) != "LOCK_TIMEOUT" {
		t.Fatalf("got %v", err)
	}
	if d := time.Since(start); d < 1500*time.Millisecond || d > 5*time.Second {
		t.Fatalf("waited %v", d)
	}
}

// TASK-03 3.4 re-issue of a policy_proposal candidate session. use, consume
// and restore (counters_integration_test.go) run the coordinator's SQL.

func expire(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
UPDATE identity.service_sessions SET expires_at = statement_timestamp() - interval '1 second' WHERE service_session_id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

// counters returns counter → [used, max] for one service session.
func counters(t *testing.T, pool *pgxpool.Pool, id string) map[string][2]int {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
SELECT counter, used_value, max_value FROM identity.service_session_counters WHERE service_session_id = $1`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][2]int{}
	for rows.Next() {
		var c string
		var used, max int
		if err := rows.Scan(&c, &used, &max); err != nil {
			t.Fatal(err)
		}
		out[c] = [2]int{used, max}
	}
	return out
}

func lastEvent(t *testing.T, s *Service) Event {
	t.Helper()
	ev := s.Audit.(*recorder).events
	if len(ev) == 0 {
		t.Fatal("no audit events")
	}
	return ev[len(ev)-1]
}

func TestServiceSessionFirstIssue(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	out, err := s.CreateService(ctx, proposer, proposalReq(uuid.NewString(), uuid.NewString()))
	if err != nil {
		t.Fatal(err)
	}
	if c := counters(t, pool, out.ServiceSessionID); c["model"] != [2]int{0, 8} || c["read_tools"] != [2]int{0, 2} {
		t.Fatalf("counters %v", c)
	}
	ev := lastEvent(t, s)
	if _, ok := ev.Payload["previous_service_session_id"]; ok {
		t.Fatalf("first session has a previous session: %v", ev.Payload)
	}
	if inh := ev.Payload["inherited_used"].(map[string]int); inh["model"] != 0 || inh["read_tools"] != 0 || len(inh) != 2 {
		t.Fatalf("inherited_used %v", inh)
	}
}

func TestServiceSessionActiveDuplicate(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	out, err := s.CreateService(ctx, proposer, proposalReq(issue, cand))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateService(ctx, proposer, proposalReq(issue, cand)); code(t, err) != CodeServiceSessionActive {
		t.Fatalf("duplicate: %v", err)
	}
	// Exhausted counters do not change the code, nor does another tenant.
	use(t, pool, out.ServiceSessionID, "model", 8)
	use(t, pool, out.ServiceSessionID, "read_tools", 2)
	r := proposalReq(issue, cand)
	r.Tenant = "other"
	if _, err := s.CreateService(ctx, proposer, r); code(t, err) != CodeServiceSessionActive {
		t.Fatalf("duplicate after exhaustion: %v", err)
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.service_sessions WHERE candidate_id = $1`, cand).Scan(&n)
	if n != 1 {
		t.Fatalf("%d sessions for one candidate", n)
	}
}

func TestServiceSessionReissueInherits(t *testing.T) {
	ctx := context.Background()
	for _, end := range []string{"expired", "revoked"} {
		t.Run(end, func(t *testing.T) {
			s, pool := setup(t)
			issue, cand := uuid.NewString(), uuid.NewString()
			first, err := s.CreateService(ctx, proposer, proposalReq(issue, cand))
			if err != nil {
				t.Fatal(err)
			}
			use(t, pool, first.ServiceSessionID, "model", 3)
			use(t, pool, first.ServiceSessionID, "read_tools", 1)
			if end == "expired" {
				expire(t, pool, first.ServiceSessionID)
			} else if _, err := pool.Exec(ctx, `
UPDATE identity.service_sessions SET state = 'revoked' WHERE service_session_id = $1;`, first.ServiceSessionID); err != nil {
				t.Fatal(err)
			}
			second, err := s.CreateService(ctx, proposer, proposalReq(issue, cand))
			if err != nil {
				t.Fatal(err)
			}
			// The new session counts only its own uses; the candidate
			// counter carries the usage.
			if c := counters(t, pool, second.ServiceSessionID); c["model"] != [2]int{0, 8} || c["read_tools"] != [2]int{0, 2} {
				t.Fatalf("counters %v", c)
			}
			if m, r := candUsed(t, pool, issue, cand, "model"), candUsed(t, pool, issue, cand, "read_tools"); m != 3 || r != 1 {
				t.Fatalf("candidate model %d read_tools %d", m, r)
			}
			use(t, pool, second.ServiceSessionID, "read_tools", 1)
			mustExhaust(t, pool, second.ServiceSessionID, "read_tools")
			ev := lastEvent(t, s)
			if ev.Type != "service_session_created" || ev.Payload["previous_service_session_id"] != first.ServiceSessionID {
				t.Fatalf("event %+v", ev)
			}
			if inh := ev.Payload["inherited_used"].(map[string]int); inh["model"] != 3 || inh["read_tools"] != 1 {
				t.Fatalf("inherited_used %v", inh)
			}
		})
	}
}

func TestServiceSessionReissueNoDoubleCount(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	out, err := s.CreateService(ctx, proposer, proposalReq(issue, cand))
	if err != nil {
		t.Fatal(err)
	}
	// Model uses per session: 2, then 3, then 1; cumulative 2, 5, 6.
	total := 0
	for i, n := range []int{2, 3, 1} {
		use(t, pool, out.ServiceSessionID, "model", n)
		total += n
		expire(t, pool, out.ServiceSessionID)
		prev := out.ServiceSessionID
		if out, err = s.CreateService(ctx, proposer, proposalReq(issue, cand)); err != nil {
			t.Fatalf("re-issue %d: %v", i+1, err)
		}
		if c := counters(t, pool, out.ServiceSessionID); c["model"] != [2]int{0, 8} {
			t.Fatalf("re-issue %d: counters %v", i+1, c)
		}
		if got := candUsed(t, pool, issue, cand, "model"); got != total {
			t.Fatalf("re-issue %d: candidate used %d, want %d", i+1, got, total)
		}
		if inh := lastEvent(t, s).Payload["inherited_used"].(map[string]int); inh["model"] != total {
			t.Fatalf("re-issue %d: inherited_used %v", i+1, inh)
		}
		if got := lastEvent(t, s).Payload["previous_service_session_id"]; got != prev {
			t.Fatalf("re-issue %d: previous %v, want %s", i+1, got, prev)
		}
	}
	use(t, pool, out.ServiceSessionID, "model", 8-total)
	mustExhaust(t, pool, out.ServiceSessionID, "model")
	checkBooks(t, pool)
}

func TestServiceSessionConcurrentReissue(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	run := func() int {
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.CreateService(ctx, proposer, proposalReq(issue, cand))
				mu.Lock()
				defer mu.Unlock()
				var e *Error
				switch {
				case err == nil:
					wins++
				case !errors.As(err, &e) || e.Code != CodeServiceSessionActive:
					t.Errorf("loser got %v, want %s", err, CodeServiceSessionActive)
				}
			}()
		}
		wg.Wait()
		return wins
	}
	// First issue of a new candidate, then a re-issue after expiry.
	if wins := run(); wins != 1 {
		t.Fatalf("first issue: %d succeeded", wins)
	}
	var id string
	pool.QueryRow(ctx, `SELECT service_session_id FROM identity.service_sessions WHERE candidate_id = $1`, cand).Scan(&id)
	use(t, pool, id, "model", 4)
	expire(t, pool, id)
	if wins := run(); wins != 1 {
		t.Fatalf("re-issue: %d succeeded", wins)
	}
	var total, live int
	pool.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE expires_at > statement_timestamp()) FROM identity.service_sessions WHERE candidate_id = $1`, cand).Scan(&total, &live)
	if used := candUsed(t, pool, issue, cand, "model"); total != 2 || live != 1 || used != 4 {
		t.Fatalf("sessions %d, live %d, candidate model used %d", total, live, used)
	}
}

// A reservation still consuming through an old session when the candidate is
// re-issued: the re-issue waits on the session lock and starts from the
// incremented candidate usage.
func TestServiceSessionReissueWaitsForCounter(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	first, err := s.CreateService(ctx, proposer, proposalReq(issue, cand))
	if err != nil {
		t.Fatal(err)
	}
	use(t, pool, first.ServiceSessionID, "model", 3)

	// The reservation: READ COMMITTED, passed its live check just before the
	// session expires, consumed, not committed yet.
	if _, err := pool.Exec(ctx, `
UPDATE identity.service_sessions SET expires_at = statement_timestamp() + interval '300 milliseconds'
WHERE service_session_id = $1`, first.ServiceSessionID); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := coordConsumeTx(ctx, tx, first.ServiceSessionID, "model"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)

	type result struct {
		out *ServiceResponse
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := s.CreateService(ctx, proposer, proposalReq(issue, cand))
		done <- result{out, err}
	}()
	waitForLock(t, pool, done)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if got := candUsed(t, pool, issue, cand, "model"); got != 4 {
		t.Fatalf("candidate used %d, want 4", got)
	}
	if inh := lastEvent(t, s).Payload["inherited_used"].(map[string]int); inh["model"] != 4 {
		t.Fatalf("inherited_used %v", inh)
	}
	checkBooks(t, pool)
}

func TestServiceSessionIssueModelCap(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue := uuid.NewString()
	cands := []string{uuid.NewString(), uuid.NewString()}
	// Each candidate spends everything its sessions allow, three times over.
	for round := 0; round < 3; round++ {
		for _, cand := range cands {
			out, err := s.CreateService(ctx, proposer, proposalReq(issue, cand))
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
			if round == 0 {
				use(t, pool, out.ServiceSessionID, "model", 8)
			}
			mustExhaust(t, pool, out.ServiceSessionID, "model")
			expire(t, pool, out.ServiceSessionID)
		}
	}
	if _, err := s.CreateService(ctx, proposer, proposalReq(issue, uuid.NewString())); code(t, err) != "TOOL_BUDGET_EXHAUSTED" {
		t.Fatal("third candidate accepted")
	}
	var total int
	pool.QueryRow(ctx, `
SELECT coalesce(sum(used_value), 0) FROM identity.issue_candidate_counters WHERE issue_id = $1 AND counter = 'model'`, issue).Scan(&total)
	if total != 16 {
		t.Fatalf("issue model usage %d", total)
	}
	checkBooks(t, pool)
}

func TestServiceSessionReissueBelowInherited(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	first, err := s.CreateService(ctx, proposer, proposalReq(issue, cand))
	if err != nil {
		t.Fatal(err)
	}
	use(t, pool, first.ServiceSessionID, "model", 5)
	expire(t, pool, first.ServiceSessionID)
	count := func() [5]int {
		var n [5]int
		pool.QueryRow(ctx, `SELECT count(*) FROM identity.service_sessions`).Scan(&n[0])
		pool.QueryRow(ctx, `SELECT count(*) FROM identity.service_session_counters`).Scan(&n[1])
		pool.QueryRow(ctx, `SELECT count(*) FROM identity.session_tokens`).Scan(&n[2])
		n[3] = len(s.Audit.(*recorder).events)
		pool.QueryRow(ctx, `SELECT coalesce(sum(used_value), 0) FROM identity.issue_candidate_counters`).Scan(&n[4])
		return n
	}
	before := count()
	r := proposalReq(issue, cand)
	r.ToolBudget.ModelCalls.PerCandidateMax = 4
	out, err := s.CreateService(ctx, proposer, r)
	if code(t, err) != "TOOL_BUDGET_EXHAUSTED" || out != nil {
		t.Fatalf("max below inherited: %+v %v", out, err)
	}
	if after := count(); after != before {
		t.Fatalf("rows/events before %v, after %v", before, after)
	}
	// A maximum equal to the inherited usage is still issued, with nothing left.
	r.ToolBudget.ModelCalls.PerCandidateMax = 5
	out, err = s.CreateService(ctx, proposer, r)
	if err != nil {
		t.Fatal(err)
	}
	if c := counters(t, pool, out.ServiceSessionID); c["model"] != [2]int{0, 5} {
		t.Fatalf("counters %v", c)
	}
	mustExhaust(t, pool, out.ServiceSessionID, "model")
}
