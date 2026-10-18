//go:build integration

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Run against an empty database; the test applies migrations/*.up.sql:
//
//	DATABASE_URL=postgres://... go test -tags integration ./services/gateway/...
//
// The service pool runs as gateway_app (SET ROLE), so every query also
// checks the migrations' grants. Fixtures use the admin pool. Bundles are the
// real policies/gateway/decision.rego, signed and loaded through
// packages/policyloader. Dependencies owned by other Tasks are fakes.

const (
	runtimeSAN    = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/p1"
	runtimeSerial = "0a01"
	serviceSAN    = "spiffe://agentarium.internal/ns/agent-observe/sa/policy-proposer"
	serviceSerial = "0a02"
	otherSAN      = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/p2"
	otherSerial   = "0a03"
	nodeUID       = "11111111-1111-4111-8111-111111111111"
)

// ---- fakes for other Tasks ----------------------------------------------------

type fakePolicy struct{ a ActivePolicy }

func (f *fakePolicy) ActivePolicy(context.Context, pgx.Tx) (ActivePolicy, error) { return f.a, nil }

type fakeHealth struct {
	mu       sync.Mutex
	holds    []Hold
	artifact string
}

func (f *fakeHealth) Holds(context.Context, pgx.Tx, HoldScope) ([]Hold, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Hold{}, f.holds...), nil
}

func (f *fakeHealth) Leases(_ context.Context, _ pgx.Tx, k LeaseKey) ([]LeaseRow, error) {
	var v *string
	if k.Component == "adapter" {
		v = &f.artifact
	}
	return []LeaseRow{{Component: k.Component, SourceID: k.Component + "-0", ObservedState: "healthy",
		LeaseUntil: time.Now().Add(time.Minute), ActiveVersion: v}}, nil
}

type fakeAdapters struct{}

func (fakeAdapters) DataState(context.Context, pgx.Tx, DataStateKey) (DataState, bool, error) {
	return DataState{DataClassHighWater: "synthetic", DataSources: []string{}}, true, nil
}
func (fakeAdapters) ExecutionState(context.Context, pgx.Tx, string) (string, bool, error) {
	return "", false, nil
}
func (fakeAdapters) Result(context.Context, pgx.Tx, string) (*ActionResult, error) { return nil, nil }

type okReadiness struct{}

func (okReadiness) Check(context.Context, Caller, ReadinessRef) error { return nil }

// recorder is an Auditor that records event types in call order. Events of
// a transaction that later rolls back stay recorded; tests read them only
// after a committed request.
//
// Like TASK-07 audit_append, it refuses a policy_decided or
// action_reevaluated event whose policy_epoch is null, so a decision
// transaction that would carry one rolls back here too.
type recorder struct {
	mu     sync.Mutex
	events []string
	last   map[string]Event // latest event of each type
	inputs int
}

func (r *recorder) Append(_ context.Context, _ pgx.Tx, ev Event) error {
	if ev.Type == "policy_decided" || ev.Type == "action_reevaluated" {
		if e, ok := ev.Payload["policy_epoch"].(*int64); !ok || e == nil {
			return errors.New("audit_append: " + ev.Type + " policy_epoch is null")
		}
	}
	r.mu.Lock()
	r.events = append(r.events, ev.Type)
	if r.last == nil {
		r.last = map[string]Event{}
	}
	r.last[ev.Type] = ev
	r.mu.Unlock()
	return nil
}

func (r *recorder) lastEvent(t string) (Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ev, ok := r.last[t]
	return ev, ok
}

func (r *recorder) EnqueueDecisionInput(context.Context, pgx.Tx, string, []byte) error {
	r.mu.Lock()
	r.inputs++
	r.mu.Unlock()
	return nil
}

func (r *recorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.events
	r.events = nil
	return out
}

// ---- setup ----------------------------------------------------------------------

type env struct {
	admin    *pgxpool.Pool
	svc      *Service
	mux      *http.ServeMux
	audit    *recorder
	health   *fakeHealth
	policy   *testPolicy
	user     string // user session_id
	userTok  string
	service  string // service_session_id
	svcTok   string
	otherTok string
}

var migrated sync.Once

func setup(t *testing.T) *env {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	migrated.Do(func() {
		var exists bool
		if err := admin.QueryRow(ctx, `SELECT to_regclass('decisions.decisions') IS NOT NULL`).Scan(&exists); err != nil || exists {
			return
		}
		if _, err := admin.Exec(ctx, `DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF;
        END $$`); err != nil {
			t.Fatal(err)
		}
		files, _ := filepath.Glob(filepath.Join(repoRoot, "migrations/*.up.sql"))
		sort.Strings(files)
		for _, f := range files {
			b, _ := os.ReadFile(f)
			if _, err := admin.Exec(ctx, string(b)); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	})
	if _, err := admin.Exec(ctx, `
TRUNCATE decisions.execute_requests, decisions.intent_checks, decisions.decisions, decisions.decision_inputs,
    decisions.action_contents, decisions.actions,
    coordinator.attempt_observations, coordinator.activation_probes, coordinator.dispatch_permits,
    coordinator.attempts, coordinator.reservations, identity.approval_nonces, identity.approvals,
    identity.issue_candidates, identity.service_session_counters, identity.session_tokens,
    identity.service_sessions, identity.session_budgets, identity.sessions, identity.issued_certificates,
    identity.registered_workloads CASCADE;
INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id, service_principal) VALUES
    ('agent-exec', 'agent-runtime', 'runtime', NULL, NULL),
    ('agent-observe', 'policy-proposer', 'service', NULL, 'policy-proposer');`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ serial, san, ns, ksa string }{
		{runtimeSerial, runtimeSAN, "agent-exec", "agent-runtime"},
		{serviceSerial, serviceSAN, "agent-observe", "policy-proposer"},
		{otherSerial, otherSAN, "agent-exec", "agent-runtime"},
	} {
		if _, err := admin.Exec(ctx, `
INSERT INTO identity.issued_certificates (serial, san_uri, namespace, ksa, pod_uid, node_uid, boot_id, issued_at, expires_at)
VALUES ($1, $2, $3, $4, gen_random_uuid(), $5, 'boot-1', now(), now() + interval '1 day')`, c.serial, c.san, c.ns, c.ksa, nodeUID); err != nil {
			t.Fatal(err)
		}
	}
	e := &env{admin: admin, audit: &recorder{}, user: uuid.NewString(), service: uuid.NewString(),
		userTok: "user-token-" + uuid.NewString(), svcTok: "svc-token-" + uuid.NewString(), otherTok: "other-token-" + uuid.NewString()}
	other := uuid.NewString()
	for _, s := range []string{e.user, other} {
		if _, err := admin.Exec(ctx, `
INSERT INTO identity.sessions (session_id, authenticated_actor, tenant, workload_id, task_statement, allowed_operation_ids,
    state, claim_code_digest, claim_expires_at, created_at, expires_at, max_expires_at)
VALUES ($1, 'google:u1', 'hackathon', 'agent-exec/agent-runtime', 'send the weekly summary', '{receiver.submit,k8s.pods.list}',
    'claimed', '\x00', now(), now(), now() + interval '30 minutes', now() + interval '8 hours')`, s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `
INSERT INTO identity.service_sessions (service_session_id, caller_principal, authenticated_actor, profile, tenant, issue_id,
    state, created_at, expires_at)
VALUES ($1, 'policy-proposer', 'service:agent-observe/policy-proposer', 'policy_proposal', 'hackathon', gen_random_uuid(),
    'active', now(), now() + interval '30 minutes')`, e.service); err != nil {
		t.Fatal(err)
	}
	tok := func(token, user, service, san string) {
		d := sha256.Sum256([]byte(token))
		var u, s *string
		if user != "" {
			u = &user
		}
		if service != "" {
			s = &service
		}
		if _, err := admin.Exec(ctx, `
INSERT INTO identity.session_tokens (token_digest, session_id, service_session_id, bound_identity, issued_at)
VALUES ($1, $2, $3, $4, now())`, d[:], u, s, san); err != nil {
			t.Fatal(err)
		}
	}
	tok(e.userTok, e.user, "", runtimeSAN)
	tok(e.svcTok, "", e.service, serviceSAN)
	tok(e.otherTok, other, "", otherSAN)

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE gateway_app")
		return err
	}
	app, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)

	e.policy = loadTestPolicy(t, "")
	e.health = &fakeHealth{artifact: e.policy.artifact}
	e.svc = &Service{
		Pool: app, Bundle: e.policy.loader, Environment: "test", GatewayIdentity: "spiffe://agentarium.internal/ns/agent-gateway/sa/gateway",
		Policy: &fakePolicy{a: ActivePolicy{Epoch: 7, ExpectedOPARevision: testRev}}, Health: e.health, Readiness: okReadiness{},
		Adapters: fakeAdapters{}, Audit: e.audit, Probes: Unwired{}, ModelProfiles: testModelProfiles(t),
	}
	e.mux = http.NewServeMux()
	(&Handler{Svc: e.svc, peer: testPeer}).Register(e.mux)
	return e
}

// testPeer stands in for the verified client certificate: X-Test-SAN and
// X-Test-Serial name it.
func testPeer(r *http.Request) *x509.Certificate {
	san := r.Header.Get("X-Test-SAN")
	if san == "" {
		return nil
	}
	b, _ := hex.DecodeString(r.Header.Get("X-Test-Serial"))
	u, _ := url.Parse(san)
	return &x509.Certificate{SerialNumber: new(big.Int).SetBytes(b), URIs: []*url.URL{u}}
}

type who struct{ san, serial, token string }

func (e *env) asUser() who    { return who{runtimeSAN, runtimeSerial, e.userTok} }
func (e *env) asService() who { return who{serviceSAN, serviceSerial, e.svcTok} }
func (e *env) asOther() who   { return who{otherSAN, otherSerial, e.otherTok} }

func (e *env) do(t *testing.T, w who, method, path, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+w.token)
	r.Header.Set("X-Test-SAN", w.san)
	r.Header.Set("X-Test-Serial", w.serial)
	r.Header.Set(WorkRunHeader, "run-1")
	r.Header.Set(ReadinessCheckHeader, "check-1")
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, r)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: %d %q", method, path, rec.Code, rec.Body.String())
	}
	return rec.Code, out
}

func (e *env) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := e.admin.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) noRows(t *testing.T) {
	t.Helper()
	for _, tbl := range []string{"decisions.actions", "decisions.decisions", "decisions.decision_inputs", "decisions.execute_requests", "decisions.action_contents"} {
		if n := e.count(t, tbl); n != 0 {
			t.Fatalf("%s has %d rows", tbl, n)
		}
	}
}

func codes(m map[string]any) []string {
	var out []string
	for _, c := range m["reason_codes"].([]any) {
		out = append(out, c.(string))
	}
	return out
}

func eqEvents(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("events %v, want %v", got, want)
		}
	}
}

// ---- tests ----------------------------------------------------------------------

func TestApprovalRequiredThenAllowOnReevaluate(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	st, out := e.do(t, e.asUser(), "POST", "/v1/actions", receiverBody(e.user, "key-appr-1", ""))
	if st != 202 || out["verdict"] != "approval_required" || out["execution_allowed"] != false || codes(out)[0] != "APPROVAL_REQUIRED" {
		t.Fatalf("submit: %d %v", st, out)
	}
	if len(out) != 7 {
		t.Fatalf("response keys %v", out)
	}
	if basis, ok := out["decision_basis"]; !ok || basis != nil {
		t.Fatalf("approval_required decision_basis %v (present %v)", basis, ok)
	}
	actionID := out["action_id"].(string)
	first := out["decision_id"].(string)
	eqEvents(t, e.audit.take(), "request_received", "policy_decided", "approval_requested")
	if e.count(t, "decisions.execute_requests") != 0 || e.count(t, "decisions.action_contents") != 1 || e.count(t, "decisions.decision_inputs") != 1 {
		t.Fatal("approval_required stored an execute request or missed content/input")
	}
	var stage, rego string
	var ref *string
	if err := e.admin.QueryRow(ctx, `SELECT decision_stage, rego_result::text, decision_input_ref FROM decisions.decisions WHERE decision_id = $1`, first).Scan(&stage, &rego, &ref); err != nil {
		t.Fatal(err)
	}
	if stage != "opa" || ref == nil {
		t.Fatalf("stage %s ref %v", stage, ref)
	}
	// The stored input digest matches the stored input.
	var input []byte
	if err := e.admin.QueryRow(ctx, `SELECT sanitized_input::text FROM decisions.decision_inputs WHERE decision_input_digest = $1`, *ref).Scan(&input); err != nil {
		t.Fatal(err)
	}

	st, view := e.do(t, e.asUser(), "GET", "/v1/actions/"+actionID, "")
	if st != 200 || view["execution_state"] != "approval_pending" {
		t.Fatalf("get: %d %v", st, view)
	}
	digest := view["action_digest"].(string)

	// Another session of the same workload cannot see or re-evaluate it.
	if st, _ := e.do(t, e.asOther(), "GET", "/v1/actions/"+actionID, ""); st != 404 {
		t.Fatalf("other caller GET: %d", st)
	}
	if st, _ := e.do(t, e.asOther(), "POST", "/v1/actions/"+actionID+":reevaluate", `{"expected_action_digest":"`+digest+`"}`); st != 404 {
		t.Fatalf("other caller reevaluate: %d", st)
	}
	if st, out := e.do(t, e.asUser(), "POST", "/v1/actions/"+actionID+":reevaluate", `{"expected_action_digest":"`+zeros+`"}`); st != 409 || codes(out)[0] != "ACTION_DIGEST_MISMATCH" {
		t.Fatalf("digest mismatch: %d %v", st, out)
	}

	// TASK-03 stores the approval of exactly this action.
	var target []byte
	var disclosure []string
	var content string
	if err := e.admin.QueryRow(ctx, `SELECT canonical_target, disclosure_fields, content_digest FROM decisions.actions WHERE action_id = $1`, actionID).Scan(&target, &disclosure, &content); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.approvals (approval_id, revision, approval_kind, action_id, authenticated_actor, session_id,
    contract_digest, displayed_contract_digest, allowed_operation, canonical_target, disclosure_fields, content_digest,
    max_actions, policy_epoch, contract_version, created_at, expires_at)
VALUES (gen_random_uuid(), 1, 'action', $1, 'google:u1', $2, $3, $3, 'receiver.submit', $4, $5, $6, 1, 7, 'v1', now(), now() + interval '5 minutes')`,
		actionID, e.user, zeros, target, disclosure, content); err != nil {
		t.Fatal(err)
	}
	st, out = e.do(t, e.asUser(), "POST", "/v1/actions/"+actionID+":reevaluate", `{"expected_action_digest":"`+digest+`"}`)
	if st != 202 || out["verdict"] != "allow" || out["execution_allowed"] != true || out["decision_id"] == first || out["expires_at"] == nil ||
		out["decision_basis"] != "approval" {
		t.Fatalf("reevaluate: %d %v", st, out)
	}
	second := out["decision_id"].(string)
	eqEvents(t, e.audit.take(), "action_reevaluated", "policy_decided", "dispatch_enqueued")
	var basis, approval string
	if err := e.admin.QueryRow(ctx, `SELECT decision_basis, approval_id::text FROM decisions.decisions WHERE decision_id = $1`, second).Scan(&basis, &approval); err != nil {
		t.Fatal(err)
	}
	if basis != "approval" || approval == "" {
		t.Fatalf("basis %s approval %s", basis, approval)
	}
	st, view = e.do(t, e.asUser(), "GET", "/v1/actions/"+actionID, "")
	if st != 200 || view["execution_state"] != "dispatch_pending" || view["dispatch_status"] != "pending" || view["decision_id"] != second ||
		view["decision_basis"] != "approval" {
		t.Fatalf("get after allow: %d %v", st, view)
	}
	// A reserved action is not re-evaluated (COMMON: 409 PERMIT_INVALID).
	if _, err := e.admin.Exec(ctx, `
INSERT INTO coordinator.reservations (reservation_id, action_id, decision_id, action_digest, decision_basis, approval_id, session_id, state, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, $3, 'approval', $4, $5, 'reserved', now(), now())`, actionID, second, digest, approval, e.user); err != nil {
		t.Fatal(err)
	}
	if st, out := e.do(t, e.asUser(), "POST", "/v1/actions/"+actionID+":reevaluate", `{"expected_action_digest":"`+digest+`"}`); st != 409 || codes(out)[0] != "PERMIT_INVALID" {
		t.Fatalf("reserved reevaluate: %d %v", st, out)
	}
}

const zeros = "0000000000000000000000000000000000000000000000000000000000000000"

func TestDenyPaths(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	// Rego deny: the email field is outside the receiver disclosure scope.
	st, out := e.do(t, e.asUser(), "POST", "/v1/actions", receiverBody(e.user, "key-deny-1", "x@y.example"))
	if st != 403 || out["verdict"] != "deny" || out["execution_allowed"] != false || codes(out)[0] != "DISCLOSURE_SCOPE_DENIED" || out["action_id"] == nil || out["decision_id"] == nil {
		t.Fatalf("disclosure deny: %d %v", st, out)
	}
	if st, view := e.do(t, e.asUser(), "GET", "/v1/actions/"+out["action_id"].(string), ""); st != 200 || view["execution_state"] != "denied" {
		t.Fatalf("get deny: %d %v", st, view)
	}
	if st, res := e.do(t, e.asUser(), "GET", "/v1/actions/"+out["action_id"].(string)+"/result", ""); st != 202 || res["execution_state"] != "denied" {
		t.Fatalf("result deny: %d %v", st, res)
	}

	// Normalize-stage deny: the content checker matches a synthetic identifier.
	body := `{"session_id":"` + e.user + `","operation_id":"receiver.submit","requested_target":{"target_id":"receiver-primary"},` +
		`"arguments":{"payload":{"summary":"about SYN-USER-0001","email":null}},"client_request_key":"key-deny-2"}`
	st, out = e.do(t, e.asUser(), "POST", "/v1/actions", body)
	if st != 403 || codes(out)[0] != "CONTENT_PATTERN_DENIED" || out["verdict"] != "deny" {
		t.Fatalf("content deny: %d %v", st, out)
	}
	var stage string
	var ref, rego *string
	var matched []string
	if err := e.admin.QueryRow(ctx, `SELECT decision_stage, decision_input_ref, rego_result::text, matched_rule_ids FROM decisions.decisions WHERE decision_id = $1`,
		out["decision_id"]).Scan(&stage, &ref, &rego, &matched); err != nil {
		t.Fatal(err)
	}
	if stage != "normalize" || ref != nil || rego != nil || len(matched) != 1 || matched[0] != "normalize.content_pattern.v1" {
		t.Fatalf("normalize decision: %s %v %v %v", stage, ref, rego, matched)
	}
	// The normalize-stage decision and its policy_decided carry the active
	// policy_epoch (7 from fakePolicy), not null or 0.
	var epoch *int64
	var revision *string
	if err := e.admin.QueryRow(ctx, `SELECT policy_epoch, opa_bundle_revision FROM decisions.decisions WHERE decision_id = $1`,
		out["decision_id"]).Scan(&epoch, &revision); err != nil {
		t.Fatal(err)
	}
	if epoch == nil || *epoch != 7 || revision != nil {
		t.Fatalf("normalize decision policy_epoch %v opa_bundle_revision %v", epoch, revision)
	}
	pd, ok := e.audit.lastEvent("policy_decided")
	if !ok || pd.Payload["decision_id"] != out["decision_id"] || pd.Payload["decision_stage"] != "normalize" {
		t.Fatalf("normalize policy_decided %v", pd.Payload)
	}
	if pe, ok := pd.Payload["policy_epoch"].(*int64); !ok || pe == nil || *pe != 7 {
		t.Fatalf("normalize policy_decided policy_epoch %v", pd.Payload["policy_epoch"])
	}

	// A hold makes the Rego deny 503.
	e.health.mu.Lock()
	e.health.holds = []Hold{{HoldID: uuid.NewString(), Scope: "global", ScopeID: "*", Reason: "export_lag"}}
	e.health.mu.Unlock()
	st, out = e.do(t, e.asService(), "POST", "/v1/actions", evidenceBody(e.service, "key-deny-3"))
	if st != 503 || codes(out)[0] != "HOLD_ACTIVE" || out["verdict"] != "deny" {
		t.Fatalf("hold deny: %d %v", st, out)
	}

	// No envelope, no rows: a schema violation and a session mismatch.
	before := e.count(t, "decisions.actions")
	if st, out := e.do(t, e.asUser(), "POST", "/v1/actions", `{"session_id":"`+e.user+`"}`); st != 422 || codes(out)[0] != "SCHEMA_INVALID" {
		t.Fatalf("schema: %d %v", st, out)
	}
	if st, out := e.do(t, e.asUser(), "POST", "/v1/actions", receiverBody(e.service, "key-deny-4", "")); st != 403 || codes(out)[0] != "SESSION_BINDING_INVALID" {
		t.Fatalf("session mismatch: %d %v", st, out)
	}
	if st, out := e.do(t, e.asUser(), "POST", "/v1/actions", `{"session_id":"`+e.user+`","operation_id":"nope.op","requested_target":{},"arguments":{},"client_request_key":"key-deny-5"}`); st != 403 || codes(out)[0] != "ENDPOINT_NOT_REGISTERED" {
		t.Fatalf("unregistered: %d %v", st, out)
	}
	if e.count(t, "decisions.actions") != before {
		t.Fatal("a rejection without envelope stored an action")
	}
}

// TestModelGenerateSubmit: with the installed model profiles attached to the
// bundle catalog, model.generate is normalized and judged instead of 403
// ENDPOINT_NOT_REGISTERED; without them it is still not registered.
func TestModelGenerateSubmit(t *testing.T) {
	e := setup(t)
	st, out := e.do(t, e.asService(), "POST", "/v1/actions", modelBody(e.service, "key-model-1", "policy_proposal"))
	if st != 202 || out["verdict"] != "allow" {
		t.Fatalf("model.generate: %d %v", st, out)
	}
	e.svc.ModelProfiles = nil
	st, out = e.do(t, e.asService(), "POST", "/v1/actions", modelBody(e.service, "key-model-2", "policy_proposal"))
	if st != 403 || codes(out)[0] != "ENDPOINT_NOT_REGISTERED" {
		t.Fatalf("model.generate without profiles: %d %v", st, out)
	}
}

func TestResubmissionAndBodyConflict(t *testing.T) {
	e := setup(t)
	body := receiverBody(e.user, "key-idem-1", "")
	st1, a := e.do(t, e.asUser(), "POST", "/v1/actions", body)
	st2, b := e.do(t, e.asUser(), "POST", "/v1/actions", body)
	if st1 != 202 || st2 != 202 || a["action_id"] != b["action_id"] || a["decision_id"] != b["decision_id"] || b["verdict"] != "approval_required" {
		t.Fatalf("resubmission: %v %v", a, b)
	}
	if basis, ok := b["decision_basis"]; !ok || basis != nil {
		t.Fatalf("replayed approval_required decision_basis %v (present %v)", basis, ok)
	}
	st, out := e.do(t, e.asUser(), "POST", "/v1/actions",
		`{"session_id":"`+e.user+`","operation_id":"receiver.submit","requested_target":{"target_id":"receiver-primary"},"arguments":{"payload":{"summary":"other text","email":null}},"client_request_key":"key-idem-1"}`)
	if st != 409 || codes(out)[0] != "CLIENT_KEY_BODY_CONFLICT" || out["action_id"] != a["action_id"] {
		t.Fatalf("body conflict: %d %v", st, out)
	}
	if n := e.count(t, "decisions.actions"); n != 1 {
		t.Fatalf("%d actions", n)
	}
	if n := e.count(t, "decisions.decisions"); n != 1 {
		t.Fatalf("%d decisions", n)
	}
}

func TestConcurrentIdenticalSubmissions(t *testing.T) {
	e := setup(t)
	body := evidenceBody(e.service, "key-race-1")
	const n = 8
	var wg sync.WaitGroup
	ids := make([]any, n)
	sts := make([]int, n)
	bases := make([]any, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, out := e.do(t, e.asService(), "POST", "/v1/actions", body)
			sts[i], ids[i], bases[i] = st, out["action_id"], out["decision_basis"]
		}(i)
	}
	wg.Wait()
	for i := range ids {
		// The winner and every replayed answer carry the service-scope basis.
		if sts[i] != 202 || ids[i] == nil || ids[i] != ids[0] || bases[i] != "service_scope" {
			t.Fatalf("request %d: %d %v basis %v (first %v)", i, sts[i], ids[i], bases[i], ids[0])
		}
	}
	if e.count(t, "decisions.actions") != 1 || e.count(t, "decisions.decisions") != 1 || e.count(t, "decisions.execute_requests") != 1 {
		t.Fatal("concurrent submissions stored more than one action/decision/execute request")
	}
}

// approvedAction submits an approval_required receiver action and stores a
// usable approval of it, so the next :reevaluate allows it. It returns the
// action_id, its first decision_id, its action_digest and the approval_id.
func (e *env) approvedAction(t *testing.T, key string) (actionID, first, digest, approvalID string) {
	t.Helper()
	ctx := context.Background()
	st, out := e.do(t, e.asUser(), "POST", "/v1/actions", receiverBody(e.user, key, ""))
	if st != 202 || out["verdict"] != "approval_required" {
		t.Fatalf("submit: %d %v", st, out)
	}
	actionID, first = out["action_id"].(string), out["decision_id"].(string)
	var target []byte
	var disclosure []string
	var content string
	if err := e.admin.QueryRow(ctx, `SELECT action_digest, canonical_target, disclosure_fields, content_digest FROM decisions.actions WHERE action_id = $1`,
		actionID).Scan(&digest, &target, &disclosure, &content); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.QueryRow(ctx, `
INSERT INTO identity.approvals (approval_id, revision, approval_kind, action_id, authenticated_actor, session_id,
    contract_digest, displayed_contract_digest, allowed_operation, canonical_target, disclosure_fields, content_digest,
    max_actions, policy_epoch, contract_version, created_at, expires_at)
VALUES (gen_random_uuid(), 1, 'action', $1, 'google:u1', $2, $3, $3, 'receiver.submit', $4, $5, $6, 1, 7, 'v1', now(), now() + interval '5 minutes')
RETURNING approval_id::text`,
		actionID, e.user, zeros, target, disclosure, content).Scan(&approvalID); err != nil {
		t.Fatal(err)
	}
	e.audit.take()
	return actionID, first, digest, approvalID
}

// TestConcurrentReevaluateStoresOneDecision: concurrent :reevaluate calls
// that all evaluated against the same previous decision store exactly one
// new allow decision and one execute request; the others store nothing and
// answer with that decision (guardReevaluate compare-and-set).
func TestConcurrentReevaluateStoresOneDecision(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	actionID, first, digest, _ := e.approvedAction(t, "key-reeval-race")

	// Hold every request after its evaluation until all n have evaluated, so
	// all of them read the same previous decision before any store.
	const n = 8
	var arrived atomic.Int32
	release := make(chan struct{})
	e.svc.beforeReevaluateStore = func(string) {
		if arrived.Add(1) == n {
			close(release)
		}
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}
	var wg sync.WaitGroup
	sts := make([]int, n)
	outs := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sts[i], outs[i] = e.do(t, e.asUser(), "POST", "/v1/actions/"+actionID+":reevaluate", `{"expected_action_digest":"`+digest+`"}`)
		}(i)
	}
	wg.Wait()
	if arrived.Load() != n {
		t.Fatalf("%d of %d requests reached the store", arrived.Load(), n)
	}

	var stored []string
	rows, err := e.admin.Query(ctx, `SELECT decision_id::text FROM decisions.decisions WHERE action_id = $1 AND decision_id <> $2`, actionID, first)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("%d new decisions stored, want 1", len(stored))
	}
	if n := e.count(t, "decisions.execute_requests"); n != 1 {
		t.Fatalf("%d execute requests, want 1", n)
	}
	for i := range outs {
		o := outs[i]
		if sts[i] != 202 || o["verdict"] != "allow" || o["execution_allowed"] != true || o["decision_id"] != stored[0] ||
			o["decision_basis"] != "approval" || o["expires_at"] == nil || o["action_id"] != actionID {
			t.Fatalf("request %d: %d %v (stored %s)", i, sts[i], o, stored[0])
		}
	}
	var reevaluated int
	for _, ev := range e.audit.take() {
		if ev == "action_reevaluated" {
			reevaluated++
		}
	}
	if reevaluated != 1 {
		t.Fatalf("%d action_reevaluated events, want 1", reevaluated)
	}
}

// TestReevaluateReservedBeforeStore: a reservation committed after the
// :reevaluate pre-check but before its decision transaction is found by the
// re-check under the action lock: 409 PERMIT_INVALID and nothing stored.
func TestReevaluateReservedBeforeStore(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	actionID, first, digest, approvalID := e.approvedAction(t, "key-reeval-resv")
	e.svc.beforeReevaluateStore = func(id string) {
		if _, err := e.admin.Exec(ctx, `
INSERT INTO coordinator.reservations (reservation_id, action_id, decision_id, action_digest, decision_basis, approval_id, session_id, state, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, $3, 'approval', $4, $5, 'reserved', now(), now())`, id, first, digest, approvalID, e.user); err != nil {
			t.Error(err)
		}
	}
	st, out := e.do(t, e.asUser(), "POST", "/v1/actions/"+actionID+":reevaluate", `{"expected_action_digest":"`+digest+`"}`)
	if st != 409 || codes(out)[0] != "PERMIT_INVALID" || out["action_id"] != actionID || out["decision_id"] != first {
		t.Fatalf("reserved before store: %d %v", st, out)
	}
	if n := e.count(t, "decisions.decisions"); n != 1 {
		t.Fatalf("%d decisions, want 1", n)
	}
	if n := e.count(t, "decisions.execute_requests"); n != 0 {
		t.Fatalf("%d execute requests, want 0", n)
	}
	if evs := e.audit.take(); len(evs) != 0 {
		t.Fatalf("events %v", evs)
	}
}

func TestExpiredOrRevokedTokenIs401(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	// A live token presented with another Pod's certificate of the same
	// workload is not accepted (session_tokens.bound_identity).
	w := e.asOther()
	w.token = e.userTok
	if st, _ := e.do(t, w, "POST", "/v1/actions", receiverBody(e.user, "key-exp-3", "")); st != 401 {
		t.Fatalf("token on another SAN: %d", st)
	}
	if _, err := e.admin.Exec(ctx, `UPDATE identity.sessions SET expires_at = now() - interval '1 second' WHERE session_id = $1`, e.user); err != nil {
		t.Fatal(err)
	}
	if st, out := e.do(t, e.asUser(), "POST", "/v1/actions", receiverBody(e.user, "key-exp-1", "")); st != 401 || codes(out)[0] != "AUTH_REQUIRED" {
		t.Fatalf("expired: %d %v", st, out)
	}
	if _, err := e.admin.Exec(ctx, `UPDATE identity.session_tokens SET revoked_at = now() WHERE service_session_id = $1`, e.service); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.do(t, e.asService(), "POST", "/v1/actions", evidenceBody(e.service, "key-exp-2")); st != 401 {
		t.Fatalf("revoked: %d", st)
	}
	e.noRows(t)
	if len(e.audit.take()) != 0 {
		t.Fatal("401 produced audit events")
	}
}

func TestUnwiredDependencyIs503WithNoRows(t *testing.T) {
	e := setup(t)
	cases := map[string]func(*Service){
		"auditor":        func(s *Service) { s.Audit = nil },
		"active_policy":  func(s *Service) { s.Policy = nil },
		"control health": func(s *Service) { s.Health = nil },
		"workload data":  func(s *Service) { s.Adapters = nil },
		"readiness":      func(s *Service) { s.Readiness = nil },
		"revision":       func(s *Service) { s.Policy = &fakePolicy{a: ActivePolicy{Epoch: 8, ExpectedOPARevision: "rev-other"}} },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			p, h, a, au, r := e.svc.Policy, e.svc.Health, e.svc.Adapters, e.svc.Audit, e.svc.Readiness
			mod(e.svc)
			defer func() { e.svc.Policy, e.svc.Health, e.svc.Adapters, e.svc.Audit, e.svc.Readiness = p, h, a, au, r }()
			st, out := e.do(t, e.asUser(), "POST", "/v1/actions", receiverBody(e.user, "key-unw-"+uuid.NewString()[:8], ""))
			if st != 503 || out["verdict"] != nil {
				t.Fatalf("%d %v", st, out)
			}
			if name == "revision" && codes(out)[0] != "POLICY_VERSION_MISMATCH" {
				t.Fatalf("revision: %v", out)
			}
			e.noRows(t)
		})
	}
}

func TestExecuteWorkerDelivers(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	var calls atomic.Int32
	var got ExecuteRequest
	// The adapter serves a TASK-03 style service certificate (one URI SAN,
	// no DNS/IP SAN) on 127.0.0.1 and requires the gateway client
	// certificate; the worker uses the production client (NewAdapterClient).
	pk := newPKI(t)
	leaf, key := pk.root.issue(t, leafSpec{uris: []string{evidenceSAN}, eku: serviceEKU})
	adapter := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.URL.Path != "/internal/adapter/evidence-reader/execute" || r.Method != "POST" {
			w.WriteHeader(404)
			return
		}
		b, _ := io.ReadAll(r.Body)
		if err := strictInto(b, &got); err != nil {
			w.WriteHeader(422)
			return
		}
		if n == 1 { // the first call fails; the worker retries
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(executeAck{DecisionID: got.DecisionID, ActionID: got.ActionID, State: "received"})
	}))
	adapter.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pk.roots,
	}
	adapter.StartTLS()
	defer adapter.Close()
	client, err := NewAdapterClient("evidence-reader", pk.roots, pk.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Adapter = func(id string) (AdapterEndpoint, bool) {
		return AdapterEndpoint{BaseURL: adapter.URL, Client: client}, id == "evidence-reader"
	}

	st, out := e.do(t, e.asService(), "POST", "/v1/actions", evidenceBody(e.service, "key-exec-1"))
	if st != 202 || out["verdict"] != "allow" {
		t.Fatalf("submit: %d %v", st, out)
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	go e.svc.RunWorker(wctx)
	deadline := time.Now().Add(4 * time.Second)
	var state string
	var attempts int
	for time.Now().Before(deadline) {
		if err := e.admin.QueryRow(ctx, `SELECT state, attempts FROM decisions.execute_requests WHERE decision_id = $1`, out["decision_id"]).Scan(&state, &attempts); err != nil {
			t.Fatal(err)
		}
		if state != "pending" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if state != "delivered" || attempts != 2 || calls.Load() != 2 {
		t.Fatalf("state %s attempts %d calls %d", state, attempts, calls.Load())
	}
	if got.DecisionID != out["decision_id"] || got.ActionID != out["action_id"] {
		t.Fatalf("adapter got %+v", got)
	}
	if st, view := e.do(t, e.asService(), "GET", "/v1/actions/"+out["action_id"].(string), ""); st != 200 || view["dispatch_status"] != "delivered" {
		t.Fatalf("get: %d %v", st, view)
	}
}

func TestExecuteWorkerExpires(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.svc.Adapter = func(string) (AdapterEndpoint, bool) { return AdapterEndpoint{}, false } // every call fails
	st, out := e.do(t, e.asService(), "POST", "/v1/actions", evidenceBody(e.service, "key-exp-w"))
	if st != 202 {
		t.Fatalf("submit: %d %v", st, out)
	}
	// Age the decision past its TTL (decisions are immutable, so drop the
	// trigger guard as admin for this fixture only).
	if _, err := e.admin.Exec(ctx, `
ALTER TABLE decisions.decisions DISABLE TRIGGER decisions_immutable;
UPDATE decisions.decisions SET created_at = now() - interval '1 minute', expires_at = now() - interval '50 seconds';
ALTER TABLE decisions.decisions ENABLE TRIGGER decisions_immutable;`); err != nil {
		t.Fatal(err)
	}
	if worked, err := e.svc.DeliverOnce(ctx); err != nil || !worked {
		t.Fatalf("DeliverOnce: %v %v", worked, err)
	}
	var state string
	if err := e.admin.QueryRow(ctx, `SELECT state FROM decisions.execute_requests`).Scan(&state); err != nil || state != "expired" {
		t.Fatalf("state %s %v", state, err)
	}
}

// fakeProbes stands in for TASK-03 coordinator.bind_activation_probe_action,
// which this branch does not have yet. It holds one registered probe keyed by
// (service_session_id, client_request_key) and, like the DB function, binds
// only that key: any other key is an error. Every key passed to Bind is
// recorded.
type fakeProbes struct {
	mu    sync.Mutex
	probe ActivationProbe
	key   string
	binds []string
}

func (f *fakeProbes) Lookup(_ context.Context, _ pgx.Tx, ssid, key, actionID string) (*ActivationProbe, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ssid != f.probe.ServiceSessionID || key != f.key {
		return nil, nil
	}
	p := f.probe
	p.ActionID = actionID
	return &p, nil
}

func (f *fakeProbes) Bind(_ context.Context, _ pgx.Tx, ssid, key, actionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binds = append(f.binds, key)
	if ssid != f.probe.ServiceSessionID || key != f.key {
		return errors.New("no activation probe for (service_session_id, client_request_key)")
	}
	if f.probe.ActionID != "" && f.probe.ActionID != actionID {
		return errors.New("activation probe bound to another action")
	}
	f.probe.ActionID = actionID
	return nil
}

// TestReevaluateActivationProbeBindsClientKey: :reevaluate of a probe action
// binds the probe with the action's client_request_key, not an empty key.
func TestReevaluateActivationProbeBindsClientKey(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	ssid, change, key := uuid.NewString(), uuid.NewString(), "key-probe-1"
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.service_sessions (service_session_id, caller_principal, authenticated_actor, profile, tenant, change_id,
    state, created_at, expires_at)
VALUES ($1, 'policy-proposer', 'service:agent-observe/policy-proposer', 'activation_probe', 'hackathon', $2,
    'active', now(), now() + interval '30 minutes')`, ssid, change); err != nil {
		t.Fatal(err)
	}
	token := "probe-token-" + uuid.NewString()
	d := sha256.Sum256([]byte(token))
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.session_tokens (token_digest, service_session_id, bound_identity, issued_at)
VALUES ($1, $2, $3, now())`, d[:], ssid, serviceSAN); err != nil {
		t.Fatal(err)
	}
	probes := &fakeProbes{key: key, probe: ActivationProbe{ActivationProbeID: uuid.NewString(), ChangeID: change,
		ServiceSessionID: ssid, TargetEpoch: 8, ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano)}}
	e.svc.Probes = probes
	w := who{serviceSAN, serviceSerial, token}

	body := `{"session_id":"` + ssid + `","operation_id":"receiver.submit","requested_target":{"target_id":"receiver-probe"},` +
		`"arguments":{"payload":{"summary":"activation probe","email":null}},"client_request_key":"` + key + `"}`
	st, out := e.do(t, w, "POST", "/v1/actions", body)
	if st != 202 || out["verdict"] != "allow" {
		t.Fatalf("submit: %d %v", st, out)
	}
	actionID, first := out["action_id"].(string), out["decision_id"].(string)
	st, view := e.do(t, w, "GET", "/v1/actions/"+actionID, "")
	if st != 200 {
		t.Fatalf("get: %d %v", st, view)
	}
	digest := view["action_digest"].(string)

	st, out = e.do(t, w, "POST", "/v1/actions/"+actionID+":reevaluate", `{"expected_action_digest":"`+digest+`"}`)
	if st != 202 || out["verdict"] != "allow" || out["decision_id"] == nil || out["decision_id"] == first ||
		out["decision_basis"] != "activation_probe" {
		t.Fatalf("reevaluate: %d %v", st, out)
	}
	second := out["decision_id"].(string)

	probes.mu.Lock()
	binds := append([]string{}, probes.binds...)
	probes.mu.Unlock()
	if len(binds) != 2 || binds[0] != key || binds[1] != key {
		t.Fatalf("Bind keys %q, want [%q %q]", binds, key, key)
	}
	var n int
	var basis, probeID string
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM decisions.decisions WHERE action_id = $1`, actionID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.QueryRow(ctx, `SELECT decision_basis, activation_probe_id::text FROM decisions.decisions WHERE decision_id = $1`, second).Scan(&basis, &probeID); err != nil {
		t.Fatal(err)
	}
	if n != 2 || basis != "activation_probe" || probeID != probes.probe.ActivationProbeID {
		t.Fatalf("decisions %d, basis %s, activation_probe_id %s", n, basis, probeID)
	}
}
