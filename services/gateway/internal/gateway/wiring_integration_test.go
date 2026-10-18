//go:build integration

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

// The M3-1 gateway wiring on PostgreSQL 16. Every migration is installed by
// a non-superuser installer; the gateway runs as a restricted login whose
// only grant is membership in gateway_app (TASK-16), so it reads holds,
// leases and desired_bundle only through the gateway_reader membership of
// 20261018092200 and appends audit through audit_producer. The service uses
// the implementations cmd/gateway wires: PGPolicy, PGHealth, PGAdapters,
// PGAuditor, PGProbes, policyloader.PGSource and HTTPReadiness.
//
// HTTPReadiness talks to a stand-in for TASK-10
// GET /internal/control-health/work-readiness/checks/{id}, which
// control-health does not serve yet; it answers the COMMON
// WorkReadinessCheck of the request's own reference.
//
// Needs a fresh, disposable cluster (roles are cluster-wide):
//
//	GATEWAY_WIRING_TEST_ADMIN_DSN=postgres://postgres@127.0.0.1:<port>/postgres?sslmode=disable \
//	  go test -tags integration -run TestWiredGatewayPostgres ./services/gateway/internal/gateway
//
// tests/gateway/run-local.sh starts such a cluster.
func TestWiredGatewayPostgres(t *testing.T) {
	dsn := os.Getenv("GATEWAY_WIRING_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable GATEWAY_WIRING_TEST_ADMIN_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	run := func(c *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%.120s: %v", sql, err)
		}
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	dbName, installer, app := "gwwire_"+suffix, "gwwireinst_"+suffix, "gwwireapp_"+suffix
	run(admin, "CREATE ROLE "+installer+" LOGIN NOSUPERUSER NOCREATEDB CREATEROLE")
	run(admin, "CREATE ROLE "+app+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	run(admin, "CREATE DATABASE "+dbName+" OWNER "+installer)
	defer func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE "+dbName+" WITH (FORCE)") }()
	connect := func(user string) *pgx.Conn {
		t.Helper()
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Database, cfg.User = dbName, user
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	owner := connect(installer)
	for _, r := range []string{"control_health_writer", "gateway_app", "timeline_app", "broker_reader"} {
		run(owner, "DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='"+r+"') THEN CREATE ROLE "+r+" NOLOGIN; END IF; END $$")
	}
	files, err := filepath.Glob(filepath.Join(repoRoot, "migrations/*.up.sql"))
	if err != nil || len(files) == 0 {
		t.Fatal("no migrations", err)
	}
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("%s as non-superuser: %v", filepath.Base(f), err)
		}
	}

	// TASK-16 install: the login's only grant is gateway_app; the audit
	// source and its event grants.
	run(admin, "GRANT gateway_app TO "+app)
	inspect := connect(admin.Config().User)
	run(inspect, "INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES($1,'gateway-test',false)", app)
	for _, ev := range []string{"request_received", "request_rejected", "policy_decided", "policy_evaluation_failed",
		"approval_requested", "action_reevaluated", "dispatch_enqueued"} {
		run(inspect, "INSERT INTO audit.producer_event_grants VALUES('gateway-test',$1,'hackathon')", ev)
	}

	// Identity fixtures (TASK-03 rows the gateway only reads).
	user, userTok := uuid.NewString(), "user-token-"+uuid.NewString()
	run(inspect, `INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id, service_principal) VALUES
    ('agent-exec', 'agent-runtime', 'runtime', NULL, NULL)`)
	run(inspect, `INSERT INTO identity.issued_certificates (serial, san_uri, namespace, ksa, pod_uid, node_uid, boot_id, issued_at, expires_at)
VALUES ($1, $2, 'agent-exec', 'agent-runtime', gen_random_uuid(), $3, 'boot-1', now(), now() + interval '1 day')`, runtimeSerial, runtimeSAN, nodeUID)
	run(inspect, `INSERT INTO identity.sessions (session_id, authenticated_actor, tenant, workload_id, task_statement, allowed_operation_ids,
    state, claim_code_digest, claim_expires_at, created_at, expires_at, max_expires_at)
VALUES ($1, 'google:u1', 'hackathon', 'agent-exec/agent-runtime', 'send the weekly summary', '{receiver.submit}',
    'claimed', '\x00', now(), now(), now() + interval '30 minutes', now() + interval '8 hours')`, user)
	d := sha256.Sum256([]byte(userTok))
	run(inspect, `INSERT INTO identity.session_tokens (token_digest, session_id, service_session_id, bound_identity, issued_at)
VALUES ($1, $2, NULL, $3, now())`, d[:], user, runtimeSAN)

	// TASK-14 rows: desired_bundle and active_policy of the signed bundle.
	p := loadTestPolicy(t, "")
	uri := "gs://agentarium-bundle/bundles/" + p.artifact + ".tar.gz"
	run(inspect, `INSERT INTO release.desired_bundle (environment, bundle_id, artifact_digest, object_uri, set_by_change_id, set_at)
VALUES ('test', $1, $2, $3, gen_random_uuid(), now())`, testBundle, p.artifact, uri)
	run(inspect, `INSERT INTO release.active_policy VALUES ('test', 7, $1, repeat('a', 64), $2, $3, $4, repeat('c', 64), gen_random_uuid(), now())`,
		testBundle, p.artifact, testRev, p.catalog.CatalogDigest)

	// TASK-10 leases: the seven required components of a user-session
	// receiver.submit, each in its lease scope.
	type leaseRow struct{ component, source, scope, scopeID string }
	required := []leaseRow{
		{"gateway", "gateway/pod-1", "global", "*"},
		{"coordinator", "coordinator/pod-1", "global", "*"},
		{"audit-db", "audit-db", "global", "*"},
		{"audit-export", "audit-export/pod-1", "global", "*"},
		{"adapter", "receiver-sender/pod-1", "workload", "agent-adapters/receiver-sender"},
		{"destination-evidence", "evidence-collector/pod-1", "target", "receiver-primary"},
		{"node-sensors", "tetragon-node/" + nodeUID, "node", nodeUID},
	}
	setLease := func(l leaseRow, ttl time.Duration) {
		t.Helper()
		var version *string
		if l.component == "adapter" {
			version = &p.artifact
		}
		run(inspect, `INSERT INTO health.control_health_leases (source_id, component, scope, scope_id, active_version, observed_state,
    lease_until, reported_at, first_reported_at)
VALUES ($1, $2, $3, $4, $5, 'healthy', now() + make_interval(secs => $6), now(), now())
ON CONFLICT (source_id, component) DO UPDATE SET lease_until = excluded.lease_until, reported_at = excluded.reported_at`,
			l.source, l.component, l.scope, l.scopeID, version, ttl.Seconds())
	}
	liveAll := func() {
		for _, l := range required {
			setLease(l, time.Minute)
		}
	}
	liveAll()

	// The gateway login.
	pcfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	pcfg.ConnConfig.Database, pcfg.ConnConfig.User = dbName, app
	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var super, createRole, reader bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper, rolcreaterole, pg_has_role(current_user, 'gateway_reader', 'USAGE')
FROM pg_roles WHERE rolname = current_user`).Scan(&super, &createRole, &reader); err != nil || super || createRole || !reader {
		t.Fatalf("app login: super %v createrole %v gateway_reader %v %v", super, createRole, reader, err)
	}
	for _, denied := range []string{
		"UPDATE health.control_health_leases SET lease_until = now() + interval '1 hour'",
		"UPDATE health.holds SET released_at = now()",
		"UPDATE release.active_policy SET epoch = epoch + 1",
		"INSERT INTO audit.audit_events (event_id) VALUES (gen_random_uuid())",
	} {
		if _, err := pool.Exec(ctx, denied); err == nil || !strings.Contains(err.Error(), "42501") {
			t.Fatalf("gateway login allowed %q: %v", denied, err)
		}
	}

	// The bundle comes from desired_bundle through the gateway login.
	loader, err := policyloader.New(policyloader.Config{Source: policyloader.PGSource{Pool: pool, Environment: "test"},
		Fetcher: p.store, Keys: map[string]string{testKeyID: p.pub}, KeyID: testKeyID, Query: policyloader.GatewayQuery})
	if err != nil {
		t.Fatal(err)
	}
	if err := loader.Poll(ctx); err != nil {
		t.Fatalf("load through PGSource: %v", err)
	}

	// Stand-in for the TASK-10 work-readiness check API.
	readyCheck := uuid.NewString()
	readyRun := uuid.NewString()
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/control-health/work-readiness/checks/"+readyCheck ||
			r.Header.Get(PeerIdentityHeader) != runtimeSAN {
			http.NotFound(w, r)
			return
		}
		ms := int64(2000)
		_ = json.NewEncoder(w).Encode(readinessCheck{CheckID: readyCheck, WorkRunID: readyRun, SessionID: user,
			WorkloadID: "agent-exec/agent-runtime", CallerIdentity: runtimeSAN, State: "ready", ReasonCodes: []string{}, RemainingValidMS: &ms})
	}))
	defer health.Close()

	auditor, err := NewPGAuditor(AuditConfig{SourceID: "gateway-test", Version: "test-v1", Epoch: "1"})
	if err != nil {
		t.Fatal(err)
	}
	profiles := testModelProfiles(t)
	newSvc := func(policy PolicySource, audit Auditor) *Service {
		return &Service{
			Pool: pool, Bundle: loader, Environment: "test", GatewayIdentity: "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway",
			Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			Policy: policy, Health: PGHealth{},
			Readiness: HTTPReadiness{BaseURL: health.URL, Client: health.Client()},
			Adapters:  PGAdapters{}, Audit: audit, Probes: PGProbes{}, ModelProfiles: profiles,
		}
	}
	svc := newSvc(PGPolicy{Environment: "test"}, auditor)
	mux := http.NewServeMux()
	(&Handler{Svc: svc, peer: testPeer}).Register(mux)
	call := func(s *Service, method, path, body, check string) (int, map[string]any) {
		t.Helper()
		m := mux
		if s != svc {
			m = http.NewServeMux()
			(&Handler{Svc: s, peer: testPeer}).Register(m)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+userTok)
		r.Header.Set("X-Test-SAN", runtimeSAN)
		r.Header.Set("X-Test-Serial", runtimeSerial)
		r.Header.Set(WorkRunHeader, readyRun)
		r.Header.Set(ReadinessCheckHeader, check)
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, r)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: %d %q", method, path, rec.Code, rec.Body.String())
		}
		return rec.Code, out
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := inspect.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	events := func(actionID string) []string {
		t.Helper()
		rows, err := inspect.Query(ctx, `SELECT event_type FROM audit.audit_events
WHERE action_id = $1 AND source_id = 'gateway-test' AND source_epoch = '1' AND tenant = 'hackathon' AND session_id = $2
ORDER BY event_type`, actionID, user)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// 1. All leases live, no approval: approval_required, stored with the
	// active epoch and audited through audit_append.
	st, out := call(svc, "POST", "/v1/actions", receiverBody(user, "key-wired-1", ""), readyCheck)
	if st != 202 || out["verdict"] != "approval_required" || out["execution_allowed"] != false {
		t.Fatalf("submit: %d %v", st, out)
	}
	actionID := out["action_id"].(string)
	if got := events(actionID); strings.Join(got, ",") != "approval_requested,policy_decided,request_received" {
		t.Fatalf("submit events %v", got)
	}
	if count("SELECT count(*) FROM decisions.decisions WHERE action_id = $1 AND policy_epoch = 7 AND opa_bundle_revision = $2", actionID, testRev) != 1 ||
		count("SELECT count(*) FROM audit.audit_outbox") == 0 {
		t.Fatal("decision epoch or audit outbox missing")
	}
	var digest string
	if err := inspect.QueryRow(ctx, `SELECT action_digest FROM decisions.actions WHERE action_id = $1`, actionID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	reeval := func(s *Service) (int, map[string]any) {
		t.Helper()
		return call(s, "POST", "/v1/actions/"+actionID+":reevaluate", `{"expected_action_digest":"`+digest+`"}`, readyCheck)
	}
	executes := func() int {
		return count("SELECT count(*) FROM decisions.execute_requests WHERE action_id = $1", actionID)
	}

	// 2. Approval missing: re-evaluation stays approval_required, no execute.
	if st, out := reeval(svc); st != 202 || out["verdict"] != "approval_required" || out["execution_allowed"] != false || executes() != 0 {
		t.Fatalf("no approval: %d %v", st, out)
	}

	// TASK-03 stores the approval of exactly this action at epoch 7.
	run(inspect, `INSERT INTO identity.approvals (approval_id, revision, approval_kind, action_id, authenticated_actor, session_id,
    contract_digest, displayed_contract_digest, allowed_operation, canonical_target, disclosure_fields, content_digest,
    max_actions, policy_epoch, contract_version, created_at, expires_at)
SELECT gen_random_uuid(), 1, 'action', a.action_id, 'google:u1', a.session_id, $2, $2, 'receiver.submit', a.canonical_target,
    a.disclosure_fields, a.content_digest, 1, 7, 'v1', now(), now() + interval '5 minutes'
FROM decisions.actions a WHERE a.action_id = $1`, actionID, zeros)

	// 3. One required lease expired: a stored deny, 503
	// CONTROL_HEALTH_UNAVAILABLE, for each of the seven, and no execute
	// request.
	for _, l := range required {
		setLease(l, -time.Second)
		st, out := reeval(svc)
		if st != 503 || out["verdict"] != "deny" || !contains(codes(out), "CONTROL_HEALTH_UNAVAILABLE") || executes() != 0 {
			t.Fatalf("expired %s: %d %v", l.component, st, out)
		}
		liveAll()
	}
	// An adapter lease of another bundle digest is not the loaded bundle's.
	run(inspect, `UPDATE health.control_health_leases SET active_version = repeat('9', 64) WHERE component = 'adapter'`)
	if st, out := reeval(svc); st != 503 || out["verdict"] != "deny" || !contains(codes(out), "CONTROL_HEALTH_UNAVAILABLE") || executes() != 0 {
		t.Fatalf("adapter version: %d %v", st, out)
	}
	run(inspect, `UPDATE health.control_health_leases SET active_version = $1 WHERE component = 'adapter'`, p.artifact)
	// An open global hold.
	hold := uuid.NewString()
	run(inspect, `INSERT INTO health.holds (hold_id, scope, scope_id, reason, owner_component, requested_by)
VALUES ($1, 'global', '*', 'policy_activation', 'releaser', 'test')`, hold)
	if st, out := reeval(svc); st != 503 || out["verdict"] != "deny" || !contains(codes(out), "HOLD_ACTIVE") || executes() != 0 {
		t.Fatalf("hold: %d %v", st, out)
	}
	run(inspect, `UPDATE health.holds SET released_at = now(), release_ref = 'test' WHERE hold_id = $1`, hold)
	// Work readiness that control-health does not report ready: 503, and no
	// decision is stored.
	before := count("SELECT count(*) FROM decisions.decisions WHERE action_id = $1", actionID)
	if st, out := call(svc, "POST", "/v1/actions/"+actionID+":reevaluate", `{"expected_action_digest":"`+digest+`"}`, uuid.NewString()); st != 503 ||
		codes(out)[0] != "WORK_READINESS_EXPIRED" || count("SELECT count(*) FROM decisions.decisions WHERE action_id = $1", actionID) != before {
		t.Fatalf("unknown readiness check: %d %v", st, out)
	}

	// 4. All leases live, the approval and the active epoch: allow, one
	// execute request, and the decision audit in the same commit.
	st, out = reeval(svc)
	if st != 202 || out["verdict"] != "allow" || out["execution_allowed"] != true || out["decision_basis"] != "approval" || executes() != 1 {
		t.Fatalf("allow: %d %v", st, out)
	}
	if count("SELECT count(*) FROM decisions.decisions WHERE decision_id = $1 AND policy_epoch = 7 AND verdict = 'allow'", out["decision_id"]) != 1 {
		t.Fatal("allow decision not at epoch 7")
	}
	if got := events(actionID); !contains(got, "action_reevaluated") || !contains(got, "dispatch_enqueued") {
		t.Fatalf("allow events %v", got)
	}

	// 5. Epoch moved to a bundle revision the gateway has not loaded: 503
	// POLICY_VERSION_MISMATCH, no action or decision, policy_evaluation_failed
	// audited.
	run(inspect, `UPDATE release.active_policy SET epoch = 8, expected_opa_revision = 'rev-other', updated_at = now() WHERE scope_id = 'test'`)
	actions := count("SELECT count(*) FROM decisions.actions")
	st, out = call(svc, "POST", "/v1/actions", receiverBody(user, "key-wired-2", ""), readyCheck)
	if st != 503 || codes(out)[0] != "POLICY_VERSION_MISMATCH" || count("SELECT count(*) FROM decisions.actions") != actions {
		t.Fatalf("epoch mismatch: %d %v", st, out)
	}
	if count(`SELECT count(*) FROM audit.audit_events WHERE event_type = 'policy_evaluation_failed' AND source_id = 'gateway-test'
  AND safe_payload->>'expected_revision' = 'rev-other'`) != 1 {
		t.Fatal("policy_evaluation_failed not audited")
	}
	run(inspect, `UPDATE release.active_policy SET epoch = 9, expected_opa_revision = $1, updated_at = now() WHERE scope_id = 'test'`, testRev)

	// 6. Another environment has no active_policy row: 503.
	other := newSvc(PGPolicy{Environment: "staging"}, auditor)
	if st, out := call(other, "POST", "/v1/actions", receiverBody(user, "key-wired-3", ""), readyCheck); st != 503 || codes(out)[0] != "POLICY_UNAVAILABLE" {
		t.Fatalf("no active_policy: %d %v", st, out)
	}

	// 7. An unregistered audit source rolls the decision back.
	unregistered, err := NewPGAuditor(AuditConfig{SourceID: "not-registered", Version: "v", Epoch: "1"})
	if err != nil {
		t.Fatal(err)
	}
	bad := newSvc(PGPolicy{Environment: "test"}, unregistered)
	actions = count("SELECT count(*) FROM decisions.actions")
	if st, out := call(bad, "POST", "/v1/actions", receiverBody(user, "key-wired-4", ""), readyCheck); st != 503 ||
		codes(out)[0] != "STATE_STORE_UNAVAILABLE" || count("SELECT count(*) FROM decisions.actions") != actions {
		t.Fatalf("unregistered audit source: %d %v", st, out)
	}
	// And the wired service still decides at the new epoch.
	st, out = call(svc, "POST", "/v1/actions", receiverBody(user, "key-wired-5", ""), readyCheck)
	if st != 202 || out["verdict"] != "approval_required" ||
		count("SELECT count(*) FROM decisions.decisions WHERE action_id = $1 AND policy_epoch = 9", out["action_id"]) != 1 {
		t.Fatalf("epoch 9: %d %v", st, out)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("timeout")
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
