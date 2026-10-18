//go:build integration

package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/coordinator/internal/dispatch"
)

const (
	wAdapterSAN  = "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-adapter/pod/p1"
	wAdapterNode = "11111111-1111-4111-8111-111111111111"
	wBoot        = "boot-1"
	wSerial      = "0abc01"
	wTarget      = "receiver-primary"
	wOPARev      = "rev-7"
	wActionD     = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

var (
	wCatalog = strings.Repeat("c", 64)
	wOther   = strings.Repeat("9", 64)
)

// The M3-1 coordinator wiring on PostgreSQL 16: every migration is installed
// by a non-superuser installer, the coordinator runs as a restricted login
// that is a member of coordinator_app (and through it coordinator_reader and
// audit_producer, the TASK-16 install grants), and the service is the one
// newService builds for main: PGPolicy (release.lock_active_policy),
// PGDecisions, PGHealth with the real lease check and PGAuditor.
//
// Needs a fresh, disposable cluster (roles are cluster-wide):
//
//	COORDINATOR_WIRING_TEST_ADMIN_DSN=postgres://postgres@127.0.0.1:<port>/postgres?sslmode=disable \
//	  go test -tags integration -run TestWiredServicePostgres ./services/coordinator/cmd/coordinator
//
// tests/coordinator/run-local.sh starts such a cluster.
func TestWiredServicePostgres(t *testing.T) {
	dsn := os.Getenv("COORDINATOR_WIRING_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable COORDINATOR_WIRING_TEST_ADMIN_DSN")
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
			t.Fatalf("%.100s: %v", sql, err)
		}
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	dbName, installer, app := "cowire_"+suffix, "cowireinst_"+suffix, "cowireapp_"+suffix
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
	// Roles of other Tasks that migrations grant to before their own
	// migration exists (TASK-16 step 2).
	for _, r := range []string{"control_health_writer", "gateway_app", "timeline_app", "broker_reader"} {
		run(owner, "DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='"+r+"') THEN CREATE ROLE "+r+" NOLOGIN; END IF; END $$")
	}
	files, err := filepath.Glob("../../../../migrations/*.up.sql")
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

	// TASK-16 install grants and the audit source registration.
	run(owner, "GRANT coordinator_reader, audit_producer TO coordinator_app")
	run(admin, "GRANT coordinator_app TO "+app)
	inspect := connect(admin.Config().User)
	run(inspect, "INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES($1,'coordinator-test',false)", app)
	for _, ev := range []string{"attempt_planned", "attempt_released", "attempt_uncertain", "activation_probe_registered"} {
		run(inspect, "INSERT INTO audit.producer_event_grants VALUES('coordinator-test',$1,'hackathon')", ev)
	}

	// Fixtures, as the database administrator: identity, gateway, control-health and
	// releaser rows the coordinator only reads.
	session := uuid.NewString()
	run(inspect, `INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id) VALUES
    ('agent-exec', 'agent-runtime', 'runtime', NULL), ('agent-adapters', 'receiver-adapter', 'adapter', 'receiver')`)
	run(inspect, `INSERT INTO identity.issued_certificates (serial, san_uri, namespace, ksa, pod_uid, node_uid, boot_id, issued_at, expires_at)
VALUES ($1, $2, 'agent-adapters', 'receiver-adapter', gen_random_uuid(), $3, $4, now(), now() + interval '1 day')`, wSerial, wAdapterSAN, wAdapterNode, wBoot)
	run(inspect, `INSERT INTO identity.sessions (session_id, authenticated_actor, tenant, workload_id, task_statement, allowed_operation_ids,
    state, claim_code_digest, claim_expires_at, created_at, expires_at, max_expires_at)
VALUES ($1, 'google:u1', 'hackathon', 'agent-exec/agent-runtime', 'task', '{receiver.submit}',
    'claimed', '\x00', now(), now(), now() + interval '30 minutes', now() + interval '8 hours')`, session)
	run(inspect, `INSERT INTO health.node_boot_generation (node_uid, boot_id, sensor_generation, guard_generation, startup_capture,
    startup_capture_measurement, state, updated_at) VALUES ($1, $2, 1, 0, 'unsupported', 'not_measured', 'ready', now())`, wAdapterNode, wBoot)
	setLease := func(component, scope, scopeID string, ttl time.Duration) {
		t.Helper()
		run(inspect, `INSERT INTO health.control_health_leases (source_id, component, scope, scope_id, observed_state, lease_until, reported_at, first_reported_at)
VALUES ($1, $2, $3, $4, 'healthy', now() + make_interval(secs => $5), now(), now())
ON CONFLICT (source_id, component) DO UPDATE SET lease_until = excluded.lease_until, reported_at = excluded.reported_at`,
			component+"/1", component, scope, scopeID, ttl.Seconds())
	}
	liveAll := func() {
		for _, c := range dispatch.DefaultRequiredGlobal {
			setLease(c, "global", "*", time.Minute)
		}
		setLease("destination-evidence", "target", wTarget, time.Minute)
	}
	liveAll()
	run(inspect, `INSERT INTO release.active_policy VALUES ('test', 7, 'bundle-1', repeat('a', 64), repeat('b', 64), $1, $2, repeat('c', 64), gen_random_uuid(), now())`, wOPARev, wCatalog)
	input := strings.Repeat("f", 64)
	run(inspect, `INSERT INTO decisions.decision_inputs VALUES ($1, 'hackathon', '{}', 'bundle-1', now())`, input)

	// newDecision writes an action, its approval and an allow decision at
	// epoch and catalog, as identity and the gateway would.
	newDecision := func(epoch int64, catalog string) dispatch.ReserveRequest {
		t.Helper()
		actionID, approvalID, decisionID, requestID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
		workload := "agent-exec/agent-runtime"
		envelope := canonical.ActionEnvelope{SchemaVersion: "1", ActionID: actionID, RequestID: uuid.NewString(),
			AuthenticatedActor: "google:u1", SessionKind: "user", SessionID: session, WorkloadID: &workload,
			EndpointID: "test-receiver-v1", OperationID: "receiver.submit",
			CanonicalTarget: canonical.CanonicalTarget{TargetID: wTarget, RouteID: "submissions-v1"},
			Environment:     "test", Tenant: "hackathon", DisclosureFields: []string{"summary"}, DataClass: "synthetic",
			DataSources: []string{}, Limits: map[string]int64{}, CatalogDigest: catalog, CatalogVersion: "test",
			CanonicalizationVersion: "v1", RawBodyDigest: strings.Repeat("a", 64), ActionDigest: wActionD}
		envJSON, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		run(inspect, `INSERT INTO decisions.actions (action_id, request_id, authenticated_actor, session_kind, session_id, workload_id,
    client_request_key, raw_body_digest, tenant, environment, operation_id, schema_version, endpoint_id,
    canonical_target, disclosure_fields, data_class, data_sources, bytes, limits, catalog_digest, catalog_version,
    canonicalization_version, action_digest, envelope, created_at)
VALUES ($1, $2, 'google:u1', 'user', $3, $4, $5, repeat('a', 64), 'hackathon', 'test', 'receiver.submit', '1', 'test-receiver-v1',
    '{"target_id": "receiver-primary", "route_id": "submissions-v1"}', '{summary}', 'synthetic', '{}', 0, '{}',
    $6, 'test', 'v1', $7, $8, now())`,
			actionID, envelope.RequestID, session, workload, "key-"+actionID, catalog, wActionD, string(envJSON))
		run(inspect, `INSERT INTO identity.approvals (approval_id, revision, approval_kind, action_id, authenticated_actor, session_id,
    contract_digest, displayed_contract_digest, allowed_operation, canonical_target, disclosure_fields,
    max_actions, policy_epoch, contract_version, created_at, expires_at)
VALUES ($1, 1, 'action', $2, 'google:u1', $3, repeat('d', 64), repeat('d', 64), 'receiver.submit', '{}', '{summary}', 1, $4, '1', now(), now() + interval '5 minutes')`,
			approvalID, actionID, session, epoch)
		run(inspect, `INSERT INTO decisions.decisions (decision_id, request_id, action_id, action_digest, adapter_id, verdict, reason_codes,
    decision_basis, approval_id, matched_rule_ids, evaluated_rule_ids, rego_result, decision_stage,
    decision_input_ref, decision_input_digest, policy_bundle_id, policy_epoch, opa_bundle_revision, catalog_digest,
    catalog_version, expires_at, authenticated_gateway, created_at)
VALUES ($1, $2, $3, $4, 'receiver', 'allow', '{}', 'approval', $5, '{approval.allow.v1}', '{approval.allow.v1}',
    '{"verdict": "allow"}', 'opa', $6, $6, 'bundle-1', $7, $8, $9, 'test', now() + interval '1 minute', 'gw', now())`,
			decisionID, requestID, actionID, wActionD, approvalID, input, epoch, wOPARev, catalog)
		return dispatch.ReserveRequest{DecisionID: decisionID, ActionID: actionID, RequestID: requestID, ActionDigest: wActionD,
			WireBodyDigest: strings.Repeat("b", 64), PolicyEpoch: epoch, CatalogDigest: catalog}
	}

	// The coordinator login.
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
	var super, createRole bool
	if err := pool.QueryRow(ctx, "SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user").Scan(&super, &createRole); err != nil || super || createRole {
		t.Fatalf("app login privileges: %v %v %v", super, createRole, err)
	}
	for _, denied := range []string{
		"SELECT 1 FROM release.active_policy",
		"UPDATE health.control_health_leases SET lease_until = now() + interval '1 hour'",
		"UPDATE health.holds SET released_at = now()",
		"SELECT 1 FROM health.holds FOR SHARE",
	} {
		if _, err := pool.Exec(ctx, denied); err == nil || !strings.Contains(err.Error(), "42501") {
			t.Fatalf("coordinator login allowed %q: %v", denied, err)
		}
	}

	c := full()
	c.environment, c.auditSourceID, c.auditSourceVersion = "test", "coordinator-test", "test-v1"
	svc, err := newService(pool, slog.New(slog.NewTextHandler(io.Discard, nil)), c, "1", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := hex.DecodeString(wSerial)
	san, _ := url.Parse(wAdapterSAN)
	adapter, err := svc.Authenticate(ctx, &x509.Certificate{SerialNumber: new(big.Int).SetBytes(serial), URIs: []*url.URL{san}})
	if err != nil {
		t.Fatal(err)
	}

	code := func(err error) string {
		var e *dispatch.Error
		if errors.As(err, &e) {
			return e.Code
		}
		if err == nil {
			return ""
		}
		return "untyped: " + err.Error()
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := inspect.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	denied := func(name string, req dispatch.ReserveRequest, want string) {
		t.Helper()
		before := count("SELECT count(*) FROM coordinator.reservations")
		events := count("SELECT count(*) FROM audit.audit_events")
		if _, err := svc.Reserve(ctx, adapter, req); code(err) != want {
			t.Fatalf("%s: %v, want %s", name, err, want)
		}
		if count("SELECT count(*) FROM coordinator.reservations") != before || count("SELECT count(*) FROM audit.audit_events") != events ||
			count("SELECT used_actions FROM identity.approvals WHERE action_id = $1", req.ActionID) != 0 {
			t.Fatalf("%s: a denied reservation left state behind", name)
		}
	}

	// All leases live, no hold, the active epoch and catalog: a permit, the
	// approval consumed and attempt_planned in audit_events, in one commit.
	req := newDecision(7, wCatalog)
	p, err := svc.Reserve(ctx, adapter, req)
	if err != nil {
		t.Fatalf("all live: %v", err)
	}
	if count("SELECT used_actions FROM identity.approvals WHERE action_id = $1", req.ActionID) != 1 {
		t.Fatal("approval not consumed")
	}
	var src, tenant, sess, action, attempt, epoch string
	if err := inspect.QueryRow(ctx, `SELECT source_id, tenant, session_id::text, action_id::text, attempt_id::text, source_epoch
FROM audit.audit_events WHERE event_type = 'attempt_planned'`).Scan(&src, &tenant, &sess, &action, &attempt, &epoch); err != nil {
		t.Fatal(err)
	}
	if src != "coordinator-test" || tenant != "hackathon" || sess != session || action != req.ActionID || attempt != p.AttemptID || epoch != "1" {
		t.Fatalf("attempt_planned: %s %s %s %s %s %s", src, tenant, sess, action, attempt, epoch)
	}
	if count("SELECT count(*) FROM audit.audit_outbox") == 0 {
		t.Fatal("no outbox row")
	}

	// A required lease expired: CONTROL_HEALTH_UNAVAILABLE, for every
	// required global component and for the target's destination-evidence.
	for _, l := range []struct{ component, scope, scopeID string }{
		{"coordinator", "global", "*"}, {"audit-export", "global", "*"}, {"node-readiness", "global", "*"},
		{"destination-evidence", "target", wTarget},
	} {
		setLease(l.component, l.scope, l.scopeID, -time.Second)
		denied("expired "+l.component, newDecision(7, wCatalog), "CONTROL_HEALTH_UNAVAILABLE")
		liveAll()
	}
	// The permit check reads the leases again: a lease that expires between
	// the reservation and the claim refuses the claim.
	req = newDecision(7, wCatalog)
	p, err = svc.Reserve(ctx, adapter, req)
	if err != nil {
		t.Fatal(err)
	}
	setLease("gateway", "global", "*", -time.Second)
	if _, err := svc.Check(ctx, adapter, p.PermitID, dispatch.CheckRequest{AttemptID: p.AttemptID, ActionDigest: p.ActionDigest,
		PolicyEpoch: p.PolicyEpoch, WireBodyDigest: p.WireBodyDigest}); code(err) != "CONTROL_HEALTH_UNAVAILABLE" {
		t.Fatalf("claim with an expired lease: %v", err)
	}
	liveAll()

	// An open policy_activation hold refuses a non-probe decision.
	hold := uuid.NewString()
	run(inspect, `INSERT INTO health.holds (hold_id, scope, scope_id, reason, owner_component, requested_by)
VALUES ($1, 'global', '*', 'policy_activation', 'releaser', 'test')`, hold)
	denied("policy_activation hold", newDecision(7, wCatalog), "HOLD_ACTIVE")
	run(inspect, `UPDATE health.holds SET released_at = now(), release_ref = 'test' WHERE hold_id = $1`, hold)

	// The active epoch moves on: a decision of the old epoch is stale.
	run(inspect, `UPDATE release.active_policy SET epoch = 8, updated_at = now() WHERE scope_id = 'test'`)
	denied("old epoch", newDecision(7, wCatalog), "POLICY_EPOCH_STALE")
	// A decision of the active epoch against another catalog.
	denied("other catalog", newDecision(8, wOther), "CATALOG_DIGEST_MISMATCH")
	// And with the active epoch and catalog it is allowed again.
	if _, err := svc.Reserve(ctx, adapter, newDecision(8, wCatalog)); err != nil {
		t.Fatalf("active epoch: %v", err)
	}

	// Another environment has no active_policy row.
	other := *svc
	other.Policy = dispatch.PGPolicy{Environment: "staging"}
	if _, err := other.Reserve(ctx, adapter, newDecision(8, wCatalog)); code(err) != "POLICY_UNAVAILABLE" {
		t.Fatalf("no active_policy: %v", err)
	}

	// An unregistered audit source rolls the reservation back.
	bad := *svc
	bad.Audit, err = dispatch.NewPGAuditor(dispatch.AuditConfig{SourceID: "not-registered", Version: "v", Epoch: "1"})
	if err != nil {
		t.Fatal(err)
	}
	req = newDecision(8, wCatalog)
	if _, err := bad.Reserve(ctx, adapter, req); code(err) != "STATE_STORE_UNAVAILABLE" {
		t.Fatalf("unregistered audit source: %v", err)
	}
	if count("SELECT used_actions FROM identity.approvals WHERE action_id = $1", req.ActionID) != 0 ||
		count("SELECT count(*) FROM coordinator.reservations WHERE action_id = $1", req.ActionID) != 0 {
		t.Fatal("audit failure left the reservation")
	}
}
