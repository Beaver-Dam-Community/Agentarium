//go:build integration

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/audit"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/bundle"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/bundle/bundletest"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/testpki"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
	"github.com/Beaver-Dam-Community/Agentarium/services/adapters/receiver-sender/internal/receiver"
)

const (
	wReceiverHost = "receiver.agent-targets.svc"
	wAdapterSAN   = "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender"
	wSource       = "receiver-sender-test"
	wBundleID     = "bundle-1"
	wTenant       = "hackathon"
)

// wKey is the receiver key (32 bytes, unpadded base64url) the fake receiver
// accepts and the fake broker gives for receiver-api-key.
var wKey = strings.Repeat("Q", 42) + "A"

var adapterEvents = []string{"preflight_passed", "preflight_rejected", "dispatch_started", "response_received", "attempt_uncertain", "attempt_failed"}

// The M3-1 receiver-sender wiring on PostgreSQL 16: every migration is
// installed by a non-superuser installer; the adapter runs as a restricted
// login that is a member of adapter_app (and through it adapter_reader and
// audit_producer, the TASK-16 install grants) with its adapter_db_roles and
// db_role_sources rows. The engine is the one newEngine builds for main: the
// postgres stored inputs, the adapter store, the bundle from desired_bundle
// through policyloader and the audit_append auditor. The coordinator, broker
// and receiver are fakes; the receiver enforces X-Agentarium-Receiver-Key.
//
// Needs a fresh, disposable cluster (roles are cluster-wide):
//
//	ADAPTER_WIRING_TEST_ADMIN_DSN=postgres://postgres@127.0.0.1:<port>/postgres?sslmode=disable \
//	  go test -tags integration -run TestWiredEnginePostgres ./services/adapters/receiver-sender
//
// tests/adapters/run-local.sh starts such a cluster.
func TestWiredEnginePostgres(t *testing.T) {
	dsn := os.Getenv("ADAPTER_WIRING_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable ADAPTER_WIRING_TEST_ADMIN_DSN")
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
	dbName, installer, app := "adwire_"+suffix, "adwireinst_"+suffix, "adwireapp_"+suffix
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
	files, err := filepath.Glob("../../../migrations/*.up.sql")
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
	// The two new migrations go down and up again cleanly.
	for _, f := range []string{"20261018123001_audit_adapter_membership.down.sql", "20261018123000_adapter_app_role.down.sql",
		"20261018123000_adapter_app_role.up.sql", "20261018123001_audit_adapter_membership.up.sql"} {
		raw, err := os.ReadFile("../../../migrations/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}

	// TASK-16 install inputs: membership, the adapter login mapping and the
	// audit source with its event grants.
	run(admin, "GRANT adapter_app TO "+app)
	run(owner, "INSERT INTO decisions.adapter_db_roles (db_role, adapter_id) VALUES ($1, 'receiver-sender')", app)
	inspect := connect(admin.Config().User)
	run(inspect, "INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES($1,$2,false)", app, wSource)
	for _, ev := range adapterEvents {
		run(inspect, "INSERT INTO audit.producer_event_grants VALUES($1,$2,$3)", wSource, ev, wTenant)
	}

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
		"DELETE FROM adapter.adapter_executions",
		"UPDATE adapter.action_results SET truncated = true",
		"UPDATE adapter.adapter_executions SET adapter_id = 'model'",
		"DELETE FROM adapter.pending_outcomes",
		"SELECT 1 FROM decisions.actions",
		"SELECT 1 FROM decisions.action_contents",
		"SELECT 1 FROM decisions.adapter_db_roles",
		"SELECT 1 FROM audit.audit_events",
		"INSERT INTO audit.audit_events (event_id) VALUES (gen_random_uuid())",
		"SELECT 1 FROM release.active_policy",
	} {
		if _, err := pool.Exec(ctx, denied); err == nil || !strings.Contains(err.Error(), "42501") {
			t.Fatalf("adapter login allowed %q: %v", denied, err)
		}
	}

	// Receiver, catalog and the signed bundle in desired_bundle.
	ca := testpki.NewCA(t, "agentarium-trust")
	recv := newWiredReceiver(t, ca)
	cat, err := canonical.LoadCatalogDir("../../../packages/canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	tg := cat.Targets["receiver-primary"]
	tg.Origin = "https://" + wReceiverHost + ":" + recv.port
	tg.AllowedCIDRs = []string{"127.0.0.0/8"}
	cat.Targets["receiver-primary"] = tg
	if cat.CatalogDigest, err = cat.ComputeDigest(); err != nil {
		t.Fatal(err)
	}
	signed := bundletest.Build(t, wBundleID, cat, map[string]any{
		"receiver": map[string]any{"allowed_disclosure_fields": []string{"summary"}},
		"adapter_constraints": map[string]any{"receiver-sender": map[string]any{
			"max_request_bytes": 65536, "max_response_bytes": 65536, "allowed_route_ids": []string{"submissions-v1"}}},
	})
	run(owner, `INSERT INTO release.desired_bundle(environment,bundle_id,artifact_digest,object_uri,set_by_change_id,set_at)
VALUES ('test',$1,$2,$3,gen_random_uuid(),now())`, signed.BundleID, signed.ArtifactDigest, signed.ObjectURI)
	fetcher := &bundletest.Fetcher{}
	fetcher.Put(signed)
	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	loader, err := newLoader(logger, pool, fetcher, "test", bundletest.KeyID, signed.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// The adapter login reads desired_bundle (adapter_reader) and verifies
	// the signed object.
	if err := loader.Poll(ctx); err != nil {
		t.Fatalf("bundle load as the adapter login: %v", err)
	}
	bundles := &bundle.Source{Loader: loader}
	if bundles.ArtifactDigest() != signed.ArtifactDigest {
		t.Fatal("lease active_version is not the loaded artifact digest")
	}

	coord := newWiredCoordinator(t, connect(admin.Config().User))
	broker := newWiredBroker(t)
	client := ca.Issue(t, nil, nil, []string{wAdapterSAN})
	podUID := uuid.NewString()
	build := func(source string) *execute.Engine {
		t.Helper()
		e, err := newEngine(ctx, deps{
			Pool: pool, Bundles: bundles,
			Audit:       auditConfig(source),
			Coordinator: &execute.HTTPCoordinator{BaseURL: coord.srv.URL, Client: coord.srv.Client()},
			Credentials: &execute.HTTPBroker{BaseURL: broker.srv.URL, Client: broker.srv.Client()},
			TLS:         wiredTLS{cert: client.TLS, pool: ca.Pool},
			Transport: transport.Config{Resolver: wiredResolver{wReceiverHost: {netip.MustParseAddr("127.0.0.1")}},
				Netns: func() *uint64 { v := uint64(4026531840); return &v }},
			PodUID: podUID, Logger: logger, CallTimeout: 5 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	engine := build(wSource)

	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := inspect.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	state := func(decisionID string) string {
		t.Helper()
		var s string
		if err := inspect.QueryRow(ctx, "SELECT state FROM adapter.adapter_executions WHERE decision_id = $1", decisionID).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	events := func(actionID string) []string {
		t.Helper()
		rows, err := inspect.Query(ctx, `SELECT event_type FROM audit.audit_events WHERE action_id = $1 ORDER BY received_at, event_type`, actionID)
		if err != nil {
			t.Fatal(err)
		}
		types, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(types)
		return types
	}
	exec := func(e *execute.Engine, f fixture) {
		t.Helper()
		if _, _, err := e.Submit(ctx, f.decisionID, f.actionID); err != nil {
			t.Fatal(err)
		}
		e.Wait()
	}
	newAction := func(expiresIn time.Duration) fixture {
		return putAction(t, ctx, inspect, cat, expiresIn)
	}

	// 1. Success: one send with the receiver key, the commit order in the
	// adapter tables and the adapter's events in audit_events, by its source.
	f := newAction(time.Minute)
	sends := recv.count.Load()
	exec(engine, f)
	if got := state(f.decisionID); got != execute.StateCompleted {
		t.Fatalf("success: state %s\n%s", got, logs)
	}
	if recv.count.Load() != sends+1 || recv.lastKey() != wKey {
		t.Fatal("success: not one send with the receiver key")
	}
	var attemptID, execState, evidence, dataClass string
	if err := inspect.QueryRow(ctx, `SELECT r.attempt_id::text, r.execution_state, r.evidence_level, r.data_class::text
FROM adapter.action_results r JOIN adapter.adapter_executions e ON e.attempt_id = r.attempt_id WHERE e.decision_id = $1`, f.decisionID).
		Scan(&attemptID, &execState, &evidence, &dataClass); err != nil {
		t.Fatal(err)
	}
	if attemptID != coord.attemptOf(f.actionID) || execState != "accepted" || evidence != "accepted" ||
		dataClass != cat.Operations[canonical.OpReceiverSubmit].ResponseDataClass {
		t.Fatalf("success: action_results %s %s %s %s", attemptID, execState, evidence, dataClass)
	}
	if count("SELECT count(*) FROM adapter.pending_outcomes WHERE attempt_id = $1 AND transition = 'response_received'", attemptID) != 1 ||
		count("SELECT count(*) FROM adapter.workload_data_state WHERE workload_id = 'agent-runtime-0' AND updated_by_attempt_id = $1", attemptID) != 1 {
		t.Fatal("success: pending_outcomes / workload_data_state rows missing")
	}
	if got := events(f.actionID); !slices.Equal(got, []string{"dispatch_started", "preflight_passed", "response_received"}) {
		t.Fatalf("success: events %v", got)
	}
	var src, tenant, epoch, session, workload string
	var attempts int
	if err := inspect.QueryRow(ctx, `SELECT min(source_id), min(tenant), min(source_epoch), min(session_id::text), min(workload_id),
    count(attempt_id) FROM audit.audit_events WHERE action_id = $1`, f.actionID).Scan(&src, &tenant, &epoch, &session, &workload, &attempts); err != nil {
		t.Fatal(err)
	}
	if src != wSource || tenant != wTenant || epoch != "7" || session != f.sessionID || workload != "agent-runtime-0" || attempts != 2 {
		t.Fatalf("success: audit rows %s %s %s %s %s %d", src, tenant, epoch, session, workload, attempts)
	}
	if count("SELECT count(*) FROM audit.audit_outbox o JOIN audit.audit_events e ON o.record_id = e.event_id::text WHERE e.action_id = $1", f.actionID) != 3 {
		t.Fatal("success: outbox rows")
	}
	if got := coord.transitions(attemptID); !slices.Equal(got, []string{"dispatched", "response_received"}) {
		t.Fatalf("success: coordinator transitions %v", got)
	}
	// A repeated execute for the same decision does nothing new.
	exec(engine, f)
	if recv.count.Load() != sends+1 || coord.reservations(f.actionID) != 1 {
		t.Fatal("success: replay did new work")
	}

	// 2. Missing audit grant: preflight_passed is refused by audit_append
	// (42501), nothing is reserved or sent and the row stays received.
	run(inspect, "DELETE FROM audit.producer_event_grants WHERE source_id = $1 AND event_type = 'preflight_passed'", wSource)
	f = newAction(time.Minute)
	sends = recv.count.Load()
	exec(engine, f)
	if state(f.decisionID) != execute.StateReceived || coord.reservations(f.actionID) != 0 || recv.count.Load() != sends || len(events(f.actionID)) != 0 {
		t.Fatalf("missing audit grant: state %s reservations %d", state(f.decisionID), coord.reservations(f.actionID))
	}
	run(inspect, "INSERT INTO audit.producer_event_grants VALUES($1,'preflight_passed',$2)", wSource, wTenant)
	// After the grant the restart correction completes it, with the stored
	// preflight_passed event_id.
	if err := engine.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	engine.Wait()
	if state(f.decisionID) != execute.StateCompleted || recv.count.Load() != sends+1 {
		t.Fatalf("missing audit grant, after the grant: state %s", state(f.decisionID))
	}

	// 3. An unregistered audit source: refused the same way.
	f = newAction(time.Minute)
	exec(build("not-registered"), f)
	if state(f.decisionID) != execute.StateReceived || coord.reservations(f.actionID) != 0 {
		t.Fatal("unregistered audit source reserved")
	}
	if err := engine.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	engine.Wait()

	// 4. Expired decision: the coordinator refuses the reservation
	// (DECISION_EXPIRED); the execution fails, no credential, no send.
	f = newAction(-time.Second)
	sends, resolves := recv.count.Load(), broker.calls.Load()
	exec(engine, f)
	if state(f.decisionID) != execute.StateFailed || recv.count.Load() != sends || broker.calls.Load() != resolves {
		t.Fatalf("expired decision: state %s", state(f.decisionID))
	}
	if got := events(f.actionID); !slices.Equal(got, []string{"preflight_passed"}) {
		t.Fatalf("expired decision: events %v", got)
	}

	// 5. Expired permit at the claim: released with PERMIT_INVALID, nothing sent.
	coord.expirePermits.Store(true)
	f = newAction(time.Minute)
	sends = recv.count.Load()
	exec(engine, f)
	coord.expirePermits.Store(false)
	if state(f.decisionID) != execute.StateFailed || recv.count.Load() != sends {
		t.Fatalf("expired permit: state %s", state(f.decisionID))
	}
	if got := coord.transitions(coord.attemptOf(f.actionID)); !slices.Equal(got, []string{"released:PERMIT_INVALID"}) {
		t.Fatalf("expired permit: transitions %v", got)
	}

	// 6. Missing broker grant (attempt_credential_scope refuses, 403): released
	// with CREDENTIAL_UNAVAILABLE before the claim, nothing sent.
	broker.mode.Store("forbidden")
	f = newAction(time.Minute)
	sends = recv.count.Load()
	exec(engine, f)
	if state(f.decisionID) != execute.StateFailed || recv.count.Load() != sends || coord.claimed(f.actionID) {
		t.Fatalf("missing broker grant: state %s", state(f.decisionID))
	}
	if got := coord.transitions(coord.attemptOf(f.actionID)); !slices.Equal(got, []string{"released:CREDENTIAL_UNAVAILABLE"}) {
		t.Fatalf("missing broker grant: transitions %v", got)
	}

	// 7. Key absent: a binding without the receiver key header is refused
	// before the claim; the receiver never sees the request.
	broker.mode.Store("no-key")
	f = newAction(time.Minute)
	sends = recv.count.Load()
	exec(engine, f)
	if state(f.decisionID) != execute.StateFailed || recv.count.Load() != sends || coord.claimed(f.actionID) {
		t.Fatalf("key absent: state %s", state(f.decisionID))
	}
	if got := coord.transitions(coord.attemptOf(f.actionID)); !slices.Equal(got, []string{"released:CREDENTIAL_UNAVAILABLE"}) {
		t.Fatalf("key absent: transitions %v", got)
	}

	// 8. Key the receiver rejects (wrong secret): 401 RECEIVER_KEY_INVALID is
	// a received response, recorded as failed/TARGET_REJECTED. One send, no
	// retry, also not on restart.
	broker.mode.Store("wrong-key")
	f = newAction(time.Minute)
	sends = recv.count.Load()
	exec(engine, f)
	if err := engine.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	engine.Wait()
	attemptID = coord.attemptOf(f.actionID)
	if state(f.decisionID) != execute.StateCompleted || recv.count.Load() != sends+1 || recv.rejected.Load() == 0 {
		t.Fatalf("rejected key: state %s sends %d", state(f.decisionID), recv.count.Load()-sends)
	}
	if count("SELECT count(*) FROM adapter.action_results WHERE attempt_id = $1 AND execution_state = 'failed' AND evidence_level = 'none'", attemptID) != 1 {
		t.Fatal("rejected key: action_results")
	}
	if got := coord.transitions(attemptID); !slices.Equal(got, []string{"dispatched", "response_received:TARGET_REJECTED"}) {
		t.Fatalf("rejected key: transitions %v", got)
	}
	var status int
	if err := inspect.QueryRow(ctx, `SELECT (safe_payload->>'status_code')::int FROM audit.audit_events
WHERE action_id = $1 AND event_type = 'response_received'`, f.actionID).Scan(&status); err != nil || status != 401 {
		t.Fatalf("rejected key: response_received status %d %v", status, err)
	}
	broker.mode.Store("")

	// A replay after a restart (new epoch, same event_id): audit_append
	// answers conflict; the incident is recorded and the event counts as
	// recorded. An action this login cannot see has no trusted tenant.
	var replayID, replayAction string
	var replayPayload map[string]any
	if err := inspect.QueryRow(ctx, `SELECT event_id::text, action_id::text, safe_payload FROM audit.audit_events
WHERE source_id = $1 AND event_type = 'preflight_passed' ORDER BY received_at LIMIT 1`, wSource).Scan(&replayID, &replayAction, &replayPayload); err != nil {
		t.Fatal(err)
	}
	restarted, err := audit.New(pool, audit.Config{SourceID: wSource, Version: "test-v1", Epoch: "8"})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Emit(ctx, execute.Event{EventID: replayID, Type: "preflight_passed", ActionID: replayAction, Payload: replayPayload}); err != nil {
		t.Fatalf("replayed event: %v", err)
	}
	if count("SELECT count(*) FROM audit.event_conflicts WHERE record_id = $1 AND source_id = $2", replayID, wSource) != 1 ||
		count("SELECT count(*) FROM audit.audit_events WHERE event_id = $1 AND source_epoch = '7'", replayID) != 1 {
		t.Fatal("replayed event: conflict not recorded or original changed")
	}
	if err := restarted.Emit(ctx, execute.Event{EventID: uuid.NewString(), Type: "preflight_passed", ActionID: uuid.NewString(),
		Payload: replayPayload}); err == nil {
		t.Fatal("event for an action the adapter cannot see")
	}

	// The receiver key is in no log line and no audit or adapter row.
	if strings.Contains(logs.String(), wKey) || strings.Contains(logs.String(), wrongKey) {
		t.Fatal("receiver key in the adapter log")
	}
	for _, q := range []string{"SELECT count(*) FROM audit.audit_events WHERE safe_payload::text LIKE '%' || $1 || '%'",
		"SELECT count(*) FROM adapter.pending_outcomes WHERE (observation::text || coalesce(event::text,'') || coalesce(result::text,'')) LIKE '%' || $1 || '%'"} {
		for _, k := range []string{wKey, wrongKey} {
			if count(q, k) != 0 {
				t.Fatal("receiver key stored")
			}
		}
	}
}

var wrongKey = strings.Repeat("w", 42) + "A"

func auditConfig(source string) audit.Config {
	return audit.Config{SourceID: source, Version: "test-v1", Epoch: "7"}
}

type fixture struct{ decisionID, actionID, sessionID string }

// putAction stores a receiver.submit action, its content and an allow
// decision as the gateway's decision transaction does.
func putAction(t *testing.T, ctx context.Context, db *pgx.Conn, cat canonical.Catalog, expiresIn time.Duration) fixture {
	t.Helper()
	w := "agent-runtime-0"
	actionID, sessionID, decisionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	raw := `{"session_id":"` + sessionID + `","operation_id":"receiver.submit","requested_target":{"target_id":"receiver-primary"},"arguments":{"payload":{"summary":"synthetic ` + actionID + `","email":null}},"client_request_key":"req-00000001"}`
	env, content, nerr := canonical.NormalizeRaw([]byte(raw), canonical.TrustedContext{
		ActionID: actionID, RequestID: uuid.NewString(), AuthenticatedActor: "user:alice@example.com", SessionKind: "user",
		SessionID: sessionID, WorkloadID: &w, Tenant: wTenant, Environment: "test",
	}, cat)
	if nerr != nil {
		t.Fatal(nerr)
	}
	js := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	input := strings.Repeat("f", 64)
	err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO decisions.actions (action_id, request_id, authenticated_actor, session_kind, session_id, workload_id,
    client_request_key, raw_body_digest, tenant, environment, operation_id, schema_version, endpoint_id,
    canonical_target, disclosure_fields, data_class, data_sources, content_digest, content_ref, bytes, limits,
    catalog_digest, catalog_version, canonicalization_version, action_digest, envelope, created_at)
VALUES ($1, $2, $3, $4, $5, $6, 'req-00000001', $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
    $21, $22, $23, $24, $25, statement_timestamp())`,
				[]any{env.ActionID, env.RequestID, env.AuthenticatedActor, env.SessionKind, env.SessionID, env.WorkloadID,
					env.RawBodyDigest, env.Tenant, env.Environment, env.OperationID, env.SchemaVersion, env.EndpointID,
					js(env.CanonicalTarget), env.DisclosureFields, env.DataClass, env.DataSources, env.ContentDigest,
					env.ContentRef, env.Bytes, js(env.Limits), env.CatalogDigest, env.CatalogVersion,
					env.CanonicalizationVersion, env.ActionDigest, js(env)}},
			{`INSERT INTO decisions.action_contents (content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)
VALUES ($1, $2, $3, 'receiver-sender', $4, statement_timestamp(), statement_timestamp() + interval '30 days')`,
				[]any{content.ContentDigest, content.Tenant, content.ActionID, content.ContentBytes}},
			{`INSERT INTO decisions.decision_inputs VALUES ($1, 'hackathon', '{}', $2, statement_timestamp()) ON CONFLICT DO NOTHING`,
				[]any{input, wBundleID}},
			{`INSERT INTO decisions.decisions (decision_id, request_id, action_id, action_digest, adapter_id, verdict, reason_codes,
    decision_basis, approval_id, matched_rule_ids, evaluated_rule_ids, rego_result, decision_stage,
    decision_input_ref, decision_input_digest, policy_bundle_id, policy_epoch, opa_bundle_revision, catalog_digest,
    catalog_version, expires_at, authenticated_gateway, created_at)
VALUES ($1, $2, $3, $4, 'receiver-sender', 'allow', '{}', 'approval', gen_random_uuid(), '{approval.allow.v1}', '{approval.allow.v1}',
    '{"verdict": "allow"}', 'opa', $5, $5, $6, 7, 'rev-1', $7, $8, statement_timestamp() + make_interval(secs => $9),
    'gw', statement_timestamp() - interval '2 seconds')`,
				[]any{decisionID, env.RequestID, env.ActionID, env.ActionDigest, input, wBundleID, env.CatalogDigest, env.CatalogVersion, expiresIn.Seconds()}},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return fmt.Errorf("%.60s: %w", s.sql, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{decisionID: decisionID, actionID: actionID, sessionID: sessionID}
}

// ---- fakes -------------------------------------------------------------------

type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type wiredTLS struct {
	cert tls.Certificate
	pool *x509.CertPool
}

func (m wiredTLS) ClientCertificate() (*tls.Certificate, error) { c := m.cert; return &c, nil }
func (m wiredTLS) RootCAs(ref string) (*x509.CertPool, error) {
	if ref != "agentarium-trust" {
		return nil, fmt.Errorf("unexpected ca_ref %s", ref)
	}
	return m.pool, nil
}

type wiredResolver map[string][]netip.Addr

func (r wiredResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// wiredReceiver is the TASK-08 receiver front: mTLS with the adapter SAN,
// then the receiver key (401 RECEIVER_KEY_INVALID), then a 201 receipt.
type wiredReceiver struct {
	port     string
	count    atomic.Int32
	rejected atomic.Int32
	mu       sync.Mutex
	keys     []string
}

func (r *wiredReceiver) lastKey() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.keys[len(r.keys)-1]
}

func newWiredReceiver(t *testing.T, ca *testpki.CA) *wiredReceiver {
	r := &wiredReceiver{}
	leaf := ca.Issue(t, []string{wReceiverHost}, nil, nil)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.count.Add(1)
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.keys = append(r.keys, req.Header.Get(receiver.KeyHeader))
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if req.Method != http.MethodPost || req.URL.Path != "/test/v1/submissions" ||
			len(req.TLS.PeerCertificates) == 0 || req.TLS.PeerCertificates[0].URIs[0].String() != wAdapterSAN {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"reason_codes":["AUTH_REQUIRED"]}`)
			return
		}
		if req.Header.Get(receiver.KeyHeader) != wKey {
			r.rejected.Add(1)
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"reason_codes":["RECEIVER_KEY_INVALID"]}`)
			return
		}
		w.WriteHeader(201)
		_, _ = fmt.Fprintf(w, `{"receipt_attempt_id":%q,"effect_id":%q,"action_key":%q,"wire_body_digest":%q,"body_bytes":%d}`,
			uuid.NewString(), uuid.NewString(), req.Header.Get("Idempotency-Key"), canonical.SHA256Hex(body), len(body))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf.TLS}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.Pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, r.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	return r
}

// wiredBroker is POST /internal/credentials:resolve. mode "" gives the
// receiver key, "forbidden" answers 403 (no attempt_credential_scope grant),
// "no-key" a binding with another header, "wrong-key" a key the receiver
// does not accept.
type wiredBroker struct {
	srv   *httptest.Server
	calls atomic.Int32
	mode  atomic.Value
}

func newWiredBroker(t *testing.T) *wiredBroker {
	b := &wiredBroker{}
	b.mode.Store("")
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.calls.Add(1)
		var in struct {
			AttemptID         string `json:"attempt_id"`
			AdapterID         string `json:"adapter_id"`
			CredentialBinding string `json:"credential_binding"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/internal/credentials:resolve" || in.AdapterID != "receiver-sender" || in.CredentialBinding != "receiver-api-key" ||
			b.mode.Load() == "forbidden" {
			w.WriteHeader(403)
			_, _ = io.WriteString(w, `{"reason_codes":["CREDENTIAL_UNAVAILABLE"]}`)
			return
		}
		header, value := receiver.KeyHeader, wKey
		switch b.mode.Load() {
		case "no-key":
			header, value = "Authorization", "Bearer "+wKey
		case "wrong-key":
			value = wrongKey
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"secret_version": "3", "header_name": header, "header_value": value,
			"expires_at": time.Now().Add(time.Minute).UTC()})
	}))
	t.Cleanup(b.srv.Close)
	return b
}

// wiredCoordinator is the TASK-03 dispatch API: it refuses a reservation of
// an expired decision (read from decisions.decisions), and with
// expirePermits refuses the claim as an expired permit.
type wiredCoordinator struct {
	srv           *httptest.Server
	db            *pgx.Conn
	expirePermits atomic.Bool

	mu       sync.Mutex
	byAction map[string]execute.Permit
	reserved map[string]int
	claims   map[string]bool
	outcomes map[string][]string
}

func newWiredCoordinator(t *testing.T, db *pgx.Conn) *wiredCoordinator {
	c := &wiredCoordinator{db: db, byAction: map[string]execute.Permit{}, reserved: map[string]int{}, claims: map[string]bool{}, outcomes: map[string][]string{}}
	mux := http.NewServeMux()
	fail := func(w http.ResponseWriter, status int, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"reason_codes": []string{code}})
	}
	var dbMu sync.Mutex
	mux.HandleFunc("POST /internal/dispatch/reservations", func(w http.ResponseWriter, r *http.Request) {
		var req execute.ReserveRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			fail(w, 400, "SCHEMA_INVALID")
			return
		}
		var expired bool
		dbMu.Lock()
		err := c.db.QueryRow(r.Context(), "SELECT expires_at <= statement_timestamp() FROM decisions.decisions WHERE decision_id = $1", req.DecisionID).Scan(&expired)
		dbMu.Unlock()
		if err != nil {
			fail(w, 409, "PERMIT_INVALID")
			return
		}
		if expired {
			fail(w, 409, "DECISION_EXPIRED")
			return
		}
		p := execute.Permit{PermitID: uuid.NewString(), DecisionID: req.DecisionID, ActionID: req.ActionID, RequestID: req.RequestID,
			AttemptID: uuid.NewString(), ReservationID: uuid.NewString(), AdapterID: "receiver-sender", ActionDigest: req.ActionDigest,
			WireBodyDigest: req.WireBodyDigest, PolicyEpoch: req.PolicyEpoch, CatalogDigest: req.CatalogDigest, ExpiresAt: time.Now().Add(10 * time.Second)}
		c.mu.Lock()
		c.byAction[req.ActionID] = p
		c.reserved[req.ActionID]++
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(p)
	})
	mux.HandleFunc("POST /internal/dispatch/permits/{permit_id}/check", func(w http.ResponseWriter, r *http.Request) {
		var req execute.CheckRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if c.expirePermits.Load() {
			fail(w, 409, "PERMIT_INVALID")
			return
		}
		c.mu.Lock()
		c.claims[req.AttemptID] = true
		c.mu.Unlock()
		_ = json.NewEncoder(w).Encode(execute.CheckResult{ExecutionAllowed: true})
	})
	mux.HandleFunc("POST /internal/dispatch/attempts/{attempt_id}/outcome", func(w http.ResponseWriter, r *http.Request) {
		var req execute.OutcomeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		rec := req.Transition
		if len(req.ReasonCodes) > 0 {
			rec += ":" + strings.Join(req.ReasonCodes, ",")
		}
		c.mu.Lock()
		c.outcomes[r.PathValue("attempt_id")] = append(c.outcomes[r.PathValue("attempt_id")], rec)
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	})
	c.srv = httptest.NewServer(mux)
	t.Cleanup(c.srv.Close)
	return c
}

func (c *wiredCoordinator) attemptOf(actionID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byAction[actionID].AttemptID
}

func (c *wiredCoordinator) reservations(actionID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reserved[actionID]
}

func (c *wiredCoordinator) claimed(actionID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.claims[c.byAction[actionID].AttemptID]
}

func (c *wiredCoordinator) transitions(attemptID string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.outcomes[attemptID]...)
}
