//go:build integration

// Package gateway holds the TASK-04 schema tests: the decisions schema
// constraints, the immutability of decisions and the role grants
// (migration 20261016181826_gateway_decisions).
//
//	DATABASE_URL=postgres://... go test -tags integration ./tests/gateway/
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

var migrated sync.Once

func admin(t *testing.T) *pgxpool.Pool {
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
	migrated.Do(func() {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('decisions.decisions') IS NOT NULL`).Scan(&exists); err != nil || exists {
			return
		}
		if _, err := pool.Exec(ctx, `DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF;
        END $$`); err != nil {
			t.Fatal(err)
		}
		files, _ := filepath.Glob("../../migrations/*.up.sql")
		sort.Strings(files)
		for _, f := range files {
			b, _ := os.ReadFile(f)
			if _, err := pool.Exec(ctx, string(b)); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	})
	if _, err := pool.Exec(ctx, `
TRUNCATE decisions.execute_requests, decisions.intent_checks, decisions.decisions, decisions.decision_inputs,
    decisions.action_contents, decisions.actions CASCADE`); err != nil {
		t.Fatal(err)
	}
	return pool
}

func asRole(t *testing.T, role string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+role)
		return err
	}
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// adapterLogin creates a LOGIN role that is a member of adapter_reader, maps
// it to adapterID in decisions.adapter_db_roles (no mapping when adapterID is
// empty) and returns a pool that logs in as it, so session_user is that role
// as for an adapter's Cloud SQL IAM user. With setRole the pool also runs
// SET ROLE adapter_reader on each connection. The role and its mapping are
// removed at cleanup.
func adapterLogin(t *testing.T, a *pgxpool.Pool, adapterID string, setRole bool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	role := "gwtest_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	password := uuid.NewString()
	if _, err := a.Exec(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD '`+password+`' IN ROLE adapter_reader`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		a.Exec(ctx, `DELETE FROM decisions.adapter_db_roles WHERE db_role = $1`, role)
		if _, err := a.Exec(ctx, `DROP ROLE `+role); err != nil {
			t.Errorf("drop %s: %v", role, err)
		}
	})
	if adapterID != "" {
		if _, err := a.Exec(ctx, `INSERT INTO decisions.adapter_db_roles (db_role, adapter_id) VALUES ($1, $2)`, role, adapterID); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.ConnConfig.Password = role, password
	if setRole {
		cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, err := c.Exec(ctx, "SET ROLE adapter_reader")
			return err
		}
	}
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var who string
	if err := p.QueryRow(ctx, `SELECT session_user`).Scan(&who); err != nil || who != role {
		t.Fatalf("session_user %q %v", who, err)
	}
	return p
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// insertAction stores env as the gateway does: the typed columns and the
// envelope jsonb (json.Marshal of canonical.ActionEnvelope); see putAction.
const insertAction = `
INSERT INTO decisions.actions (action_id, request_id, authenticated_actor, session_kind, session_id, workload_id,
    client_request_key, raw_body_digest, tenant, environment, operation_id, schema_version, endpoint_id,
    canonical_target, disclosure_fields, data_class, data_sources, content_digest, content_ref, bytes, limits,
    catalog_digest, catalog_version, canonicalization_version, action_digest, envelope, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21,
    $22, $23, $24, $25, $26, now())`

const (
	insertInput = `
INSERT INTO decisions.decision_inputs (decision_input_digest, tenant, sanitized_input, policy_bundle_id, created_at)
VALUES (repeat('f', 64), 'hackathon', '{}', 'bundle-1', now()) ON CONFLICT DO NOTHING`
	// $1 decision_id, $2 action_id, $3 verdict, $4 reason_codes, $5 decision_basis, $6 approval_id,
	// $7 decision_stage, $8 decision_input_ref, $9 adapter_id, $10 rego_result, $11 opa_bundle_revision
	insertDecision = `
INSERT INTO decisions.decisions (decision_id, request_id, action_id, action_digest, adapter_id, verdict, reason_codes,
    decision_basis, approval_id, matched_rule_ids, evaluated_rule_ids, rego_result, decision_stage,
    decision_input_ref, decision_input_digest, policy_bundle_id, policy_epoch, opa_bundle_revision, catalog_digest,
    catalog_version, expires_at, authenticated_gateway, created_at)
VALUES ($1, gen_random_uuid(), $2, repeat('e', 64), $9, $3, $4, $5, $6, '{x.y.v1}', '{x.y.v1}', $10, $7,
    $8, $8, 'bundle-1', 7, $11, repeat('d', 64), 'test', now() + interval '10 seconds', 'gw', now())`
)

type dec struct {
	verdict  string
	codes    []string
	basis    any
	approval any
	stage    string
	input    any
	adapter  any
	rego     any
	revision any
}

func okAllow() dec {
	return dec{"allow", []string{}, "approval", uuid.NewString(), "opa", strings.Repeat("f", 64), "receiver", `{"verdict": "allow"}`, "rev-7"}
}

func (d dec) insert(ctx context.Context, p *pgxpool.Pool, actionID string) error {
	_, err := p.Exec(ctx, insertDecision, uuid.NewString(), actionID, d.verdict, d.codes, d.basis, d.approval,
		d.stage, d.input, d.adapter, d.rego, d.revision)
	return err
}

// testEnvelope is a user-session receiver.submit envelope with content
// digest c..c.
func testEnvelope() canonical.ActionEnvelope {
	workload := "agent-exec/agent-runtime"
	digest := strings.Repeat("c", 64)
	return canonical.ActionEnvelope{
		SchemaVersion:           "1",
		ActionID:                uuid.NewString(),
		RequestID:               uuid.NewString(),
		AuthenticatedActor:      "google:alice",
		SessionKind:             "user",
		SessionID:               uuid.NewString(),
		WorkloadID:              &workload,
		EndpointID:              "test-receiver-v1",
		OperationID:             "receiver.submit",
		CanonicalTarget:         canonical.CanonicalTarget{TargetID: "receiver-primary", RouteID: "submissions-v1"},
		Environment:             "test",
		Tenant:                  "hackathon",
		DisclosureFields:        []string{"summary"},
		DataClass:               "synthetic",
		DataSources:             []string{},
		ContentDigest:           &digest,
		ContentRef:              &digest,
		Bytes:                   12,
		Limits:                  map[string]int64{},
		CatalogDigest:           strings.Repeat("d", 64),
		CatalogVersion:          "test",
		CanonicalizationVersion: "v1",
		RawBodyDigest:           strings.Repeat("a", 64),
		ActionDigest:            strings.Repeat("e", 64),
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// putAction inserts env with client_request_key key. envelope overrides the
// stored envelope jsonb when not nil.
func putAction(ctx context.Context, t *testing.T, p *pgxpool.Pool, env canonical.ActionEnvelope, key string, envelope any) error {
	t.Helper()
	if envelope == nil {
		envelope = mustJSON(t, env)
	}
	_, err := p.Exec(ctx, insertAction, env.ActionID, env.RequestID, env.AuthenticatedActor, env.SessionKind, env.SessionID,
		env.WorkloadID, key, env.RawBodyDigest, env.Tenant, env.Environment, env.OperationID, env.SchemaVersion,
		env.EndpointID, mustJSON(t, env.CanonicalTarget), env.DisclosureFields, env.DataClass, env.DataSources,
		env.ContentDigest, env.ContentRef, env.Bytes, mustJSON(t, env.Limits), env.CatalogDigest, env.CatalogVersion,
		env.CanonicalizationVersion, env.ActionDigest, envelope)
	return err
}

// newEnvAction stores env (key derived from its action_id) and the shared
// decision input.
func newEnvAction(t *testing.T, p *pgxpool.Pool, env canonical.ActionEnvelope) string {
	t.Helper()
	ctx := context.Background()
	if err := putAction(ctx, t, p, env, "key-"+env.ActionID[:8], nil); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, insertInput); err != nil {
		t.Fatal(err)
	}
	return env.ActionID
}

func newAction(t *testing.T, p *pgxpool.Pool) string {
	t.Helper()
	return newEnvAction(t, p, testEnvelope())
}

func TestDecisionConstraints(t *testing.T) {
	ctx := context.Background()
	a := admin(t)
	gw := asRole(t, "gateway_app")
	aid := newAction(t, gw)

	if err := okAllow().insert(ctx, gw, aid); err != nil {
		t.Fatalf("valid allow: %v", err)
	}
	normalize := dec{"deny", []string{"CONTENT_PATTERN_DENIED"}, nil, nil, "normalize", nil, nil, nil, nil}
	if err := normalize.insert(ctx, gw, aid); err != nil {
		t.Fatalf("valid normalize deny: %v", err)
	}

	bad := map[string]func(d *dec){
		"allow without basis":         func(d *dec) { d.basis = nil },
		"deny with basis":             func(d *dec) { d.verdict, d.codes = "deny", []string{"HOLD_ACTIVE"} },
		"approval basis without id":   func(d *dec) { d.approval = nil },
		"allow without adapter":       func(d *dec) { d.adapter = nil },
		"opa without input ref":       func(d *dec) { d.input = nil },
		"opa without rego result":     func(d *dec) { d.rego = nil },
		"opa without revision":        func(d *dec) { d.revision = nil },
		"normalize allow":             func(d *dec) { d.stage = "normalize"; d.input = nil; d.rego = nil; d.revision = nil },
		"unknown verdict":             func(d *dec) { d.verdict = "permit" },
		"deny without codes":          func(d *dec) { d.verdict, d.basis, d.approval = "deny", nil, nil },
		"unknown basis":               func(d *dec) { d.basis = "operator" },
		"input ref to missing input":  func(d *dec) { d.input = strings.Repeat("0", 64) },
		"unknown stage":               func(d *dec) { d.stage = "intent" },
		"service basis without id":    func(d *dec) { d.basis, d.approval = "service_scope", nil },
		"standing basis without rule": func(d *dec) { d.basis, d.approval = "standing_rule", nil },
		"probe basis without probe":   func(d *dec) { d.basis, d.approval = "activation_probe", nil },
	}
	for name, mod := range bad {
		d := okAllow()
		mod(&d)
		if err := d.insert(ctx, gw, aid); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// The same (actor, session, client_request_key) is one action.
	var sess, key string
	if err := a.QueryRow(ctx, `SELECT session_id::text, client_request_key FROM decisions.actions WHERE action_id = $1`, aid).Scan(&sess, &key); err != nil {
		t.Fatal(err)
	}
	again := testEnvelope()
	again.SessionID = sess
	if err := putAction(ctx, t, gw, again, key, nil); pgCode(err) != "23505" {
		t.Errorf("duplicate client_request_key: %v", err)
	}
	if err := putAction(ctx, t, gw, again, "bad key!", nil); pgCode(err) != "23514" {
		t.Errorf("malformed client_request_key: %v", err)
	}
}

func TestDecisionsAreImmutable(t *testing.T) {
	ctx := context.Background()
	a := admin(t)
	gw := asRole(t, "gateway_app")
	aid := newAction(t, gw)
	if err := okAllow().insert(ctx, gw, aid); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Exec(ctx, `UPDATE decisions.decisions SET verdict = 'deny'`); pgCode(err) != "42501" {
		t.Errorf("gateway_app UPDATE decisions: %v", err)
	}
	if _, err := gw.Exec(ctx, `DELETE FROM decisions.decisions`); pgCode(err) != "42501" {
		t.Errorf("gateway_app DELETE decisions: %v", err)
	}
	if _, err := gw.Exec(ctx, `UPDATE decisions.actions SET raw_body_digest = repeat('b', 64)`); pgCode(err) != "42501" {
		t.Errorf("gateway_app UPDATE actions: %v", err)
	}
	// Even the owner cannot rewrite a decision.
	if _, err := a.Exec(ctx, `UPDATE decisions.decisions SET verdict = 'deny', reason_codes = '{HOLD_ACTIVE}', decision_basis = NULL, approval_id = NULL`); err == nil ||
		!strings.Contains(err.Error(), "immutable") {
		t.Errorf("owner UPDATE decisions: %v", err)
	}
}

func TestExecuteRequestGrants(t *testing.T) {
	ctx := context.Background()
	admin(t)
	gw := asRole(t, "gateway_app")
	aid := newAction(t, gw)
	did := uuid.NewString()
	d := okAllow()
	if _, err := gw.Exec(ctx, insertDecision, did, aid, d.verdict, d.codes, d.basis, d.approval, d.stage, d.input, d.adapter, d.rego, d.revision); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Exec(ctx, `
INSERT INTO decisions.execute_requests (decision_id, action_id, adapter_id, state, next_attempt_at, updated_at)
VALUES ($1, $2, 'receiver', 'pending', now(), now())`, did, aid); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Exec(ctx, `
UPDATE decisions.execute_requests SET state = 'delivered', attempts = attempts + 1, lease_until = NULL, updated_at = now()
WHERE decision_id = $1`, did); err != nil {
		t.Errorf("state update: %v", err)
	}
	if _, err := gw.Exec(ctx, `UPDATE decisions.execute_requests SET adapter_id = 'model'`); pgCode(err) != "42501" {
		t.Errorf("adapter_id update: %v", err)
	}
	if _, err := gw.Exec(ctx, `UPDATE decisions.execute_requests SET state = 'done'`); pgCode(err) != "23514" {
		t.Errorf("unknown state: %v", err)
	}
	// The coordinator reads decisions and actions and writes nothing here.
	co := asRole(t, "coordinator_app")
	if _, err := co.Exec(ctx, `SELECT 1 FROM decisions.decisions`); err != nil {
		t.Errorf("coordinator_app read: %v", err)
	}
	for _, q := range []string{
		`SELECT 1 FROM decisions.actions`,
		`SELECT 1 FROM decisions.action_contents`,
		`SELECT 1 FROM decisions.execute_requests`,
		`DELETE FROM decisions.actions`,
	} {
		if _, err := co.Exec(ctx, q); pgCode(err) != "42501" {
			t.Errorf("coordinator_app %s: %v", q, err)
		}
	}
}

func TestViews(t *testing.T) {
	ctx := context.Background()
	a := admin(t)
	gw := asRole(t, "gateway_app")
	aid := newAction(t, gw)
	content := `{"summary":"short"}`
	if _, err := gw.Exec(ctx, `
INSERT INTO decisions.action_contents (content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)
VALUES (repeat('c', 64), 'hackathon', $1, 'receiver', $2, now(), now() + interval '30 days')`, aid, []byte(content)); err != nil {
		t.Fatal(err)
	}
	var text string
	var cut bool
	if err := a.QueryRow(ctx, `SELECT preview_text, truncated FROM decisions.action_content_previews`).Scan(&text, &cut); err != nil || text != content || cut {
		t.Fatalf("preview %q %v %v", text, cut, err)
	}
	var target string
	if err := a.QueryRow(ctx, `SELECT canonical_target->>'target_id' FROM decisions.actions_target_view WHERE action_id = $1`, aid).Scan(&target); err != nil || target != "receiver-primary" {
		t.Fatalf("actions_target_view %q %v", target, err)
	}
	// Only content of an action evaluated at data class none (nothing read
	// yet) or synthetic has a preview: internal and confidential do not.
	for i, class := range []string{"none", "internal", "confidential"} {
		env := testEnvelope()
		digest := strings.Repeat(string(rune('6'+i)), 64)
		env.DataClass, env.ContentDigest, env.ContentRef = class, &digest, &digest
		other := newEnvAction(t, gw, env)
		if _, err := gw.Exec(ctx, `
INSERT INTO decisions.action_contents (content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)
VALUES ($2, 'hackathon', $1, 'receiver', '{"summary":"not synthetic"}', now(), now() + interval '30 days')`, other, digest); err != nil {
			t.Fatal(err)
		}
		var shown int
		want := 0
		if class == "none" {
			want = 1
		}
		if err := a.QueryRow(ctx, `SELECT count(*) FROM decisions.action_content_previews WHERE content_digest = $1`, digest).Scan(&shown); err != nil || shown != want {
			t.Errorf("%s content preview rows: %d, want %d %v", class, shown, want, err)
		}
	}

	// An action without an envelope (normalize-stage rejection) is not in the
	// target view.
	bare := uuid.NewString()
	if _, err := gw.Exec(ctx, `
INSERT INTO decisions.actions (action_id, request_id, authenticated_actor, session_kind, session_id, workload_id,
    client_request_key, raw_body_digest, tenant, environment, operation_id, created_at)
VALUES ($1, gen_random_uuid(), 'google:alice', 'user', gen_random_uuid(), 'agent-exec/agent-runtime', 'bare-key-1',
    repeat('a', 64), 'hackathon', 'test', 'receiver.submit', now())`, bare); err != nil {
		t.Fatal(err)
	}
	var n int
	a.QueryRow(ctx, `SELECT count(*) FROM decisions.actions_target_view WHERE action_id = $1`, bare).Scan(&n)
	if n != 0 {
		t.Error("bare action in actions_target_view")
	}
	// Envelope columns without the envelope are rejected.
	if _, err := gw.Exec(ctx, `
INSERT INTO decisions.actions (action_id, request_id, authenticated_actor, session_kind, session_id, workload_id,
    client_request_key, raw_body_digest, tenant, environment, operation_id, action_digest, created_at)
VALUES (gen_random_uuid(), gen_random_uuid(), 'google:alice', 'user', gen_random_uuid(), 'agent-exec/agent-runtime', 'bare-key-2',
    repeat('a', 64), 'hackathon', 'test', 'receiver.submit', repeat('e', 64), now())`); pgCode(err) != "23514" {
		t.Errorf("action_digest without envelope: %v", err)
	}
	// A service-session action has no workload_id.
	if _, err := gw.Exec(ctx, `
INSERT INTO decisions.actions (action_id, request_id, authenticated_actor, session_kind, session_id, workload_id,
    client_request_key, raw_body_digest, tenant, environment, operation_id, created_at)
VALUES (gen_random_uuid(), gen_random_uuid(), 'service:agentarium-control/intent-check', 'service', gen_random_uuid(), 'x/y',
    'svc-key-01', repeat('a', 64), 'hackathon', 'test', 'model.generate', now())`); pgCode(err) != "23514" {
		t.Errorf("service action with workload_id: %v", err)
	}
}

// The action columns of a decision come from its action, whatever the writer
// passed.
func TestDecisionCopiesActionFields(t *testing.T) {
	ctx := context.Background()
	a := admin(t)
	gw := asRole(t, "gateway_app")
	aid := newAction(t, gw)
	did := uuid.NewString()
	d := okAllow()
	if _, err := gw.Exec(ctx, insertDecision, did, aid, d.verdict, d.codes, d.basis, d.approval, d.stage, d.input, d.adapter, d.rego, d.revision); err != nil {
		t.Fatal(err)
	}
	var kind, workload, op, target string
	var same bool
	if err := a.QueryRow(ctx, `
SELECT d.session_kind, d.workload_id, d.operation_id, d.target_id, d.session_id = x.session_id
FROM decisions.decisions d JOIN decisions.actions x USING (action_id) WHERE d.decision_id = $1`, did).
		Scan(&kind, &workload, &op, &target, &same); err != nil {
		t.Fatal(err)
	}
	if kind != "user" || workload != "agent-exec/agent-runtime" || op != "receiver.submit" || target != "receiver-primary" || !same {
		t.Fatalf("copied fields %s %s %s %s %v", kind, workload, op, target, same)
	}
	// A forged value is overwritten.
	forged := uuid.NewString()
	if _, err := gw.Exec(ctx, `
INSERT INTO decisions.decisions (decision_id, request_id, action_id, session_kind, session_id, operation_id, verdict,
    reason_codes, matched_rule_ids, evaluated_rule_ids, decision_stage, policy_bundle_id, catalog_digest,
    catalog_version, expires_at, authenticated_gateway, created_at)
VALUES ($1, gen_random_uuid(), $2, 'service', gen_random_uuid(), 'model.generate', 'deny', '{CONTENT_PATTERN_DENIED}',
    '{normalize.content_pattern.v1}', '{normalize.content_pattern.v1}', 'normalize', 'bundle-1', repeat('d', 64),
    'test', now() + interval '10 seconds', 'gw', now())`, forged, aid); err != nil {
		t.Fatal(err)
	}
	if err := a.QueryRow(ctx, `SELECT session_kind, operation_id FROM decisions.decisions WHERE decision_id = $1`, forged).Scan(&kind, &op); err != nil ||
		kind != "user" || op != "receiver.submit" {
		t.Fatalf("forged fields kept: %s %s %v", kind, op, err)
	}
	// A decision for an unknown action is refused.
	if err := okAllow().insert(ctx, gw, uuid.NewString()); pgCode(err) != "23503" {
		t.Errorf("unknown action: %v", err)
	}
}

const insertContent = `
INSERT INTO decisions.action_contents (content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, now(), now() + interval '30 days')`

// Two actions with byte-identical content each own a content row with their
// own action_id and tenant, so the adapter's per-action check
// (canonical.VerifyContent) passes for both.
func TestSharedContentPerAction(t *testing.T) {
	ctx := context.Background()
	a := admin(t)
	gw := asRole(t, "gateway_app")
	content := []byte(`{"summary":"same bytes"}`)
	digest := canonical.SHA256Hex(content)
	var envs []canonical.ActionEnvelope
	for _, tenant := range []string{"hackathon", "other-tenant"} {
		env := testEnvelope()
		env.Tenant, env.ContentDigest, env.ContentRef, env.Bytes = tenant, &digest, &digest, int64(len(content))
		newEnvAction(t, gw, env)
		if _, err := gw.Exec(ctx, insertContent, digest, tenant, env.ActionID, "receiver", content); err != nil {
			t.Fatalf("content of %s: %v", tenant, err)
		}
		if err := okAllow().insert(ctx, gw, env.ActionID); err != nil {
			t.Fatal(err)
		}
		envs = append(envs, env)
	}
	ad := adapterLogin(t, a, "receiver", false)
	for _, env := range envs {
		var c canonical.Content
		if err := ad.QueryRow(ctx, `
SELECT content_digest, tenant, action_id::text, adapter_id, content_bytes FROM decisions.adapter_action_contents
WHERE content_digest = $1 AND action_id = $2 AND adapter_id = 'receiver'`, digest, env.ActionID).
			Scan(&c.ContentDigest, &c.Tenant, &c.ActionID, &c.AdapterID, &c.ContentBytes); err != nil {
			t.Fatalf("content of %s: %v", env.ActionID, err)
		}
		if err := canonical.VerifyContent(env, c); err != nil {
			t.Errorf("VerifyContent %s: %v", env.Tenant, err)
		}
	}
	// One preview per digest, even with two rows.
	var n int
	if err := a.QueryRow(ctx, `SELECT count(*) FROM decisions.action_content_previews WHERE content_digest = $1`, digest).Scan(&n); err != nil || n != 1 {
		t.Errorf("previews for shared digest: %d %v", n, err)
	}
	// An action has one content row, and it must be the action's own content
	// in the action's tenant.
	if _, err := gw.Exec(ctx, insertContent, digest, "hackathon", envs[0].ActionID, "receiver", content); pgCode(err) != "23505" {
		t.Errorf("second row for one action: %v", err)
	}
	other := newAction(t, gw) // content_ref c..c
	if _, err := gw.Exec(ctx, insertContent, digest, "hackathon", other, "receiver", content); pgCode(err) != "23503" {
		t.Errorf("content that is not the action's content_ref: %v", err)
	}
	if _, err := gw.Exec(ctx, insertContent, strings.Repeat("c", 64), "other-tenant", other, "receiver", content); pgCode(err) != "23503" {
		t.Errorf("content in another tenant: %v", err)
	}
}

// adapter_reader reads decisions and, through the two adapter views, the
// envelope and content of the actions allowed for its own adapter only. The
// adapter is the adapter_db_roles row of session_user.
func TestAdapterReaderGrants(t *testing.T) {
	ctx := context.Background()
	a := admin(t)
	gw := asRole(t, "gateway_app")
	adA := adapterLogin(t, a, "receiver", false)   // adapter A
	adB := adapterLogin(t, a, "model", false)      // adapter B
	adASet := adapterLogin(t, a, "receiver", true) // A after SET ROLE adapter_reader
	unmapped := adapterLogin(t, a, "", false)      // member of adapter_reader, no mapping
	noLogin := asRole(t, "adapter_reader")         // session_user is the test superuser

	put := func(env canonical.ActionEnvelope, adapter string, d dec) {
		t.Helper()
		newEnvAction(t, gw, env)
		if _, err := gw.Exec(ctx, insertContent, *env.ContentDigest, env.Tenant, env.ActionID, adapter, []byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := d.insert(ctx, gw, env.ActionID); err != nil {
			t.Fatal(err)
		}
	}
	// allowed: allow decision for receiver, content for receiver.
	allowed := testEnvelope()
	put(allowed, "receiver", okAllow())
	// pending: only an approval_required decision.
	pending := testEnvelope()
	put(pending, "receiver", dec{"approval_required", []string{"APPROVAL_REQUIRED"}, nil, nil, "opa",
		strings.Repeat("f", 64), nil, `{"verdict": "approval_required"}`, "rev-7"})
	// denied: only a deny decision that names receiver.
	denied := testEnvelope()
	put(denied, "receiver", dec{"deny", []string{"HOLD_ACTIVE"}, nil, nil, "opa",
		strings.Repeat("f", 64), "receiver", `{"verdict": "deny"}`, "rev-7"})
	// mismatched: allowed for receiver, but the content names another adapter.
	mismatched := testEnvelope()
	put(mismatched, "model", okAllow())
	// other: allowed for model, content for model.
	other := testEnvelope()
	toModel := okAllow()
	toModel.adapter = "model"
	put(other, "model", toModel)
	// expired: allowed, content past expires_at.
	expired := testEnvelope()
	newEnvAction(t, gw, expired)
	if _, err := gw.Exec(ctx, `
INSERT INTO decisions.action_contents (content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)
VALUES ($1, $2, $3, 'receiver', 'x', now() - interval '31 days', now() - interval '1 day')`,
		*expired.ContentDigest, expired.Tenant, expired.ActionID); err != nil {
		t.Fatal(err)
	}
	if err := okAllow().insert(ctx, gw, expired.ActionID); err != nil {
		t.Fatal(err)
	}

	visible := func(p *pgxpool.Pool, view, id string) bool {
		t.Helper()
		var n int
		if err := p.QueryRow(ctx, `SELECT count(*) FROM decisions.`+view+` WHERE action_id = $1`, id).Scan(&n); err != nil {
			t.Fatalf("%s: %v", view, err)
		}
		return n == 1
	}
	type want struct{ envelope, contents bool }
	none := want{}
	for _, c := range []struct {
		name                     string
		id                       string
		a, b, aSet, unmapped, no want
	}{
		{"allowed", allowed.ActionID, want{true, true}, none, want{true, true}, none, none},
		{"pending", pending.ActionID, none, none, none, none, none},
		{"denied", denied.ActionID, none, none, none, none, none},
		{"other adapter content", mismatched.ActionID, want{true, false}, none, want{true, false}, none, none},
		{"other adapter decision", other.ActionID, none, want{true, true}, none, none, none},
		{"expired content", expired.ActionID, want{true, false}, none, want{true, false}, none, none},
	} {
		for _, r := range []struct {
			who  string
			p    *pgxpool.Pool
			want want
		}{
			{"A", adA, c.a}, {"B", adB, c.b}, {"A after SET ROLE", adASet, c.aSet},
			{"unmapped login", unmapped, c.unmapped}, {"superuser as adapter_reader", noLogin, c.no},
		} {
			if got := visible(r.p, "adapter_action_envelopes", c.id); got != r.want.envelope {
				t.Errorf("%s, %s: envelope visible %v", c.name, r.who, got)
			}
			if got := visible(r.p, "adapter_action_contents", c.id); got != r.want.contents {
				t.Errorf("%s, %s: content visible %v", c.name, r.who, got)
			}
		}
	}
	// The envelope read through the view is the envelope as stored.
	var raw []byte
	if err := adA.QueryRow(ctx, `SELECT envelope FROM decisions.adapter_action_envelopes WHERE action_id = $1`, allowed.ActionID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var got canonical.ActionEnvelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if mustJSON(t, got) != mustJSON(t, allowed) {
		t.Errorf("envelope\n got %s\nwant %s", mustJSON(t, got), mustJSON(t, allowed))
	}
	// decisions itself is readable in full (COMMON adapter_reader SELECT).
	for name, p := range map[string]*pgxpool.Pool{"A": adA, "A after SET ROLE": adASet, "unmapped login": unmapped} {
		var n int
		if err := p.QueryRow(ctx, `SELECT count(*) FROM decisions.decisions`).Scan(&n); err != nil || n != 6 {
			t.Errorf("%s decisions: %d %v", name, n, err)
		}
	}
	for name, p := range map[string]*pgxpool.Pool{"A": adA, "A after SET ROLE": adASet, "superuser as adapter_reader": noLogin} {
		for _, q := range []string{
			`SELECT 1 FROM decisions.actions`,
			`SELECT 1 FROM decisions.action_contents`,
			`SELECT 1 FROM decisions.decision_inputs`,
			`SELECT 1 FROM decisions.execute_requests`,
			`SELECT 1 FROM decisions.intent_checks`,
			`SELECT 1 FROM decisions.adapter_db_roles`,
			`SELECT 1 FROM decisions.actions_target_view`,
			`SELECT 1 FROM decisions.pending_approval_actions`,
			`SELECT 1 FROM decisions.action_content_previews`,
			`DELETE FROM decisions.decisions`,
			`INSERT INTO decisions.adapter_db_roles (db_role, adapter_id) VALUES (session_user, 'model')`,
			`UPDATE decisions.adapter_db_roles SET adapter_id = 'model'`,
			`INSERT INTO decisions.action_contents (content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)
VALUES (repeat('c', 64), 'hackathon', gen_random_uuid(), 'receiver', 'x', now(), now() + interval '1 day')`,
		} {
			if _, err := p.Exec(ctx, q); pgCode(err) != "42501" {
				t.Errorf("%s %s: %v", name, q, err)
			}
		}
	}
	// Other readers do not get the adapter views; no application role reads
	// the login mapping.
	for _, c := range []struct {
		role  string
		views []string
	}{
		{"coordinator_app", []string{"adapter_action_envelopes", "adapter_action_contents", "adapter_db_roles"}},
		{"identity_app", []string{"adapter_action_envelopes", "adapter_action_contents", "adapter_db_roles"}},
		{"gateway_app", []string{"adapter_db_roles"}},
	} {
		p := asRole(t, c.role)
		for _, v := range c.views {
			if _, err := p.Exec(ctx, `SELECT 1 FROM decisions.`+v); pgCode(err) != "42501" {
				t.Errorf("%s %s: %v", c.role, v, err)
			}
		}
	}
}

// The envelope jsonb must be the ActionEnvelope of the typed columns.
func TestEnvelopeMatchesColumns(t *testing.T) {
	ctx := context.Background()
	a := admin(t)
	gw := asRole(t, "gateway_app")
	set := func(f func(m map[string]any)) func(env canonical.ActionEnvelope) any {
		return func(env canonical.ActionEnvelope) any {
			var m map[string]any
			if err := json.Unmarshal([]byte(mustJSON(t, env)), &m); err != nil {
				t.Fatal(err)
			}
			f(m)
			return mustJSON(t, m)
		}
	}
	for name, envelope := range map[string]func(env canonical.ActionEnvelope) any{
		"empty object":           func(canonical.ActionEnvelope) any { return `{}` },
		"other tenant":           set(func(m map[string]any) { m["tenant"] = "other" }),
		"other action_id":        set(func(m map[string]any) { m["action_id"] = uuid.NewString() }),
		"other target":           set(func(m map[string]any) { m["canonical_target"] = map[string]any{"target_id": "x", "route_id": "y"} }),
		"null disclosure":        set(func(m map[string]any) { m["disclosure_fields"] = nil }),
		"other bytes":            set(func(m map[string]any) { m["bytes"] = 13 }),
		"string bytes":           set(func(m map[string]any) { m["bytes"] = "12" }),
		"other limits":           set(func(m map[string]any) { m["limits"] = map[string]any{"max_bytes": 1} }),
		"missing workload_id":    set(func(m map[string]any) { delete(m, "workload_id") }),
		"null content_digest":    set(func(m map[string]any) { m["content_digest"] = nil }),
		"extra key":              set(func(m map[string]any) { m["note"] = "x" }),
		"other action_digest":    set(func(m map[string]any) { m["action_digest"] = strings.Repeat("0", 64) }),
		"other data_class":       set(func(m map[string]any) { m["data_class"] = "internal" }),
		"other operation":        set(func(m map[string]any) { m["operation_id"] = "model.generate" }),
		"reordered data_sources": set(func(m map[string]any) { m["data_sources"] = []string{"b", "a"} }),
	} {
		env := testEnvelope()
		env.DataSources = []string{"a", "b"}
		if err := putAction(ctx, t, gw, env, "key-"+env.ActionID[:8], envelope(env)); pgCode(err) != "23514" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A service-session envelope (workload_id null) without content is
	// accepted.
	svc := testEnvelope()
	svc.AuthenticatedActor, svc.SessionKind, svc.WorkloadID = "service:agentarium-control/intent-check", "service", nil
	svc.ContentDigest, svc.ContentRef, svc.Bytes = nil, nil, 0
	svc.Limits = map[string]int64{"max_bytes": 4096}
	if err := putAction(ctx, t, gw, svc, "svc-"+svc.ActionID[:8], nil); err != nil {
		t.Errorf("service envelope: %v", err)
	}
	// Changing a column without the envelope is refused, even for the owner.
	aid := newAction(t, gw)
	if _, err := a.Exec(ctx, `UPDATE decisions.actions SET data_class = 'internal' WHERE action_id = $1`, aid); pgCode(err) != "23514" {
		t.Errorf("column update without envelope: %v", err)
	}
}
