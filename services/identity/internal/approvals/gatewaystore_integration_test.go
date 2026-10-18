//go:build integration

package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/sessions"
)

// rolePool connects as the admin DSN and switches to role for every
// connection, so each query also checks that role's grants.
func rolePool(t *testing.T, role string) *pgxpool.Pool {
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

func truncateDecisions(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
TRUNCATE decisions.execute_requests, decisions.intent_checks, decisions.decisions, decisions.decision_inputs,
    decisions.action_contents, decisions.actions CASCADE`); err != nil {
		t.Fatal(err)
	}
}

// gatewayAction writes a user-session receiver action, its content and an
// approval_required decision the way the gateway does, as gateway_app.
func gatewayAction(t *testing.T, gw *pgxpool.Pool, sessionID string, content []byte) (actionID, decisionID string) {
	t.Helper()
	ctx := context.Background()
	actionID, decisionID = uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("c", 64)
	target := `{"target_id": "receiver-primary", "route_id": "submissions-v1"}`
	// The envelope jsonb must equal the columns (CHECK on decisions.actions).
	workload := "agent-exec/agent-runtime"
	env := canonical.ActionEnvelope{
		SchemaVersion:           "1",
		ActionID:                actionID,
		RequestID:               uuid.NewString(),
		AuthenticatedActor:      "google:alice",
		SessionKind:             "user",
		SessionID:               sessionID,
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
		Bytes:                   int64(len(content)),
		Limits:                  map[string]int64{},
		CatalogDigest:           strings.Repeat("d", 64),
		CatalogVersion:          "test",
		CanonicalizationVersion: "v1",
		RawBodyDigest:           strings.Repeat("a", 64),
		ActionDigest:            strings.Repeat("e", 64),
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := gw.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
INSERT INTO decisions.actions (action_id, request_id, authenticated_actor, session_kind, session_id, workload_id,
    client_request_key, raw_body_digest, tenant, environment, operation_id, schema_version, endpoint_id,
    canonical_target, disclosure_fields, data_class, data_sources, content_digest, content_ref, bytes, limits,
    catalog_digest, catalog_version, canonicalization_version, action_digest, envelope, created_at)
VALUES ($1, $11, 'google:alice', 'user', $2, 'agent-exec/agent-runtime', $3, $4, 'hackathon', 'test',
    'receiver.submit', '1', 'test-receiver-v1', $5, '{summary}', 'synthetic', '{}', $6, $6, $7, '{}',
    $8, 'test', 'v1', $9, $10, statement_timestamp())`,
		actionID, sessionID, "key-"+actionID[:8], strings.Repeat("a", 64), target, digest, len(content),
		strings.Repeat("d", 64), strings.Repeat("e", 64), string(envJSON), env.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO decisions.action_contents (content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)
VALUES ($1, 'hackathon', $2, 'receiver', $3, statement_timestamp(), statement_timestamp() + interval '30 days')`,
		digest, actionID, content); err != nil {
		t.Fatal(err)
	}
	insertDecision(t, tx, actionID, decisionID, "approval_required")
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return actionID, decisionID
}

func insertDecision(t *testing.T, tx pgx.Tx, actionID, decisionID, verdict string) {
	t.Helper()
	ctx := context.Background()
	input := strings.Repeat("f", 64)
	if _, err := tx.Exec(ctx, `
INSERT INTO decisions.decision_inputs (decision_input_digest, tenant, sanitized_input, policy_bundle_id, created_at)
VALUES ($1, 'hackathon', '{}', 'bundle-1', statement_timestamp()) ON CONFLICT (decision_input_digest) DO NOTHING`, input); err != nil {
		t.Fatal(err)
	}
	codes, basis, matched, adapter := []string{"APPROVAL_REQUIRED"}, (*string)(nil), []string{"approval.required_default.v1"}, (*string)(nil)
	var standing *string
	if verdict == "allow" {
		b, s, a := "standing_rule", "standing.k8s_read.v1", "receiver"
		codes, basis, matched, standing, adapter = []string{}, &b, []string{s}, &s, &a
	}
	rego, _ := json.Marshal(map[string]any{"verdict": verdict, "reason_codes": codes, "matched_rule_ids": matched})
	if _, err := tx.Exec(ctx, `
INSERT INTO decisions.decisions (decision_id, request_id, action_id, action_digest, adapter_id, verdict, reason_codes,
    decision_basis, standing_rule_id, matched_rule_ids, evaluated_rule_ids, rego_result, decision_stage,
    decision_input_ref, decision_input_digest, policy_bundle_id, policy_epoch, opa_bundle_revision, catalog_digest,
    catalog_version, expires_at, authenticated_gateway, created_at)
VALUES ($1, gen_random_uuid(), $2, $3, $4, $5, $6, $7, $8, $9, '{session.binding.v1}', $10, 'opa', $11, $11, 'bundle-1', 7,
    'rev-7', $12, 'test', statement_timestamp() + interval '10 seconds', 'spiffe://agentarium.internal/ns/agent-gateway/sa/gateway',
    statement_timestamp())`,
		decisionID, actionID, strings.Repeat("e", 64), adapter, verdict, codes, basis, standing, matched, rego, input,
		strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayStoreApprovalFlow(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	truncateDecisions(t, e.pool)
	gw := rolePool(t, "gateway_app")
	ident := rolePool(t, "identity_app")
	store := GatewayStore{}
	// The action itself still comes from the fake ActionSource (no registered
	// view for it); the pending list and the preview come from the views.
	e.svc.Pool, e.svc.Pending, e.svc.Previews = ident, store, store

	cr, err := e.sess.Create(ctx, alice, sessions.CreateRequest{WorkloadID: "agent-exec/agent-runtime", TaskStatement: "send a summary",
		RequestedScope: sessions.RequestedScope{OperationIDs: []string{"receiver.submit"}, TargetIDs: []string{"receiver-primary"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.sess.Claim(ctx, pod, cr.SessionID, cr.ClaimCode); err != nil {
		t.Fatal(err)
	}
	long := `{"summary":"` + strings.Repeat("x", 600) + `"}`
	aid, did := gatewayAction(t, gw, cr.SessionID, []byte(long))
	setFake := func(verdict string) {
		e.actions.mu.Lock()
		defer e.actions.mu.Unlock()
		e.actions.m[aid] = Action{ActionID: aid, SessionID: cr.SessionID, Tenant: "hackathon", Environment: "test",
			OperationID: "receiver.submit", CanonicalTarget: json.RawMessage(`{"target_id": "receiver-primary", "route_id": "submissions-v1"}`),
			TargetID: "receiver-primary", DisclosureFields: []string{"summary"}, ContentDigest: strings.Repeat("c", 64), Verdict: verdict}
	}
	setFake("approval_required")

	// Pending lists the action with its approval_required decision.
	p, err := e.svc.PendingFor(ctx, alice, cr.SessionID)
	if err != nil || len(p) != 1 || p[0].ActionID != aid || p[0].DecisionID != did || p[0].OperationID != "receiver.submit" {
		t.Fatalf("pending %+v %v", p, err)
	}
	if p, err := e.svc.PendingFor(ctx, bob, cr.SessionID); err == nil || len(p) != 0 {
		t.Fatalf("other user saw pending %+v", p)
	}

	// The contract preview comes from action_content_previews (512 characters).
	c, err := e.svc.Contract(ctx, alice, aid)
	if err != nil {
		t.Fatal(err)
	}
	if c.Contract.ContentPreview == nil || !c.Contract.ContentPreview.Truncated || c.Contract.Target.TargetID != "receiver-primary" ||
		len([]rune(c.Contract.ContentPreview.Text)) != 512 || c.Contract.OperationID != "receiver.submit" {
		t.Fatalf("contract %+v", c.Contract)
	}
	out, err := e.svc.Approve(ctx, fresh(alice), ApproveRequest{ActionID: aid, DisplayedContractDigest: c.ContractDigest, Nonce: c.Nonce})
	if err != nil {
		t.Fatal(err)
	}
	// The approval stores the envelope's canonical_target as-is.
	var same bool
	if err := e.pool.QueryRow(ctx, `SELECT a.canonical_target = x.canonical_target FROM identity.approvals a, decisions.actions x
WHERE a.approval_id = $1 AND x.action_id = $2`, out.ApprovalID, aid).Scan(&same); err != nil || !same {
		t.Fatalf("canonical_target copy: %v %v", same, err)
	}

	// A usable approval removes the action from the pending view.
	if p, _ := e.svc.PendingFor(ctx, alice, cr.SessionID); len(p) != 0 {
		t.Fatalf("approved action still pending: %+v", p)
	}
	// Revoked: pending again.
	if _, err := e.svc.Revoke(ctx, alice, out.ApprovalID); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.svc.PendingFor(ctx, alice, cr.SessionID); len(p) != 1 {
		t.Fatalf("revoked approval: pending %+v", p)
	}

	// A newer allow decision is the latest one: not pending, no contract.
	tx, err := gw.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	insertDecision(t, tx, aid, uuid.NewString(), "allow")
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.svc.PendingFor(ctx, alice, cr.SessionID); len(p) != 0 {
		t.Fatalf("allowed action still pending: %+v", p)
	}
	if _, _, err := func() (string, bool, error) {
		var s string
		var b bool
		var err error
		_ = pgx.BeginTxFunc(ctx, ident, pgx.TxOptions{}, func(tx pgx.Tx) error {
			s, b, err = store.Preview(ctx, tx, strings.Repeat("0", 64))
			return nil
		})
		return s, b, err
	}(); !errors.Is(err, ErrNoPreview) {
		t.Fatalf("missing preview: %v", err)
	}
}

// identity_app reads the views only, never the tables behind them.
func TestGatewayStorePrivileges(t *testing.T) {
	e := setup(t)
	truncateDecisions(t, e.pool)
	ident := rolePool(t, "identity_app")
	for _, q := range []string{
		`SELECT 1 FROM decisions.actions`,
		`SELECT 1 FROM decisions.decisions`,
		`SELECT 1 FROM decisions.action_contents`,
		`SELECT 1 FROM decisions.decision_inputs`,
		`SELECT 1 FROM decisions.actions_target_view`,
		`INSERT INTO decisions.intent_checks (intent_check_id) VALUES (gen_random_uuid())`,
	} {
		_, err := ident.Exec(context.Background(), q)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Errorf("%s: err = %v, want permission denied", q, err)
		}
	}
	for _, q := range []string{
		`SELECT 1 FROM decisions.pending_approval_actions`,
		`SELECT 1 FROM decisions.action_content_previews`,
		`SELECT 1 FROM decisions.intent_checks`,
	} {
		if _, err := ident.Exec(context.Background(), q); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
}

// Content of an action evaluated at data class internal has no preview, so
// the contract is not rendered (fail closed).
func TestGatewayStoreNoPreviewFailsClosed(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	truncateDecisions(t, e.pool)
	gw := rolePool(t, "gateway_app")
	e.svc.Pool, e.svc.Pending, e.svc.Previews = rolePool(t, "identity_app"), GatewayStore{}, GatewayStore{}
	sid, aid := e.claimedSession(t, alice)
	gid, _ := gatewayAction(t, gw, sid, []byte(`{"summary":"hello"}`))
	if _, err := e.pool.Exec(ctx, `UPDATE decisions.actions SET data_class = 'internal', envelope = jsonb_set(envelope, '{data_class}', '"internal"')
WHERE action_id = $1`, gid); err != nil {
		t.Fatal(err)
	}
	// The fake action carries the same content digest as the gateway row.
	e.actions.mu.Lock()
	a := e.actions.m[aid]
	a.ContentDigest = strings.Repeat("c", 64)
	e.actions.m[aid] = a
	e.actions.mu.Unlock()
	if _, err := e.svc.Contract(ctx, alice, aid); code(t, err) != "STATE_STORE_UNAVAILABLE" {
		t.Fatalf("contract without preview: %v", err)
	}
}
