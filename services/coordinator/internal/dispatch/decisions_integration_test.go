//go:build integration

package dispatch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// putDecision writes an action and an allow decision into the decisions
// schema (TASK-04 tables) as the gateway would, and returns the decision ID.
func putDecision(t *testing.T, e *env, service bool) (string, string) {
	t.Helper()
	ctx := context.Background()
	actionID, decisionID, sessionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	kind, workload, basis, approval, serviceSession := "user", ptr("agent-exec/agent-runtime"), "approval", any(uuid.NewString()), any(nil)
	matched := []string{"approval.allow.v1"}
	if service {
		kind, workload, basis, approval, serviceSession = "service", nil, "service_scope", nil, sessionID
		matched = []string{"service.scope_allow.v1"}
	}
	input := strings.Repeat("f", 64)
	if _, err := e.admin.Exec(ctx, `
TRUNCATE decisions.execute_requests, decisions.decisions, decisions.decision_inputs, decisions.action_contents, decisions.actions CASCADE`); err != nil {
		t.Fatal(err)
	}
	putAction(t, e, actionID, kind, sessionID, workload)
	if _, err := e.admin.Exec(ctx, `
INSERT INTO decisions.decision_inputs VALUES ($1, 'hackathon', '{}', 'bundle-1', now())`, input); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `
INSERT INTO decisions.decisions (decision_id, request_id, action_id, action_digest, adapter_id, verdict, reason_codes,
    decision_basis, approval_id, service_session_id, matched_rule_ids, evaluated_rule_ids, rego_result, decision_stage,
    decision_input_ref, decision_input_digest, policy_bundle_id, policy_epoch, opa_bundle_revision, catalog_digest,
    catalog_version, expires_at, authenticated_gateway, created_at)
VALUES ($1, gen_random_uuid(), $2, repeat('e', 64), 'receiver', 'allow', '{}', $3, $4, $5, $6, $6,
    '{"verdict": "allow"}', 'opa', $7, $7, 'bundle-1', 7, $8, $9, 'test', now() + interval '10 seconds', 'gw', now())`,
		decisionID, actionID, basis, approval, serviceSession, matched, input, opaRev, catalogD); err != nil {
		t.Fatal(err)
	}
	return decisionID, sessionID
}

// putAction writes a decisions.actions row for actionID (operation
// receiver.submit) as the gateway would.
func putAction(t *testing.T, e *env, actionID, kind, sessionID string, workload *string) {
	t.Helper()
	ctx := context.Background()
	// The envelope jsonb must equal the columns (CHECK on decisions.actions).
	envelope := canonical.ActionEnvelope{
		SchemaVersion:           "1",
		ActionID:                actionID,
		RequestID:               uuid.NewString(),
		AuthenticatedActor:      "google:u1",
		SessionKind:             kind,
		SessionID:               sessionID,
		WorkloadID:              workload,
		EndpointID:              "test-receiver-v1",
		OperationID:             "receiver.submit",
		CanonicalTarget:         canonical.CanonicalTarget{TargetID: "receiver-primary", RouteID: "submissions-v1"},
		Environment:             "test",
		Tenant:                  "hackathon",
		DisclosureFields:        []string{"summary"},
		DataClass:               "synthetic",
		DataSources:             []string{},
		Limits:                  map[string]int64{},
		CatalogDigest:           catalogD,
		CatalogVersion:          "test",
		CanonicalizationVersion: "v1",
		RawBodyDigest:           strings.Repeat("a", 64),
		ActionDigest:            strings.Repeat("e", 64),
	}
	envJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `
INSERT INTO decisions.actions (action_id, request_id, authenticated_actor, session_kind, session_id, workload_id,
    client_request_key, raw_body_digest, tenant, environment, operation_id, schema_version, endpoint_id,
    canonical_target, disclosure_fields, data_class, data_sources, bytes, limits, catalog_digest, catalog_version,
    canonicalization_version, action_digest, envelope, created_at)
VALUES ($1, $2, 'google:u1', $3, $4, $5, 'client-key-1',
    repeat('a', 64), 'hackathon', 'test', 'receiver.submit', '1', 'test-receiver-v1',
    '{"target_id": "receiver-primary", "route_id": "submissions-v1"}', '{summary}', 'synthetic', '{}', 0, '{}',
    $6, 'test', 'v1', repeat('e', 64), $7, now())`,
		actionID, envelope.RequestID, kind, sessionID, workload, catalogD, string(envJSON)); err != nil {
		t.Fatal(err)
	}
}

func ptr(s string) *string { return &s }

func readDecision(t *testing.T, e *env, id string) (Decision, error) {
	t.Helper()
	var d Decision
	var derr error
	err := pgx.BeginTxFunc(context.Background(), e.svc.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		d, derr = PGDecisions{}.Decision(context.Background(), tx, id)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return d, derr
}

func TestPGDecisions(t *testing.T) {
	e := setup(t)
	id, sess := putDecision(t, e, false)
	d, err := readDecision(t, e, id)
	if err != nil {
		t.Fatal(err)
	}
	if d.DecisionID != id || d.Verdict != "allow" || d.DecisionBasis != "approval" || d.ApprovalID == "" ||
		d.SessionID != sess || d.WorkloadID != "agent-exec/agent-runtime" || d.ServiceSessionID != "" ||
		d.OperationID != "receiver.submit" || d.TargetID != "receiver-primary" || d.AdapterID != "receiver" ||
		d.PolicyEpoch != 7 || d.OPABundleRevision != opaRev || d.CatalogDigest != catalogD ||
		d.ActionDigest != strings.Repeat("e", 64) || time.Until(d.ExpiresAt) <= 0 {
		t.Fatalf("user decision %+v", d)
	}

	id, sess = putDecision(t, e, true)
	d, err = readDecision(t, e, id)
	if err != nil {
		t.Fatal(err)
	}
	if d.DecisionBasis != "service_scope" || d.ServiceSessionID != sess || d.SessionID != "" || d.WorkloadID != "" || d.ApprovalID != "" {
		t.Fatalf("service decision %+v", d)
	}

	if _, err := readDecision(t, e, uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown decision: %v", err)
	}
}
