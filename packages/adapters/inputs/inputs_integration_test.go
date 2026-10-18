//go:build integration

package inputs_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/inputs"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// The TASK-04 decisions schema comes from migration
// 20261016181826_gateway_decisions (TASK-04). The test database may not have
// it applied yet.
// The test is skipped unless the schema exists in DATABASE_URL or
// AGENTARIUM_GATEWAY_MIGRATION lists SQL files (os.PathListSeparator
// separated, applied in order) that create it. The test uses the migration
// as revised in #46 (commit 017b16a) without a copy of its own: the
// adapter_reader role (created if missing) gets SELECT on decisions.decisions
// and the views adapter_action_envelopes and adapter_action_contents only;
// the base tables and decisions.adapter_db_roles are revoked from it and from
// PUBLIC; the views show only rows of the adapter that
// decisions.adapter_db_roles maps to session_user. The reader therefore runs
// as its own LOGIN role in adapter_reader, mapped to receiver-sender (see
// adapterLogin), not as SET ROLE adapter_reader. #46's migration needs its
// identity and coordinator migrations first (roles identity_app and
// coordinator_app, table identity.approvals), for example:
//
//	for f in 20261014144500_identity_workload_pki 20261016120000_identity_sessions_tokens \
//	         20261016175130_identity_approvals 20261016180757_coordinator_dispatch \
//	         20261016181826_gateway_decisions; do
//	  cp migrations/$f.up.sql /tmp/gw/$f.up.sql
//	done
//	DATABASE_URL=postgres://... AGENTARIUM_GATEWAY_MIGRATION=$(ls /tmp/gw/*.up.sql | paste -sd: -) \
//	  go test -tags integration ./packages/adapters/inputs/

const (
	adapterID  = "receiver-sender"
	readerRole = "adapter_reader" // created and granted by #46's migration; adapter logins are its members
	bundleID   = "bundle-1"
)

var setupOnce sync.Once

func admin(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var skip string
	setupOnce.Do(func() { skip = setup(t, p) })
	if skip == "" {
		skip = schemaMissing(t, p)
	}
	if skip != "" {
		t.Skip(skip)
	}
	return p
}

func schemaMissing(t *testing.T, p *pgxpool.Pool) string {
	t.Helper()
	var exists bool
	if err := p.QueryRow(context.Background(), `SELECT to_regclass('decisions.decisions') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		return ""
	}
	return "decisions schema not present: the TASK-04 migration 20261016181826_gateway_decisions " +
		"is not applied to DATABASE_URL; set AGENTARIUM_GATEWAY_MIGRATION to its SQL files to run this test"
}

// setup applies the gateway migration files when the schema is missing and
// lets the test user SET ROLE to the migration's coordinator_app. The grants
// are the migration's; the test adds none. Adapter logins are created per
// test (adapterLogin).
func setup(t *testing.T, p *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(20261016181826)`); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec(ctx, `SELECT pg_advisory_unlock(20261016181826)`)
	if schemaMissing(t, p) != "" {
		files := filepath.SplitList(os.Getenv("AGENTARIUM_GATEWAY_MIGRATION"))
		if len(files) == 0 {
			return schemaMissing(t, p)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Exec(ctx, string(b)); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
		if msg := schemaMissing(t, p); msg != "" {
			t.Fatalf("AGENTARIUM_GATEWAY_MIGRATION applied but %s", msg)
		}
	}
	var roles int
	var mapping bool
	if err := conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_roles WHERE rolname IN ($1, 'coordinator_app')),
       to_regclass('decisions.adapter_db_roles') IS NOT NULL`, readerRole).Scan(&roles, &mapping); err != nil {
		t.Fatal(err)
	}
	if roles != 2 || !mapping {
		t.Fatalf("decisions schema present but roles %s and coordinator_app or table decisions.adapter_db_roles missing: not the #46 migration of 017b16a", readerRole)
	}
	if _, err := conn.Exec(ctx, `GRANT coordinator_app TO CURRENT_USER`); err != nil {
		t.Fatal(err)
	}
	return ""
}

// poolAs opens a pool whose sessions run as role.
func poolAs(t *testing.T, role string) *pgxpool.Pool {
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

// adapterLogin creates a LOGIN role in adapter_reader, maps it to mapTo in
// decisions.adapter_db_roles (no mapping when mapTo is empty) and returns a
// pool that logs in as it, so session_user is that role as for an adapter's
// Cloud SQL IAM DB user. a is the admin pool; the mapping row is written by
// the admin, as at install time. The role and its mapping are removed at
// cleanup, after the pool is closed.
func adapterLogin(t *testing.T, a *pgxpool.Pool, mapTo string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	role := "adtest_" + strings.ReplaceAll(newUUID(), "-", "")[:12]
	password := newUUID()
	if _, err := a.Exec(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD '`+password+`' IN ROLE `+readerRole); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := a.Exec(ctx, `DELETE FROM decisions.adapter_db_roles WHERE db_role = $1`, role); err != nil {
			t.Errorf("unmap %s: %v", role, err)
		}
		if _, err := a.Exec(ctx, `DROP ROLE `+role); err != nil {
			t.Errorf("drop %s: %v", role, err)
		}
	})
	if mapTo != "" {
		if _, err := a.Exec(ctx, `INSERT INTO decisions.adapter_db_roles (db_role, adapter_id) VALUES ($1, $2)`, role, mapTo); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.ConnConfig.Password = role, password
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

// reader is the receiver-sender reader, logged in as a login mapped to
// receiver-sender.
func reader(t *testing.T, a *pgxpool.Pool) *inputs.PG {
	return &inputs.PG{Pool: adapterLogin(t, a, adapterID), AdapterID: adapterID}
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

var catalog = sync.OnceValues(func() (canonical.Catalog, error) {
	return canonical.LoadCatalogDir("../../canonical/testdata/catalog")
})

type stored struct {
	DecisionID string
	ActionID   string
	Env        canonical.ActionEnvelope
	Content    canonical.Content
}

type putOpts struct {
	summary        string
	decisionAdapt  string // adapter_id of the decision
	contentAdapter string // adapter_id written into action_contents
	contentExpired bool
	verdict        string // allow (default) or approval_required
	envelopeJSON   string // overrides the envelope jsonb (the CHECK refuses one that differs from the columns)
	limitsJSON     string // overrides the limits column and the envelope's limits together
	serviceSession string // decisions.service_session_id; null when empty
}

// put stores a receiver.submit action, its content and a decision the way
// the gateway's decision transaction does (COMMON decision storage transaction).
func put(t *testing.T, p *pgxpool.Pool, o putOpts) stored {
	t.Helper()
	s, err := tryPut(t, p, o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func tryPut(t *testing.T, p *pgxpool.Pool, o putOpts) (stored, error) {
	t.Helper()
	ctx := context.Background()
	cat, err := catalog()
	if err != nil {
		t.Fatal(err)
	}
	if o.decisionAdapt == "" {
		o.decisionAdapt = adapterID
	}
	if o.contentAdapter == "" {
		o.contentAdapter = adapterID
	}
	if o.verdict == "" {
		o.verdict = "allow"
	}
	w := "agent-runtime-0"
	actionID, sessionID := newUUID(), newUUID()
	raw := `{"session_id":"` + sessionID + `","operation_id":"receiver.submit","requested_target":{"target_id":"receiver-primary"},"arguments":{"payload":{"summary":` + mustJSON(t, o.summary) + `,"email":null}},"client_request_key":"req-00000001"}`
	env, content, nerr := canonical.NormalizeRaw([]byte(raw), canonical.TrustedContext{
		ActionID: actionID, RequestID: newUUID(), AuthenticatedActor: "user:alice@example.com", SessionKind: "user",
		SessionID: sessionID, WorkloadID: &w, Tenant: "hackathon", Environment: "test",
		WorkloadDataState: canonical.WorkloadDataState{DataClassHighWater: "synthetic", DataSources: []string{"receiver-primary"}},
	}, cat)
	if nerr != nil {
		t.Fatal(nerr)
	}
	limits := mustJSON(t, env.Limits)
	envelope := o.envelopeJSON
	if envelope == "" {
		envelope = mustJSON(t, env)
	}
	if o.limitsJSON != "" {
		limits = o.limitsJSON
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(envelope), &m); err != nil {
			t.Fatal(err)
		}
		m["limits"] = json.RawMessage(limits)
		envelope = mustJSON(t, m)
	}
	reasons, basis, approval := "{}", any("approval"), any(newUUID())
	if o.verdict != "allow" {
		reasons, basis, approval = "{APPROVAL_REQUIRED}", nil, nil
	}
	created := "statement_timestamp()"
	if o.contentExpired {
		created = "statement_timestamp() - interval '31 days'"
	}
	decisionID, input := newUUID(), strings.Repeat("f", 64)
	var serviceSession *string
	if o.serviceSession != "" {
		serviceSession = &o.serviceSession
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		return stored{}, err
	}
	defer tx.Rollback(ctx)
	steps := []struct {
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
				mustJSON(t, env.CanonicalTarget), env.DisclosureFields, env.DataClass, env.DataSources, env.ContentDigest,
				env.ContentRef, env.Bytes, limits, env.CatalogDigest, env.CatalogVersion,
				env.CanonicalizationVersion, env.ActionDigest, envelope}},
		// (content_digest, action_id) is the key: each action has its own row.
		{`INSERT INTO decisions.action_contents (content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, ` + created + `, ` + created + ` + interval '30 days')`,
			[]any{content.ContentDigest, content.Tenant, content.ActionID, o.contentAdapter, content.ContentBytes}},
		{`INSERT INTO decisions.decision_inputs VALUES ($1, 'hackathon', '{}', $2, statement_timestamp())
ON CONFLICT DO NOTHING`, []any{input, bundleID}},
		{`INSERT INTO decisions.decisions (decision_id, request_id, action_id, action_digest, adapter_id, verdict, reason_codes,
    decision_basis, approval_id, matched_rule_ids, evaluated_rule_ids, rego_result, decision_stage,
    decision_input_ref, decision_input_digest, policy_bundle_id, policy_epoch, opa_bundle_revision, catalog_digest,
    catalog_version, expires_at, authenticated_gateway, created_at, service_session_id)
VALUES ($1, $2, $3, $4, $5, $11, $12, $13, $6, '{approval.allow.v1}', '{approval.allow.v1}',
    '{"verdict": "allow"}', 'opa', $7, $7, $8, 7, 'rev-1', $9, $10, statement_timestamp() + interval '10 seconds',
    'gw', statement_timestamp(), $14)`,
			[]any{decisionID, env.RequestID, env.ActionID, env.ActionDigest, o.decisionAdapt, approval, input, bundleID,
				env.CatalogDigest, env.CatalogVersion, o.verdict, reasons, basis, serviceSession}},
	}
	if o.verdict == "allow" {
		steps = append(steps, struct {
			sql  string
			args []any
		}{`INSERT INTO decisions.execute_requests (decision_id, action_id, adapter_id, state, next_attempt_at, updated_at)
VALUES ($1, $2, $3, 'pending', statement_timestamp(), statement_timestamp())`, []any{decisionID, env.ActionID, o.decisionAdapt}})
	}
	for _, s := range steps {
		if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
			return stored{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return stored{}, err
	}
	return stored{DecisionID: decisionID, ActionID: actionID, Env: env, Content: content}, nil
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoadAllowDecision(t *testing.T) {
	p := admin(t)
	s := put(t, p, putOpts{summary: "synthetic " + newUUID()})
	in, err := reader(t, p).Load(context.Background(), s.DecisionID, s.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	d := in.Decision
	if d.DecisionID != s.DecisionID || d.ActionID != s.ActionID || d.RequestID != s.Env.RequestID ||
		d.ActionDigest != s.Env.ActionDigest || d.AdapterID != adapterID || d.Verdict != "allow" ||
		d.PolicyBundleID != bundleID || d.PolicyEpoch != 7 || d.CatalogDigest != s.Env.CatalogDigest ||
		time.Until(d.ExpiresAt) <= 0 || time.Until(d.ExpiresAt) > 11*time.Second || d.ServiceSessionID != "" {
		t.Fatalf("decision %+v", d)
	}
	if !reflect.DeepEqual(in.Envelope, s.Env) {
		t.Fatalf("envelope\n got %+v\nwant %+v", in.Envelope, s.Env)
	}
	if !reflect.DeepEqual(in.Content, s.Content) {
		t.Fatalf("content\n got %+v\nwant %+v", in.Content, s.Content)
	}
	// The engine preflight's own checks pass on what was read.
	if ad, err := canonical.ActionDigest(in.Envelope.HashObject()); err != nil || ad != d.ActionDigest {
		t.Fatalf("action_digest %s %v", ad, err)
	}
	if err := canonical.VerifyContent(in.Envelope, in.Content); err != nil {
		t.Fatal(err)
	}
}

func TestLoadNotFound(t *testing.T) {
	p := admin(t)
	s := put(t, p, putOpts{summary: "synthetic " + newUUID()})
	r := reader(t, p)
	for name, ids := range map[string][2]string{
		"unknown decision":      {newUUID(), s.ActionID},
		"decision of another":   {s.DecisionID, newUUID()},
		"action id as decision": {s.ActionID, s.ActionID},
		"not a uuid":            {"not-a-uuid", s.ActionID},
	} {
		if _, err := r.Load(context.Background(), ids[0], ids[1]); !errors.Is(err, execute.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A decision for another adapter is read, but the views show its envelope
// and content only to that adapter's login.
func TestLoadOtherAdapterReadsNoContent(t *testing.T) {
	p := admin(t)
	s := put(t, p, putOpts{summary: "synthetic " + newUUID(), decisionAdapt: "evidence-reader", contentAdapter: "evidence-reader"})
	in, err := reader(t, p).Load(context.Background(), s.DecisionID, s.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	if in.Decision.AdapterID != "evidence-reader" || in.Decision.DecisionID != s.DecisionID ||
		!reflect.DeepEqual(in.Envelope, canonical.ActionEnvelope{}) || !reflect.DeepEqual(in.Content, canonical.Content{}) {
		t.Fatalf("inputs %+v", in)
	}
}

// The views isolate adapters by login (decisions.adapter_db_roles and
// session_user), not by the reader's AdapterID: a login mapped to another
// adapter, or a login without a mapping, reads the receiver-sender decision
// row but no envelope or content, even with AdapterID receiver-sender. The
// views are also queried directly so the result does not depend on the
// reader skipping the content query.
func TestLoadIsolatedByLogin(t *testing.T) {
	p := admin(t)
	ctx := context.Background()
	s := put(t, p, putOpts{summary: "synthetic " + newUUID()})
	// The same decision is fully visible to the receiver-sender login.
	if in, err := reader(t, p).Load(ctx, s.DecisionID, s.ActionID); err != nil ||
		!reflect.DeepEqual(in.Envelope, s.Env) || !reflect.DeepEqual(in.Content, s.Content) {
		t.Fatalf("receiver-sender login: %+v %v", in, err)
	}
	for name, mapTo := range map[string]string{
		"login of another adapter": "evidence-reader",
		"unmapped login":           "",
	} {
		login := adapterLogin(t, p, mapTo)
		in, err := (&inputs.PG{Pool: login, AdapterID: adapterID}).Load(ctx, s.DecisionID, s.ActionID)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if in.Decision.DecisionID != s.DecisionID || in.Decision.AdapterID != adapterID || in.Decision.Verdict != "allow" {
			t.Fatalf("%s: decision %+v", name, in.Decision)
		}
		if !reflect.DeepEqual(in.Envelope, canonical.ActionEnvelope{}) || !reflect.DeepEqual(in.Content, canonical.Content{}) {
			t.Fatalf("%s: envelope %+v content %+v", name, in.Envelope, in.Content)
		}
		var envelopes, contents int
		if err := login.QueryRow(ctx, `SELECT
    (SELECT count(*) FROM decisions.adapter_action_envelopes WHERE action_id = $1),
    (SELECT count(*) FROM decisions.adapter_action_contents WHERE action_id = $1)`, s.ActionID).Scan(&envelopes, &contents); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if envelopes != 0 || contents != 0 {
			t.Fatalf("%s: %d envelope rows, %d content rows", name, envelopes, contents)
		}
	}
}

// adapter_action_contents hides an expired row and a row whose adapter_id is
// not the allow decision's; the reader also filters by its own adapter_id.
func TestLoadContentOfOtherAdapterOrExpiredIsMissing(t *testing.T) {
	p := admin(t)
	for name, o := range map[string]putOpts{
		"other adapter": {contentAdapter: "evidence-reader"},
		"expired":       {contentExpired: true},
	} {
		o.summary = "synthetic " + newUUID()
		s := put(t, p, o)
		in, err := reader(t, p).Load(context.Background(), s.DecisionID, s.ActionID)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(in.Content, canonical.Content{}) || in.Envelope.ContentDigest == nil {
			t.Fatalf("%s: content %+v", name, in.Content)
		}
		if canonical.VerifyContent(in.Envelope, in.Content) == nil {
			t.Fatalf("%s: missing content verified", name)
		}
	}
}

// Two actions with byte-identical content each have their own content row
// (key (content_digest, action_id)), and each reads its own.
func TestLoadSharedContentPerAction(t *testing.T) {
	p := admin(t)
	summary := "synthetic " + newUUID()
	first := put(t, p, putOpts{summary: summary})
	second := put(t, p, putOpts{summary: summary})
	if *first.Env.ContentDigest != *second.Env.ContentDigest {
		t.Fatal("content digests differ")
	}
	for _, s := range []stored{first, second} {
		in, err := reader(t, p).Load(context.Background(), s.DecisionID, s.ActionID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(in.Content, s.Content) {
			t.Fatalf("content\n got %+v\nwant %+v", in.Content, s.Content)
		}
		if err := canonical.VerifyContent(in.Envelope, in.Content); err != nil {
			t.Fatal(err)
		}
	}
}

// The CHECK on decisions.actions refuses an envelope jsonb that differs from
// the typed columns (SQLSTATE 23514), so the reader never sees one.
func TestInconsistentEnvelopeRefusedAtInsert(t *testing.T) {
	p := admin(t)
	for name, envelope := range map[string]string{
		"empty object": `{}`,
		"other data_class": func() string {
			s := put(t, p, putOpts{summary: "synthetic " + newUUID()})
			e := s.Env
			e.DataClass = "internal"
			return mustJSON(t, e)
		}(),
	} {
		_, err := tryPut(t, p, putOpts{summary: "synthetic " + newUUID(), envelopeJSON: envelope})
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "23514" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The database does not check the shape of the limits value; an envelope
// whose limits do not decode as integers is ErrInconsistent.
func TestLoadUndecodableEnvelope(t *testing.T) {
	p := admin(t)
	s := put(t, p, putOpts{summary: "synthetic " + newUUID(), limitsJSON: `{"max_bytes": 1.5}`})
	if _, err := reader(t, p).Load(context.Background(), s.DecisionID, s.ActionID); !errors.Is(err, inputs.ErrInconsistent) {
		t.Fatal(err)
	}
}

// adapter_action_envelopes has only actions with an allow decision: an
// action awaiting approval gives a zero envelope and no content.
func TestLoadWithoutAllowHasNoEnvelope(t *testing.T) {
	p := admin(t)
	s := put(t, p, putOpts{summary: "synthetic " + newUUID(), verdict: "approval_required"})
	in, err := reader(t, p).Load(context.Background(), s.DecisionID, s.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	if in.Decision.Verdict != "approval_required" || !reflect.DeepEqual(in.Envelope, canonical.ActionEnvelope{}) ||
		!reflect.DeepEqual(in.Content, canonical.Content{}) {
		t.Fatalf("inputs %+v", in)
	}
}

func TestLoadNormalizeStageDeny(t *testing.T) {
	p := admin(t)
	ctx := context.Background()
	actionID, decisionID := newUUID(), newUUID()
	if _, err := p.Exec(ctx, `
INSERT INTO decisions.actions (action_id, request_id, authenticated_actor, session_kind, session_id, workload_id,
    client_request_key, raw_body_digest, tenant, environment, operation_id, created_at)
VALUES ($1, gen_random_uuid(), 'user:alice@example.com', 'user', gen_random_uuid(), 'agent-runtime-0', 'req-00000001',
    repeat('a', 64), 'hackathon', 'test', 'receiver.submit', statement_timestamp())`, actionID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `
INSERT INTO decisions.decisions (decision_id, request_id, action_id, verdict, reason_codes, matched_rule_ids,
    evaluated_rule_ids, decision_stage, policy_bundle_id, catalog_digest, catalog_version, expires_at,
    authenticated_gateway, created_at)
VALUES ($1, gen_random_uuid(), $2, 'deny', '{CONTENT_PATTERN_DENIED}', '{normalize.content_pattern.v1}',
    '{normalize.content_pattern.v1}', 'normalize', $3, repeat('c', 64), 'test',
    statement_timestamp() + interval '10 seconds', 'gw', statement_timestamp())`, decisionID, actionID, bundleID); err != nil {
		t.Fatal(err)
	}
	in, err := reader(t, p).Load(ctx, decisionID, actionID)
	if err != nil {
		t.Fatal(err)
	}
	if in.Decision.Verdict != "deny" || in.Decision.AdapterID != "" || in.Decision.ActionDigest != "" ||
		in.Decision.PolicyEpoch != 0 || !reflect.DeepEqual(in.Envelope, canonical.ActionEnvelope{}) {
		t.Fatalf("inputs %+v", in)
	}
}

// The reader relies on decisions being immutable (trigger decisions_immutable).
func TestDecisionsImmutable(t *testing.T) {
	p := admin(t)
	s := put(t, p, putOpts{summary: "synthetic " + newUUID()})
	if _, err := p.Exec(context.Background(), `UPDATE decisions.decisions SET adapter_id = 'other' WHERE decision_id = $1`, s.DecisionID); err == nil ||
		!strings.Contains(err.Error(), "immutable") {
		t.Fatalf("update: %v", err)
	}
}

func TestCheckNeedsExactlyTheReaderGrants(t *testing.T) {
	p := admin(t)
	r := reader(t, p)
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	// adapter_reader has no grant on the tables behind the views or on the
	// login mapping (revoked from adapter_reader and PUBLIC).
	for _, table := range []string{"decisions.actions", "decisions.action_contents", "decisions.decision_inputs",
		"decisions.execute_requests", "decisions.intent_checks", "decisions.adapter_db_roles"} {
		rows, err := r.Pool.Query(context.Background(), `SELECT 1 FROM `+table+` LIMIT 0`)
		if err == nil {
			rows.Close()
			err = rows.Err()
		}
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("%s as %s: %v", table, readerRole, err)
		}
	}
	// coordinator_app may read decisions.decisions only (#46): the reader's
	// view query fails at startup instead of at the first execution.
	coord := &inputs.PG{Pool: poolAs(t, "coordinator_app"), AdapterID: adapterID}
	if err := coord.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("coordinator_app check: %v", err)
	}
}

// decisions.service_session_id is read into Decision.ServiceSessionID in the
// canonical lowercase form (the column is uuid). The preflight compares it
// with a service session envelope's session_id.
func TestLoadServiceSessionID(t *testing.T) {
	p := admin(t)
	ss := newUUID()
	s := put(t, p, putOpts{summary: "synthetic " + newUUID(), serviceSession: strings.ToUpper(ss)})
	in, err := reader(t, p).Load(context.Background(), s.DecisionID, s.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	if in.Decision.ServiceSessionID != ss {
		t.Fatalf("service_session_id %q want %q", in.Decision.ServiceSessionID, ss)
	}
	// A login mapped to another adapter reads the same decision column.
	other := &inputs.PG{Pool: adapterLogin(t, p, "evidence-reader"), AdapterID: "evidence-reader"}
	if in, err := other.Load(context.Background(), s.DecisionID, s.ActionID); err != nil || in.Decision.ServiceSessionID != ss {
		t.Fatalf("other login: %+v %v", in.Decision, err)
	}
	// Check covers the column.
	if err := reader(t, p).Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}
