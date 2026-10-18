//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/open-policy-agent/opa/v1/bundle"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/consoleauth"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/sessions"
)

// The M3-1 identity wiring on PostgreSQL 16: every migration is installed by
// a non-superuser installer (and the two M3-1 migrations go down and up
// again), identity runs as a restricted identity_app login, and the routes
// are the ones registerAPIs builds for main: consoleauth with a fake JWKS,
// policyloader with a signed bundle (local fetcher instead of GCS),
// release.active_policy, the approval views, ReleaseEpochs and PGAuditor.
//
// Needs a fresh, disposable cluster (roles are cluster-wide):
//
//	IDENTITY_WIRING_TEST_ADMIN_DSN=postgres://postgres@127.0.0.1:<port>/postgres?sslmode=disable \
//	  go test -tags integration -run TestWiredAPIsPostgres ./services/identity/cmd/identity
//
// tests/identity/run-wiring-local.sh starts such a cluster.
func TestWiredAPIsPostgres(t *testing.T) {
	dsn := os.Getenv("IDENTITY_WIRING_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable IDENTITY_WIRING_TEST_ADMIN_DSN")
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
			t.Fatalf("%.80s: %v", sql, err)
		}
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	dbName, installer, app := "idwire_"+suffix, "idwireinst_"+suffix, "idwireapp_"+suffix
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
	// TASK-10's role must exist before the identity migration (TASK-16 step 2).
	run(owner, "DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$")

	// Migrations up, the two M3-1 migrations down, and up again.
	files, err := filepath.Glob("../../../../migrations/*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatal("no migrations", err)
	}
	sort.Strings(files)
	apply := func(path string) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
	}
	for _, f := range files {
		apply(f)
	}
	m3 := []string{"20261018092000_release_active_policy", "20261018092001_gateway_approval_contract_actions"}
	exists := func() (bool, bool) {
		var table, view bool
		if err := owner.QueryRow(ctx, "SELECT to_regclass('release.active_policy') IS NOT NULL, to_regclass('decisions.approval_contract_actions') IS NOT NULL").Scan(&table, &view); err != nil {
			t.Fatal(err)
		}
		return table, view
	}
	if table, view := exists(); !table || !view {
		t.Fatal("M3-1 objects missing after up")
	}
	for i := len(m3) - 1; i >= 0; i-- {
		apply("../../../../migrations/" + m3[i] + ".down.sql")
	}
	if table, view := exists(); table || view {
		t.Fatal("M3-1 objects left after down")
	}
	var leftover bool
	if err := owner.QueryRow(ctx, "SELECT has_table_privilege('identity_app', 'release.desired_bundle', 'SELECT')").Scan(&leftover); err != nil || leftover {
		t.Fatalf("desired_bundle grant left after down: %v %v", leftover, err)
	}
	for _, m := range m3 {
		apply("../../../../migrations/" + m + ".up.sql")
	}

	// identity runs as a restricted login: identity_app (and through it
	// audit_producer), registered as audit source identity-test.
	run(admin, "GRANT identity_app TO "+app)
	// TASK-16 step 3 registrations are made by the database administrator.
	inspect := connect(admin.Config().User)
	run(inspect, "INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES($1,'identity-test',false)", app)
	for _, ev := range []string{"session_created", "session_claimed", "contract_created", "approval_granted"} {
		run(inspect, "INSERT INTO audit.producer_event_grants VALUES('identity-test',$1,'hackathon')", ev)
	}
	run(owner, "INSERT INTO identity.registered_workloads(namespace,ksa,role) VALUES('agent-exec','agent-runtime','runtime')")
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
		"UPDATE release.active_policy SET updated_at = now()",
		"INSERT INTO release.active_policy VALUES ('x',1,'b',repeat('a',64),repeat('a',64),'r',repeat('a',64),repeat('b',64),gen_random_uuid(),now())",
		"SELECT count(*) FROM decisions.actions",
		"SELECT * FROM release.lock_active_policy('test')",
	} {
		if _, err := pool.Exec(ctx, denied); err == nil || !strings.Contains(err.Error(), "42501") {
			t.Fatalf("identity_app allowed %q: %v", denied, err)
		}
	}

	// Signed bundle, desired_bundle row (read by identity_app through
	// policyloader.PGSource) and the first active_policy epoch.
	pol := newSignedBundle(t, "rev-a")
	run(owner, `INSERT INTO release.desired_bundle(environment,bundle_id,artifact_digest,object_uri,set_by_change_id,set_at)
VALUES ('test',$1,$2,$3,gen_random_uuid(),now())`, pol.bundleID, pol.artifactDigest, pol.objectURI)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	loader, err := newLoader(logger, pool, pol, "test", "prod-v1", pol.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := loader.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	activate := func(epoch int64, bundleID, artifact, revision string) {
		t.Helper()
		if epoch == 1 {
			run(owner, `INSERT INTO release.active_policy VALUES ('test',1,$1,$2,$2,$3,$4,repeat('b',64),gen_random_uuid(),now())`, bundleID, artifact, revision, pol.catalogDigest)
			return
		}
		run(owner, `UPDATE release.active_policy SET epoch=$1, bundle_id=$2, artifact_digest=$3, bundle_digest=$3, expected_opa_revision=$4, updated_at=now() WHERE scope_id='test'`,
			epoch, bundleID, artifact, revision)
	}

	// The wired routes behind TLS with optional client certificates, as main.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	console, err := apiFlags{audiences: listFlag{gcloudAudience}, domains: listFlag{"example.org"}, roleMap: writeRoleMap(t)}.console(staticKeys{"k1": &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := sessions.NewPGAuditor(sessions.AuditConfig{SourceID: "identity-test", Version: "test", Epoch: "1"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAPIs(mux, apiDeps{Pool: pool, Loader: loader, Console: console, Audit: auditor, Environment: "test",
		ClaimKey: []byte(strings.Repeat("k", 32)), GatewaySAN: "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"})
	srv, consoleClient, runtimeClient := tlsServer(t, mux)

	alice := idToken(t, key, map[string]any{})
	call := func(c *http.Client, method, path, token string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, srv.URL+path, rd)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	reason := func(out map[string]any) string {
		codes, _ := out["reason_codes"].([]any)
		if len(codes) == 0 {
			return ""
		}
		s, _ := codes[0].(string)
		return s
	}
	create := map[string]any{"workload_id": "agent-exec/agent-runtime", "task_statement": "send a summary",
		"requested_scope": map[string]any{"operation_ids": []string{"receiver.submit"}, "target_ids": []string{"receiver-primary"}}}

	// Console authentication: no token, a bad signature, another aud, another
	// domain and an expired token are 401 AUTH_REQUIRED.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{
		"missing token": "",
		"bad signature": idToken(t, other, map[string]any{}),
		"wrong aud":     idToken(t, key, map[string]any{"aud": "other.apps.googleusercontent.com", "azp": "other.apps.googleusercontent.com"}),
		"wrong hd":      idToken(t, key, map[string]any{"hd": "evil.example", "email": "alice@evil.example"}),
		"expired":       idToken(t, key, map[string]any{"exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix()}),
	} {
		if status, out := call(consoleClient, "POST", "/v1/sessions", tok, create); status != http.StatusUnauthorized || reason(out) != "AUTH_REQUIRED" {
			t.Fatalf("%s: %d %v", name, status, out)
		}
		if status, _ := call(consoleClient, "GET", "/v1/approvals/pending", tok, nil); status != http.StatusUnauthorized {
			t.Fatalf("%s pending: %d", name, status)
		}
	}

	// Loaded but not yet active: no session.
	if status, out := call(consoleClient, "POST", "/v1/sessions", alice, create); status != http.StatusServiceUnavailable || reason(out) != "POLICY_UNAVAILABLE" {
		t.Fatalf("no active_policy: %d %v", status, out)
	}
	activate(1, pol.bundleID, pol.artifactDigest, pol.revision)

	// A valid ID token creates the session (200 with the claim code).
	status, cr := call(consoleClient, "POST", "/v1/sessions", alice, create)
	if status != http.StatusOK || cr["session_id"] == nil || cr["claim_code"] == nil {
		t.Fatalf("create: %d %v", status, cr)
	}
	sessionID := cr["session_id"].(string)
	if status, out := call(runtimeClient, "POST", "/v1/sessions/"+sessionID+":claim", "", map[string]any{"claim_code": cr["claim_code"]}); status != http.StatusOK || out["token"] == nil {
		t.Fatalf("claim: %d %v", status, out)
	}
	actionID := insertAction(t, owner, sessionID)

	contract := func() map[string]any {
		t.Helper()
		status, out := call(consoleClient, "GET", "/v1/actions/"+actionID+"/approval-contract", alice, nil)
		if status != http.StatusOK || out["nonce"] == nil {
			t.Fatalf("contract: %d %v", status, out)
		}
		return out
	}
	approve := func(c map[string]any) (int, map[string]any) {
		return call(consoleClient, "POST", "/v1/approvals", alice, map[string]any{
			"action_id": actionID, "displayed_contract_digest": c["contract_digest"], "nonce": c["nonce"]})
	}

	// The epoch CAS moves to a bundle identity has not loaded between the
	// contract and the approval: 503 POLICY_VERSION_MISMATCH, nothing stored.
	c := contract()
	activate(2, "bundle-b", strings.Repeat("b", 64), "rev-b")
	if status, out := approve(c); status != http.StatusServiceUnavailable || reason(out) != "POLICY_VERSION_MISMATCH" {
		t.Fatalf("approve after epoch CAS: %d %v", status, out)
	}
	if status, out := call(consoleClient, "GET", "/v1/actions/"+actionID+"/approval-contract", alice, nil); status != http.StatusServiceUnavailable || reason(out) != "POLICY_VERSION_MISMATCH" {
		t.Fatalf("contract under another bundle: %d %v", status, out)
	}
	var approvals int
	if err := owner.QueryRow(ctx, "SELECT count(*) FROM identity.approvals").Scan(&approvals); err != nil || approvals != 0 {
		t.Fatalf("approvals stored on mismatch: %d %v", approvals, err)
	}

	// Rolling back to the loaded bundle is a new epoch (3); the approval is
	// recorded under it.
	activate(3, pol.bundleID, pol.artifactDigest, pol.revision)
	status, out := approve(contract())
	if status != http.StatusOK || out["policy_epoch"] != float64(3) {
		t.Fatalf("approve: %d %v", status, out)
	}

	// Every state change has its AuditEvent from source identity-test.
	rows, err := inspect.Query(ctx, "SELECT event_type FROM audit.audit_events WHERE source_id='identity-test' AND source_epoch='1' ORDER BY event_type")
	if err != nil {
		t.Fatal(err)
	}
	events, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(events, ","); got != "approval_granted,contract_created,contract_created,session_claimed,session_created" {
		t.Fatalf("audit events: %s", got)
	}
}

const gcloudAudience = "32555940559.apps.googleusercontent.com"

// staticKeys is the fake JWKS injected through consoleauth.Config.Keys.
type staticKeys map[string]*rsa.PublicKey

func (k staticKeys) Key(_ context.Context, kid string) (*rsa.PublicKey, error) {
	if key, ok := k[kid]; ok {
		return key, nil
	}
	return nil, errors.New("unknown kid")
}

var _ consoleauth.KeySource = staticKeys{}

func writeRoleMap(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "role-map.yaml")
	if err := os.WriteFile(p, []byte("tenant: hackathon\nusers:\n  - email: alice@example.org\n    roles: [approver]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// idToken is a gcloud-style Google user ID token for alice, with overrides.
func idToken(t *testing.T, key *rsa.PrivateKey, override map[string]any) string {
	t.Helper()
	now := time.Now()
	c := map[string]any{
		"iss": "https://accounts.google.com", "sub": "1001", "aud": gcloudAudience, "azp": gcloudAudience,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(), "auth_time": now.Add(-time.Minute).Unix(),
		"hd": "example.org", "email": "alice@example.org", "email_verified": true,
	}
	for k, v := range override {
		c[k] = v
	}
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	b, _ := json.Marshal(c)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// signedBundle is an ES256-signed OPA bundle served by a local Fetcher in
// place of GCS; loading, signature checks and the catalog are production code.
type signedBundle struct {
	mu                                                           sync.Mutex
	object                                                       []byte
	publicKey                                                    string
	bundleID, artifactDigest, objectURI, revision, catalogDigest string
}

func (b *signedBundle) Fetch(_ context.Context, uri string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if uri != b.objectURI {
		return nil, fmt.Errorf("unknown object %s", uri)
	}
	return append([]byte(nil), b.object...), nil
}

func newSignedBundle(t *testing.T, revision string) *signedBundle {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := canonical.LoadCatalogDir("../../../../packages/canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	var catalog any
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	rules := map[string]any{"standing.k8s_read.v1": map[string]any{"standing_rule_id": "standing.k8s_read.v1", "session_kind": "user",
		"operation_ids": []string{"k8s.pods.list", "k8s.pods.logs"}, "target_pattern": "k8s-agent-targets", "session_budget": 10}}
	b := bundle.Bundle{Manifest: bundle.Manifest{Revision: revision}, Data: map[string]any{"catalog": catalog, "standing_rules": rules}}
	signing := bundle.NewSigningConfig(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})), "ES256", "")
	if err := b.GenerateSignature(signing, "prod-v1", false); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := bundle.NewWriter(&buf).Write(b); err != nil {
		t.Fatal(err)
	}
	digest := canonical.SHA256Hex(buf.Bytes())
	return &signedBundle{
		object: buf.Bytes(), publicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})),
		bundleID: "bundle-a", artifactDigest: digest, objectURI: "gs://agentarium-test/bundles/" + digest + ".tar.gz",
		revision: revision, catalogDigest: cat.CatalogDigest,
	}
}

// tlsServer serves h like main (TLS 1.3, client certificates optional) and
// returns a console client without a certificate and a runtime Pod client.
func tlsServer(t *testing.T, h http.Handler) (*httptest.Server, *http.Client, *http.Client) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	podKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	san, _ := url.Parse("spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/p1")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, URIs: []*url.URL{san},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &podKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	s.StartTLS()
	t.Cleanup(s.Close)
	consoleClient := s.Client()
	consoleClient.Timeout = 10 * time.Second
	runtimeClient := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      consoleClient.Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: podKey}},
	}}}
	return s, consoleClient, runtimeClient
}

// insertAction writes a user-session receiver.submit action with an
// approval_required decision as the gateway does (envelope = columns).
func insertAction(t *testing.T, owner *pgx.Conn, sessionID string) string {
	t.Helper()
	ctx := context.Background()
	actionID := uuid.NewString()
	digest := strings.Repeat("c", 64)
	workload := "agent-exec/agent-runtime"
	content := []byte(`{"summary":"synthetic"}`)
	env := canonical.ActionEnvelope{
		SchemaVersion: "1", ActionID: actionID, RequestID: uuid.NewString(), AuthenticatedActor: "google:1001",
		SessionKind: "user", SessionID: sessionID, WorkloadID: &workload, EndpointID: "test-receiver-v1",
		OperationID: "receiver.submit", CanonicalTarget: canonical.CanonicalTarget{TargetID: "receiver-primary", RouteID: "submissions-v1"},
		Environment: "test", Tenant: "hackathon", DisclosureFields: []string{"summary"}, DataClass: "synthetic",
		DataSources: []string{}, ContentDigest: &digest, ContentRef: &digest, Bytes: int64(len(content)), Limits: map[string]int64{},
		CatalogDigest: strings.Repeat("d", 64), CatalogVersion: "test", CanonicalizationVersion: "v1",
		RawBodyDigest: strings.Repeat("a", 64), ActionDigest: strings.Repeat("e", 64),
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
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
VALUES ($1, $2, 'google:1001', 'user', $3, 'agent-exec/agent-runtime', $4, $5, 'hackathon', 'test',
    'receiver.submit', '1', 'test-receiver-v1', $6, '{summary}', 'synthetic', '{}', $7, $7, $8, '{}',
    $9, 'test', 'v1', $10, $11, statement_timestamp())`,
			[]any{actionID, env.RequestID, sessionID, "key-" + actionID[:8], strings.Repeat("a", 64),
				`{"target_id": "receiver-primary", "route_id": "submissions-v1"}`, digest, len(content),
				strings.Repeat("d", 64), strings.Repeat("e", 64), string(envJSON)}},
		{`INSERT INTO decisions.action_contents (content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)
VALUES ($1, 'hackathon', $2, 'receiver', $3, statement_timestamp(), statement_timestamp() + interval '30 days')`,
			[]any{digest, actionID, content}},
		{`INSERT INTO decisions.decision_inputs (decision_input_digest, tenant, sanitized_input, policy_bundle_id, created_at)
VALUES ($1, 'hackathon', '{}', 'bundle-a', statement_timestamp()) ON CONFLICT (decision_input_digest) DO NOTHING`,
			[]any{strings.Repeat("f", 64)}},
		{`INSERT INTO decisions.decisions (decision_id, request_id, action_id, action_digest, adapter_id, verdict, reason_codes,
    decision_basis, standing_rule_id, matched_rule_ids, evaluated_rule_ids, rego_result, decision_stage,
    decision_input_ref, decision_input_digest, policy_bundle_id, policy_epoch, opa_bundle_revision, catalog_digest,
    catalog_version, expires_at, authenticated_gateway, created_at)
VALUES (gen_random_uuid(), gen_random_uuid(), $1, $2, NULL, 'approval_required', '{APPROVAL_REQUIRED}', NULL, NULL,
    '{approval.required_default.v1}', '{session.binding.v1}',
    '{"verdict":"approval_required","reason_codes":["APPROVAL_REQUIRED"],"matched_rule_ids":["approval.required_default.v1"]}',
    'opa', $3, $3, 'bundle-a', 1, 'rev-a', $4, 'test', statement_timestamp() + interval '10 seconds',
    'spiffe://agentarium.internal/ns/agent-gateway/sa/gateway', statement_timestamp())`,
			[]any{actionID, strings.Repeat("e", 64), strings.Repeat("f", 64), strings.Repeat("d", 64)}},
	}
	for _, s := range steps {
		if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("%.60s: %v", s.sql, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return actionID
}
