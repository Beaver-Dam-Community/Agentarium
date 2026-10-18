//go:build integration

package sessions

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires an explicitly disposable cluster. No IAM, production schema, epoch
// allocator, console BFF or policy-source wiring is exercised by this fixture.
func TestPGAuditorPostgres(t *testing.T) {
	dsn := os.Getenv("IDENTITY_AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable IDENTITY_AUDIT_TEST_ADMIN_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	exec := func(c *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("SQL failed: %v", err)
		}
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	dbName, installer, writer := "idauditdb_"+suffix, "idauditinst_"+suffix, "idauditwriter_"+suffix
	groups := []string{"control_health_writer", "coordinator_app", "identity_app", "gateway_app", "audit_owner", "audit_producer", "audit_writer", "audit_exporter"}
	var createdGroups []string
	for _, name := range groups {
		var exists bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)", name).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			createdGroups = append(createdGroups, name)
		}
	}
	exec(admin, "CREATE ROLE "+installer+" LOGIN NOSUPERUSER NOCREATEDB CREATEROLE")
	exec(admin, "CREATE ROLE "+writer+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	exec(admin, "CREATE DATABASE "+dbName+" OWNER "+installer)
	defer func() {
		cleanup := context.Background()
		_, _ = admin.Exec(cleanup, "DROP DATABASE "+dbName+" WITH (FORCE)")
		for _, name := range append(append([]string{writer}, createdGroups...), installer) {
			if _, err := admin.Exec(cleanup, "DROP ROLE "+pgx.Identifier{name}.Sanitize()); err != nil {
				t.Errorf("cleanup role %s: %v", name, err)
			}
		}
	}()
	connect := func(user string) *pgx.Conn {
		t.Helper()
		cfg, e := pgx.ParseConfig(dsn)
		if e != nil {
			t.Fatal(e)
		}
		cfg.Database, cfg.User = dbName, user
		c, e := pgx.ConnectConfig(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	install := connect(installer)
	inspect := connect(admin.Config().User)
	// These existing prerequisite NOLOGIN roles have no privileges in this DB.
	for _, name := range []string{"control_health_writer", "coordinator_app"} {
		exec(install, "DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='"+name+"') THEN CREATE ROLE "+name+" NOLOGIN; END IF; END $$")
	}
	for _, name := range []string{"20261014144500_identity_workload_pki.up.sql", "20261016120000_identity_sessions_tokens.up.sql", "20261016132230_audit_store.up.sql", "20261016175130_identity_approvals.up.sql", "20261017105252_audit_application_membership.up.sql"} {
		raw, e := os.ReadFile(filepath.Join("../../../../migrations", name))
		if e != nil {
			t.Fatal(e)
		}
		exec(install, string(raw))
	}
	exec(admin, "GRANT identity_app TO "+writer)
	exec(inspect, "INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES($1,'identity-test',false)", writer)
	exec(inspect, "INSERT INTO audit.producer_event_grants VALUES('identity-test','service_session_created','tenant-a')")
	exec(inspect, "INSERT INTO identity.registered_workloads(namespace,ksa,role,service_principal) VALUES('agent-release','releaser','service','releaser')")
	pc, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	pc.ConnConfig.Database, pc.ConnConfig.User = dbName, writer
	pc.MaxConns = 2
	pool, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	var isSuper, canCreateRole, hasOwner bool
	if err := pool.QueryRow(ctx, "SELECT rolsuper,rolcreaterole,pg_has_role(current_user,'audit_owner','MEMBER') FROM pg_roles WHERE rolname=current_user").Scan(&isSuper, &canCreateRole, &hasOwner); err != nil || isSuper || canCreateRole || hasOwner {
		t.Fatalf("runtime privileges: %v %v %v %v", isSuper, canCreateRole, hasOwner, err)
	}
	auditor, e := NewPGAuditor(AuditConfig{SourceID: "identity-test", Version: "test-v1", Epoch: "installed-counter-1"})
	if e != nil {
		t.Fatal(e)
	}
	svc := &Service{Pool: pool, Audit: auditor}
	mux := http.NewServeMux()
	(&Handler{Svc: svc}).Register(mux)
	server, client := auditMTLSServer(t, mux)
	request := func(tenant string, max, used int) (int, []byte) {
		t.Helper()
		raw, e := json.Marshal(map[string]any{"profile": "activation_probe", "change_id": uuid.NewString(), "tenant": tenant, "tool_budget": map[string]any{"probe_actions": map[string]int{"max": max, "used": used}}})
		if e != nil {
			t.Fatal(e)
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/internal/service-sessions", bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		body, e := io.ReadAll(resp.Body)
		if e != nil {
			t.Fatal(e)
		}
		if resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "2" {
			t.Fatal("missing retry hint")
		}
		return resp.StatusCode, body
	}
	counts := func() [6]int {
		t.Helper()
		var got [6]int
		for i, table := range []string{"identity.service_sessions", "identity.service_session_counters", "identity.session_tokens", "audit.audit_events", "audit.audit_outbox", "audit.event_conflicts"} {
			if e := inspect.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&got[i]); e != nil {
				t.Fatal(e)
			}
		}
		return got
	}
	t.Run("activation_HTTP_budget_event_and_counter_commit", func(t *testing.T) {
		status, body := request("tenant-a", 99, 0)
		if status != http.StatusOK {
			t.Fatalf("status=%d body=%s", status, body)
		}
		var response ServiceResponse
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		if response.ToolBudget == nil || response.ToolBudget.ProbeActions == nil || response.ToolBudget.ProbeActions.Max != 4 || response.ToolBudget.ProbeActions.Used != 0 || response.Token == "" {
			t.Fatal("incorrect applied budget/token")
		}
		var payload []byte
		var maximum, used int
		var tenant, source, version, epoch, actor string
		var unsequenced, clockOK bool
		if err := inspect.QueryRow(ctx, `SELECT a.safe_payload,c.max_value,c.used_value,a.tenant,a.source_id,a.source_version,a.source_epoch,a.authenticated_actor,a.source_sequence IS NULL,a.source_time<=a.received_at
FROM audit.audit_events a JOIN identity.service_sessions s ON a.session_id=s.service_session_id JOIN identity.service_session_counters c USING(service_session_id) WHERE s.service_session_id=$1`, response.ServiceSessionID).Scan(&payload, &maximum, &used, &tenant, &source, &version, &epoch, &actor, &unsequenced, &clockOK); err != nil {
			t.Fatal(err)
		}
		var event struct {
			ServiceSessionID string         `json:"service_session_id"`
			ToolBudget       *ToolBudget    `json:"tool_budget"`
			Counters         map[string]int `json:"counters"`
		}
		if err := json.Unmarshal(payload, &event); err != nil {
			t.Fatal(err)
		}
		if maximum != 4 || used != 0 || event.Counters["probe_actions"] != maximum || !reflect.DeepEqual(event.ToolBudget, response.ToolBudget) || event.ServiceSessionID != response.ServiceSessionID || tenant != "tenant-a" || source != "identity-test" || version != "test-v1" || epoch != "installed-counter-1" || actor != "service:agent-release/releaser" || !unsequenced || !clockOK {
			t.Fatal("API/event/counter/source values diverged")
		}
		if got := counts(); got != ([6]int{1, 1, 1, 1, 1, 0}) {
			t.Fatalf("partial commit: %v", got)
		}
	})
	expectRollback := func(t *testing.T, tenant string, max, used, status int) {
		t.Helper()
		before := counts()
		got, body := request(tenant, max, used)
		if got != status {
			t.Fatalf("HTTP=%d want%d", got, status)
		}
		if status == http.StatusServiceUnavailable {
			var envelope errorBody
			if err := json.Unmarshal(body, &envelope); err != nil || !reflect.DeepEqual(envelope.ReasonCodes, []string{"STATE_STORE_UNAVAILABLE"}) {
				t.Fatalf("database failure response: %s %v", body, err)
			}
		}
		if after := counts(); after != before {
			t.Fatalf("partial state before%v after%v", before, after)
		}
	}
	t.Run("invalid_budget_before_audit", func(t *testing.T) { expectRollback(t, "tenant-a", 4, 1, 422) })
	t.Run("tenant_grant_exact_not_wildcard", func(t *testing.T) { expectRollback(t, "tenant-other", 4, 0, 503) })
	t.Run("missing_event_grant", func(t *testing.T) {
		exec(inspect, "DELETE FROM audit.producer_event_grants")
		defer exec(inspect, "INSERT INTO audit.producer_event_grants VALUES('identity-test','service_session_created','tenant-a')")
		expectRollback(t, "tenant-a", 4, 0, 503)
	})
	t.Run("audit_schema_rejection_is_store_failure", func(t *testing.T) {
		exec(inspect, `UPDATE audit.event_types SET required_payload_fields=required_payload_fields || '["missing_server_field"]'::jsonb WHERE event_type='service_session_created'`)
		defer exec(inspect, `UPDATE audit.event_types SET required_payload_fields=required_payload_fields - 'missing_server_field' WHERE event_type='service_session_created'`)
		expectRollback(t, "tenant-a", 4, 0, 503)
	})
	t.Run("source_impersonation_denied", func(t *testing.T) {
		wrong, e := NewPGAuditor(AuditConfig{"other-source", "test-v1", "epoch"})
		if e != nil {
			t.Fatal(e)
		}
		svc.Audit = wrong
		defer func() { svc.Audit = auditor }()
		expectRollback(t, "tenant-a", 4, 0, 503)
	})
	t.Run("audit_outbox_failure_rolls_back_all", func(t *testing.T) {
		exec(inspect, `CREATE FUNCTION audit.reject_test_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected outbox failure'; END $$; CREATE TRIGGER reject_test_outbox BEFORE INSERT ON audit.audit_outbox FOR EACH ROW EXECUTE FUNCTION audit.reject_test_outbox()`)
		defer exec(inspect, "DROP TRIGGER reject_test_outbox ON audit.audit_outbox; DROP FUNCTION audit.reject_test_outbox()")
		expectRollback(t, "tenant-a", 4, 0, 503)
	})
	t.Run("deferred_commit_failure_rolls_back_audit", func(t *testing.T) {
		exec(inspect, `CREATE FUNCTION identity.reject_test_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$; CREATE CONSTRAINT TRIGGER reject_test_commit AFTER INSERT ON identity.service_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity.reject_test_commit()`)
		defer exec(inspect, "DROP TRIGGER reject_test_commit ON identity.service_sessions; DROP FUNCTION identity.reject_test_commit()")
		expectRollback(t, "tenant-a", 4, 0, 503)
	})
	t.Run("conflict_incident_after_business_rollback", func(t *testing.T) {
		var id, digest string
		if e := inspect.QueryRow(ctx, "SELECT event_id::text,payload_digest FROM audit.audit_events LIMIT 1").Scan(&id, &digest); e != nil {
			t.Fatal(e)
		}
		auditor.newID = func() string { return id }
		defer func() { auditor.newID = uuid.NewString }()
		before := counts()
		status, body := request("tenant-a", 4, 0)
		if status != 409 || !bytes.Contains(body, []byte("EVENT_ID_CONFLICT")) {
			t.Fatalf("conflict status%d %s", status, body)
		}
		want := before
		want[5]++
		if got := counts(); got != want {
			t.Fatalf("business not rolled back before incident: %v want%v", got, want)
		}
		var unchanged bool
		if e := inspect.QueryRow(ctx, "SELECT payload_digest=$2 FROM audit.audit_events WHERE event_id=$1", id, digest).Scan(&unchanged); e != nil || !unchanged {
			t.Fatal("original event changed")
		}
		exec(inspect, `CREATE FUNCTION audit.reject_test_incident() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected incident failure'; END $$; CREATE TRIGGER reject_test_incident BEFORE INSERT ON audit.event_conflicts FOR EACH ROW EXECUTE FUNCTION audit.reject_test_incident()`)
		defer exec(inspect, "DROP TRIGGER reject_test_incident ON audit.event_conflicts; DROP FUNCTION audit.reject_test_incident()")
		expectRollback(t, "tenant-a", 4, 0, 503)
	})
	t.Run("identical_append_duplicate_within_transaction", func(t *testing.T) {
		id := uuid.NewString()
		auditor.newID = func() string { return id }
		defer func() { auditor.newID = uuid.NewString }()
		ev := Event{Tenant: "tenant-a", Type: "service_session_created", Actor: "service:agent-release/releaser", Payload: map[string]any{"service_session_id": uuid.NewString(), "caller_principal": "releaser", "tool_budget": map[string]any{}, "counters": map[string]int{"probe_actions": 4}}}
		before := counts()
		if err := InTx(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
			if e := auditor.Append(ctx, tx, ev); e != nil {
				return e
			}
			return auditor.Append(ctx, tx, ev)
		}); err != nil {
			t.Fatal(err)
		}
		want := before
		want[3]++
		want[4]++
		if got := counts(); got != want {
			t.Fatalf("duplicate created extra rows: %v want%v", got, want)
		}
	})
	t.Run("explicit_query_references", func(t *testing.T) {
		exec(inspect, "INSERT INTO audit.producer_event_grants VALUES('identity-test','contract_created','tenant-a')")
		action, session := uuid.NewString(), uuid.NewString()
		ev := Event{Tenant: "tenant-a", Type: "contract_created", Actor: "google:operator", ActionID: action, SessionID: session, WorkloadID: "agent-exec/agent-runtime", Payload: map[string]any{"action_id": action, "contract_digest": strings.Repeat("a", 64), "displayed_contract_digest": strings.Repeat("a", 64), "contract_version": "1", "workload_id": "must-not-be-promoted"}}
		if err := InTx(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error { return auditor.Append(ctx, tx, ev) }); err != nil {
			t.Fatal(err)
		}
		var storedSession, workload string
		if err := inspect.QueryRow(ctx, "SELECT session_id::text, workload_id FROM audit.audit_events WHERE action_id=$1", action).Scan(&storedSession, &workload); err != nil || storedSession != session || workload != ev.WorkloadID {
			t.Fatalf("indexed audit references lost or taken from payload: %s %s %v", storedSession, workload, err)
		}
	})
	t.Run("runtime_base_table_and_owner_denied", func(t *testing.T) {
		for _, sql := range []string{"SELECT * FROM audit.audit_events", "SELECT * FROM audit.audit_outbox", "DELETE FROM audit.audit_events", "UPDATE audit.producer_event_grants SET tenant='*'", "SET ROLE audit_owner", "CREATE TABLE audit.unauthorized(id integer)"} {
			if _, err := pool.Exec(ctx, sql); err == nil {
				t.Fatalf("allowed %s", sql)
			}
		}
	})
}

func auditMTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://agentarium.internal/ns/agent-release/sa/releaser")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parsed, &clientKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	s.StartTLS()
	t.Cleanup(s.Close)
	c := s.Client()
	c.Timeout = 10 * time.Second
	c.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: clientKey}}
	return s, c
}

func TestPGAuditorConfiguration(t *testing.T) {
	for _, config := range []AuditConfig{{}, {SourceID: "source", Version: "v"}, {SourceID: "source", Version: "v", Epoch: "\xff"}} {
		if _, err := NewPGAuditor(config); err == nil {
			t.Fatal("invalid trusted configuration accepted")
		}
	}
	a, err := NewPGAuditor(AuditConfig{"source", "v", "epoch"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Append(context.Background(), nil, Event{}); err == nil || errors.Is(err, ErrAuditUnwired) {
		t.Fatal("incomplete call accepted")
	}
}
