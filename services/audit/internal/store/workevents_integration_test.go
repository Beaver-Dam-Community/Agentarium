package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// testWorkEventsPostgres runs POST /internal/audit/work-events over real
// mTLS against the migrated database with the real writer role: the event is
// committed with the server-derived source/tenant/session/workload, the ack is
// the stored received_at, a retry is a duplicate, and wrong callers store
// nothing. The CA is local; no identity or gateway service is simulated as
// verified (the gateway's forwarded context is the request body).
func testWorkEventsPostgres(t *testing.T, store Store, db *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	const (
		gatewaySAN = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"
		runtimeSAN = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f"
		source     = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime"
	)
	for _, typ := range []string{"agent_work_start_requested", "agent_work_started", "agent_work_finished"} {
		if _, err := db.Exec(ctx, "INSERT INTO audit.producer_event_grants VALUES ($1,$2,'tenant-a')", source, typ); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local integration CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if ca, err = x509.ParseCertificate(caDER); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	issue := func(name, san string, serial int64, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(san)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, DNSNames: []string{"localhost"}, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
		if err := os.WriteFile(certPath, cp, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, kp, 0600); err != nil {
			t.Fatal(err)
		}
		cert, err := tls.X509KeyPair(cp, kp)
		if err != nil {
			t.Fatal(err)
		}
		return cert, certPath, keyPath
	}
	_, certPath, keyPath := issue("server", "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer", 2, x509.ExtKeyUsageServerAuth)
	gateway, _, _ := issue("gateway", gatewaySAN, 3, x509.ExtKeyUsageClientAuth)
	coordinator, _, _ := issue("coordinator", "spiffe://agentarium.internal/ns/agent-control/sa/coordinator", 4, x509.ExtKeyUsageClientAuth)
	runtime, _, _ := issue("runtime", runtimeSAN, 5, x509.ExtKeyUsageClientAuth)
	server := httptest.NewUnstartedServer(ingest.WorkEventsHandler{GatewaySAN: gatewaySAN, Store: store})
	if server.TLS, err = ingest.LoadTLS(certPath, keyPath, caPath); err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := func(cert tls.Certificate) *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 3 * time.Second}
	}
	post := func(c *http.Client, peer string, req ingest.WorkEventRequest, expected int) ingest.Ack {
		t.Helper()
		body, _ := json.Marshal(req)
		r, _ := http.NewRequest(http.MethodPost, server.URL+ingest.WorkEventsPath, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if peer != "" {
			r.Header.Set(ingest.PeerIdentityHeader, peer)
		}
		resp, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != expected {
			t.Fatalf("HTTP %d, expected %d: %s", resp.StatusCode, expected, raw)
		}
		var ack ingest.Ack
		if expected == 200 || expected == 201 {
			if err := json.Unmarshal(raw, &ack); err != nil {
				t.Fatal(err)
			}
		}
		return ack
	}
	rows := func(id string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE event_id=$1", id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	outbox := func(id string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_outbox WHERE record_id=$1", id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	session, check, run, epoch := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	request := func(typ string) ingest.WorkEventRequest {
		root, gen, pe := "exec-77", int64(4), int64(9)
		return ingest.WorkEventRequest{
			Context: ingest.WorkEventContext{SessionID: session, Tenant: "tenant-a", WorkloadID: "agent-exec/agent-runtime"},
			Check: ingest.WorkEventCheck{CheckID: check, WorkRunID: run, SessionID: session, WorkloadID: "agent-exec/agent-runtime",
				CallerIdentity: runtimeSAN, RuntimeProcessEpoch: epoch, WorkerInstanceID: "wi-1", WorkerBindingID: "wb-1", RootExecID: &root,
				InstanceBinding: json.RawMessage(`{"pod_uid":"pod-1","node_uid":"node-1","boot_id":"boot-1"}`), SensorGeneration: &gen, PolicyEpoch: &pe,
				State: "ready", AuditEventRef: uuid.NewString()},
			Event: ingest.WorkEvent{EventID: uuid.NewString(), EventType: typ, SourceVersion: "runtime-test", SourceTime: "2026-10-18T01:02:03Z",
				SafePayload: ingest.WorkEventPayload{WorkRunID: run, CheckID: check, RuntimeProcessEpoch: epoch, WorkerInstanceID: "wi-1", WorkerBindingID: "wb-1"}},
		}
	}
	gw := client(gateway)

	start := request("agent_work_start_requested")
	created := post(gw, runtimeSAN, start, 201)
	if created.EventID != start.Event.EventID || created.Result != "created" || created.ReceivedAt.IsZero() {
		t.Fatalf("ack %+v", created)
	}
	var src, tenant, sid, wid, sepoch, payloadSession, caller, ref string
	var seq *int64
	var received time.Time
	if err := db.QueryRow(ctx, `SELECT source_id, tenant, session_id::text, workload_id, source_epoch, source_sequence, received_at,
		safe_payload->>'session_id', safe_payload->>'caller_identity', evidence_refs->>0 FROM audit.audit_events WHERE event_id=$1`,
		start.Event.EventID).Scan(&src, &tenant, &sid, &wid, &sepoch, &seq, &received, &payloadSession, &caller, &ref); err != nil {
		t.Fatal(err)
	}
	if src != source || tenant != "tenant-a" || sid != session || wid != "agent-exec/agent-runtime" || sepoch != epoch || seq != nil ||
		payloadSession != session || caller != runtimeSAN || ref != start.Check.AuditEventRef || !received.Equal(created.ReceivedAt) {
		t.Fatalf("stored %s %s %s %s %s %v %s %s %s", src, tenant, sid, wid, sepoch, seq, payloadSession, caller, ref)
	}
	if outbox(start.Event.EventID) != 1 {
		t.Fatal("outbox not written once")
	}
	dup := post(gw, runtimeSAN, start, 200)
	if dup.Result != "duplicate" || !dup.ReceivedAt.Equal(created.ReceivedAt) {
		t.Fatalf("duplicate %+v", dup)
	}
	if rows(start.Event.EventID) != 1 || outbox(start.Event.EventID) != 1 {
		t.Fatal("duplicate stored twice")
	}
	changed := start
	o := "different"
	changed.Event.EventType = "agent_work_finished"
	changed.Event.SafePayload.Outcome = &o
	post(gw, runtimeSAN, changed, 409)
	var conflicts int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.event_conflicts WHERE record_id=$1", start.Event.EventID).Scan(&conflicts); err != nil || conflicts != 1 {
		t.Fatalf("conflict count %d %v", conflicts, err)
	}

	// Wrong callers and unverifiable context store nothing.
	denied := request("agent_work_start_requested")
	post(client(coordinator), runtimeSAN, denied, 403)
	post(client(runtime), runtimeSAN, denied, 401)
	post(gw, "", denied, 403)
	post(gw, "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/other", denied, 403)
	other := denied
	other.Context.SessionID = uuid.NewString()
	post(gw, runtimeSAN, other, 403)
	ungranted := denied
	ungranted.Context.Tenant = "tenant-b"
	post(gw, runtimeSAN, ungranted, 403)
	paused := request("agent_work_paused") // no grant installed for this type
	post(gw, runtimeSAN, paused, 403)
	pending := denied
	pending.Check.State = "pending"
	post(gw, runtimeSAN, pending, 503)
	readiness := denied
	readiness.Event.EventType = "work_readiness_passed"
	post(gw, runtimeSAN, readiness, 422)
	for _, id := range []string{denied.Event.EventID, paused.Event.EventID} {
		if rows(id) != 0 || outbox(id) != 0 {
			t.Fatal("rejected work event stored")
		}
	}
	// The same check later reports the runner call (TASK-15 agent_work_started).
	started := request("agent_work_started")
	if ack := post(gw, runtimeSAN, started, 201); ack.Result != "created" {
		t.Fatalf("started %+v", ack)
	}
}
