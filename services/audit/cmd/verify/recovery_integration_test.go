package main

// Process-level recovery test for the TASK-07 M2-2 completion criterion
// ("records remain queryable after the producing Pod is deleted"). It runs the
// actual writer and verifier binaries against disposable PostgreSQL 16 with
// every merged migration, kills the writer with SIGKILL, and checks that the
// committed record is still returned by a fresh writer process, by PostgreSQL,
// and by the signed GCS export checked in a separate verifier process. Failed
// verification must be stored as an incident AuditEvent through a running
// writer and raise an audit_integrity hold.
//
// Not covered: GKE Pod deletion, Cloud SQL, real GCS/KMS/IAM, or the TASK-10
// service. The exporter runs in-process here; cmd/exporter has its own process
// test. GCS/KMS and control-health are local contract fixtures.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	export "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/export"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	fx "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/testfixture"
	"github.com/google/uuid"
	"google.golang.org/api/googleapi"
)

const evidenceBucket = "audit-evidence"

func TestRecordsSurviveWriterProcessDeletion(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_TEST_ADMIN_DSN for disposable PostgreSQL")
	}
	ctx := context.Background()
	dir := t.TempDir()
	db, dbCfg := fx.InstallDatabase(t, ctx, dsn)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	writerLogin := fx.Login(t, ctx, db, "e2e_writer_"+suffix, "audit_writer")
	exporterLogin := fx.Login(t, ctx, db, "e2e_exporter_"+suffix, "audit_exporter")
	verifierLogin := fx.Login(t, ctx, db, "e2e_verifier_"+suffix, "audit_verifier")
	// Installer steps from services/audit/README.md: proxy source binding,
	// exact event grants, column read of TASK-03 registrations, live workloads.
	fx.MustExec(t, ctx, db, "INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES ($1,'audit-writer',true)", writerLogin)
	fx.MustExec(t, ctx, db, "INSERT INTO audit.producer_event_grants VALUES ('coordinator','approval_revoked','tenant-a'),('audit-verifier','export_verification_failed','*')")
	fx.MustExec(t, ctx, db, "GRANT SELECT (namespace,ksa,role,service_principal,enabled) ON identity.registered_workloads TO audit_writer")
	fx.MustExec(t, ctx, db, "INSERT INTO identity.registered_workloads(namespace,ksa,role,service_principal,enabled) VALUES ('agent-control','coordinator','service','coordinator',true),('agent-observe','audit-verifier','service','audit-verifier',true)")

	pki := fx.NewPKI(t, dir)
	_, writerCert, writerKey := pki.Issue(t, "writer", fx.WriterSAN, false, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	_, verifierCert, verifierKey := pki.Issue(t, "verifier", fx.VerifierSAN, false, x509.ExtKeyUsageClientAuth)
	producerTLS, _, _ := pki.Issue(t, "producer", fx.CoordinatorSAN, false, x509.ExtKeyUsageClientAuth)
	health := fx.NewControlHealth(t, pki)
	sources := filepath.Join(dir, "sources.json")
	if err := os.WriteFile(sources, []byte(`[{"source_id":"coordinator","namespace":"agent-control","ksa":"coordinator","principal":"coordinator"},{"source_id":"audit-verifier","namespace":"agent-observe","ksa":"audit-verifier","principal":"audit-verifier"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	writerBin := fx.BuildBinary(t, dir, "writer", "./services/audit/cmd/writer")
	verifyBin := fx.BuildBinary(t, dir, "verify", "./services/audit/cmd/verify")
	startWriter := func() (*fx.Process, string) {
		t.Helper()
		addr := fx.FreeAddr(t)
		p := fx.Start(t, writerBin, []string{"DATABASE_URL=" + fx.DSN(dbCfg, writerLogin)}, "--listen", addr, "--tls-cert", writerCert, "--tls-key", writerKey,
			"--tls-ca", pki.CAPath, "--sources", sources, "--health-url", health.URL, "--health-source-id", "audit-writer", "--version", "e2e")
		p.WaitListening(t, addr)
		return p, "https://" + addr
	}
	client := pki.ServiceClient(t, producerTLS, fx.WriterSAN)
	post := func(base string, raw []byte, want int) ingest.Ack {
		t.Helper()
		resp, err := client.Post(base+"/internal/audit/events", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("HTTP %d, expected %d: %s", resp.StatusCode, want, body)
		}
		var ack ingest.Ack
		if err := json.Unmarshal(body, &ack); err != nil {
			t.Fatal(err)
		}
		return ack
	}
	waitHealthy := func(n int) {
		t.Helper()
		fx.Eventually(t, 10*time.Second, "healthy audit-db leases", func() bool { return health.HealthyLeases("audit-db") >= n })
	}

	eventA, rawA := businessEvent(t, 1)
	eventB, rawB := businessEvent(t, 2)

	first, firstURL := startWriter()
	created := post(firstURL, rawA, 201)
	if created.Result != "created" || created.EventID != eventA.EventID || created.ReceivedAt.IsZero() {
		t.Fatalf("invalid first acknowledgement: %+v", created)
	}
	waitHealthy(1)
	// SIGKILL models abrupt Pod deletion: no shutdown hook, flush or cleanup runs.
	first.Kill()
	if conn, err := net.DialTimeout("tcp", strings.TrimPrefix(firstURL, "https://"), 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("deleted writer still accepts connections")
	}

	// The replacement process has no state from the first one. A same-ID retry
	// returns the original durable receipt instead of creating a second record.
	second, secondURL := startWriter()
	again := post(secondURL, rawA, 200)
	if again.Result != "duplicate" || !again.ReceivedAt.Equal(created.ReceivedAt) {
		t.Fatalf("record lost or replaced after writer deletion: %+v vs %+v", again, created)
	}
	createdB := post(secondURL, rawB, 201)
	waitHealthy(2)
	var events, outbox int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE event_id = ANY($1::uuid[])", []string{eventA.EventID, eventB.EventID}).Scan(&events); err != nil || events != 2 {
		t.Fatalf("stored events %d err=%v", events, err)
	}

	// Export both records through the actual outbox worker and publisher using
	// the restricted audit_exporter login and the PostgreSQL manifest lease.
	cloud := fx.NewCloud(t, evidenceBucket)
	exporterPool := fx.Pool(t, ctx, dbCfg, exporterLogin)
	lease := &export.PGLease{Pool: exporterPool, Holder: "recovery-exporter"}
	if _, err := lease.Acquire(ctx, "gcs"); err != nil {
		t.Fatal(err)
	}
	signer := export.KMS{Service: cloud.KMSService(t), KeyVersion: fx.KeyVersion, PublicKey: &cloud.Key.PublicKey}
	publisher := export.ManifestPublisher{Chain: "gcs", Pool: exporterPool, Objects: export.GCS{Bucket: cloud.StorageClient(t).Bucket(evidenceBucket)}, Signer: signer,
		KeyVersion: fx.KeyVersion, Keys: map[string]*ecdsa.PublicKey{fx.KeyVersion: &cloud.Key.PublicKey}, Leader: lease}
	worker := export.Worker{Outbox: export.Outbox{Pool: exporterPool}, Publisher: publisher}
	if worked, err := worker.Once(ctx); err != nil || !worked {
		t.Fatalf("export: %v %v", worked, err)
	}
	if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_outbox WHERE state='acked' AND record_id = ANY($1)", []string{eventA.EventID, eventB.EventID}).Scan(&outbox); err != nil || outbox != 2 {
		t.Fatalf("acked outbox %d err=%v", outbox, err)
	}

	// Remove the second writer too. The intact verification does not need it.
	second.Kill()

	keys := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keys, cloud.PublicKeysJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	writerURL := secondURL
	verify := func(extra ...string) (string, string, error) {
		args := append([]string{"--bucket", evidenceBucket, "--chain", "gcs", "--keys", keys, "--through", "1"}, extra...)
		p := fx.Start(t, verifyBin, []string{"DATABASE_URL=" + fx.DSN(dbCfg, verifierLogin), "STORAGE_EMULATOR_HOST=" + cloud.Host()}, args...)
		<-waitExit(p)
		var stdout, stderr string
		if parts := strings.SplitN(p.Logs(), "\n", 2); len(parts) > 0 {
			stdout = parts[0]
		}
		stderr = p.Logs()
		if p.Cmd.ProcessState.ExitCode() != 0 {
			return stdout, stderr, errors.New("exit " + strconv.Itoa(p.Cmd.ProcessState.ExitCode()))
		}
		return stdout, stderr, nil
	}
	incidentArgs := func() []string {
		return []string{"--writer-url", writerURL, "--health-url", health.URL, "--source-id", "audit-verifier", "--version", "e2e",
			"--tls-cert", verifierCert, "--tls-key", verifierKey, "--tls-ca", pki.CAPath}
	}
	if _, logs, err := verify(); err == nil || !strings.Contains(logs, "incident reporting inputs") {
		t.Fatalf("verifier ran without incident delivery: %v %s", err, logs)
	}
	out, logs, err := verify(incidentArgs()...)
	if err != nil {
		t.Fatalf("verifier rejected intact chain: %v %s", err, logs)
	}
	var summary struct {
		Verified bool   `json:"verified"`
		Digest   string `json:"last_manifest_digest"`
	}
	if json.Unmarshal([]byte(out), &summary) != nil || !summary.Verified || len(summary.Digest) != 64 {
		t.Fatalf("unexpected verifier output: %s", logs)
	}

	// The independent GCS copy contains both records with the server receipt.
	exported := cloud.ExportedRecords(t, evidenceBucket)
	for _, want := range []ingest.Ack{created, createdB} {
		got, ok := exported[want.EventID]
		if !ok || !got.Equal(want.ReceivedAt) {
			t.Fatalf("event %s export received_at %s, expected %s", want.EventID, got, want.ReceivedAt)
		}
	}

	t.Run("retention refuses deletion and overwrite", func(t *testing.T) {
		sc := cloud.StorageClient(t)
		for name := range cloud.Snapshot(evidenceBucket) {
			err := sc.Bucket(evidenceBucket).Object(name).Delete(ctx)
			var apiErr *googleapi.Error
			if !errors.As(err, &apiErr) || apiErr.Code != 403 || !strings.Contains(apiErr.Message, "retentionPolicyNotMet") {
				t.Fatalf("delete %s: %v", name, err)
			}
			w := sc.Bucket(evidenceBucket).Object(name).NewWriter(ctx)
			_, _ = w.Write([]byte("replacement\n"))
			if err = w.Close(); !errors.As(err, &apiErr) || apiErr.Code != 403 {
				t.Fatalf("overwrite %s: %v", name, err)
			}
		}
		if _, logs, err := verify(incidentArgs()...); err != nil {
			t.Fatalf("refused mutation changed evidence: %v %s", err, logs)
		}
	})

	// A fresh writer process receives the verifier's incident events.
	_, writerURL = startWriter()
	incident := func(t *testing.T, wantCode string) (string, string) {
		t.Helper()
		out, logs, err := verify(incidentArgs()...)
		if err == nil {
			t.Fatalf("tampering accepted: %s", logs)
		}
		var report struct {
			Verified bool            `json:"verified"`
			Incident export.Incident `json:"incident"`
		}
		if json.Unmarshal([]byte(out), &report) != nil || report.Verified || report.Incident.FailureCode != wantCode || report.Incident.ManifestSeq != 1 {
			t.Fatalf("incident output: %s", logs)
		}
		var payload map[string]any
		var tenant, source string
		if err := db.QueryRow(ctx, "SELECT tenant,source_id,safe_payload FROM audit.audit_events WHERE event_id=$1 AND event_type='export_verification_failed'", report.Incident.EventID).Scan(&tenant, &source, &payload); err != nil {
			t.Fatalf("incident event not stored: %v", err)
		}
		if tenant != "*" || source != "audit-verifier" || payload["failure_code"] != wantCode || payload["chain_id"] != "gcs" {
			t.Fatalf("incident event: %s %s %v", tenant, source, payload)
		}
		_, holds, _ := health.Snapshot()
		for _, h := range holds {
			if h.ID == report.Incident.HoldID && h.Reason == "audit_integrity" && h.Scope == "global" && h.ScopeID == "*" && h.ReleasedAt == nil && len(h.EvidenceRefs) == 1 && strings.HasPrefix(h.EvidenceRefs[0], "audit_event:") {
				return report.Incident.EventID, h.ID
			}
		}
		t.Fatalf("audit_integrity hold missing: %+v", holds)
		return "", ""
	}
	var firstHold string
	t.Run("verifier reports acknowledgement drift as incident", func(t *testing.T) {
		fx.MustExec(t, ctx, db, "UPDATE audit.audit_outbox SET state='pending',ack_ref=NULL WHERE record_id=$1", eventB.EventID)
		event, hold := incident(t, export.FailAckMismatch)
		_, holds, _ := health.Snapshot()
		for _, h := range holds {
			if h.ID == hold && h.EvidenceRefs[0] != "audit_event:"+event {
				t.Fatalf("hold evidence %v", h.EvidenceRefs)
			}
		}
		firstHold = hold
		fx.MustExec(t, ctx, db, "UPDATE audit.audit_outbox o SET state='acked',ack_ref=a.ack_ref FROM audit.audit_outbox a WHERE o.record_id=$1 AND a.record_id=$2", eventB.EventID, eventA.EventID)
		if _, logs, err := verify(incidentArgs()...); err != nil {
			t.Fatalf("restored ACK rejected: %v %s", err, logs)
		}
	})
	t.Run("signed time differing from the DB intent time is an incident", func(t *testing.T) {
		// A DB administrator bypassing the immutability trigger models the
		// stated trust boundary; the verifier must detect it, not skip.
		fx.MustExec(t, ctx, db, "ALTER TABLE audit.manifest_intents DISABLE TRIGGER manifest_intents_db_time")
		fx.MustExec(t, ctx, db, "UPDATE audit.manifest_intents SET created_at=created_at-interval '31 days' WHERE chain_id='gcs' AND manifest_seq=1")
		fx.MustExec(t, ctx, db, "ALTER TABLE audit.manifest_intents ENABLE TRIGGER manifest_intents_db_time")
		incident(t, export.FailManifestInvalid)
		fx.MustExec(t, ctx, db, "ALTER TABLE audit.manifest_intents DISABLE TRIGGER manifest_intents_db_time")
		fx.MustExec(t, ctx, db, "UPDATE audit.manifest_intents SET created_at=created_at+interval '31 days' WHERE chain_id='gcs' AND manifest_seq=1")
		fx.MustExec(t, ctx, db, "ALTER TABLE audit.manifest_intents ENABLE TRIGGER manifest_intents_db_time")
	})
	t.Run("verifier reports object removed outside retention", func(t *testing.T) {
		// Models a privileged bypass (retention removed by a bucket admin), the
		// stated trust boundary: deletion is not prevented, only detected.
		for name := range cloud.Snapshot(evidenceBucket) {
			if !strings.HasPrefix(name, "manifests/") {
				cloud.AdminRemove(evidenceBucket, name)
			}
		}
		if _, hold := incident(t, export.FailObjectMissing); hold != firstHold {
			t.Fatalf("open audit_integrity hold not reused: %s vs %s", hold, firstHold)
		}
		// PostgreSQL still answers for the committed record after both writer
		// processes and the evidence object are gone.
		var receivedAt time.Time
		if err := db.QueryRow(ctx, "SELECT received_at FROM audit.audit_events WHERE event_id=$1", eventA.EventID).Scan(&receivedAt); err != nil || !receivedAt.Equal(created.ReceivedAt) {
			t.Fatalf("DB record after deletions: %s %v", receivedAt, err)
		}
	})
	t.Run("manifest outside the window is still verified, or reported as skipped", func(t *testing.T) {
		// A batch whose intent (and therefore signed created_at) is 31 days old:
		// the intent is pre-created by a DB administrator before publication,
		// so the KMS signature covers the old time.
		id, raw := businessEvent(t, 3)
		_ = raw
		fx.MustExec(t, ctx, db, `INSERT INTO audit.audit_events(event_id,event_type,tenant,source_id,source_version,source_epoch,source_sequence,source_time,received_at,schema_version,payload_digest,safe_payload)
			VALUES($1,'approval_revoked','tenant-a','coordinator','v1','epoch-recovery',3,statement_timestamp(),statement_timestamp(),1,$2,'{"approval_id":"a","revoke_reason":"user"}')`, id.EventID, strings.Repeat("a", 64))
		fx.MustExec(t, ctx, db, `INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state) VALUES('audit_event',$1,'gcs','business',50,'pending')`, id.EventID)
		if _, err := lease.Acquire(ctx, "gcs"); err != nil {
			t.Fatal(err)
		}
		out := export.Outbox{Pool: exporterPool}
		c, err := out.Claim(ctx, "gcs", "business")
		if err != nil || c == nil {
			t.Fatalf("claim: %v", err)
		}
		token, err := lease.Check(ctx, "gcs")
		if err != nil {
			t.Fatal(err)
		}
		fx.MustExec(t, ctx, db, "ALTER TABLE audit.manifest_intents DISABLE TRIGGER manifest_intents_db_time")
		fx.MustExec(t, ctx, db, "INSERT INTO audit.manifest_intents(chain_id,manifest_seq,batch_id,fencing_token,created_at) VALUES('gcs',2,$1,$2,statement_timestamp()-interval '31 days')", c.BatchID, token)
		fx.MustExec(t, ctx, db, "ALTER TABLE audit.manifest_intents ENABLE TRIGGER manifest_intents_db_time")
		data, sources, err := out.Records(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := publisher.Publish(ctx, c, data, sources)
		if err != nil {
			t.Fatal(err)
		}
		if err = out.Ack(ctx, c, receipt); err != nil {
			t.Fatal(err)
		}
		before := 0
		_ = db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE event_type='export_verification_failed'").Scan(&before)
		out2, logs, err := verify(append(incidentArgs(), "--from", "2", "--through", "2")...)
		if err != nil || !strings.Contains(out2, `"result":"verified_outside_window"`) || !strings.Contains(out2, `"verified":true`) {
			t.Fatalf("outside-window manifest with objects present: %v %s", err, logs)
		}
		// Expired batch object: an explicit skipped result and exit code 2.
		cloud.AdminRemove(evidenceBucket, c.ObjectKey)
		out2, logs, err = verify(append(incidentArgs(), "--from", "2", "--through", "2")...)
		if err == nil || err.Error() != "exit 2" || !strings.Contains(out2, `"result":"skipped_outside_window"`) || !strings.Contains(out2, `"skipped_outside_window":1`) {
			t.Fatalf("skipped result not recorded: %v %s", err, logs)
		}
		after := 0
		_ = db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE event_type='export_verification_failed'").Scan(&after)
		if after != before {
			t.Fatal("outside-window manifest raised an incident")
		}
	})
	t.Run("incident delivery failure is not success", func(t *testing.T) {
		writerURL = "https://" + fx.FreeAddr(t) // nothing listens here
		if _, logs, err := verify(incidentArgs()...); err == nil || !strings.Contains(logs, "incident reporting failed") {
			t.Fatalf("undelivered incident: %v %s", err, logs)
		}
	})
}

func waitExit(p *fx.Process) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		for !p.Exited() {
			time.Sleep(20 * time.Millisecond)
		}
		close(ch)
	}()
	return ch
}

func businessEvent(t *testing.T, sequence int64) (ingest.Event, []byte) {
	t.Helper()
	e := ingest.Event{EventID: uuid.NewString(), EventType: "approval_revoked", Tenant: "tenant-a", SourceID: "coordinator", SourceVersion: "v1",
		SourceEpoch: "epoch-recovery", SourceSequence: &sequence, SourceTime: "2026-10-17T00:00:00Z", SchemaVersion: 1, EvidenceRefs: []json.RawMessage{},
		SafePayload: map[string]json.RawMessage{"approval_id": json.RawMessage(strconv.Quote("approval-" + strconv.FormatInt(sequence, 10))), "revoke_reason": json.RawMessage(`"user"`)}}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if e.PayloadDigest, err = canonical.PayloadDigest(raw); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return e, raw
}
