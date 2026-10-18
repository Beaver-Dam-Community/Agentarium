package main

// Process-level test of the exporter binary on PostgreSQL 16 with every merged
// migration: two replicas share the PostgreSQL manifest lease, a storage outage
// raises an export_lag hold through the control-health contract fake, recovery
// releases it only after a passing export probe, and SIGKILL of the lease
// holder hands the chain to the other replica without a fork. GCS/KMS and
// control-health are local contract fixtures, not Google or TASK-10 services.

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	export "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/export"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	fx "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	evidenceBucket = "audit-evidence"
	decisionBucket = "decision-input-exports"
)

func TestExporterProcesses(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_TEST_ADMIN_DSN for disposable PostgreSQL")
	}
	ctx := context.Background()
	dir := t.TempDir()
	db, cfg := fx.InstallDatabase(t, ctx, dsn)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	exporterLogin := fx.Login(t, ctx, db, "exp_"+suffix, "audit_exporter")
	verifierLogin := fx.Login(t, ctx, db, "ver_"+suffix, "audit_verifier")
	gatewayLogin := fx.Login(t, ctx, db, "gw_"+suffix, "gateway_app")
	pki := fx.NewPKI(t, dir)
	_, cert, key := pki.Issue(t, "exporter", fx.ExporterSAN, false, x509.ExtKeyUsageClientAuth)
	health := fx.NewControlHealth(t, pki)
	cloud := fx.NewCloud(t, evidenceBucket, decisionBucket)
	keys := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keys, cloud.PublicKeysJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := fx.BuildBinary(t, dir, "exporter", "./services/audit/cmd/exporter")
	start := func(instance string) *fx.Process {
		return fx.Start(t, bin, []string{"DATABASE_URL=" + fx.DSN(cfg, exporterLogin), "STORAGE_EMULATOR_HOST=" + cloud.Host()},
			"--evidence-bucket", evidenceBucket, "--decision-bucket", decisionBucket, "--kms-key-version", fx.KeyVersion, "--keys", keys,
			"--kms-endpoint", cloud.KMSEndpoint(), "--health-url", health.URL, "--health-source-id", "audit-export", "--version", "e2e",
			"--instance-id", instance, "--tls-cert", cert, "--tls-key", key, "--tls-ca", pki.CAPath,
			"--poll-interval", "200ms", "--lease-renew-interval", "1s", "--health-interval", "1s")
	}
	insertEvent := func(sequence *int64, age time.Duration) string {
		t.Helper()
		id := uuid.NewString()
		fx.MustExec(t, ctx, db, `INSERT INTO audit.audit_events(event_id,event_type,tenant,source_id,source_version,source_epoch,source_sequence,source_time,received_at,schema_version,payload_digest,safe_payload)
			VALUES($1,'approval_revoked','t','producer','v1','epoch',$2,statement_timestamp(),statement_timestamp(),1,$3,'{"approval_id":"a","revoke_reason":"user"}')`, id, sequence, strings.Repeat("a", 64))
		fx.MustExec(t, ctx, db, `INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state,enqueued_at) VALUES('audit_event',$1,'gcs','business',50,'pending',statement_timestamp()-$2::interval)`, id, age.String())
		return id
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	seq := func(n int64) *int64 { return &n }

	// Storage outage first: a business row already 200s old exceeds the 120s
	// export_lag limit and cannot be exported while uploads fail.
	cloud.FailUploads(true)
	insertEvent(seq(1), 200*time.Second)
	insertEvent(nil, 200*time.Second) // unsequenced (COMMON source_sequence=null)
	gw := fx.Pool(t, ctx, cfg, gatewayLogin)
	digest := strings.Repeat("c", 64)
	tx, err := gw.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO decisions.decision_inputs VALUES($1,'tenant-a','{}','bundle',statement_timestamp())`, digest); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SELECT audit.enqueue_decision_input($1,120)`, digest); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	a, b := start("exporter-a"), start("exporter-b")

	var hold fx.Hold
	fx.Eventually(t, 15*time.Second, "export_lag hold", func() bool {
		_, holds, _ := health.Snapshot()
		for _, h := range holds {
			if h.Reason == "export_lag" && h.Scope == "global" && h.ScopeID == "*" {
				hold = h
				return true
			}
		}
		return false
	})
	time.Sleep(2 * time.Second)
	_, holds, probes := health.Snapshot()
	if len(probes) != 0 || len(holds) != 1 || holds[0].ReleasedAt != nil {
		t.Fatalf("probe or release during outage: holds=%+v probes=%+v", holds, probes)
	}
	if count("SELECT count(*) FROM audit.export_manifests") != 0 {
		t.Fatal("manifest committed during storage outage")
	}

	// Recovery: export resumes, the backlog drops below the degraded limit, a
	// passing export probe is reported, and only then the hold is released.
	cloud.FailUploads(false)
	fx.Eventually(t, 20*time.Second, "hold release", func() bool {
		_, holds, _ := health.Snapshot()
		return len(holds) == 1 && holds[0].ReleasedAt != nil
	})
	_, holds, probes = health.Snapshot()
	released := holds[0]
	var passing *fx.Probe
	for i, p := range probes {
		if released.ReleaseRef == "auto:audit-export:"+p.ID {
			passing = &probes[i]
		}
	}
	if released.ID != hold.ID || passing == nil || passing.Kind != "export" || passing.Outcome != "pass" || passing.Scope != "global" || len(passing.EvidenceRefs) != 1 ||
		!strings.HasPrefix(passing.EvidenceRefs[0], "gs://"+evidenceBucket+"/probes/") || passing.At.Before(hold.CreatedAt) {
		t.Fatalf("release without matching probe: hold=%+v probes=%+v", released, probes)
	}
	probeKey := strings.TrimPrefix(strings.SplitN(passing.EvidenceRefs[0], "#", 2)[0], "gs://"+evidenceBucket+"/")
	if _, ok := cloud.Snapshot(evidenceBucket)[probeKey]; !ok {
		t.Fatalf("probe object %s not stored", probeKey)
	}
	fx.Eventually(t, 10*time.Second, "decision input export", func() bool {
		return count("SELECT count(*) FROM audit.audit_outbox WHERE state<>'acked'") == 0
	})
	if _, ok := cloud.Snapshot(decisionBucket)["manifests/1.json"]; !ok {
		t.Fatal("decision input chain not published")
	}

	// Failover: SIGKILL the gcs lease holder. Lease expiry is simulated by the
	// DB administrator instead of waiting 30 seconds; the survivor takes over
	// with a higher fencing token and continues the same chain.
	var holder string
	var firstToken int64
	if err := db.QueryRow(ctx, "SELECT holder,fencing_token FROM audit.manifest_leases WHERE chain_id='gcs'").Scan(&holder, &firstToken); err != nil {
		t.Fatal(err)
	}
	survivor := b
	if strings.HasPrefix(holder, "exporter-b/") {
		b.Kill()
		survivor = a
	} else {
		a.Kill()
	}
	fx.MustExec(t, ctx, db, "UPDATE audit.manifest_leases SET lease_until=clock_timestamp()-interval '1 second' WHERE chain_id='gcs'")
	later := []string{insertEvent(seq(2), 0), insertEvent(seq(3), 0)}
	fx.Eventually(t, 15*time.Second, "export after failover", func() bool {
		return count("SELECT count(*) FROM audit.audit_outbox WHERE state='acked' AND record_id = ANY($1)", later) == 2
	})
	var newHolder string
	var newToken int64
	if err := db.QueryRow(ctx, "SELECT holder,fencing_token FROM audit.manifest_leases WHERE chain_id='gcs'").Scan(&newHolder, &newToken); err != nil {
		t.Fatal(err)
	}
	if newHolder == holder || newToken <= firstToken {
		t.Fatalf("no takeover: %s/%d -> %s/%d", holder, firstToken, newHolder, newToken)
	}

	// The whole gcs chain verifies as audit_verifier: one manifest per batch,
	// contiguous sequences, every batch fully acknowledged.
	verifier := fx.Pool(t, ctx, cfg, verifierLogin)
	objects := export.GCS{Bucket: cloud.StorageClient(t).Bucket(evidenceBucket)}
	trusted := map[string]*ecdsa.PublicKey{fx.KeyVersion: &cloud.Key.PublicKey}
	manifests := count("SELECT count(*) FROM audit.export_manifests WHERE chain_id='gcs'")
	if manifests < 2 || manifests != count("SELECT count(*) FROM audit.export_batches WHERE destination='gcs'") {
		t.Fatalf("manifest/batch mismatch: %d", manifests)
	}
	var prev *string
	for i := 1; i <= manifests; i++ {
		raw, err := objects.ReadManifest(ctx, "manifests/"+strconv.Itoa(i)+".json")
		if err != nil {
			t.Fatal(err)
		}
		d, err := export.Verify(ctx, raw, int64(i), prev, trusted, objects, export.PGAcks{Queries: auditdb.New(verifier), Destination: "gcs"})
		if err != nil {
			t.Fatalf("manifest %d: %v", i, err)
		}
		prev = &d
	}
	var tokens []int64
	rows, err := db.Query(ctx, "SELECT fencing_token FROM audit.export_manifests WHERE chain_id='gcs' ORDER BY manifest_seq")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err = pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil || tokens[len(tokens)-1] != newToken {
		t.Fatalf("manifest tokens %v (current %d) %v", tokens, newToken, err)
	}

	// SIGTERM is a clean shutdown: the process exits 0 and releases its lease.
	if err := survivor.Cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	fx.Eventually(t, 10*time.Second, "graceful exit", survivor.Exited)
	if code := survivor.Cmd.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("exit %d: %s", code, survivor.Logs())
	}
	// The SIGKILLed replica could not release its leases; they expire by TTL.
	if count("SELECT count(*) FROM audit.manifest_leases WHERE holder=$1 AND lease_until > clock_timestamp()", newHolder) != 0 {
		t.Fatal("lease not released on shutdown")
	}
	if strings.Contains(survivor.Logs(), "BEGIN") || strings.Contains(survivor.Logs(), "PRIVATE KEY") {
		t.Fatal("secret material in logs")
	}
}
