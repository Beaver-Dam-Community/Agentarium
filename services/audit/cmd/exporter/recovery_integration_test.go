package main

// Restart recovery of owned holds (#177): a new exporter process has no memory
// of the export_lag hold its predecessor obtained. It must reload the hold from
// control-health, keep it while the export probe fails, release it only after
// a passing probe, never touch other components' holds, and retry the listing
// with backoff while control-health is unavailable.

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	export "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/export"
	fx "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/testfixture"
	"github.com/google/uuid"
)

func TestExporterRecoversOwnedHoldsAfterRestart(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_TEST_ADMIN_DSN for disposable PostgreSQL")
	}
	ctx := context.Background()
	dir := t.TempDir()
	db, cfg := fx.InstallDatabase(t, ctx, dsn)
	exporterLogin := fx.Login(t, ctx, db, "exp_"+strings.ReplaceAll(uuid.NewString(), "-", "")[:12], "audit_exporter")
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
			"--poll-interval", "200ms", "--lease-renew-interval", "1s", "--health-interval", "500ms", "--hold-recovery-backoff", "200ms")
	}
	exportLag := func() []fx.Hold {
		_, holds, _ := health.Snapshot()
		var out []fx.Hold
		for _, h := range holds {
			if h.Reason == "export_lag" {
				out = append(out, h)
			}
		}
		return out
	}

	// 1. The first exporter obtains an export_lag hold during a storage outage
	//    and is then SIGKILLed: the hold ID existed only in its memory.
	cloud.FailUploads(true)
	id := uuid.NewString()
	fx.MustExec(t, ctx, db, `INSERT INTO audit.audit_events(event_id,event_type,tenant,source_id,source_version,source_epoch,source_sequence,source_time,received_at,schema_version,payload_digest,safe_payload)
		VALUES($1,'approval_revoked','t','producer','v1','epoch',1,statement_timestamp(),statement_timestamp(),1,$2,'{"approval_id":"a","revoke_reason":"user"}')`, id, strings.Repeat("a", 64))
	fx.MustExec(t, ctx, db, `INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state,enqueued_at) VALUES('audit_event',$1,'gcs','business',50,'pending',statement_timestamp()-interval '200 seconds')`, id)
	first := start("exporter-first")
	fx.Eventually(t, 15*time.Second, "export_lag hold", func() bool { return len(exportLag()) == 1 })
	hold := exportLag()[0]
	first.Kill()

	// 2. Drain the backlog out of band (in-process worker on the real lease) so
	//    the next exporter has no lag of its own and never re-requests the hold:
	//    only the owned-hold listing can tell it about the hold.
	fx.MustExec(t, ctx, db, "UPDATE audit.manifest_leases SET lease_until=clock_timestamp()-interval '1 second'")
	cloud.FailUploads(false)
	pool := fx.Pool(t, ctx, cfg, exporterLogin)
	lease := &export.PGLease{Pool: pool, Holder: "drain"}
	if _, err := lease.Acquire(ctx, "gcs"); err != nil {
		t.Fatal(err)
	}
	pub := export.ManifestPublisher{Chain: "gcs", Pool: pool, Objects: export.GCS{Bucket: cloud.StorageClient(t).Bucket(evidenceBucket)},
		Signer: export.KMS{Service: cloud.KMSService(t), KeyVersion: fx.KeyVersion, PublicKey: &cloud.Key.PublicKey}, KeyVersion: fx.KeyVersion,
		Keys: map[string]*ecdsa.PublicKey{fx.KeyVersion: &cloud.Key.PublicKey}, Leader: lease}
	fx.MustExec(t, ctx, db, "UPDATE audit.audit_outbox SET next_retry_at=statement_timestamp()-interval '1 second',lease_until=NULL,state='pending' WHERE state<>'acked'")
	if worked, err := (export.Worker{Outbox: export.Outbox{Pool: pool}, Publisher: pub}).Once(ctx); err != nil || !worked {
		t.Fatalf("drain: %v %v", worked, err)
	}
	if err := lease.Release(ctx, "gcs"); err != nil {
		t.Fatal(err)
	}

	// 3. Holds of other components are open too; storage fails again (probes
	//    fail) and control-health refuses the first two listings.
	// A second owned hold (node scope) is recovered and released with the same
	// single probe per round as the global one.
	nodeHold := health.SeedHold("node", uuid.NewString(), "export_lag", "audit-export")
	dbHold := health.SeedHold("global", "*", "db_unavailable", "audit-db")
	integrity := health.SeedHold("global", "*", "audit_integrity", "control-health")
	cloud.FailUploads(true)
	health.FailListings(2)
	second := start("exporter-second")
	fx.Eventually(t, 15*time.Second, "failed probe for recovered hold", func() bool {
		_, _, probes := health.Snapshot()
		for _, p := range probes {
			if p.Outcome == "fail" && p.Scope == "global" {
				return true
			}
		}
		return false
	})
	if health.ListCalls() < 3 {
		t.Fatalf("listing not retried: %d", health.ListCalls())
	}
	for _, id := range []string{hold.ID, nodeHold} {
		if h, _ := health.HoldByID(id); h.ReleasedAt != nil || health.ReleaseCalls(id) != 0 {
			t.Fatalf("recovered hold released despite failing probe: %+v", h)
		}
	}
	// Failing probes for two scopes must not starve the audit-export lease.
	healthy := health.HealthyLeases("audit-export")
	fx.Eventually(t, 5*time.Second, "healthy audit-export leases during failing probes", func() bool {
		return health.HealthyLeases("audit-export") >= healthy+3
	})

	// 4. Storage recovers: a passing probe releases the recovered hold.
	cloud.FailUploads(false)
	fx.Eventually(t, 15*time.Second, "release of recovered holds", func() bool {
		h, _ := health.HoldByID(hold.ID)
		n, _ := health.HoldByID(nodeHold)
		return h.ReleasedAt != nil && n.ReleasedAt != nil
	})
	released, _ := health.HoldByID(hold.ID)
	_, _, probes := health.Snapshot()
	matched := false
	for _, p := range probes {
		if released.ReleaseRef == "auto:audit-export:"+p.ID && p.Outcome == "pass" && p.At.After(hold.CreatedAt) {
			matched = true
		}
	}
	if !matched || len(exportLag()) != 2 {
		t.Fatalf("release not backed by a passing probe or hold re-requested: %+v", exportLag())
	}
	for _, id := range []string{dbHold, integrity} {
		if h, _ := health.HoldByID(id); h.ReleasedAt != nil || health.ReleaseCalls(id) != 0 {
			t.Fatalf("foreign hold touched: %+v", h)
		}
	}
	if !strings.Contains(second.Logs(), "owned hold recovery failed, retrying") {
		t.Fatalf("listing failures not retried visibly: %s", second.Logs())
	}
}
