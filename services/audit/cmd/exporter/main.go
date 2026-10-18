// Command exporter runs the TASK-07 outbox exporter: PostgreSQL manifest lease
// with fencing token, fixed-batch claim, create-only GCS upload, KMS-signed
// manifest chain per bucket, whole-batch ACK, the audit-export health lease,
// export_lag holds, and probe-based hold release through the TASK-10 API.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	export "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/export"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/healthreport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	kms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

const (
	exporterSAN      = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-exporter"
	controlHealthSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
)

func main() {
	if err := run(); err != nil {
		log.Print("audit exporter stopped: ", err)
		os.Exit(1)
	}
}

func run() error {
	evidenceBucket := flag.String("evidence-bucket", "", "evidence bucket for the gcs chain")
	decisionBucket := flag.String("decision-bucket", "", "decision-input-exports bucket for the gcs_decision_inputs chain")
	keyVersion := flag.String("kms-key-version", "", "exact Cloud KMS key version used to sign manifests")
	keysFile := flag.String("keys", "", "trusted JSON mapping of KMS key versions to PEM public keys, including retired versions")
	kmsEndpoint := flag.String("kms-endpoint", "", "emulator/test only: KMS endpoint override; disables Google authentication")
	healthURL := flag.String("health-url", "", "control-health HTTPS origin")
	healthSource := flag.String("health-source-id", "", "registered audit-export source")
	version := flag.String("version", "", "deployed exporter version")
	instance := flag.String("instance-id", "", "lease holder prefix (e.g. Pod name); a per-process UUID is always appended")
	cert := flag.String("tls-cert", "", "client certificate PEM path (file mode)")
	key := flag.String("tls-key", "", "client private key PEM path (file mode)")
	ca := flag.String("tls-ca", "", "trust bundle PEM path")
	identityURL := flag.String("identity-url", "", "identity HTTPS origin for in-memory certificate bootstrap")
	token := flag.String("bootstrap-token", "", "projected agentarium-identity token file")
	poll := flag.Duration("poll-interval", time.Second, "idle wait between outbox scans")
	renew := flag.Duration("lease-renew-interval", 10*time.Second, "manifest lease renewal interval, below the 30s TTL")
	healthEvery := flag.Duration("health-interval", 5*time.Second, "audit-export lease report interval")
	recoverBase := flag.Duration("hold-recovery-backoff", time.Second, "initial retry delay for owned hold recovery (doubles up to 30s)")
	flag.Parse()
	if *evidenceBucket == "" || *decisionBucket == "" || *keyVersion == "" || *keysFile == "" || *healthURL == "" || *healthSource == "" || *version == "" ||
		*poll <= 0 || *renew <= 0 || *renew >= export.ManifestLeaseTTL/2 || *healthEvery <= 0 || *recoverBase <= 0 || os.Getenv("DATABASE_URL") == "" {
		return errors.New("required exporter inputs missing or invalid")
	}
	// Holders must be unique per process: replicas sharing one string would
	// share a fencing token. Always append a fresh UUID (TASK-07 3.2.1).
	holder := *instance
	if holder == "" {
		holder, _ = os.Hostname()
	}
	holder += "/" + uuid.NewString()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	keys, err := export.LoadTrustedKeys(*keysFile)
	if err != nil {
		return err
	}
	if keys[*keyVersion] == nil {
		return errors.New("signing key version is not in the trusted key file")
	}
	identity, err := healthreport.LoadIdentity(ctx, *identityURL, *token, *ca, *cert, *key, exporterSAN)
	if err != nil {
		return errors.New("cannot load TLS material")
	}
	healthClient, err := identity.Client(*healthURL, controlHealthSAN)
	if err != nil {
		return errors.New("invalid health client configuration")
	}
	pc, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		return errors.New("invalid database configuration")
	}
	pc.MaxConns = 10
	pc.ConnConfig.ConnectTimeout = 5 * time.Second
	pc.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	pc.ConnConfig.RuntimeParams["lock_timeout"] = "2000"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return errors.New("database initialization failed")
	}
	defer pool.Close()
	ready, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(ready)
	cancel()
	if err != nil {
		return errors.New("database unavailable")
	}
	gcs, err := storage.NewClient(ctx)
	if err != nil {
		return errors.New("GCS client initialization failed")
	}
	defer gcs.Close()
	var kmsOpts []option.ClientOption
	if *kmsEndpoint != "" {
		kmsOpts = append(kmsOpts, option.WithEndpoint(*kmsEndpoint), option.WithoutAuthentication())
	}
	kmsService, err := kms.NewService(ctx, kmsOpts...)
	if err != nil {
		return errors.New("KMS client initialization failed")
	}
	signer := export.KMS{Service: kmsService, KeyVersion: *keyVersion, PublicKey: keys[*keyVersion]}
	lease := &export.PGLease{Pool: pool, Holder: holder}
	evidence := export.GCS{Bucket: gcs.Bucket(*evidenceBucket)}
	decisions := export.GCS{Bucket: gcs.Bucket(*decisionBucket)}
	publisher := func(chain string, objects export.GCS) export.ManifestPublisher {
		return export.ManifestPublisher{Chain: chain, Pool: pool, Objects: objects, Signer: signer, KeyVersion: *keyVersion, Keys: keys, Leader: lease}
	}
	outbox := export.Outbox{Pool: pool}
	workers := []export.Worker{
		{Outbox: outbox, Publisher: publisher("gcs", evidence), SourceClass: "business"},
		{Outbox: outbox, Publisher: publisher("gcs", evidence), SourceClass: "kernel"},
		{Outbox: outbox, Publisher: publisher("gcs", evidence), SourceClass: "lifecycle"},
		{Outbox: outbox, Publisher: publisher("gcs_decision_inputs", decisions), SourceClass: "decision_input"},
	}
	reporter := &export.HealthReporter{Pool: pool, Client: healthClient, URL: *healthURL, SourceID: *healthSource, Version: *version,
		Prober: &export.ExportProber{Objects: evidence, Bucket: *evidenceBucket}, Interval: *healthEvery,
		OnReleaseError: func(err error) { log.Printf("export_lag release attempt failed: %v", err) }}
	// Owned holds survive restarts in control-health; reload them at start and
	// whenever this replica obtains a new gcs lease token (takeover).
	lease.OnNewToken = func(chain string, _ int64) {
		if chain == "gcs" {
			reporter.RequestRecovery()
		}
	}
	done := make(chan struct{}, 3)
	go func() {
		reporter.RecoverLoop(ctx, *recoverBase, 30*time.Second, func(err error) { log.Printf("owned hold recovery failed, retrying: %v", err) })
		done <- struct{}{}
	}()
	go func() {
		if err := lease.Run(ctx, []string{"gcs", "gcs_decision_inputs"}, *renew, func(chain string, err error) {
			if !errors.Is(err, export.ErrLeaseHeld) {
				log.Printf("manifest lease renewal failed for %s: %v", chain, err)
			}
		}); err != nil {
			log.Print("manifest lease disabled: ", err)
		}
		done <- struct{}{}
	}()
	go func() {
		reporter.Run(ctx, func() { log.Print("audit-export health report failed") })
		done <- struct{}{}
	}()
	log.Printf("audit exporter started as %s", holder)
	for ctx.Err() == nil {
		progressed := false
		for _, w := range workers {
			worked, err := w.Once(ctx)
			switch {
			case err == nil:
				progressed = progressed || worked
			case errors.Is(err, export.ErrLeaseLost), errors.Is(err, export.ErrLeaseHeld), ctx.Err() != nil:
				// Not the manifest writer right now; another holder exports.
			default:
				log.Printf("export %s batch failed and will be retried: %v", w.SourceClass, err)
			}
		}
		if !progressed {
			select {
			case <-ctx.Done():
			case <-time.After(*poll):
			}
		}
	}
	<-done
	<-done
	<-done
	return nil
}
