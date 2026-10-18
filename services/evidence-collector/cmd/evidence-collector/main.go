// Command evidence-collector is the TASK-08 destination evidence collector
// (agent-observe/evidence-collector). It has no listener: it polls
// audit.collector_feed, reads receiver receipts over mTLS, stores
// evidence.destination_observations revisions with their destination_observed
// audit event (audit_append in the same transaction), and reports the
// destination-evidence lease with a 5-second receipt probe.
//
// With --identity-url the client certificate is bootstrapped and renewed in
// memory (packages/workloadcert, TASK-03 3.3.2); without it the
// --tls-cert/--tls-key files are re-read per connection. Every other flag is
// required; a missing input stops the start.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/healthlease"
	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/collector"
	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/epoch"
	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/feed"
	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/probe"
	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/receipt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// selfSAN is the collector's service identity (TASK-06 KSA table,
// agent-observe/evidence-collector) requested in --identity-url mode.
const selfSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/evidence-collector"

type config struct {
	databaseURL, tenant, receiverURL, targetID  string
	trustBundle, certFile, keyFile              string
	identityURL, tokenFile                      string
	healthURL, healthSourceID, version          string
	auditSourceID, auditSourceVersion, epochDir string
	probeActionKey                              string
	settle, lateWindow                          time.Duration
}

func main() {
	var c config
	flag.StringVar(&c.databaseURL, "database-url", "", "PostgreSQL URL (Cloud SQL Auth Proxy on localhost); the login is an evidence_collector member")
	flag.StringVar(&c.tenant, "tenant", "", "trusted installation tenant, e.g. hackathon")
	flag.StringVar(&c.receiverURL, "receiver-url", "", "receiver HTTPS origin, e.g. https://receiver.agent-targets.svc:8443")
	flag.StringVar(&c.targetID, "target-id", "", "catalog target_id of the receiver, e.g. receiver-primary (lease and probe scope target/<id>)")
	flag.StringVar(&c.trustBundle, "tls-ca", "", "PEM trust bundle, e.g. /etc/agentarium-trust/ca.pem")
	flag.StringVar(&c.certFile, "tls-cert", "", "evidence-collector client certificate file (required without --identity-url)")
	flag.StringVar(&c.keyFile, "tls-key", "", "evidence-collector client key file (required without --identity-url)")
	flag.StringVar(&c.identityURL, "identity-url", "", "identity HTTPS origin for in-memory certificate bootstrap; empty uses --tls-cert/--tls-key")
	flag.StringVar(&c.tokenFile, "bootstrap-token", "", "projected agentarium-identity token file (required with --identity-url)")
	flag.StringVar(&c.healthURL, "health-url", "", "control-health HTTPS origin")
	flag.StringVar(&c.healthSourceID, "health-source-id", "", "lease source_id of this replica")
	flag.StringVar(&c.version, "version", "", "deployed collector version (lease active_version)")
	flag.StringVar(&c.auditSourceID, "audit-source-id", "", "audit source_id registered for the DB login (audit.db_role_sources)")
	flag.StringVar(&c.auditSourceVersion, "audit-source-version", "", "audit source_version (the deployed collector version)")
	flag.StringVar(&c.epochDir, "epoch-dir", "", "persistent audit producer epoch directory, exclusive per process")
	flag.StringVar(&c.probeActionKey, "probe-action-key", "", "fixed UUID used only by the 5-second receipt probe")
	flag.DurationVar(&c.settle, "feed-settle", 5*time.Second, "keep the feed cursor this far behind DB time (received_at is not commit order)")
	flag.DurationVar(&c.lateWindow, "late-window", 10*time.Minute, "keep polling a receipt this long after first trigger for a late receipt")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, c); err != nil {
		log.Error("evidence-collector stopped", "err", err)
		os.Exit(1)
	}
}

func (c config) validate() error {
	required := []struct{ name, value string }{
		{"--database-url", c.databaseURL}, {"--tenant", c.tenant}, {"--receiver-url", c.receiverURL}, {"--target-id", c.targetID},
		{"--tls-ca", c.trustBundle},
		{"--health-url", c.healthURL}, {"--health-source-id", c.healthSourceID}, {"--version", c.version},
		{"--audit-source-id", c.auditSourceID}, {"--audit-source-version", c.auditSourceVersion}, {"--epoch-dir", c.epochDir},
		{"--probe-action-key", c.probeActionKey},
	}
	if c.identityURL != "" {
		required = append(required, struct{ name, value string }{"--bootstrap-token", c.tokenFile})
	} else {
		required = append(required, struct{ name, value string }{"--tls-cert", c.certFile}, struct{ name, value string }{"--tls-key", c.keyFile})
	}
	for _, f := range required {
		if f.value == "" {
			return fmt.Errorf("%s is required", f.name)
		}
	}
	if !healthlease.ValidOrigin(c.healthURL) {
		return errors.New("--health-url must be an https origin")
	}
	if id, err := uuid.Parse(c.probeActionKey); err != nil || id.String() != c.probeActionKey {
		return errors.New("--probe-action-key must be a lower-case UUID")
	}
	if c.settle < 0 || c.lateWindow < 0 {
		return errors.New("--feed-settle and --late-window must not be negative")
	}
	return nil
}

func run(log *slog.Logger, c config) error {
	if err := c.validate(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cert, healthClient, err := certSource(ctx, log, certFlags{identityURL: c.identityURL, tokenFile: c.tokenFile,
		trustBundle: c.trustBundle, certFile: c.certFile, keyFile: c.keyFile})
	if err != nil {
		return err
	}
	receipts, err := receipt.NewClientWithCertificate(c.receiverURL, c.trustBundle, cert)
	if err != nil {
		return err
	}
	sourceEpoch, release, err := epoch.Acquire(c.epochDir)
	if err != nil {
		return err
	}
	defer release()
	pool, err := pgxpool.New(ctx, c.databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return err
	}
	reader, err := feed.New(pool, c.tenant)
	if err != nil {
		return err
	}
	col := &collector.Collector{Pool: pool, Feed: reader, Receipts: receipts, Log: log,
		Cfg: collector.Config{Tenant: c.tenant, Settle: c.settle, LateWindow: c.lateWindow, PageSize: feed.MaxPageSize,
			Audit: collector.AuditConfig{SourceID: c.auditSourceID, Version: c.auditSourceVersion, Epoch: sourceEpoch}}}
	prober := &probe.Prober{Receipts: receipts, ProbeActionKey: c.probeActionKey, TargetID: c.targetID,
		HealthURL: c.healthURL, Client: healthClient, Log: log}
	started := time.Now()
	lease := healthlease.Reporter{
		URL: c.healthURL, Client: healthClient, SourceID: c.healthSourceID,
		Component: probe.Component, Scope: "target", ScopeID: c.targetID,
		State: func(context.Context) healthlease.State {
			return healthlease.State{ObservedState: observedState(prober.Unhealthy(), col.LastSuccess(), started, time.Now()), ActiveVersion: &c.version}
		},
	}
	if err := lease.Validate(); err != nil {
		return err
	}
	go prober.Run(ctx)
	go lease.Run(ctx, func(err error) { log.Error("destination-evidence lease report failed", "err", err) })
	log.Info("evidence-collector running", "tenant", c.tenant, "target_id", c.targetID, "source_epoch", sourceEpoch)
	return col.Run(ctx)
}

// staleAfter is three heartbeats: a collection loop that has not completed a
// pass in that time no longer produces evidence.
const staleAfter = 3 * healthlease.HeartbeatInterval

// observedState is unhealthy after 3 consecutive receipt probe failures
// (TASK-08 4) or when the collection loop is stale.
func observedState(probeUnhealthy bool, lastPass, started, now time.Time) string {
	if probeUnhealthy {
		return healthlease.Unhealthy
	}
	ref := lastPass
	if ref.IsZero() {
		ref = started
	}
	if now.Sub(ref) > staleAfter {
		return healthlease.Unhealthy
	}
	return healthlease.Healthy
}

// certFlags selects the certificate source. With identityURL the
// certificate is bootstrapped and renewed in memory; without it the
// cert/key files are re-read per connection.
type certFlags struct {
	identityURL, tokenFile, trustBundle, certFile, keyFile string
}

// certSource starts the certificate source cf selects and returns the
// current client certificate and the control-health mTLS client using it.
// A failed first bootstrap or load stops the start; --identity-url wins over
// files (no silent fallback).
func certSource(ctx context.Context, log *slog.Logger, cf certFlags) (func() (*tls.Certificate, error), *http.Client, error) {
	if cf.identityURL != "" {
		if cf.tokenFile == "" {
			return nil, nil, errors.New("--bootstrap-token is required with --identity-url")
		}
		m := &workloadcert.Manager{URL: cf.identityURL, TokenFile: cf.tokenFile, CAFile: cf.trustBundle, SAN: selfSAN}
		if err := m.Start(ctx, func() { log.Error("service certificate renewal failed") }); err != nil {
			return nil, nil, fmt.Errorf("identity certificate bootstrap: %w", err)
		}
		return m.Certificate, m.Client(healthlease.ControlHealthSAN, true), nil
	}
	health, err := healthlease.FileClient(cf.certFile, cf.keyFile, cf.trustBundle, healthlease.ControlHealthSAN)
	if err != nil {
		return nil, nil, err
	}
	load := func() (*tls.Certificate, error) {
		kp, err := tls.LoadX509KeyPair(cf.certFile, cf.keyFile)
		if err != nil {
			return nil, err
		}
		return &kp, nil
	}
	return load, health, nil
}
