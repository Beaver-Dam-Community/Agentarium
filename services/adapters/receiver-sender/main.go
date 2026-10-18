// Command receiver-sender is the TASK-05 receiver-sender adapter: it serves
// POST /internal/adapter/receiver-sender/execute for the gateway and sends
// approved receiver.submit requests to the registered test receiver.
//
//	receiver-sender [flags]                         run the adapter
//	receiver-sender canonical-vectors <vectors.json> tests/contracts digest check
//
// Every dependency is wired; a missing input stops the start:
//   - stored decision, envelope and content: the TASK-04 decisions schema
//     (packages/adapters/inputs), checked at start;
//   - policy bundle: packages/policyloader on the environment's
//     desired_bundle row, GCS object and ES256 key --bundle-key-id
//     (packages/adapters/bundle);
//   - audit: audit.audit_append() over the adapter DB login with
//     --audit-source-id/--audit-source-version and a durable --epoch-dir
//     epoch (packages/adapters/audit);
//   - coordinator and credential broker over mTLS; the broker binding
//     receiver-api-key gives the X-Agentarium-Receiver-Key header;
//   - the component = adapter lease to control-health every 5 seconds, with
//     active_version = the loaded bundle artifact_digest.
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
	"regexp"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/audit"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/bundle"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/inputs"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/store"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/healthlease"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/services/adapters/receiver-sender/internal/epoch"
	"github.com/Beaver-Dam-Community/Agentarium/services/adapters/receiver-sender/internal/receiver"
)

// Internal service SANs (COMMON service PKI, KSA table).
const (
	coordinatorSAN = "spiffe://agentarium.internal/ns/agent-control/sa/coordinator"
	brokerSAN      = "spiffe://agentarium.internal/ns/agent-control/sa/credential-broker"
	// selfSAN is this adapter's identity (agent-adapters/receiver-sender),
	// requested in --identity-url mode.
	selfSAN = "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender"
)

// transportConfig is the transport test seam (transport.Config). The binary
// leaves it zero, so netns_inode is read from /proc/self/ns/net. Only the
// local M3-1 harness test sets Netns: a macOS host has no /proc, and the
// coordinator refuses a connection key without netns_inode.
var transportConfig transport.Config

// adapterWorkload is the lease scope_id: workload <namespace>/<ksa> of this
// adapter (COMMON KSA table). control-health checks it against the certificate.
const adapterWorkload = "agent-adapters/receiver-sender"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "canonical-vectors" {
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: receiver-sender canonical-vectors <vectors.json>")
			os.Exit(2)
		}
		if err := runVectors(os.Args[2], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	c := parseFlags(flag.CommandLine, os.Args[1:])
	if err := run(logger, c); err != nil {
		logger.Error("receiver-sender exited", "err", err)
		os.Exit(1)
	}
}

// config is the trusted process configuration (flags).
type config struct {
	listen, certFile, keyFile, trustFile, clusterCAFile string
	// identityURL and bootstrapToken select in-memory certificate bootstrap
	// (TASK-03 3.3.2); empty identityURL uses the cert/key files.
	identityURL, bootstrapToken string
	coordinatorURL, brokerURL   string
	callTimeout                 time.Duration
	storedInputs                string
	// environment is the desired_bundle environment this deployment serves.
	environment, bundleKeyID, bundleKeyFile string
	// auditSourceID is registered for the adapter DB login in
	// audit.db_role_sources; auditSourceVersion is the deployed version.
	auditSourceID, auditSourceVersion string
	// epochDir is the persistent, per-process producer epoch directory.
	epochDir string
	// healthURL is the control-health https origin; healthSourceID the
	// lease source_id <adapter_id>/<pod name>.
	healthURL, healthSourceID string
}

func parseFlags(fs *flag.FlagSet, args []string) config {
	var c config
	fs.StringVar(&c.listen, "listen", ":8443", "execute API listen address (mTLS)")
	fs.StringVar(&c.certFile, "tls-cert-file", "", "adapter certificate PEM issued by the identity service (required without --identity-url)")
	fs.StringVar(&c.keyFile, "tls-key-file", "", "adapter private key PEM (required without --identity-url)")
	fs.StringVar(&c.identityURL, "identity-url", "", "identity HTTPS origin for in-memory certificate bootstrap; empty uses --tls-cert-file/--tls-key-file")
	fs.StringVar(&c.bootstrapToken, "bootstrap-token", "", "projected agentarium-identity token file (required with --identity-url)")
	fs.StringVar(&c.trustFile, "tls-ca-file", "", "agentarium-trust bundle PEM (required)")
	fs.StringVar(&c.clusterCAFile, "cluster-ca-file", "", "CA bundle for catalog ca_ref=cluster (optional)")
	fs.StringVar(&c.coordinatorURL, "coordinator-url", "", "dispatch coordinator base URL, https://host:port (required)")
	fs.StringVar(&c.brokerURL, "broker-url", "", "credential broker base URL, https://host:port (required)")
	fs.DurationVar(&c.callTimeout, "call-timeout", 5*time.Second, "internal call timeout")
	fs.StringVar(&c.storedInputs, "stored-inputs", inputsPostgres, "reader of the stored TASK-04 decision/envelope/content; only postgres (decisions schema, migration 20261016181826_gateway_decisions)")
	fs.StringVar(&c.environment, "environment", os.Getenv("AGENTARIUM_ENVIRONMENT"), "catalog environment this deployment serves (release.desired_bundle environment)")
	fs.StringVar(&c.bundleKeyID, "bundle-key-id", "prod-v1", "the only bundle signing key the adapter trusts")
	fs.StringVar(&c.bundleKeyFile, "bundle-key-file", "/etc/agentarium-bundle-keys/prod-v1.pem", "PEM PUBLIC KEY of --bundle-key-id (ConfigMap agentarium-bundle-keys)")
	fs.StringVar(&c.auditSourceID, "audit-source-id", "", "audit source_id registered for the adapter DB login (audit.db_role_sources)")
	fs.StringVar(&c.auditSourceVersion, "audit-source-version", "", "audit source_version (the deployed adapter version)")
	fs.StringVar(&c.epochDir, "epoch-dir", "", "persistent audit producer epoch directory, exclusive per process")
	fs.StringVar(&c.healthURL, "health-url", "", "control-health HTTPS origin for the adapter lease (TASK-10)")
	fs.StringVar(&c.healthSourceID, "health-source-id", "", "lease source_id receiver-sender/<pod name> (one per replica)")
	_ = fs.Parse(args)
	return c
}

// --stored-inputs values. The unwired reader is gone: the binary always
// reads the stored inputs from PostgreSQL.
const inputsPostgres = "postgres"

var reSourceID = regexp.MustCompile(`^` + receiver.AdapterID + `/[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// validate fails the start on any missing input, before anything is opened.
func (c config) validate() error {
	var missing []string
	required := []struct{ name, value string }{
		{"--tls-ca-file", c.trustFile},
		{"--coordinator-url", c.coordinatorURL}, {"--broker-url", c.brokerURL},
		{"--environment", c.environment}, {"--bundle-key-id", c.bundleKeyID}, {"--bundle-key-file", c.bundleKeyFile},
		{"--audit-source-id", c.auditSourceID}, {"--audit-source-version", c.auditSourceVersion},
		{"--epoch-dir", c.epochDir}, {"--health-url", c.healthURL}, {"--health-source-id", c.healthSourceID},
	}
	if c.identityURL != "" {
		required = append(required, struct{ name, value string }{"--bootstrap-token", c.bootstrapToken})
	} else {
		required = append(required, struct{ name, value string }{"--tls-cert-file", c.certFile}, struct{ name, value string }{"--tls-key-file", c.keyFile})
	}
	for _, f := range required {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required: %v", missing)
	}
	if c.storedInputs != inputsPostgres {
		return fmt.Errorf("--stored-inputs %q: only %s is supported", c.storedInputs, inputsPostgres)
	}
	if !healthlease.ValidOrigin(c.healthURL) {
		return errors.New("--health-url must be an https origin")
	}
	if !reSourceID.MatchString(c.healthSourceID) {
		return fmt.Errorf("--health-source-id %q must be %s/<pod name>", c.healthSourceID, receiver.AdapterID)
	}
	if c.callTimeout <= 0 {
		return errors.New("--call-timeout must be positive")
	}
	return nil
}

func run(logger *slog.Logger, c config) error {
	if err := c.validate(); err != nil {
		return err
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required (the Cloud SQL Auth Proxy sidecar on 127.0.0.1:5432)")
	}
	pod, err := podUID(os.Getenv)
	if err != nil {
		return err
	}
	bundleKey, err := os.ReadFile(c.bundleKeyFile)
	if err != nil {
		return fmt.Errorf("--bundle-key-file: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cert, healthClient, err := certSource(ctx, logger, c)
	if err != nil {
		return err
	}
	coordTLS, err := execute.ClientTLSConfigFrom(c.trustFile, cert, coordinatorSAN)
	if err != nil {
		return err
	}
	brokerTLS, err := execute.ClientTLSConfigFrom(c.trustFile, cert, brokerSAN)
	if err != nil {
		return err
	}
	serverTLS, err := execute.ServerTLSConfigFrom(c.trustFile, cert)
	if err != nil {
		return err
	}
	caRefs := map[string]string{"agentarium-trust": c.trustFile}
	if c.clusterCAFile != "" {
		caRefs["cluster"] = c.clusterCAFile
	}

	producerEpoch, releaseEpoch, err := epoch.Acquire(c.epochDir)
	if err != nil {
		return fmt.Errorf("--epoch-dir: %w", err)
	}
	defer releaseEpoch()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	gcs, err := storage.NewClient(ctx) // Workload Identity, bundle bucket read
	if err != nil {
		return err
	}
	defer gcs.Close()
	loader, err := newLoader(logger, pool, policyloader.GCSFetcher{Client: gcs}, c.environment, c.bundleKeyID, string(bundleKey))
	if err != nil {
		return err
	}
	bundles := &bundle.Source{Loader: loader}

	internal := func(t *tls.Config) *http.Client {
		return &http.Client{Timeout: c.callTimeout, Transport: &http.Transport{TLSClientConfig: t}}
	}
	engine, err := newEngine(ctx, deps{
		Pool:        pool,
		Bundles:     bundles,
		Audit:       audit.Config{SourceID: c.auditSourceID, Version: c.auditSourceVersion, Epoch: producerEpoch},
		Coordinator: &execute.HTTPCoordinator{BaseURL: c.coordinatorURL, Client: internal(coordTLS)},
		Credentials: &execute.HTTPBroker{BaseURL: c.brokerURL, Client: internal(brokerTLS)},
		TLS:         execute.SourceTLSMaterial{Cert: cert, CARefFiles: caRefs},
		Transport:   transportConfig,
		PodUID:      pod,
		Logger:      logger,
		CallTimeout: c.callTimeout,
	})
	if err != nil {
		return err
	}
	lease, err := newLease(c, healthClient, bundles, loader, pool)
	if err != nil {
		return err
	}

	// The bundle loader and the lease run for the whole process; an
	// execution before the first load stays received (nothing reserved).
	go loader.Run(ctx)
	go lease.Run(ctx, func(err error) { logger.Warn("adapter lease not reported", "err", err) })
	// In-flight executions are not cut by SIGTERM: a cancel after the claim
	// would turn a send into unknown. Shutdown waits for them instead.
	engine.Start(context.WithoutCancel(ctx))
	if err := engine.Recover(ctx); err != nil {
		return fmt.Errorf("restart correction: %w", err)
	}

	mux := http.NewServeMux()
	(&execute.Handler{Engine: engine, Logger: logger}).Register(mux)
	srv := &http.Server{
		Addr:              c.listen,
		Handler:           mux,
		TLSConfig:         serverTLS,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	logger.Info("receiver-sender listening", "addr", c.listen, "environment", c.environment,
		"audit_source_id", c.auditSourceID, "source_epoch", producerEpoch, "lease_source_id", c.healthSourceID)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdown)
	engine.Wait()
	return err
}

// deps are the wired dependencies of the engine. Coordinator, Credentials
// and TLS are the mTLS clients in main and fakes in the integration test.
type deps struct {
	Pool        *pgxpool.Pool
	Bundles     execute.BundleSource
	Audit       audit.Config
	Coordinator execute.Coordinator
	Credentials execute.Credentials
	TLS         execute.TLSMaterial
	Transport   transport.Config
	PodUID      string
	Logger      *slog.Logger
	CallTimeout time.Duration
}

// certSource starts the certificate source c selects and returns it with the
// control-health lease client that presents it. With --identity-url the
// certificate is bootstrapped and renewed in memory (TASK-03 3.3.2); without
// it --tls-cert-file/--tls-key-file are re-read on every handshake. A failed
// first bootstrap or load stops the start.
func certSource(ctx context.Context, logger *slog.Logger, c config) (execute.CertSource, *http.Client, error) {
	if c.trustFile == "" {
		return nil, nil, errors.New("--tls-ca-file is required")
	}
	if c.identityURL == "" {
		if c.certFile == "" || c.keyFile == "" {
			return nil, nil, errors.New("--tls-cert-file and --tls-key-file are required without --identity-url")
		}
		hc, err := healthlease.FileClient(c.certFile, c.keyFile, c.trustFile, healthlease.ControlHealthSAN)
		if err != nil {
			return nil, nil, fmt.Errorf("control-health client: %w", err)
		}
		return execute.FileCertSource(execute.TLSFiles{CertFile: c.certFile, KeyFile: c.keyFile, CAFile: c.trustFile}), hc, nil
	}
	if c.bootstrapToken == "" {
		return nil, nil, errors.New("--bootstrap-token is required with --identity-url")
	}
	m := &workloadcert.Manager{URL: c.identityURL, TokenFile: c.bootstrapToken, CAFile: c.trustFile, SAN: selfSAN}
	if err := m.Start(ctx, func() { logger.Error("service certificate renewal failed") }); err != nil {
		return nil, nil, fmt.Errorf("identity certificate bootstrap: %w", err)
	}
	return m.Certificate, m.Client(healthlease.ControlHealthSAN, true), nil
}

// newEngine builds the engine main runs. The stored-input reader checks at
// start that its queries run (tables, views, columns and SELECT grants), so a
// missing schema stops the adapter instead of failing every execution.
func newEngine(ctx context.Context, d deps) (*execute.Engine, error) {
	if d.Pool == nil {
		return nil, errors.New("receiver-sender needs a database pool")
	}
	in := &inputs.PG{Pool: d.Pool, AdapterID: receiver.AdapterID}
	if err := in.Check(ctx); err != nil {
		return nil, fmt.Errorf("stored inputs: %w", err)
	}
	auditor, err := audit.New(d.Pool, d.Audit)
	if err != nil {
		return nil, err
	}
	cfg := execute.Config{
		Adapter:     receiver.Adapter{},
		Store:       &store.PG{Pool: d.Pool},
		Inputs:      in,
		Bundles:     d.Bundles,
		Coordinator: d.Coordinator,
		// TASK-05 3.1: mTLS plus the broker's synthetic API key header (#245).
		Credential:  execute.CredentialStrategy{Kind: execute.CredentialBroker},
		Credentials: d.Credentials,
		TLS:         d.TLS,
		Auditor:     auditor,
		Transport:   d.Transport,
		PodUID:      d.PodUID,
		Logger:      d.Logger,
		CallTimeout: d.CallTimeout,
	}
	if err := cfg.Wired(); err != nil {
		return nil, err
	}
	return execute.New(cfg)
}

// newLoader is the adapter's policyloader: the environment's desired_bundle
// row, the signature-verified bundle and no prepared query (TASK-05 3.4: the
// adapter reads bundle data only).
func newLoader(log *slog.Logger, pool *pgxpool.Pool, fetcher policyloader.Fetcher, environment, keyID, publicKey string) (*policyloader.Loader, error) {
	return policyloader.New(policyloader.Config{
		Source:  policyloader.PGSource{Pool: pool, Environment: environment},
		Fetcher: fetcher,
		Keys:    map[string]string{keyID: publicKey},
		KeyID:   keyID,
		OnLoaded: func(s policyloader.Status) error {
			log.Info("policy bundle loaded", "bundle_id", s.Loaded.BundleID, "artifact_digest", s.Loaded.ArtifactDigest, "revision", s.Revision)
			return nil
		},
		OnFailed: func(s policyloader.Status, err error) error {
			log.Error("policy bundle load failed", "artifact_digest", s.LastAttempt.ArtifactDigest, "err", err)
			return nil
		},
	})
}

// loaderStatus is the part of *policyloader.Loader the lease reads.
type loaderStatus interface{ Status() policyloader.Status }

// pinger is the part of *pgxpool.Pool the lease reads.
type pinger interface{ Ping(context.Context) error }

// newLease is the TASK-05 lease: component adapter, scope workload
// agent-adapters/receiver-sender, source_id receiver-sender/<pod>,
// active_version and loaded_artifact_digest = the loaded bundle
// artifact_digest (the gateway requires it to equal the active one) and
// canonical_version = packages/canonical's version. Before the first load
// the lease is unhealthy with no version; a failed newer load or a failed
// database ping makes it degraded or unhealthy.
func newLease(c config, client *http.Client, bundles *bundle.Source, loader loaderStatus, db pinger) (healthlease.Reporter, error) {
	canonicalVersion := canonical.CanonicalizationVersion
	r := healthlease.Reporter{
		URL: c.healthURL, Client: client, SourceID: c.healthSourceID,
		Component: "adapter", Scope: "workload", ScopeID: adapterWorkload,
		State: func(ctx context.Context) healthlease.State {
			st := healthlease.State{ObservedState: healthlease.Healthy, CanonicalVersion: &canonicalVersion}
			digest := bundles.ArtifactDigest()
			if digest == "" {
				st.ObservedState = healthlease.Unhealthy
				return st
			}
			st.ActiveVersion, st.LoadedArtifactDigest = &digest, &digest
			if loader.Status().LastError != "" {
				st.ObservedState = healthlease.Degraded
			}
			if err := db.Ping(ctx); err != nil {
				st.ObservedState = healthlease.Unhealthy
			}
			return st
		},
	}
	return r, r.Validate()
}

// podUID reads POD_UID (Downward API metadata.uid). Every post-claim
// observation carries pod_uid and the coordinator refuses one without a
// canonical UUID, so the adapter does not start without it.
func podUID(getenv func(string) string) (string, error) {
	v := getenv("POD_UID")
	if !execute.ValidUUID(v) {
		return "", fmt.Errorf("POD_UID %q is required and must be a canonical lowercase UUID (Downward API metadata.uid)", v)
	}
	return v, nil
}
