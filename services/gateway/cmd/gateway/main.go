// Command gateway is the TASK-04 policy gateway: the typed action API on
// 8443 (POST /v1/actions, :reevaluate, GET /v1/actions/{action_id} and
// /result), the runtime relays to identity and control-health (relay.go;
// only POST /internal/workload-certificates is served without a client
// certificate), the embedded OPA loaded by packages/policyloader, and the
// execute_requests worker.
//
// Every dependency reads or writes the database in the request's
// transaction: identity and coordinator rows, release.active_policy
// (TASK-14), health.holds and health.control_health_leases (TASK-10),
// workload_data_state, adapter_executions and action_results (TASK-05),
// audit_append and enqueue_decision_input (TASK-07) with a durable producer
// epoch, and the activation probe binding (TASK-03). Work readiness of user
// sessions is checked with control-health over HTTP (TASK-10
// GET /internal/control-health/work-readiness/checks/{id}); while
// control-health does not serve that API, every user-session POST answers 503
// and stores nothing. The gateway reports its component = gateway lease to
// control-health. The intent checker (TASK-04 M5) is not wired: its default
// is not_run, which keeps the Rego verdict (TASK-04 3.3). A missing input
// stops the start.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/healthlease"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/services/gateway/internal/epoch"
	"github.com/Beaver-Dam-Community/Agentarium/services/gateway/internal/gateway"
)

// selfSAN is the gateway's service identity (TASK-06 KSA table,
// agent-control/policy-gateway) requested in --identity-url mode.
const selfSAN = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"

type config struct {
	listen, dbURL, environment, gatewaySAN string
	trustBundle, certFile, keyFile         string
	bootstrapToken                         string
	keyID, bundleKeyFile                   string
	adapterURLs                            string
	modelProfiles                          string
	// auditSourceID is registered for the gateway DB login in
	// audit.db_role_sources; auditSourceVersion is the deployed version.
	auditSourceID, auditSourceVersion string
	// epochDir is the persistent, per-process producer epoch directory.
	epochDir string
	// healthURL is the control-health https origin (lease and work
	// readiness); healthSourceID the lease source_id of this replica.
	healthURL, healthSourceID string
	// identityURL is the workload-identity https origin the runtime relays
	// forward to (TASK-03 3.3, TASK-04 relay row); identitySAN its server SAN.
	identityURL, identitySAN string
	// auditURL is the audit-writer https origin the runtime work-events
	// relay forwards to (TASK-07, TASK-04 relay row); auditWriterSAN its
	// server SAN.
	auditURL, auditWriterSAN string
}

func main() {
	// This offline contract-test command must run before service configuration:
	// its fixture supplies trusted context and catalog, without HTTP, DB or OPA.
	if len(os.Args) > 1 && os.Args[1] == "canonical-vectors" {
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: gateway canonical-vectors <vectors.json>")
			os.Exit(2)
		}
		if err := runVectors(os.Args[2], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	var c config
	flag.StringVar(&c.listen, "listen", ":8443", "HTTPS listen address")
	flag.StringVar(&c.dbURL, "database-url", os.Getenv("GATEWAY_DATABASE_URL"), "PostgreSQL URL (Cloud SQL Auth Proxy on localhost)")
	flag.StringVar(&c.environment, "environment", "", "installation environment (ActionEnvelope environment, desired_bundle row)")
	flag.StringVar(&c.gatewaySAN, "gateway-san", "", "the gateway's own SAN, stored as authenticated_gateway")
	flag.StringVar(&c.trustBundle, "trust-bundle", "/etc/agentarium-trust/ca.pem", "PEM trust bundle (ConfigMap agentarium-trust)")
	flag.StringVar(&c.certFile, "tls-cert", "/var/run/agentarium/tls/tls.crt", "workload certificate from the identity bootstrap (server and adapter client)")
	flag.StringVar(&c.keyFile, "tls-key", "/var/run/agentarium/tls/tls.key", "workload key (file mode)")
	flag.StringVar(&c.bootstrapToken, "bootstrap-token", "", "projected agentarium-identity token file; enables in-memory certificates, otherwise uses --tls-cert/--tls-key")
	flag.StringVar(&c.keyID, "bundle-key-id", "prod-v1", "the only bundle signing key this gateway trusts")
	flag.StringVar(&c.bundleKeyFile, "bundle-key-file", "/etc/agentarium-bundle-keys/prod-v1.pem", "PEM PUBLIC KEY of --bundle-key-id (ConfigMap agentarium-bundle-keys)")
	flag.StringVar(&c.adapterURLs, "adapter-urls", "", "comma-separated adapter_id=https://host:port for execute delivery")
	flag.StringVar(&c.modelProfiles, "model-profiles", os.Getenv("GATEWAY_MODEL_PROFILES"), "JSON file of model.generate profile constants (canonical.ParseModelProfiles); required")
	flag.StringVar(&c.auditSourceID, "audit-source-id", "", "audit source_id registered for the gateway DB login (audit.db_role_sources)")
	flag.StringVar(&c.auditSourceVersion, "audit-source-version", "", "audit source_version (the deployed gateway version)")
	flag.StringVar(&c.epochDir, "epoch-dir", "", "persistent audit producer epoch directory, exclusive per process")
	flag.StringVar(&c.healthURL, "health-url", "", "control-health HTTPS origin for the gateway lease and work readiness (TASK-10)")
	flag.StringVar(&c.healthSourceID, "health-source-id", "", "lease source_id (one per gateway replica)")
	flag.StringVar(&c.identityURL, "identity-url", "", "workload-identity HTTPS origin for the runtime relays (TASK-03 3.3)")
	flag.StringVar(&c.identitySAN, "identity-san", gateway.IdentitySAN, "workload-identity server SAN the relay client accepts")
	flag.StringVar(&c.auditURL, "audit-url", "", "audit-writer HTTPS origin for the runtime work-events relay (TASK-07)")
	flag.StringVar(&c.auditWriterSAN, "audit-writer-san", gateway.AuditWriterSAN, "audit-writer server SAN the relay client accepts")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, c); err != nil {
		log.Error("gateway stopped", "err", err)
		os.Exit(1)
	}
}

// validate fails the start on any missing input, before anything is opened.
func (c config) validate() error {
	var missing []string
	for _, f := range []struct{ name, value string }{
		{"--database-url", c.dbURL}, {"--environment", c.environment}, {"--gateway-san", c.gatewaySAN},
		{"--trust-bundle", c.trustBundle},
		{"--bundle-key-id", c.keyID}, {"--bundle-key-file", c.bundleKeyFile},
		{"--audit-source-id", c.auditSourceID}, {"--audit-source-version", c.auditSourceVersion},
		{"--epoch-dir", c.epochDir}, {"--health-url", c.healthURL}, {"--health-source-id", c.healthSourceID},
		{"--identity-url", c.identityURL}, {"--identity-san", c.identitySAN},
		{"--audit-url", c.auditURL}, {"--audit-writer-san", c.auditWriterSAN},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if c.bootstrapToken == "" {
		if c.certFile == "" {
			missing = append(missing, "--tls-cert")
		}
		if c.keyFile == "" {
			missing = append(missing, "--tls-key")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required: %v", missing)
	}
	if !healthlease.ValidOrigin(c.healthURL) {
		return errors.New("--health-url must be an https origin")
	}
	if !healthlease.ValidOrigin(c.identityURL) {
		return errors.New("--identity-url must be an https origin")
	}
	if !healthlease.ValidOrigin(c.auditURL) {
		return errors.New("--audit-url must be an https origin")
	}
	return nil
}

func run(log *slog.Logger, c config) error {
	if err := c.validate(); err != nil {
		return err
	}
	// The bootstrap relay is a required route (TASK-03 3.3.2, TASK-06 3.1), so
	// a missing or malformed identity origin stops the gateway instead of
	// leaving a ready gateway without it.
	if c.identityURL == "" || !validOrigin(c.identityURL) || c.identitySAN == "" {
		return errors.New("--identity-url must be https://host:port and --identity-san must be set")
	}
	adapters, err := parseAdapterURLs(c.adapterURLs)
	if err != nil {
		return err
	}
	// Bundle data.catalog carries no model profile constants, so they are an
	// install input read once here, before any listener or readiness exists.
	// A missing or invalid file stops the gateway (fail closed).
	profiles, err := loadModelProfiles(log, c.modelProfiles)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, c.dbURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	roots := x509.NewCertPool()
	pemBytes, err := os.ReadFile(c.trustBundle)
	if err != nil {
		return err
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return errors.New("trust bundle has no certificates")
	}
	getCert, err := certSource(ctx, log, c)
	if err != nil {
		return err
	}
	healthClient, err := gateway.NewIdentityClient(roots, healthlease.ControlHealthSAN, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return getCert() })
	if err != nil {
		return fmt.Errorf("control-health client: %w", err)
	}
	producerEpoch, releaseEpoch, err := epoch.Acquire(c.epochDir)
	if err != nil {
		return fmt.Errorf("--epoch-dir: %w", err)
	}
	defer releaseEpoch()

	pub, err := os.ReadFile(c.bundleKeyFile)
	if err != nil {
		return err
	}
	gcs, err := storage.NewClient(ctx)
	if err != nil {
		return err
	}
	defer gcs.Close()
	loader, err := policyloader.New(policyloader.Config{
		Source:  policyloader.PGSource{Pool: pool, Environment: c.environment},
		Fetcher: policyloader.GCSFetcher{Client: gcs},
		Keys:    map[string]string{c.keyID: string(pub)},
		KeyID:   c.keyID,
		Query:   policyloader.GatewayQuery,
		// SPEC-QUESTION: policy_bundle_loaded / policy_bundle_load_failed
		// (COMMON event registry) have no tenant, which AuditEvent requires
		// and producer_event_grants keys on; they are logged until one is
		// defined. The lease carries the load result.
		OnLoaded: func(s policyloader.Status) error {
			log.Info("policy bundle loaded", "bundle_id", s.Loaded.BundleID, "artifact_digest", s.Loaded.ArtifactDigest, "revision", s.Revision)
			return nil
		},
		OnFailed: func(s policyloader.Status, err error) error {
			log.Error("policy bundle load failed", "artifact_digest", s.LastAttempt.ArtifactDigest, "err", err)
			return nil
		},
	})
	if err != nil {
		return err
	}
	go loader.Run(ctx)

	// One execute client per configured adapter, each accepting only that
	// adapter's service SAN (gateway.AdapterSAN).
	endpoints := map[string]gateway.AdapterEndpoint{}
	for id, u := range adapters {
		client, err := gateway.NewAdapterClient(id, roots, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return getCert() })
		if err != nil {
			return err
		}
		endpoints[id] = gateway.AdapterEndpoint{BaseURL: u, Client: client}
	}
	svc, err := newService(pool, loader, log, c, producerEpoch, healthClient)
	if err != nil {
		return err
	}
	svc.ModelProfiles = profiles
	svc.Adapter = func(id string) (gateway.AdapterEndpoint, bool) { ep, ok := endpoints[id]; return ep, ok }
	lease, err := newLease(pool, loader, c, healthClient)
	if err != nil {
		return err
	}
	go svc.RunWorker(ctx)
	go lease.Run(ctx, func(err error) { log.Error("gateway lease report failed", "err", err) })

	identityClient, err := gateway.NewRelayClient(roots, c.identitySAN, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return getCert() })
	if err != nil {
		return fmt.Errorf("identity relay client: %w", err)
	}
	auditClient, err := gateway.NewRelayClient(roots, c.auditWriterSAN, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return getCert() })
	if err != nil {
		return fmt.Errorf("audit relay client: %w", err)
	}

	mux := http.NewServeMux()
	(&gateway.Handler{Svc: svc}).Register(mux)
	(&gateway.Relay{
		IdentityURL: strings.TrimSuffix(c.identityURL, "/"), Identity: identityClient,
		HealthURL: strings.TrimSuffix(c.healthURL, "/"), Health: healthClient,
		AuditURL: strings.TrimSuffix(c.auditURL, "/"), Audit: auditClient,
		Live: svc.LiveCertificate, Auth: svc.Authenticate, Log: log,
	}).Register(mux)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	// Readiness fails until a bundle is loaded (TASK-04 3.1).
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if loader.Current() == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{
		Addr:              c.listen,
		Handler:           http.MaxBytesHandler(gateway.RequireClientCert(mux), 2<<20),
		ReadHeaderTimeout: 10 * time.Second,
		// Bootstrap callers have no certificate yet, so the handshake accepts
		// a missing one and RequireClientCert demands it on every other path
		// (TASK-03 3.3.1). A certificate that is presented must still verify.
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return getCert() },
			ClientAuth:     tls.VerifyClientCertIfGiven,
			ClientCAs:      roots,
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("gateway listening", "addr", c.listen, "environment", c.environment, "audit_source_id", c.auditSourceID,
		"source_epoch", producerEpoch)
	if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// newService wires every dependency the decision path reads to its
// database or control-health implementation (see the package comment for
// the work-readiness gap and the intent checker).
func newService(pool *pgxpool.Pool, bundle gateway.Snapshots, log *slog.Logger, c config, producerEpoch string,
	healthClient *http.Client) (*gateway.Service, error) {
	if pool == nil || bundle == nil || c.environment == "" || c.gatewaySAN == "" {
		return nil, errors.New("gateway needs a database pool, a bundle loader, an environment and its SAN")
	}
	if healthClient == nil || !healthlease.ValidOrigin(c.healthURL) {
		return nil, errors.New("gateway needs a control-health client and https origin")
	}
	auditor, err := gateway.NewPGAuditor(gateway.AuditConfig{SourceID: c.auditSourceID, Version: c.auditSourceVersion, Epoch: producerEpoch})
	if err != nil {
		return nil, err
	}
	return &gateway.Service{
		Pool: pool, Bundle: bundle, Environment: c.environment, GatewayIdentity: c.gatewaySAN, Log: log,
		Policy:    gateway.PGPolicy{Environment: c.environment},
		Health:    gateway.PGHealth{},
		Readiness: gateway.HTTPReadiness{BaseURL: strings.TrimSuffix(c.healthURL, "/"), Client: healthClient},
		Adapters:  gateway.PGAdapters{},
		Audit:     auditor,
		Probes:    gateway.PGProbes{},
	}, nil
}

// newLease is the gateway's component = gateway, global/* lease (TASK-04
// 3.5, TASK-10 3.2 scope rule: every component but node, target and adapter
// ones is global).
func newLease(pool *pgxpool.Pool, bundle gateway.BundleStatus, c config, healthClient *http.Client) (healthlease.Reporter, error) {
	r := healthlease.Reporter{
		URL: c.healthURL, Client: healthClient, SourceID: c.healthSourceID,
		Component: "gateway", Scope: "global", ScopeID: "*",
		State: gateway.LeaseState(bundle, pool.Ping),
	}
	return r, r.Validate()
}

// loadModelProfiles reads and validates --model-profiles and logs the
// canonical digest of the validated profiles so operators can compare it with
// the model adapter's.
func loadModelProfiles(log *slog.Logger, path string) (map[string]canonical.ModelProfileConfig, error) {
	if path == "" {
		return nil, errors.New("--model-profiles is required")
	}
	m, err := canonical.LoadModelProfiles(path)
	if err != nil {
		return nil, fmt.Errorf("--model-profiles: %w", err)
	}
	d, err := canonical.ModelProfilesDigest(m)
	if err != nil {
		return nil, fmt.Errorf("--model-profiles: digest: %w", err)
	}
	log.Info("model profiles loaded", "path", path, "model_profiles_digest", d)
	return m, nil
}

func parseAdapterURLs(s string) (map[string]string, error) {
	out := map[string]string{}
	if s == "" {
		return out, nil
	}
	for _, kv := range strings.Split(s, ",") {
		id, u, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || id == "" || !validOrigin(u) {
			return nil, errors.New("--adapter-urls entries must be adapter_id=https://host:port")
		}
		if _, known := gateway.AdapterSAN(id); !known {
			return nil, fmt.Errorf("--adapter-urls: unknown adapter_id %q", id)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("--adapter-urls: adapter_id %q given twice", id)
		}
		out[id] = strings.TrimSuffix(u, "/")
	}
	return out, nil
}

// validOrigin accepts only https://host[:port] with an optional bare
// trailing slash: no userinfo, path, query (not even a bare "?") or
// fragment. The worker appends /internal/adapter/<id>/execute to an adapter
// origin, and the bootstrap relay appends /internal/workload-certificates to
// the identity origin.
func validOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Opaque == "" && u.Hostname() != "" && u.User == nil &&
		(u.Path == "" || u.Path == "/") && u.RawPath == "" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawFragment == "" &&
		!strings.Contains(raw, "#")
}

// certSource uses --bootstrap-token to select in-memory certificates. The
// required --identity-url remains the relay origin in both certificate modes.
// A failed bootstrap never falls back to files.
func certSource(ctx context.Context, log *slog.Logger, c config) (func() (*tls.Certificate, error), error) {
	if c.bootstrapToken != "" {
		if !validOrigin(c.identityURL) || c.identitySAN == "" {
			return nil, errors.New("--identity-url and --identity-san are required for certificate bootstrap")
		}
		// authenticated_gateway must be the identity this certificate carries.
		if c.gatewaySAN != selfSAN {
			return nil, fmt.Errorf("--gateway-san must be %s with --bootstrap-token", selfSAN)
		}
		m := &workloadcert.Manager{URL: strings.TrimSuffix(c.identityURL, "/"), TokenFile: c.bootstrapToken, CAFile: c.trustBundle, SAN: selfSAN, IdentityServerSAN: c.identitySAN}
		if err := m.Start(ctx, func() { log.Error("service certificate renewal failed") }); err != nil {
			return nil, fmt.Errorf("identity certificate bootstrap: %w", err)
		}
		return m.Certificate, nil
	}
	certs := &certReloader{cert: c.certFile, key: c.keyFile}
	if err := certs.load(); err != nil {
		return nil, err
	}
	go certs.run(ctx, log)
	return certs.get, nil
}

// certReloader serves the workload certificate the bootstrap client writes
// and picks up its renewal (24h lifetime, renewed at 50%).
type certReloader struct {
	cert, key string
	mu        sync.RWMutex
	current   *tls.Certificate
}

func (c *certReloader) load() error {
	kp, err := tls.LoadX509KeyPair(c.cert, c.key)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.current = &kp
	c.mu.Unlock()
	return nil
}

func (c *certReloader) get() (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current, nil
}

func (c *certReloader) run(ctx context.Context, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.load(); err != nil {
				log.Error("certificate reload failed", "err", err)
			}
		}
	}
}
