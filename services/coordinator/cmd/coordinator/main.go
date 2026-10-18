// Command coordinator is the TASK-03 3.2 dispatch coordinator: reservations,
// permit claims, attempt outcomes, activation probe registration and the
// sweeper (expired permits, missing outcomes).
//
// Every dependency reads or writes the database in the business transaction:
// release.active_policy through release.lock_active_policy (TASK-14),
// decisions (TASK-04), holds, node_boot_generation and the required
// control_health_leases (TASK-10), and audit_append (TASK-07) with a durable
// producer epoch. The sweeper reports the component = coordinator lease to
// control-health on its cycle. A missing input stops the start; no
// dependency is left unwired.
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
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/healthlease"
	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/services/coordinator/internal/dispatch"
	"github.com/Beaver-Dam-Community/Agentarium/services/coordinator/internal/epoch"
)

// selfSAN is the coordinator's service identity (TASK-06 KSA table,
// agent-control/coordinator) requested in --identity-url mode.
const selfSAN = "spiffe://agentarium.internal/ns/agent-control/sa/coordinator"

// certFlags selects the certificate source. With identityURL the
// certificate is bootstrapped and renewed in memory (TASK-03 3.3.2);
// without it the cert/key files are loaded and reloaded.
type certFlags struct {
	identityURL, tokenFile, trustBundle, certFile, keyFile string
}

// config is the trusted process configuration (flags and environment).
type config struct {
	listen, dbURL, trustBundle, certFile, keyFile string
	identityURL, tokenFile                        string
	// environment is the catalog environment, the release.active_policy
	// scope_id this deployment serves.
	environment string
	// auditSourceID is registered for the coordinator DB login in
	// audit.db_role_sources; auditSourceVersion is the deployed version and
	// also the lease's active_version.
	auditSourceID, auditSourceVersion string
	// epochDir is the persistent, per-process producer epoch directory.
	epochDir string
	// healthURL is the control-health https origin; healthSourceID the
	// lease source_id.
	healthURL, healthSourceID string
}

func main() {
	var c config
	flag.StringVar(&c.listen, "listen", ":8443", "HTTPS listen address")
	flag.StringVar(&c.dbURL, "database-url", os.Getenv("COORDINATOR_DATABASE_URL"), "PostgreSQL URL (Cloud SQL Auth Proxy on localhost)")
	flag.StringVar(&c.trustBundle, "trust-bundle", "/etc/agentarium-trust/ca.pem", "PEM trust bundle (ConfigMap agentarium-trust) for client and control-health certificates")
	flag.StringVar(&c.certFile, "tls-cert", "/var/run/agentarium/tls/tls.crt", "service certificate from the identity bootstrap (TASK-03 3.3.2), also the control-health client certificate")
	flag.StringVar(&c.keyFile, "tls-key", "/var/run/agentarium/tls/tls.key", "service key")
	flag.StringVar(&c.environment, "environment", os.Getenv("AGENTARIUM_ENVIRONMENT"), "catalog environment this deployment serves (release.active_policy scope_id)")
	flag.StringVar(&c.auditSourceID, "audit-source-id", "", "audit source_id registered for the coordinator DB login (audit.db_role_sources)")
	flag.StringVar(&c.auditSourceVersion, "audit-source-version", "", "audit source_version and lease active_version (the deployed coordinator version)")
	flag.StringVar(&c.epochDir, "epoch-dir", "", "persistent audit producer epoch directory, exclusive per process")
	flag.StringVar(&c.healthURL, "health-url", "", "control-health HTTPS origin for the coordinator lease (TASK-10)")
	flag.StringVar(&c.healthSourceID, "health-source-id", "", "lease source_id (one per coordinator replica)")
	flag.StringVar(&c.identityURL, "identity-url", "", "identity HTTPS origin for in-memory certificate bootstrap")
	flag.StringVar(&c.tokenFile, "bootstrap-token", "", "projected agentarium-identity token file")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, c); err != nil {
		log.Error("coordinator stopped", "err", err)
		os.Exit(1)
	}
}

// validate fails the start on any missing input, before anything is opened.
func (c config) validate() error {
	var missing []string
	for _, f := range []struct{ name, value string }{
		{"--database-url", c.dbURL}, {"--environment", c.environment},
		{"--audit-source-id", c.auditSourceID}, {"--audit-source-version", c.auditSourceVersion},
		{"--epoch-dir", c.epochDir}, {"--health-url", c.healthURL}, {"--health-source-id", c.healthSourceID},
		{"--trust-bundle", c.trustBundle},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if c.identityURL != "" {
		if c.tokenFile == "" {
			missing = append(missing, "--bootstrap-token")
		}
	} else {
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
	return nil
}

func run(log *slog.Logger, c config) error {
	if err := c.validate(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	roots := x509.NewCertPool()
	pemBytes, err := os.ReadFile(c.trustBundle)
	if err != nil {
		return err
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return errors.New("trust bundle has no certificates")
	}
	getCert, err := certSource(ctx, log, certFlags{identityURL: c.identityURL, tokenFile: c.tokenFile, trustBundle: c.trustBundle, certFile: c.certFile, keyFile: c.keyFile})
	if err != nil {
		return err
	}
	healthClient := &http.Client{
		Timeout:       4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			// VerifyConnection validates the chain and exact service URI SAN.
			InsecureSkipVerify:   true,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return getCert() },
			VerifyConnection: func(cs tls.ConnectionState) error {
				pem, err := os.ReadFile(c.trustBundle)
				if err != nil {
					return err
				}
				roots := x509.NewCertPool()
				if !roots.AppendCertsFromPEM(pem) {
					return errors.New("trust bundle has no certificates")
				}
				return healthlease.VerifyServer(cs.PeerCertificates, roots, healthlease.ControlHealthSAN)
			},
		}},
	}

	producerEpoch, releaseEpoch, err := epoch.Acquire(c.epochDir)
	if err != nil {
		return fmt.Errorf("--epoch-dir: %w", err)
	}
	defer releaseEpoch()

	pool, err := pgxpool.New(ctx, c.dbURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	svc, err := newService(pool, log, c, producerEpoch, healthClient)
	if err != nil {
		return err
	}
	go svc.RunSweeper(ctx)

	mux := http.NewServeMux()
	(&dispatch.Handler{Svc: svc}).Register(mux)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	srv := &http.Server{
		Addr:              c.listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return getCert() },
			ClientAuth:     tls.RequireAndVerifyClientCert,
			ClientCAs:      roots,
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("coordinator listening", "addr", c.listen, "environment", c.environment, "audit_source_id", c.auditSourceID,
		"source_epoch", producerEpoch)
	if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// newService wires every coordinator dependency to its database or
// control-health implementation. The lease reports healthy while the
// database answers a ping, and unhealthy otherwise.
func newService(pool *pgxpool.Pool, log *slog.Logger, c config, producerEpoch string, healthClient *http.Client) (*dispatch.Service, error) {
	if pool == nil || c.environment == "" {
		return nil, errors.New("coordinator needs a database pool and an environment")
	}
	auditor, err := dispatch.NewPGAuditor(dispatch.AuditConfig{SourceID: c.auditSourceID, Version: c.auditSourceVersion, Epoch: producerEpoch})
	if err != nil {
		return nil, err
	}
	version := c.auditSourceVersion
	lease := healthlease.Reporter{
		URL: c.healthURL, Client: healthClient, SourceID: c.healthSourceID,
		Component: "coordinator", Scope: "global", ScopeID: "*",
		State: func(ctx context.Context) healthlease.State {
			st := healthlease.State{ObservedState: healthlease.Healthy, ActiveVersion: &version}
			if err := pool.Ping(ctx); err != nil {
				st.ObservedState = healthlease.Unhealthy
			}
			return st
		},
	}
	if err := lease.Validate(); err != nil {
		return nil, err
	}
	return &dispatch.Service{
		Pool:      pool,
		Log:       log,
		Policy:    dispatch.PGPolicy{Environment: c.environment},
		Decisions: dispatch.PGDecisions{},
		Health:    dispatch.PGHealth{},
		Audit:     auditor,
		Leases:    lease,
	}, nil
}

// certSource starts the certificate source cf selects and returns its
// current certificate. A failed first bootstrap or load stops the start.
func certSource(ctx context.Context, log *slog.Logger, cf certFlags) (func() (*tls.Certificate, error), error) {
	if cf.identityURL != "" {
		if cf.tokenFile == "" {
			return nil, errors.New("--bootstrap-token is required with --identity-url")
		}
		m := &workloadcert.Manager{URL: cf.identityURL, TokenFile: cf.tokenFile, CAFile: cf.trustBundle, SAN: selfSAN}
		if err := m.Start(ctx, func() { log.Error("service certificate renewal failed") }); err != nil {
			return nil, fmt.Errorf("identity certificate bootstrap: %w", err)
		}
		return m.Certificate, nil
	}
	certs := &certReloader{cert: cf.certFile, key: cf.keyFile}
	if err := certs.load(); err != nil {
		return nil, err
	}
	go certs.run(ctx, log)
	return func() (*tls.Certificate, error) { return certs.get(nil) }, nil
}

// certReloader serves the server certificate the bootstrap client writes and
// picks up its renewal (24h lifetime, renewed at 50%).
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

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
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
				log.Error("server certificate reload failed", "err", err)
			}
		}
	}
}
