// Command receiver is the TASK-08 3.1 test receiver (agent-targets/receiver):
// POST /test/v1/submissions from the receiver-sender adapter and
// GET /test/v1/receipts/{action_id} for the evidence collector, both over
// mTLS. It is a test target only and is never a production send API.
// Submissions also need X-Agentarium-Receiver-Key, checked against the
// versions in --api-key-dir (re-read every 30s); receipt reads are mTLS only.
//
// Not part of this command: the evidence collector (TASK-08 3.2, 4) and a
// control-health lease of the receiver itself (see the report of M2-8).
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

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/services/receiver/internal/receiver"
)

// selfSAN is the receiver's service identity (TASK-06 KSA table,
// agent-targets/receiver) requested in --identity-url mode.
const selfSAN = "spiffe://agentarium.internal/ns/agent-targets/sa/receiver"

// certFlags selects the certificate source. With identityURL the
// certificate is bootstrapped and renewed in memory (TASK-03 3.3.2);
// without it the cert/key files are loaded and reloaded.
type certFlags struct {
	identityURL, tokenFile, trustBundle, certFile, keyFile string
}

// version is set with -ldflags "-X main.version=..." and reported as the
// receipt target_version unless --target-version is given.
//
// SPEC-QUESTION: TASK-08 4 lists target_version in the receipt without a
// definition; the receiver build version is used.
var version = "dev"

func main() {
	listen := flag.String("listen", ":8443", "HTTPS listen address")
	dbURL := flag.String("database-url", os.Getenv("RECEIVER_DATABASE_URL"), "PostgreSQL URL (Cloud SQL Auth Proxy on localhost)")
	mode := flag.String("receiver-mode", "", "receiver_mode from the environment lock: idempotent or non_idempotent (required)")
	targetID := flag.String("target-id", "", "catalog target_id served by this deployment, e.g. receiver-primary (required)")
	routeID := flag.String("route-id", "submissions-v1", "catalog route_id of receiver.submit")
	targetVersion := flag.String("target-version", version, "receipt target_version")
	trustBundle := flag.String("trust-bundle", "/etc/agentarium-trust/ca.pem", "PEM trust bundle (ConfigMap agentarium-trust) for client certificates")
	certFile := flag.String("tls-cert", "/var/run/agentarium/tls/tls.crt", "server certificate from the identity bootstrap (TASK-03 3.3.2)")
	keyFile := flag.String("tls-key", "/var/run/agentarium/tls/tls.key", "server key (file mode)")
	identityURL := flag.String("identity-url", "", "identity HTTPS origin for in-memory certificate bootstrap; empty uses --tls-cert/--tls-key")
	bootstrapToken := flag.String("bootstrap-token", "", "projected agentarium-identity token file (required with --identity-url)")
	apiKeyDir := flag.String("api-key-dir", "", "receiver API key directory, one file per active secret version (required)")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	certs := certFlags{identityURL: *identityURL, tokenFile: *bootstrapToken, trustBundle: *trustBundle, certFile: *certFile, keyFile: *keyFile}
	if err := run(log, *listen, *dbURL, *mode, *targetID, *routeID, *targetVersion, certs, *apiKeyDir); err != nil {
		log.Error("receiver stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, listen, dbURL, modeFlag, targetID, routeID, targetVersion string, cf certFlags, apiKeyDir string) error {
	mode, err := receiver.ParseMode(modeFlag)
	if err != nil {
		return err
	}
	if dbURL == "" {
		return errors.New("--database-url is required")
	}
	if targetID == "" || routeID == "" {
		return errors.New("--target-id and --route-id are required")
	}
	if apiKeyDir == "" {
		return errors.New("--api-key-dir is required")
	}
	// A key directory that is unreadable or invalid at start stops the receiver.
	keys, err := receiver.NewKeySet(apiKeyDir)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Both pools connect and switch role here; a failure stops the start.
	writer, err := receiver.NewRolePool(ctx, dbURL, receiver.RoleWriter)
	if err != nil {
		return err
	}
	defer writer.Close()
	reader, err := receiver.NewRolePool(ctx, dbURL, receiver.RoleReader)
	if err != nil {
		return err
	}
	defer reader.Close()

	roots := x509.NewCertPool()
	pemBytes, err := os.ReadFile(cf.trustBundle)
	if err != nil {
		return err
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return errors.New("trust bundle has no certificates")
	}
	getCert, err := certSource(ctx, log, cf)
	if err != nil {
		return err
	}
	go keys.Run(ctx, receiver.KeyReloadInterval, log)

	mux := http.NewServeMux()
	(&receiver.Handler{
		Store: &receiver.PGStore{Writer: writer, Reader: reader},
		Cfg:   receiver.Config{Mode: mode, TargetID: targetID, RouteID: routeID, TargetVersion: targetVersion},
		Log:   log,
		Keys:  keys,
	}).Register(mux)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
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
	log.Info("receiver listening", "addr", listen, "receiver_mode", mode, "target_id", targetID, "api_key_versions", keys.Versions())
	if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
	return certs.get, nil
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
				log.Error("server certificate reload failed", "err", err)
			}
		}
	}
}
