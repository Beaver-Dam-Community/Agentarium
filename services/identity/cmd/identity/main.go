// Command identity is the TASK-03 identity service: the workload certificate
// bootstrap (M1-2), the session APIs and the approval APIs (M2-5).
//
// With --session-apis the session and approval APIs are served with their
// real dependencies: Google OIDC ID token console authentication
// (consoleauth), the signed policy bundle (packages/policyloader) matched to
// release.active_policy, the TASK-04 approval views, the active epoch and
// audit_append in the business transaction. A missing input fails startup.
// Without --session-apis only the certificate bootstrap is served.
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
	"strings"
	"syscall"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/approvals"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/bootstrap"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/consoleauth"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/epoch"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/issuer"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/kube"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/revoker"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/servercert"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/sessions"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/store"
)

func main() {
	listen := flag.String("listen", ":8443", "HTTPS listen address")
	caPool := flag.String("ca-pool", os.Getenv("IDENTITY_CA_POOL"), "CAS pool: projects/<p>/locations/<l>/caPools/<pool>")
	serviceTemplate := flag.String("service-certificate-template", os.Getenv("IDENTITY_SERVICE_CERTIFICATE_TEMPLATE"), "CAS certificate template resource name for service serverAuth+clientAuth certificates")
	clientTemplate := flag.String("client-certificate-template", os.Getenv("IDENTITY_CLIENT_CERTIFICATE_TEMPLATE"), "CAS certificate template resource name for clientAuth-only certificates")
	dbURL := flag.String("database-url", os.Getenv("IDENTITY_DATABASE_URL"), "PostgreSQL URL (Cloud SQL Auth Proxy on localhost)")
	trustBundle := flag.String("trust-bundle", "/etc/agentarium-trust/ca.pem", "PEM trust bundle (ConfigMap agentarium-trust) for client certificates")
	namespace := flag.String("namespace", "agent-control", "own namespace")
	ksa := flag.String("ksa", "workload-identity", "own KSA")
	claimKeyFile := flag.String("claim-key-file", "/var/run/secrets/agentarium/claim-key", "HMAC key for session claim codes (Secret Manager)")
	gatewaySAN := flag.String("gateway-san", "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway", "SAN allowed to set X-Agentarium-Peer-Identity")
	environment := flag.String("environment", os.Getenv("AGENTARIUM_ENVIRONMENT"), "catalog environment this deployment serves")
	var podNamespaces revoker.NamespaceList
	flag.Var(&podNamespaces, "pod-namespaces", "namespaces whose Pods the revoker watches (repeatable, comma-separated): every namespace where Pod-bound certificates can be issued, i.e. those of the identity KSA pods Roles")
	var api apiFlags
	flag.BoolVar(&api.enabled, "session-apis", false, "serve the session and approval APIs; every input below is then required")
	flag.Var(&api.audiences, "oidc-audience", "accepted Google ID token aud (repeatable, comma-separated), e.g. the gcloud client ID for CLI tokens")
	flag.Var(&api.domains, "oidc-allowed-hd", "allowed Google Workspace domain, the token hd claim (repeatable, comma-separated)")
	flag.StringVar(&api.roleMap, "oidc-role-map", "/etc/agentarium-identity/role-map.yaml", "console user → tenant and role map (YAML)")
	flag.StringVar(&api.bundleKeyID, "bundle-key-id", "prod-v1", "the only bundle signing key identity trusts")
	flag.StringVar(&api.bundleKeyFile, "bundle-key-file", "/etc/agentarium-bundle-keys/prod-v1.pem", "PEM PUBLIC KEY of --bundle-key-id (ConfigMap agentarium-bundle-keys)")
	flag.StringVar(&api.auditSourceID, "audit-source-id", "", "audit source_id registered for the identity DB login (audit.db_role_sources)")
	flag.StringVar(&api.auditSourceVersion, "audit-source-version", "", "audit source_version (the deployed identity version)")
	flag.StringVar(&api.epochDir, "epoch-dir", "", "persistent audit producer epoch directory, exclusive per process")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, *listen, *caPool, *serviceTemplate, *clientTemplate, *dbURL, *trustBundle, *namespace, *ksa, *claimKeyFile, *gatewaySAN, *environment, podNamespaces, api); err != nil {
		log.Error("identity stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, listen, caPool, serviceTemplate, clientTemplate, dbURL, trustBundle, namespace, ksa, claimKeyFile, gatewaySAN, environment string, podNamespaces []string, api apiFlags) error {
	if caPool == "" || dbURL == "" || environment == "" {
		return errors.New("--ca-pool, --database-url and --environment are required")
	}
	// Validate the API inputs before any client is created: a console
	// deployment without OIDC, bundle key or audit source does not start.
	var console *consoleauth.Verifier
	var bundleKey []byte
	if api.enabled {
		var err error
		if console, err = api.console(&consoleauth.JWKS{URL: consoleauth.GoogleJWKSURL}); err != nil {
			return err
		}
		if bundleKey, err = api.bundleKey(); err != nil {
			return err
		}
		if api.auditSourceID == "" || api.auditSourceVersion == "" || api.epochDir == "" {
			return errors.New("--session-apis requires --audit-source-id, --audit-source-version and --epoch-dir")
		}
	}
	cas := issuer.CAS{Pool: caPool, ServiceTemplate: serviceTemplate, ClientTemplate: clientTemplate}
	if err := cas.ValidateIssuanceConfig(); err != nil {
		return err
	}
	claimKey, err := os.ReadFile(claimKeyFile)
	if err != nil {
		return err
	}
	if len(claimKey) < 32 {
		return errors.New("claim key must be at least 32 bytes")
	}
	if err := revoker.ValidateNamespaces(podNamespaces); err != nil {
		return fmt.Errorf("--pod-namespaces: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	casClient, err := privateca.NewCertificateAuthorityClient(ctx) // Workload Identity
	if err != nil {
		return err
	}
	defer casClient.Close()
	cas.Client = issuer.GoogleCAS{C: casClient}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	st := store.Store{Pool: pool}

	kcfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	kc, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	pemBytes, err := os.ReadFile(trustBundle)
	if err != nil {
		return err
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return errors.New("trust bundle has no certificates")
	}

	certs := &servercert.Manager{Issuer: cas, Recorder: st, Namespace: namespace, KSA: ksa, Log: log}
	if err := certs.Refresh(ctx); err != nil {
		return err // readiness never turns true without a server certificate
	}
	go certs.Run(ctx)

	rv := &revoker.Revoker{Client: kc, Store: st, Log: log, Namespaces: podNamespaces}
	go func() {
		if err := rv.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("revoker stopped", "err", err)
			stop()
		}
	}()

	svc := &bootstrap.Service{Cluster: kube.Cluster{Client: kc}, Store: st, Issuer: cas}
	mux := http.NewServeMux()
	mux.Handle("/internal/workload-certificates", svc.Handler())

	if api.enabled {
		producerEpoch, releaseEpoch, err := epoch.Acquire(api.epochDir)
		if err != nil {
			return fmt.Errorf("--epoch-dir: %w", err)
		}
		defer releaseEpoch()
		auditor, err := sessions.NewPGAuditor(sessions.AuditConfig{SourceID: api.auditSourceID, Version: api.auditSourceVersion, Epoch: producerEpoch})
		if err != nil {
			return err
		}
		gcs, err := storage.NewClient(ctx) // Workload Identity, bundle bucket read
		if err != nil {
			return err
		}
		defer gcs.Close()
		loader, err := newLoader(log, pool, policyloader.GCSFetcher{Client: gcs}, environment, api.bundleKeyID, string(bundleKey))
		if err != nil {
			return err
		}
		go loader.Run(ctx)
		registerAPIs(mux, apiDeps{Pool: pool, Loader: loader, Console: console, Audit: auditor,
			Environment: environment, ClaimKey: claimKey, GatewaySAN: gatewaySAN})
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !certs.Ready() {
			http.Error(w, "server certificate not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			GetCertificate: certs.GetCertificate,
			// The bootstrap route is called before the caller has a
			// certificate; routes added with M2-5 require one.
			ClientAuth: tls.VerifyClientCertIfGiven,
			ClientCAs:  roots,
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("identity listening", "addr", listen)
	if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// apiFlags are the --session-apis inputs.
type apiFlags struct {
	enabled                           bool
	audiences, domains                listFlag
	roleMap                           string
	bundleKeyID, bundleKeyFile        string
	auditSourceID, auditSourceVersion string
	epochDir                          string
}

// console builds the OIDC verifier; keys is Google's JWKS in production.
func (f apiFlags) console(keys consoleauth.KeySource) (*consoleauth.Verifier, error) {
	if len(f.audiences) == 0 || len(f.domains) == 0 || f.roleMap == "" {
		return nil, errors.New("--session-apis requires --oidc-audience, --oidc-allowed-hd and --oidc-role-map")
	}
	roles, err := consoleauth.LoadRoleMap(f.roleMap)
	if err != nil {
		return nil, fmt.Errorf("--oidc-role-map: %w", err)
	}
	return consoleauth.New(consoleauth.Config{Audiences: f.audiences, AllowedDomains: f.domains, Roles: roles, Keys: keys})
}

func (f apiFlags) bundleKey() ([]byte, error) {
	if f.bundleKeyID == "" || f.bundleKeyFile == "" {
		return nil, errors.New("--session-apis requires --bundle-key-id and --bundle-key-file")
	}
	b, err := os.ReadFile(f.bundleKeyFile)
	if err != nil {
		return nil, fmt.Errorf("--bundle-key-file: %w", err)
	}
	return b, nil
}

// listFlag is a repeatable, comma-separated string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}

// newLoader is identity's policyloader: the environment's desired_bundle row,
// the signature-verified bundle and no prepared query (identity reads only
// the catalog and data.standing_rules).
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

// apiDeps are the wired dependencies of the session and approval APIs.
type apiDeps struct {
	Pool        *pgxpool.Pool
	Loader      *policyloader.Loader
	Console     sessions.ConsoleAuth
	Audit       sessions.Auditor
	Environment string
	ClaimKey    []byte
	GatewaySAN  string
}

// registerAPIs adds the session and approval routes. Policy is the loaded
// snapshot only while it matches release.active_policy (sessions.SnapshotPolicy);
// approvals read the TASK-04 views and the active epoch in their transaction.
// The intent checker (TASK-04 POST /internal/intent-checks) is not wired yet,
// so contracts carry intent_check_status = not_run.
func registerAPIs(mux *http.ServeMux, d apiDeps) {
	policy := sessions.SnapshotPolicy{Loader: d.Loader, Active: sessions.PGActivePolicy{}, Environment: d.Environment, DB: d.Pool}
	sessionsSvc := &sessions.Service{Pool: d.Pool, Policy: policy, Audit: d.Audit, Environment: d.Environment, ClaimKey: d.ClaimKey}
	(&sessions.Handler{Svc: sessionsSvc, Console: d.Console, GatewaySAN: d.GatewaySAN}).Register(mux)
	gw := approvals.GatewayStore{}
	approvalsSvc := &approvals.Service{Pool: d.Pool, Policy: policy, Actions: gw, Pending: gw, Previews: gw,
		Epochs: approvals.ReleaseEpochs{Environment: d.Environment}, Audit: d.Audit}
	(&approvals.Handler{Svc: approvalsSvc, Console: d.Console}).Register(mux)
}
