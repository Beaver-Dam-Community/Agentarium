//go:build integration

package main

// Local M3-1 end-to-end harness (tests/m3-1/run-local.sh). It is a test, not
// a production entry point: run() needs Google CAS, the in-cluster Kubernetes
// API and Google's JWKS, none of which exist on a laptop. This test serves
// the same identity routes from the same packages with three test-only
// fakes, all confined to this _test.go file:
//
//   - fakeCAS: issuer.CASClient that signs the config-based CAS request with
//     a local CA (the issuer.CAS request building and issuer.Verify checks
//     stay real).
//   - harnessCluster: bootstrap.Cluster answering TokenReview/Pod/Node from
//     a fixed table of local "pods" instead of the Kubernetes API.
//   - staticKeys (wiring_integration_test.go): the console OIDC key source,
//     a test RSA key instead of Google's JWKS.
//
// The revoker (Pod watch) is not started. Everything else is the code
// main.go wires: bootstrap.Service, servercert.Manager, the policyloader
// (GCS client, pointed at a local emulator with STORAGE_EMULATOR_HOST),
// sessions/approvals through registerAPIs, the audit producer epoch.
//
// It runs only when M31_IDENTITY_HARNESS_CONFIG names a JSON config file and
// serves until the process receives SIGTERM.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"cloud.google.com/go/security/privateca/apiv1/privatecapb"
	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/bootstrap"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/epoch"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/issuer"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/servercert"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/sessions"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/store"
)

type harnessPod struct {
	Namespace string `json:"namespace"`
	KSA       string `json:"ksa"`
	PodName   string `json:"pod_name"`
	PodUID    string `json:"pod_uid"`
	NodeName  string `json:"node_name"`
}

type harnessNode struct {
	UID    string `json:"uid"`
	BootID string `json:"boot_id"`
}

type harnessConfig struct {
	Listen             string                 `json:"listen"`
	DatabaseURL        string                 `json:"database_url"`
	Environment        string                 `json:"environment"`
	TrustBundle        string                 `json:"trust_bundle"`
	CACert             string                 `json:"ca_cert"`
	CAKey              string                 `json:"ca_key"`
	ClaimKeyFile       string                 `json:"claim_key_file"`
	GatewaySAN         string                 `json:"gateway_san"`
	OIDCAudience       string                 `json:"oidc_audience"`
	OIDCAllowedHD      string                 `json:"oidc_allowed_hd"`
	RoleMap            string                 `json:"role_map"`
	JWKSKeyID          string                 `json:"jwks_kid"`
	JWKSPublicKey      string                 `json:"jwks_public_key"`
	BundleKeyID        string                 `json:"bundle_key_id"`
	BundleKeyFile      string                 `json:"bundle_key_file"`
	AuditSourceID      string                 `json:"audit_source_id"`
	AuditSourceVersion string                 `json:"audit_source_version"`
	EpochDir           string                 `json:"epoch_dir"`
	Tokens             map[string]harnessPod  `json:"tokens"`
	Nodes              map[string]harnessNode `json:"nodes"`
}

func TestM31LocalIdentityHarness(t *testing.T) {
	path := os.Getenv("M31_IDENTITY_HARNESS_CONFIG")
	if path == "" {
		t.Skip("M31_IDENTITY_HARNESS_CONFIG not set (tests/m3-1/run-local.sh)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c harnessConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		t.Fatal(err)
	}
	if err := serveHarness(c); err != nil {
		t.Fatal(err)
	}
}

func serveHarness(c harnessConfig) error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ca, caKey, caPEM, err := loadCA(c.CACert, c.CAKey)
	if err != nil {
		return err
	}
	jwk, err := loadRSAPublic(c.JWKSPublicKey)
	if err != nil {
		return err
	}
	api := apiFlags{enabled: true, audiences: listFlag{c.OIDCAudience}, domains: listFlag{c.OIDCAllowedHD}, roleMap: c.RoleMap,
		bundleKeyID: c.BundleKeyID, bundleKeyFile: c.BundleKeyFile, auditSourceID: c.AuditSourceID,
		auditSourceVersion: c.AuditSourceVersion, epochDir: c.EpochDir}
	console, err := api.console(staticKeys{c.JWKSKeyID: jwk})
	if err != nil {
		return err
	}
	bundleKey, err := api.bundleKey()
	if err != nil {
		return err
	}
	cas := issuer.CAS{
		Pool:            "projects/m31-local/locations/local/caPools/m31-local",
		ServiceTemplate: "projects/m31-local/locations/local/certificateTemplates/m31-local-service",
		ClientTemplate:  "projects/m31-local/locations/local/certificateTemplates/m31-local-client",
		Client:          &fakeCAS{ca: ca, key: caKey, caPEM: caPEM},
	}
	claimKey, err := os.ReadFile(c.ClaimKeyFile)
	if err != nil || len(claimKey) < 32 {
		return errors.New("claim key missing or shorter than 32 bytes")
	}
	pool, err := pgxpool.New(ctx, c.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	st := store.Store{Pool: pool}
	roots := x509.NewCertPool()
	trust, err := os.ReadFile(c.TrustBundle)
	if err != nil || !roots.AppendCertsFromPEM(trust) {
		return errors.New("trust bundle unreadable")
	}
	certs := &servercert.Manager{Issuer: cas, Recorder: st, Namespace: "agent-control", KSA: "workload-identity", Log: log}
	if err := certs.Refresh(ctx); err != nil {
		return err
	}
	go certs.Run(ctx)

	svc := &bootstrap.Service{Cluster: harnessCluster{pods: c.Tokens, nodes: c.Nodes}, Store: st, Issuer: cas}
	mux := http.NewServeMux()
	mux.Handle("/internal/workload-certificates", svc.Handler())

	producerEpoch, releaseEpoch, err := epoch.Acquire(c.EpochDir)
	if err != nil {
		return fmt.Errorf("epoch dir: %w", err)
	}
	defer releaseEpoch()
	auditor, err := sessions.NewPGAuditor(sessions.AuditConfig{SourceID: c.AuditSourceID, Version: c.AuditSourceVersion, Epoch: producerEpoch})
	if err != nil {
		return err
	}
	gcs, err := storage.NewClient(ctx) // STORAGE_EMULATOR_HOST: the harness's local bucket
	if err != nil {
		return err
	}
	defer gcs.Close()
	loader, err := newLoader(log, pool, policyloader.GCSFetcher{Client: gcs}, c.Environment, c.BundleKeyID, string(bundleKey))
	if err != nil {
		return err
	}
	go loader.Run(ctx)
	registerAPIs(mux, apiDeps{Pool: pool, Loader: loader, Console: console, Audit: auditor,
		Environment: c.Environment, ClaimKey: claimKey, GatewaySAN: c.GatewaySAN})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !certs.Ready() || loader.Current() == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Addr: c.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: certs.GetCertificate,
			ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("identity harness listening", "addr", c.Listen)
	if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// harnessCluster answers the three Kubernetes reads of the bootstrap from a
// fixed table: token -> pod -> node.
type harnessCluster struct {
	pods  map[string]harnessPod
	nodes map[string]harnessNode
}

func (h harnessCluster) ReviewToken(_ context.Context, token string, _ []string) (bootstrap.TokenReview, error) {
	p, ok := h.pods[token]
	if !ok {
		return bootstrap.TokenReview{Authenticated: false}, nil
	}
	return bootstrap.TokenReview{Authenticated: true, Audiences: []string{bootstrap.Audience},
		Username: "system:serviceaccount:" + p.Namespace + ":" + p.KSA,
		Extra: map[string][]string{"authentication.kubernetes.io/pod-uid": {p.PodUID},
			"authentication.kubernetes.io/pod-name": {p.PodName}}}, nil
}

func (h harnessCluster) GetPod(_ context.Context, namespace, name string) (bootstrap.Pod, error) {
	for _, p := range h.pods {
		if p.Namespace == namespace && p.PodName == name {
			return bootstrap.Pod{UID: p.PodUID, Namespace: p.Namespace, Name: p.PodName, ServiceAccount: p.KSA, NodeName: p.NodeName}, nil
		}
	}
	return bootstrap.Pod{}, bootstrap.ErrNotFound
}

func (h harnessCluster) GetNode(_ context.Context, name string) (bootstrap.Node, error) {
	n, ok := h.nodes[name]
	if !ok {
		return bootstrap.Node{}, bootstrap.ErrNotFound
	}
	return bootstrap.Node{UID: n.UID, BootID: n.BootID}, nil
}

// fakeCAS signs what the config-based CreateCertificate asks for: the
// requested URI and DNS SANs, the requested lifetime and the profile EKU of the selected template
// (service: serverAuth+clientAuth, client: clientAuth), never a CA.
type fakeCAS struct {
	ca    *x509.Certificate
	key   any
	caPEM string
}

func (f *fakeCAS) CreateCertificate(_ context.Context, req *privatecapb.CreateCertificateRequest) (*privatecapb.Certificate, error) {
	cfg := req.GetCertificate().GetConfig()
	block, _ := pem.Decode(cfg.GetPublicKey().GetKey())
	if block == nil {
		return nil, errors.New("fake cas: public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// Sign exactly the SANs the issuer requested: every URI and DNS name of
	// the request config, nothing added or dropped.
	san := cfg.GetSubjectConfig().GetSubjectAltName()
	var uris []*url.URL
	for _, raw := range san.GetUris() {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		uris = append(uris, u)
	}
	if len(uris) == 0 {
		return nil, errors.New("fake cas: no URI SAN requested")
	}
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if strings.HasSuffix(req.GetCertificate().GetCertificateTemplate(), "-client") {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(req.GetCertificate().GetLifetime().AsDuration() - time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku, URIs: uris, DNSNames: san.GetDnsNames(), BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca, pub, f.key)
	if err != nil {
		return nil, err
	}
	return &privatecapb.Certificate{PemCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PemCertificateChain: []string{f.caPEM}}, nil
}

func (f *fakeCAS) FetchCaCerts(context.Context, *privatecapb.FetchCaCertsRequest) (*privatecapb.FetchCaCertsResponse, error) {
	return &privatecapb.FetchCaCertsResponse{CaCerts: []*privatecapb.FetchCaCertsResponse_CertChain{{Certificates: []string{f.caPEM}}}}, nil
}

func loadCA(certFile, keyFile string) (*x509.Certificate, any, string, error) {
	cb, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, "", err
	}
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, "", err
	}
	pair, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		return nil, nil, "", err
	}
	ca, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, "", err
	}
	return ca, pair.PrivateKey, string(cb), nil
}

func loadRSAPublic(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("jwks public key is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("jwks public key is not RSA")
	}
	return rk, nil
}
