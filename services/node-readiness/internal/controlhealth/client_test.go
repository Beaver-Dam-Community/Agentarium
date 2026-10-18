package controlhealth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const clientSAN = "spiffe://agentarium.internal/ns/agent-control/sa/node-readiness"

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issue(t *testing.T, san string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(san)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// mtlsServer starts an httptest TLS server that requires a client cert from ca.
func mtlsServer(t *testing.T, ca *testCA, serverSAN string, h http.Handler) *httptest.Server {
	t.Helper()
	certPEM, keyPEM := ca.issue(t, serverSAN, x509.ExtKeyUsageServerAuth)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func clientFiles(t *testing.T, ca *testCA, trust []byte) TLSFiles {
	t.Helper()
	dir := t.TempDir()
	c, k := ca.issue(t, clientSAN, x509.ExtKeyUsageClientAuth)
	return TLSFiles{
		CertFile: writeFile(t, dir, "tls.crt", c),
		KeyFile:  writeFile(t, dir, "tls.key", k),
		CAFile:   writeFile(t, dir, "ca.crt", trust),
	}
}

func newTestClient(t *testing.T, files TLSFiles, san, base string) *Client {
	t.Helper()
	cfg, err := LoadTLSConfig(files, san)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(base, NewHTTPClient(cfg, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const sampleResponse = `{
  "scope": "node", "scope_id": "node-uid-1", "evaluated_at": "2026-10-14T12:00:00Z",
  "state": "healthy",
  "leases": [{"component": "node-sensors", "source_id": "s1", "observed_state": "healthy",
              "lease_until": "2026-10-14T12:00:10Z", "active_version": "v", "sensor_generation": 3}],
  "missing_components": [],
  "open_holds": [],
  "probes": [{"probe_kind": "tcp", "last_judged_at": "2026-10-14T11:59:50Z", "last_result": "pass",
              "consecutive_passes": 2}],
  "open_gaps": [],
  "bundle_ack": null,
  "startup_capture": "unsupported",
  "pending_work_readiness_challenges": [],
  "pending_worker_observation_challenges": []
}`

func TestNodeHealthOverMTLS(t *testing.T) {
	ca := newCA(t)
	var gotPeer string
	srv := mtlsServer(t, ca, DefaultServerSAN, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/control-health" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("scope") != "node" || r.URL.Query().Get("scope_id") != "node-uid-1" {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		gotPeer = r.TLS.PeerCertificates[0].URIs[0].String()
		io.WriteString(w, sampleResponse)
	}))

	c := newTestClient(t, clientFiles(t, ca, ca.pem), DefaultServerSAN, srv.URL)
	h, err := c.NodeHealth(context.Background(), "node-uid-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotPeer != clientSAN {
		t.Fatalf("server saw client SAN %q", gotPeer)
	}
	if h.State != "healthy" || len(h.Leases) != 1 || h.Leases[0].Component != "node-sensors" ||
		h.Probes[0].ConsecutivePasses != 2 || h.StartupCapture == nil || *h.StartupCapture != "unsupported" {
		t.Fatalf("unexpected decode: %+v", h)
	}
}

func TestNodeHealthRejectsWrongServerSAN(t *testing.T) {
	ca := newCA(t)
	srv := mtlsServer(t, ca, "spiffe://agentarium.internal/ns/agent-observe/sa/timeline",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, sampleResponse) }))
	c := newTestClient(t, clientFiles(t, ca, ca.pem), DefaultServerSAN, srv.URL)
	if _, err := c.NodeHealth(context.Background(), "node-uid-1"); err == nil || !strings.Contains(err.Error(), "SAN") {
		t.Fatalf("want SAN mismatch error, got %v", err)
	}
}

func TestNodeHealthRejectsUntrustedCA(t *testing.T) {
	ca, other := newCA(t), newCA(t)
	srv := mtlsServer(t, ca, DefaultServerSAN,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, sampleResponse) }))
	// Client cert from ca, but trust bundle only holds the other CA.
	c := newTestClient(t, clientFiles(t, ca, other.pem), DefaultServerSAN, srv.URL)
	if _, err := c.NodeHealth(context.Background(), "node-uid-1"); err == nil {
		t.Fatal("want chain verification error")
	}
}

func TestNodeHealthResponseValidation(t *testing.T) {
	ca := newCA(t)
	cases := map[string]struct {
		status int
		body   string
		want   string
	}{
		"missing key":    {200, strings.Replace(sampleResponse, `"startup_capture": "unsupported",`, "", 1), "startup_capture"},
		"scope mismatch": {200, strings.Replace(sampleResponse, `"node-uid-1"`, `"node-uid-2"`, 1), "does not match"},
		"503":            {503, `{"request_id":"r","reason_codes":["CONTROL_HEALTH_UNAVAILABLE"]}`, "CONTROL_HEALTH_UNAVAILABLE"},
		"not json":       {200, `<html>`, "decode"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := mtlsServer(t, ca, DefaultServerSAN, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			c := newTestClient(t, clientFiles(t, ca, ca.pem), DefaultServerSAN, srv.URL)
			_, err := c.NodeHealth(context.Background(), "node-uid-1")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestNoRedirectFollow(t *testing.T) {
	ca := newCA(t)
	srv := mtlsServer(t, ca, DefaultServerSAN, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	c := newTestClient(t, clientFiles(t, ca, ca.pem), DefaultServerSAN, srv.URL)
	var apiErr *APIError
	_, err := c.NodeHealth(context.Background(), "node-uid-1")
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusFound {
		t.Fatalf("want 302 APIError, got %v", err)
	}
}

func TestReportLease(t *testing.T) {
	ca := newCA(t)
	var got map[string]any
	srv := mtlsServer(t, ca, DefaultServerSAN, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/control-health/leases" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		io.WriteString(w, `{"lease_until":"2026-10-14T12:00:15Z","scope_state":"healthy"}`)
	}))
	c := newTestClient(t, clientFiles(t, ca, ca.pem), DefaultServerSAN, srv.URL)
	at := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	ack, err := c.ReportLease(context.Background(), Lease{
		SourceID: "node-readiness-0", Component: "node-readiness", Scope: "global", ScopeID: "*",
		LeaseUntil: at.Add(15 * time.Second), ObservedState: "healthy", ReportedAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ack.ScopeState != "healthy" {
		t.Fatalf("ack %+v", ack)
	}
	wantKeys := []string{"source_id", "component", "scope", "scope_id", "active_version", "active_bundle_revision",
		"loaded_artifact_digest", "canonical_version", "sensor_generation", "lease_until", "observed_state", "reported_at"}
	if len(got) != len(wantKeys) {
		t.Fatalf("lease body has %d keys, want %d: %v", len(got), len(wantKeys), got)
	}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Fatalf("lease body missing %q", k)
		}
	}
	if got["component"] != "node-readiness" || got["active_version"] != nil {
		t.Fatalf("lease body %v", got)
	}
}

func TestLoadTLSConfigErrors(t *testing.T) {
	if _, err := LoadTLSConfig(TLSFiles{}, DefaultServerSAN); err == nil {
		t.Fatal("want error for empty paths")
	}
	ca := newCA(t)
	files := clientFiles(t, ca, []byte("not pem"))
	if _, err := LoadTLSConfig(files, DefaultServerSAN); err == nil {
		t.Fatal("want error for empty CA bundle")
	}
	if _, err := NewClient("http://control-health:8443", http.DefaultClient); err == nil {
		t.Fatal("want error for non-https base URL")
	}
}
