package healthlease

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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const coordinatorSAN = "spiffe://agentarium.internal/ns/agent-control/sa/coordinator"

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns a leaf with one URI SAN (and dns, if set) as a tls pair and
// its PEM files.
func (ca testCA) issue(t *testing.T, san, dns string, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(san)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u}, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		KeyUsage: x509.KeyUsageDigitalSignature}
	if dns != "" {
		tmpl.DNSNames = []string{dns}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(cf, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return pair, cf, kf
}

type fakeHealth struct {
	mu      sync.Mutex
	leases  []map[string]any
	callers []string
	status  int
	ack     string
}

func (f *fakeHealth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.Path != "/internal/control-health/leases" || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(r.TLS.PeerCertificates) > 0 {
		f.callers = append(f.callers, r.TLS.PeerCertificates[0].URIs[0].String())
	}
	var l map[string]any
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	f.leases = append(f.leases, l)
	if f.status != 0 {
		w.WriteHeader(f.status)
	}
	if f.ack != "" {
		_, _ = io.WriteString(w, f.ack)
		return
	}
	_, _ = io.WriteString(w, `{"lease_until":"`+l["lease_until"].(string)+`","scope_state":"healthy"}`)
}

// server starts an mTLS control-health fake whose certificate has serverSAN.
func server(t *testing.T, ca testCA, serverSAN, dns string, h http.Handler) *httptest.Server {
	t.Helper()
	pair, _, _ := ca.issue(t, serverSAN, dns, x509.ExtKeyUsageServerAuth)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func client(t *testing.T, ca testCA) *http.Client {
	t.Helper()
	_, cf, kf := ca.issue(t, coordinatorSAN, "", x509.ExtKeyUsageClientAuth)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.pem, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := FileClient(cf, kf, caFile, ControlHealthSAN)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func reporter(url string, c *http.Client, state string) Reporter {
	v := "coordinator-v1"
	return Reporter{URL: url, Client: c, SourceID: "coordinator", Component: "coordinator", Scope: "global", ScopeID: "*",
		State: func(context.Context) State { return State{ObservedState: state, ActiveVersion: &v} },
		Now:   func() time.Time { return time.Date(2026, 10, 18, 1, 2, 3, 456789000, time.UTC) }}
}

func TestReportSendsLease(t *testing.T) {
	ca := newCA(t)
	h := &fakeHealth{}
	srv := server(t, ca, ControlHealthSAN, "", h)
	if err := reporter(srv.URL, client(t, ca), Healthy).Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.leases) != 1 || len(h.callers) != 1 || h.callers[0] != coordinatorSAN {
		t.Fatalf("leases %v callers %v", h.leases, h.callers)
	}
	l := h.leases[0]
	for k, want := range map[string]any{"source_id": "coordinator", "component": "coordinator", "scope": "global", "scope_id": "*",
		"active_version": "coordinator-v1", "observed_state": "healthy",
		"reported_at": "2026-10-18T01:02:03.456Z", "lease_until": "2026-10-18T01:02:18.456Z"} {
		if l[k] != want {
			t.Errorf("%s = %v, want %v", k, l[k], want)
		}
	}
	if _, ok := l["details"]; ok {
		t.Error("details sent")
	}
	for _, k := range []string{"active_bundle_revision", "loaded_artifact_digest", "canonical_version", "sensor_generation"} {
		if v, ok := l[k]; !ok || v != nil {
			t.Errorf("%s = %v, want null", k, v)
		}
	}
}

func TestReportFailures(t *testing.T) {
	ca := newCA(t)
	c := client(t, ca)
	for name, h := range map[string]*fakeHealth{
		"403":       {status: http.StatusForbidden, ack: `{"reason_codes":["FORBIDDEN"]}`},
		"no ack":    {ack: `{}`},
		"not json":  {ack: `nope`},
		"too large": {ack: strings.Repeat("x", maxAckBytes+2)},
	} {
		srv := server(t, ca, ControlHealthSAN, "", h)
		if err := reporter(srv.URL, c, Healthy).Report(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// A server with another identity, or with an extra DNS name, is refused
	// before any lease is sent.
	for name, s := range map[string]struct{ san, dns string }{
		"other SAN": {"spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway", ""},
		"DNS name":  {ControlHealthSAN, "control-health.agent-observe.svc"},
	} {
		h := &fakeHealth{}
		srv := server(t, ca, s.san, s.dns, h)
		if err := reporter(srv.URL, c, Healthy).Report(context.Background()); err == nil || len(h.leases) != 0 {
			t.Errorf("%s: %v, %d leases", name, err, len(h.leases))
		}
	}

	// A server from another CA is refused.
	h := &fakeHealth{}
	srv := server(t, newCA(t), ControlHealthSAN, "", h)
	if err := reporter(srv.URL, c, Healthy).Report(context.Background()); err == nil || len(h.leases) != 0 {
		t.Errorf("other CA: %v", err)
	}

	if err := reporter("https://x", c, "fine").Report(context.Background()); err == nil {
		t.Error("invalid observed_state accepted")
	}
}

func TestValidate(t *testing.T) {
	c := &http.Client{}
	ok := reporter("https://control-health.agent-observe.svc:8443", c, Healthy)
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Reporter){
		"http":      func(r *Reporter) { r.URL = "http://control-health:8443" },
		"path":      func(r *Reporter) { r.URL = "https://control-health:8443/x" },
		"query":     func(r *Reporter) { r.URL = "https://control-health:8443?x=1" },
		"user":      func(r *Reporter) { r.URL = "https://u@control-health:8443" },
		"no client": func(r *Reporter) { r.Client = nil },
		"no state":  func(r *Reporter) { r.State = nil },
		"no source": func(r *Reporter) { r.SourceID = "" },
		"no scope":  func(r *Reporter) { r.ScopeID = "" },
	} {
		r := ok
		mut(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFileClientInputs(t *testing.T) {
	ca := newCA(t)
	_, cf, kf := ca.issue(t, coordinatorSAN, "", x509.ExtKeyUsageClientAuth)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.pem, 0600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("no certs"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][4]string{
		"no SAN":      {cf, kf, caFile, ""},
		"no cert":     {"/nonexistent", kf, caFile, ControlHealthSAN},
		"no CA":       {cf, kf, "/nonexistent", ControlHealthSAN},
		"empty roots": {cf, kf, empty, ControlHealthSAN},
	} {
		if _, err := FileClient(args[0], args[1], args[2], args[3]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRunReportsUntilCancelled(t *testing.T) {
	ca := newCA(t)
	h := &fakeHealth{status: http.StatusServiceUnavailable, ack: `{}`}
	srv := server(t, ca, ControlHealthSAN, "", h)
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 4)
	done := make(chan struct{})
	go func() {
		reporter(srv.URL, client(t, ca), Degraded).Run(ctx, func(err error) { errs <- err })
		close(done)
	}()
	select {
	case <-errs:
	case <-time.After(5 * time.Second):
		t.Fatal("first report error not delivered")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.leases) == 0 || h.leases[0]["observed_state"] != "degraded" {
		t.Fatalf("leases %v", h.leases)
	}
}
