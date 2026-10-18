package workload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	"testing"
	"time"
)

const (
	testPod  = "3b0f2c39-5d0b-4b0e-9a5e-0c5f0d1e2a3b"
	testNode = "6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f"
)

func jwt(claims any) string {
	raw, _ := json.Marshal(claims)
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(raw) + ".c2ln"
}

func k8sClaims(ns, sa, pod, nodeUID string) map[string]any {
	return map[string]any{"aud": []string{"agentarium-identity"}, "kubernetes.io": map[string]any{
		"namespace": ns, "serviceaccount": map[string]any{"name": sa, "uid": "x"},
		"pod": map[string]any{"name": "probe-runner-abc", "uid": pod}, "node": map[string]any{"name": "gke-exec-1", "uid": nodeUID}}}
}

func TestParseSelf(t *testing.T) {
	s, err := ParseSelf(jwt(k8sClaims("agent-exec", "probe-runner", testPod, testNode)))
	if err != nil || s.Namespace != "agent-exec" || s.PodUID != testPod || s.NodeUID != testNode || s.NodeName != "gke-exec-1" {
		t.Fatalf("%+v %v", s, err)
	}
	if s.SAN() != "spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner/pod/"+testPod {
		t.Fatal(s.SAN())
	}
	for name, tok := range map[string]string{
		"other namespace":   jwt(k8sClaims("agent-control", "probe-runner", testPod, testNode)),
		"other KSA":         jwt(k8sClaims("agent-exec", "agent-runtime", testPod, testNode)),
		"no node uid":       jwt(k8sClaims("agent-exec", "probe-runner", testPod, "")),
		"bad pod uid":       jwt(k8sClaims("agent-adapters", "probe-runner", "x", testNode)),
		"not a jwt":         "abc",
		"payload not JSON":  "a." + base64.RawURLEncoding.EncodeToString([]byte("{")) + ".c",
		"payload not b64":   "a.***.c",
		"upper-case node":   jwt(k8sClaims("agent-exec", "probe-runner", testPod, strings.ToUpper(testNode))),
		"legacy token only": jwt(map[string]any{"sub": "system:serviceaccount:agent-exec:probe-runner"}),
	} {
		if _, err := ParseSelf(tok); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestReadBootID(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "boot_id")
	_ = os.WriteFile(good, []byte("0b8f3a52-7c1d-4e9a-8f6b-2d3c4e5f6a7b\n"), 0o600)
	if id, err := ReadBootID(good); err != nil || id != "0b8f3a52-7c1d-4e9a-8f6b-2d3c4e5f6a7b" {
		t.Fatalf("%q %v", id, err)
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("a/b\n"), 0o600)
	if _, err := ReadBootID(bad); err == nil {
		t.Fatal("bad boot id accepted")
	}
}

type pki struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newPKI(t *testing.T) pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return pki{ca, key, roots}
}

func (p pki) issue(t *testing.T, san string, pub any, usage []x509.ExtKeyUsage, notAfter time.Time) *x509.Certificate {
	t.Helper()
	u, _ := url.Parse(san)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, pub, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// identityServer is a TLS server with the given SAN that issues per mode.
func identityServer(t *testing.T, p pki, serverSAN string, issue func(csr *x509.CertificateRequest) (*x509.Certificate, time.Time)) *httptest.Server {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := p.issue(t, serverSAN, &key.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, time.Now().Add(time.Hour))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != BootstrapPath || r.Header.Get("Content-Type") != "application/json" || len(r.TLS.PeerCertificates) != 0 {
			w.WriteHeader(400)
			return
		}
		var req struct{ CSR, Token string }
		raw, _ := io.ReadAll(r.Body)
		if json.Unmarshal(raw, &req) != nil || req.Token != "tok" {
			w.WriteHeader(401)
			return
		}
		b, _ := pem.Decode([]byte(req.CSR))
		csr, err := x509.ParseCertificateRequest(b.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			w.WriteHeader(422)
			return
		}
		cert, expires := issue(csr)
		_ = json.NewEncoder(w).Encode(map[string]any{"certificate": pemOf(cert), "certificate_chain": []string{pemOf(p.ca)}, "serial": cert.SerialNumber.Text(16), "expires_at": expires})
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}}, ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestCertsRefresh(t *testing.T) {
	p := newPKI(t)
	podSAN := "spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/" + testPod
	const identity = "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity"
	tokenFile := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tokenFile, []byte("tok\n"), 0o600)
	notAfter := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	cases := map[string]struct {
		issue func(*x509.CertificateRequest) (*x509.Certificate, time.Time)
		ok    bool
	}{
		"pod clientAuth leaf": {func(csr *x509.CertificateRequest) (*x509.Certificate, time.Time) {
			return p.issue(t, podSAN, csr.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notAfter), notAfter
		}, true},
		"other Pod SAN": {func(csr *x509.CertificateRequest) (*x509.Certificate, time.Time) {
			return p.issue(t, "spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/00000000-0000-4000-8000-000000000000", csr.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notAfter), notAfter
		}, false},
		"serverAuth too": {func(csr *x509.CertificateRequest) (*x509.Certificate, time.Time) {
			return p.issue(t, podSAN, csr.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, notAfter), notAfter
		}, false},
		"other key": {func(*x509.CertificateRequest) (*x509.Certificate, time.Time) {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return p.issue(t, podSAN, &k.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notAfter), notAfter
		}, false},
		"expires_at mismatch": {func(csr *x509.CertificateRequest) (*x509.Certificate, time.Time) {
			return p.issue(t, podSAN, csr.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notAfter), notAfter.Add(time.Hour)
		}, false},
	}
	for name, c := range cases {
		srv := identityServer(t, p, identity, c.issue)
		certs := &Certs{TokenFile: tokenFile, Roots: p.roots, URL: srv.URL, Client: NewClient(p.roots, identity, nil), SAN: podSAN}
		err := certs.Refresh(t.Context())
		if (err == nil) != c.ok {
			t.Fatalf("%s: %v", name, err)
		}
		_, gerr := certs.GetClientCertificate(nil)
		if (gerr == nil) != c.ok {
			t.Fatalf("%s: current certificate %v", name, gerr)
		}
		if c.ok {
			if want := certs.RenewAt(); want.After(time.Now().Add(13*time.Hour)) || want.Before(time.Now().Add(11*time.Hour)) {
				t.Fatalf("renew at %s, want ~12h", want)
			}
		}
	}
	// The bootstrap peer must carry the expected server SAN.
	srv := identityServer(t, p, "spiffe://agentarium.internal/ns/agent-control/sa/other", cases["pod clientAuth leaf"].issue)
	certs := &Certs{TokenFile: tokenFile, Roots: p.roots, URL: srv.URL, Client: NewClient(p.roots, identity, nil), SAN: podSAN}
	if err := certs.Refresh(t.Context()); err == nil {
		t.Fatal("unexpected server SAN accepted")
	}
}

func TestOrigin(t *testing.T) {
	if o, err := Origin("https://10.96.0.20:8443/"); err != nil || o != "https://10.96.0.20:8443" {
		t.Fatalf("%q %v", o, err)
	}
	for _, bad := range []string{"http://x:8443", "https://x:8443/v1", "https://u@x", "https://x?a=1", ""} {
		if _, err := Origin(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
