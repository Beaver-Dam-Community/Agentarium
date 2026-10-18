package workloadcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sensor = "spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon"

func TestRefreshVerifiesIssuedIdentityAndPurpose(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 48), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(pub any, san string, usage x509.ExtKeyUsage, notAfter time.Time) []byte {
		u, _ := url.Parse(san)
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, URIs: []*url.URL{u}, ExtKeyUsage: []x509.ExtKeyUsage{usage}}, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	san, usage := sensor, x509.ExtKeyUsageClientAuth
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ CSR, Token string }
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Token != "tok" {
			w.WriteHeader(401)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		csr, _ := x509.ParseCertificateRequest(block.Bytes)
		na := time.Now().Add(time.Hour).Truncate(time.Second)
		json.NewEncoder(w).Encode(map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issue(csr.PublicKey, san, usage, na)})), "certificate_chain": []string{}, "serial": "1", "expires_at": na})
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{issue(&srvKey.PublicKey, IdentitySAN, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))}, PrivateKey: srvKey}}}
	srv.StartTLS()
	defer srv.Close()
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "token")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)
	os.WriteFile(tokenFile, []byte("tok\n"), 0o600)
	m := &Manager{URL: srv.URL, TokenFile: tokenFile, CAFile: caFile, SAN: sensor}
	if _, err := m.Certificate(); err == nil {
		t.Fatal("certificate before bootstrap")
	}
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, err := m.GetClientCertificate(nil); err != nil || c.Leaf.URIs[0].String() != sensor {
		t.Fatalf("%v %v", c, err)
	}
	for _, bad := range []struct {
		san   string
		usage x509.ExtKeyUsage
	}{{"spiffe://agentarium.internal/ns/agent-exec/sa/runtime", x509.ExtKeyUsageClientAuth}, {sensor, x509.ExtKeyUsageServerAuth}} {
		san, usage = bad.san, bad.usage
		if err := (&Manager{URL: srv.URL, TokenFile: tokenFile, CAFile: caFile, SAN: sensor}).Refresh(context.Background()); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	// The gateway relay identity is accepted only when configured.
	if err := (&Manager{URL: srv.URL, PeerSAN: GatewaySAN, TokenFile: tokenFile, CAFile: caFile, SAN: sensor}).Refresh(context.Background()); err == nil {
		t.Fatal("identity service certificate accepted as gateway relay")
	}
	if err := (&Manager{URL: srv.URL, PeerSAN: "spiffe://agentarium.internal/ns/agent-exec/sa/runtime", TokenFile: tokenFile, CAFile: caFile, SAN: sensor}).Refresh(context.Background()); err == nil {
		t.Fatal("arbitrary peer SAN accepted")
	}
	os.WriteFile(tokenFile, []byte("wrong"), 0o600)
	if err := (&Manager{URL: srv.URL, TokenFile: tokenFile, CAFile: caFile, SAN: sensor}).Refresh(context.Background()); err == nil {
		t.Fatal("rejected token accepted")
	}
}
