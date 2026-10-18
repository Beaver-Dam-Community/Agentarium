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
	"sync/atomic"
	"testing"
	"time"
)

func TestBootstrapAndIdentityValidation(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	ca, _ = x509.ParseCertificate(der)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("bound-test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	sign := func(pub any, san string) []byte {
		u, _ := url.Parse(san)
		c := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(23 * time.Hour), URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		b, err := x509.CreateCertificate(rand.Reader, c, ca, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	serviceSAN := "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"
	var wrong atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ CSR, Token string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token != "bound-test-token" {
			w.WriteHeader(401)
			return
		}
		block, _ := pem.Decode([]byte(body.CSR))
		if block == nil {
			w.WriteHeader(422)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			w.WriteHeader(422)
			return
		}
		san := serviceSAN
		if wrong.Load() {
			san = IdentitySAN
		}
		issued := sign(csr.PublicKey, san)
		_ = json.NewEncoder(w).Encode(map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued})), "certificate_chain": []string{string(caPEM)}, "serial": "02", "expires_at": now.Add(23 * time.Hour).Format(time.RFC3339)})
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{sign(&key.PublicKey, IdentitySAN)}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	m := &Manager{URL: server.URL, TokenFile: tokenPath, CAFile: caPath, SAN: serviceSAN}
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := m.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ServerTLS(); err != nil {
		t.Fatal(err)
	}
	wrong.Store(true)
	if err := m.Refresh(context.Background()); err == nil {
		t.Fatal("wrong service SAN accepted")
	}
	after, _ := m.Certificate()
	if first != after {
		t.Fatal("failed rotation discarded valid identity")
	}
	if err := os.WriteFile(caPath, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(context.Background()); err == nil {
		t.Fatal("untrusted issuer accepted")
	}
	if _, err := m.ServerTLS(); err == nil {
		t.Fatal("invalid roots accepted")
	}
}
