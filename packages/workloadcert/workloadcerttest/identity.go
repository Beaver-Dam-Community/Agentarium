// Package workloadcerttest is a fake TASK-03 identity service for tests:
// a local CA, a projected-token file and POST /internal/workload-certificates
// that signs the submitted CSR for a fixed service SAN.
package workloadcerttest

import (
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

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
)

// Token is the bootstrap token the fake identity service accepts.
const Token = "bound-test-token"

// Identity is a running fake identity service.
type Identity struct {
	URL       string // https origin for Manager.URL
	CAFile    string // trust bundle PEM (the local CA)
	TokenFile string // projected token file holding Token
	// Wrong makes the service issue the identity service's own SAN instead
	// of the registered one.
	Wrong atomic.Bool

	san  string
	now  time.Time
	key  *ecdsa.PrivateKey
	ca   *x509.Certificate
	caPM []byte
}

// Start runs a fake identity service that issues san. It stops at test end.
func Start(t testing.TB, san string) *Identity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{san: san, now: now, key: key, ca: ca, caPM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	dir := t.TempDir()
	id.CAFile = filepath.Join(dir, "ca.pem")
	id.TokenFile = filepath.Join(dir, "token")
	if err := os.WriteFile(id.CAFile, id.caPM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(id.TokenFile, []byte(Token), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ CSR, Token string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token != Token {
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
		issueSAN := id.san
		if id.Wrong.Load() {
			issueSAN = workloadcert.IdentitySAN
		}
		issued, err := id.sign(csr.PublicKey, issueSAN)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued})), "certificate_chain": []string{string(id.caPM)}, "serial": "02", "expires_at": now.Add(23 * time.Hour).Format(time.RFC3339)})
	}))
	own, err := id.sign(&key.PublicKey, workloadcert.IdentitySAN)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{own}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	id.URL = server.URL
	return id
}

func (id *Identity) sign(pub any, san string) ([]byte, error) {
	u, err := url.Parse(san)
	if err != nil {
		return nil, err
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: id.now.Add(-time.Minute), NotAfter: id.now.Add(23 * time.Hour), URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	return x509.CreateCertificate(rand.Reader, c, id.ca, pub, id.key)
}

// IssueFiles writes a key pair for san signed by the same CA, for tests of
// the --tls-cert/--tls-key file mode.
func (id *Identity) IssueFiles(t testing.TB, san string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := id.sign(&key.PublicKey, san)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
