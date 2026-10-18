package testfixture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const (
	CoordinatorSAN   = "spiffe://agentarium.internal/ns/agent-control/sa/coordinator"
	WriterSAN        = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"
	ExporterSAN      = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-exporter"
	VerifierSAN      = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-verifier"
	ControlHealthSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
)

// PKI is a local CA. It does not model identity/CAS issuance.
type PKI struct {
	CAPath string
	Roots  *x509.CertPool
	ca     *x509.Certificate
	key    *ecdsa.PrivateKey
	dir    string
	mu     sync.Mutex
	serial int64
}

func NewPKI(t *testing.T, dir string) *PKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p := &PKI{CAPath: filepath.Join(dir, "ca.pem"), Roots: x509.NewCertPool(), ca: ca, key: key, dir: dir, serial: 1}
	p.Roots.AddCert(ca)
	if err := os.WriteFile(p.CAPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Issue creates a URI-SAN service leaf. A 127.0.0.1 IP SAN is added only for
// listeners that callers reach with ordinary hostname verification.
func (p *PKI) Issue(t *testing.T, name, san string, localhost bool, usages ...x509.ExtKeyUsage) (tls.Certificate, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(san)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.serial++
	serial := p.serial
	p.mu.Unlock()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: p.ca.NotBefore, NotAfter: p.ca.NotAfter, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	if localhost {
		leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPath, keyPath := filepath.Join(p.dir, name+".crt"), filepath.Join(p.dir, name+".key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, certPath, keyPath
}

// Client is an mTLS client presenting cert and verifying servers against the CA.
func (p *PKI) Client(t *testing.T, cert tls.Certificate) *http.Client {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.Roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

// ServiceClient presents cert and accepts only a server leaf for peerSAN that
// chains to the CA, like the services' own URI-SAN verification.
func (p *PKI) ServiceClient(t *testing.T, cert tls.Certificate, peerSAN string) *http.Client {
	t.Helper()
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			leaf := cs.PeerCertificates[0]
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: p.Roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return err
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != peerSAN {
				return errors.New("unexpected server identity")
			}
			return nil
		}}
	tr := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}
