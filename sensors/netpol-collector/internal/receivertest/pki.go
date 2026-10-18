package receivertest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"
)

// PKI is a throwaway CA issuing URI-SAN certificates like TASK-03.
type PKI struct {
	CA   *x509.Certificate
	Key  *ecdsa.PrivateKey
	Pool *x509.CertPool
	PEM  []byte
}

func NewPKI() *PKI {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &PKI{CA: ca, Key: key, Pool: pool, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (p *PKI) Issue(pub any, san string, usage x509.ExtKeyUsage, notAfter time.Time) []byte {
	u, _ := url.Parse(san)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, URIs: []*url.URL{u}, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}, p.CA, pub, p.Key)
	if err != nil {
		panic(err)
	}
	return der
}

func (p *PKI) Pair(san string, usage x509.ExtKeyUsage) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := p.Issue(&key.PublicKey, san, usage, time.Now().Add(time.Hour))
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// Server starts an mTLS server (clientAuth optional) with a URI-SAN identity.
func (p *PKI) Server(san string, h http.Handler, clientAuth bool) *httptest.Server {
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{p.Pair(san, x509.ExtKeyUsageServerAuth)}}
	if clientAuth {
		s.TLS.ClientAuth, s.TLS.ClientCAs = tls.RequireAndVerifyClientCert, p.Pool
	}
	s.StartTLS()
	return s
}
