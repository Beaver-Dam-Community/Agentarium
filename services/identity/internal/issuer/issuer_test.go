package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

type leafSpec struct {
	uris       []string
	eku        []x509.ExtKeyUsage
	unknownEKU []asn1.ObjectIdentifier
	isCA       bool
	notBefore  time.Time
	notAfter   time.Time
	key        *ecdsa.PrivateKey
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func issue(t *testing.T, s leafSpec) string {
	t.Helper()
	caKey := mustKey(t)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: s.notBefore, NotAfter: s.notAfter.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	var us []*url.URL
	for _, u := range s.uris {
		p, _ := url.Parse(u)
		us = append(us, p)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0xabcdef), NotBefore: s.notBefore, NotAfter: s.notAfter,
		URIs: us, ExtKeyUsage: s.eku, UnknownExtKeyUsage: s.unknownEKU, IsCA: s.isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &s.key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestVerify(t *testing.T) {
	now := time.Date(2026, 10, 14, 15, 0, 0, 0, time.UTC)
	key := mustKey(t)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	const san = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/11111111-2222-3333-4444-555555555555"
	clientReq := Request{RequestID: "r", PublicKeyDER: pub, SAN: san, ClientOnly: true, Lifetime: 24 * time.Hour}
	good := leafSpec{uris: []string{san}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		notBefore: now.Add(-time.Minute), notAfter: now.Add(24*time.Hour - time.Minute), key: key}

	c, err := Verify(clientReq, issue(t, good), now)
	if err != nil {
		t.Fatalf("good leaf: %v", err)
	}
	if c.Serial != "abcdef" {
		t.Fatalf("serial = %q", c.Serial)
	}

	bad := map[string]func(s *leafSpec){
		"server EKU on client-only": func(s *leafSpec) {
			s.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		},
		"unknown EKU": func(s *leafSpec) { s.unknownEKU = []asn1.ObjectIdentifier{{1, 2, 3, 4}} },
		"second SAN":  func(s *leafSpec) { s.uris = append(s.uris, "spiffe://agentarium.internal/ns/x/sa/y") },
		"other SAN":   func(s *leafSpec) { s.uris = []string{"spiffe://agentarium.internal/ns/agent-exec/sa/other"} },
		"other key":   func(s *leafSpec) { s.key = mustKey(t) },
		"CA leaf":     func(s *leafSpec) { s.isCA = true },
		"too long":    func(s *leafSpec) { s.notAfter = now.Add(48 * time.Hour) },
		"expired": func(s *leafSpec) {
			s.notBefore = now.Add(-25 * time.Hour)
			s.notAfter = now.Add(-time.Hour)
		},
		"not yet valid": func(s *leafSpec) {
			s.notBefore = now.Add(time.Hour)
			s.notAfter = now.Add(20 * time.Hour)
		},
	}
	for name, mutate := range bad {
		s := good
		s.uris = append([]string(nil), good.uris...)
		mutate(&s)
		if _, err := Verify(clientReq, issue(t, s), now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	serviceReq := clientReq
	serviceReq.ClientOnly = false
	s := good
	s.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if _, err := Verify(serviceReq, issue(t, s), now); err != nil {
		t.Errorf("service leaf: %v", err)
	}
	if _, err := Verify(serviceReq, issue(t, good), now); err == nil {
		t.Errorf("client-only leaf accepted for service request")
	}
}
