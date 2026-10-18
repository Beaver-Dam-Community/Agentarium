package ingest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, name string, client bool) (tls.Certificate, string, string) {
		t.Helper()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		u, _ := url.Parse("spiffe://agentarium.internal/ns/agent-control/sa/coordinator")
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if client {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		cf := filepath.Join(dir, name+".crt")
		kf := filepath.Join(dir, name+".key")
		_ = os.WriteFile(cf, cp, 0600)
		_ = os.WriteFile(kf, kp, 0600)
		pair, err := tls.X509KeyPair(cp, kp)
		if err != nil {
			t.Fatal(err)
		}
		return pair, cf, kf
	}
	_, certFile, keyFile := issue(2, "server", false)
	clientPair, _, _ := issue(3, "client", true)
	config, err := LoadTLS(certFile, keyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := peerSAN(r.TLS); err != nil {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(204)
	}))
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	request := func(certificates []tls.Certificate) (int, error) {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: certificates, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		c := &http.Client{Transport: tr, Timeout: 2 * time.Second}
		res, err := c.Get(server.URL)
		if err != nil {
			return 0, err
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode, nil
	}
	if _, err := request(nil); err == nil {
		t.Fatal("TLS accepted no client cert")
	}
	if code, err := request([]tls.Certificate{clientPair}); err != nil || code != 204 {
		t.Fatalf("mTLS failed %d %v", code, err)
	}
	// A broken rotated trust bundle must fail closed on the very next handshake.
	_ = os.WriteFile(caFile, []byte("invalid"), 0600)
	if _, err := request([]tls.Certificate{clientPair}); err == nil {
		t.Fatal("ignored trust rotation")
	}
}
