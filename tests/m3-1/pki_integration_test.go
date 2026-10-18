//go:build integration

package m31

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// localCA is the stand-in for the Google CAS pool: a fresh self-signed
// ECDSA root written into the run's temp dir. The identity harness's fake
// CAS signs every workload certificate with it; every service trusts it as
// the agentarium-trust bundle.
func localCA(t *testing.T, e env) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "m31-local-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = e.path("cfg", "ca.pem"), e.path("cfg", "ca-key.pem")
	writeFile(t, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	writeFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
	return certFile, keyFile
}

// oidcKey is the stand-in for Google's JWKS: a test RSA key whose public half
// the identity harness trusts under kid "m31-k1".
type oidcKey struct {
	key *rsa.PrivateKey
	kid string
}

func newOIDCKey(t *testing.T, e env) (oidcKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := e.path("cfg", "oidc-public.pem")
	writeFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
	return oidcKey{key: k, kid: "m31-k1"}, path
}

// The console user's Google ID token claims (COMMON console authentication).
const (
	oidcAudience = "m31-local.apps.googleusercontent.com"
	oidcDomain   = "example.org"
	consoleEmail = "operator@example.org"
)

func (k oidcKey) idToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	c := map[string]any{
		"iss": "https://accounts.google.com", "sub": "m31-operator", "aud": oidcAudience, "azp": oidcAudience,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(), "auth_time": now.Add(-time.Minute).Unix(),
		"hd": oidcDomain, "email": consoleEmail, "email_verified": true,
	}
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": k.kid, "typ": "JWT"})
	b, _ := json.Marshal(c)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeFile(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, b, 0o600)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const hexd = "0123456789abcdef"
	out := make([]byte, 2*n)
	for i, c := range b {
		out[2*i], out[2*i+1] = hexd[c>>4], hexd[c&15]
	}
	return string(out)
}
