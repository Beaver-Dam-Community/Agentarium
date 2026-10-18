package supervisor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/certs"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/gwclient"
)

// The runtime refuses a gateway whose certificate names another SAN.
func TestGatewaySANEnforced(t *testing.T) {
	pki := newPKI(t)
	g := newFakeGateway(t, pki)
	m := &certs.Manager{TokenFile: tokenFile(t), Roots: pki.roots, Namespace: "agent-exec", KSA: "agent-runtime"}
	gw, err := gwclient.New(g.srv.URL, pki.roots, "spiffe://agentarium.internal/ns/agent-control/sa/coordinator", m.GetClientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(context.Background(), gw); err == nil || !strings.Contains(err.Error(), "gateway SAN") {
		t.Fatalf("refresh against wrong SAN: %v", err)
	}
}

func TestVerifyServerRejectsClientOnlyLeaf(t *testing.T) {
	pki := newPKI(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(gatewaySAN)
	der := pki.sign(t, &key.PublicKey, u, x509.ExtKeyUsageClientAuth)
	leaf, _ := x509.ParseCertificate(der)
	if err := gwclient.VerifyServer([]*x509.Certificate{leaf}, pki.roots, gatewaySAN, time.Now()); err == nil {
		t.Fatal("clientAuth leaf accepted as gateway")
	}
	sl, _ := x509.ParseCertificate(pki.server.Certificate[0])
	if err := gwclient.VerifyServer([]*x509.Certificate{sl}, pki.roots, gatewaySAN, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// fakeIssuer returns a certificate for a different SAN or EKU than a
// runtime Pod certificate.
type fakeIssuer struct {
	pki *testPKI
	t   *testing.T
	san string
	eku x509.ExtKeyUsage
}

func (f fakeIssuer) Bootstrap(_ context.Context, r gwclient.CertRequest) (gwclient.CertResponse, error) {
	b, _ := pem.Decode([]byte(r.CSR))
	csr, _ := x509.ParseCertificateRequest(b.Bytes)
	u, _ := url.Parse(f.san)
	der := f.pki.sign(f.t, csr.PublicKey, u, f.eku)
	return gwclient.CertResponse{Certificate: pemCert(der), CertificateChain: []string{pemCert(f.pki.ca.Raw)}}, nil
}

func pemCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestIssuedCertificateChecked(t *testing.T) {
	pki := newPKI(t)
	pod := "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/0b6e3d47-3f4c-4a49-9b2f-2b2b7b9c8e11"
	for name, iss := range map[string]fakeIssuer{
		"other ksa":   {san: "spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner/pod/0b6e3d47-3f4c-4a49-9b2f-2b2b7b9c8e11", eku: x509.ExtKeyUsageClientAuth},
		"serverAuth":  {san: pod, eku: x509.ExtKeyUsageServerAuth},
		"service SAN": {san: gatewaySAN, eku: x509.ExtKeyUsageClientAuth},
	} {
		iss.pki, iss.t = pki, t
		m := &certs.Manager{TokenFile: tokenFile(t), Roots: pki.roots, Namespace: "agent-exec", KSA: "agent-runtime"}
		if err := m.Refresh(context.Background(), iss); err == nil {
			t.Errorf("%s: certificate accepted", name)
		}
		if _, err := m.GetClientCertificate(&tls.CertificateRequestInfo{}); err == nil {
			t.Errorf("%s: certificate installed", name)
		}
	}
	m := &certs.Manager{TokenFile: tokenFile(t), Roots: pki.roots, Namespace: "agent-exec", KSA: "agent-runtime"}
	if err := m.Refresh(context.Background(), fakeIssuer{pki: pki, t: t, san: pod, eku: x509.ExtKeyUsageClientAuth}); err != nil || m.SAN() != pod {
		t.Fatalf("valid certificate: %v %q", err, m.SAN())
	}
	if !m.RenewAt().After(time.Now().Add(11*time.Hour)) || !m.RenewAt().Before(time.Now().Add(13*time.Hour)) {
		t.Fatalf("renew at %v, want ~12h (50%% of 24h)", m.RenewAt())
	}
}
