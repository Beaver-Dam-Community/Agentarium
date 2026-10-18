// Package workloadcert bootstraps the exporter's client identity from
// POST /internal/workload-certificates (TASK-03) with the projected KSA token,
// keeping the private key in memory. It follows the service copies in
// services/*/internal/workloadcert but only requires the clientAuth purpose:
// the exporter has no inbound listener (TASK-09 3.3).
package workloadcert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

const IdentitySAN = "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity"

// GatewaySAN is the relay for hostNetwork node components: TASK-03 3.3 routes
// their `/internal/workload-certificates` bootstrap through the gateway, which
// forwards the CSR and token unchanged to the identity service.
const GatewaySAN = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"

type Manager struct {
	URL, TokenFile, CAFile, SAN string
	// PeerSAN is the TLS peer of URL: IdentitySAN (direct) or GatewaySAN
	// (relay). Empty means IdentitySAN.
	PeerSAN string
	current atomic.Pointer[tls.Certificate]
}

// Roots reads the trust bundle on every call so a rotated bundle is used.
func (m *Manager) Roots() (*x509.CertPool, error) {
	b, err := os.ReadFile(m.CAFile)
	if err != nil {
		return nil, err
	}
	r := x509.NewCertPool()
	if !r.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid trust roots")
	}
	return r, nil
}

func (m *Manager) verify(certs []*x509.Certificate, san string, usage x509.ExtKeyUsage) error {
	if len(certs) == 0 {
		return errors.New("missing certificate")
	}
	r, err := m.Roots()
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: r, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return err
	}
	leaf := certs[0]
	if leaf.IsCA || !slices.Contains(leaf.ExtKeyUsage, usage) {
		return errors.New("invalid certificate purpose")
	}
	if san == "" || len(leaf.URIs) != 1 || leaf.URIs[0].String() != san || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return errors.New("unexpected certificate identity")
	}
	return nil
}

// Certificate returns the current unexpired client certificate.
func (m *Manager) Certificate() (*tls.Certificate, error) {
	c := m.current.Load()
	if c == nil || !time.Now().Before(c.Leaf.NotAfter) {
		return nil, errors.New("client certificate unavailable")
	}
	return c, nil
}

// GetClientCertificate adapts Certificate to tls.Config.
func (m *Manager) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return m.Certificate()
}

func (m *Manager) identityClient() *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			peer := m.PeerSAN
			if peer == "" {
				peer = IdentitySAN
			}
			return m.verify(cs.PeerCertificates, peer, x509.ExtKeyUsageServerAuth)
		}}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: cfg, DisableKeepAlives: true, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (m *Manager) Refresh(ctx context.Context) error {
	if m.PeerSAN != "" && m.PeerSAN != IdentitySAN && m.PeerSAN != GatewaySAN {
		return errors.New("identity peer must be the identity service or the gateway relay")
	}
	u, err := url.Parse(m.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid identity origin")
	}
	token, err := os.ReadFile(m.TokenFile)
	if err != nil {
		return errors.New("cannot read bootstrap token")
	}
	if len(token) == 0 || len(token) > 16384 {
		return errors.New("invalid bootstrap token")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "token": strings.TrimSpace(string(token))})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL+"/internal/workload-certificates", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := m.identityClient().Do(req)
	if err != nil {
		return errors.New("identity bootstrap unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("identity bootstrap rejected")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, (64<<10)+1))
	if err != nil || len(b) > 64<<10 {
		return errors.New("invalid certificate response")
	}
	var reply struct {
		Certificate string    `json:"certificate"`
		Chain       []string  `json:"certificate_chain"`
		Serial      string    `json:"serial"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&reply) != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("invalid certificate response")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair([]byte(reply.Certificate+"\n"+strings.Join(reply.Chain, "\n")), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return errors.New("invalid issued keypair")
	}
	chain := make([]*x509.Certificate, 0, len(pair.Certificate))
	for _, der := range pair.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		chain = append(chain, c)
	}
	if err = m.verify(chain, m.SAN, x509.ExtKeyUsageClientAuth); err != nil {
		return err
	}
	leaf := chain[0]
	if leaf.NotAfter.Sub(leaf.NotBefore) > 24*time.Hour+5*time.Minute || !leaf.NotAfter.Equal(reply.ExpiresAt) {
		return errors.New("invalid issued lifetime")
	}
	pair.Leaf = leaf
	m.current.Store(&pair)
	return nil
}

// Run renews after half of the certificate lifetime.
func (m *Manager) Run(ctx context.Context, onError func()) {
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c, err := m.Certificate()
			if err == nil && time.Now().Before(c.Leaf.NotBefore.Add(c.Leaf.NotAfter.Sub(c.Leaf.NotBefore)/2)) {
				continue
			}
			call, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = m.Refresh(call)
			cancel()
			if err != nil && ctx.Err() == nil {
				onError()
			}
		}
	}
}
