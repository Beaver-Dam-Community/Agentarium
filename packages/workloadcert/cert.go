// Package workloadcert bootstraps and renews a service identity without writing
// private keys to disk. The TASK-03 wire adapter follows its current CSR/token API.
// It is shared so every control-plane service bootstraps the same way.
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

type Manager struct {
	URL, TokenFile, CAFile, SAN string
	// IdentityServerSAN defaults to the standard identity service SAN.
	IdentityServerSAN string
	current           atomic.Pointer[tls.Certificate]
}

func roots(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
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
	r, err := roots(m.CAFile)
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
	return VerifyServiceLeaf(certs[0], san, usage)
}

// VerifyServiceLeaf checks the service identity profile after chain and validity
// verification. An absent EKU or anyExtendedKeyUsage must not stand in for an
// explicit service-auth purpose. Runtime Pod and node-bridge profiles are not
// accepted by this service-peer check.
func VerifyServiceLeaf(leaf *x509.Certificate, san string, usage x509.ExtKeyUsage) error {
	if leaf == nil || leaf.IsCA || !slices.Contains(leaf.ExtKeyUsage, usage) {
		return errors.New("invalid service certificate purpose")
	}
	if san == "" || len(leaf.URIs) != 1 || leaf.URIs[0].String() != san || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return errors.New("unexpected service identity")
	}
	return nil
}
func (m *Manager) Certificate() (*tls.Certificate, error) {
	c := m.current.Load()
	if c == nil || !time.Now().Before(c.Leaf.NotAfter) {
		return nil, errors.New("service certificate unavailable")
	}
	return c, nil
}

// Client authenticates the exact URI SAN and verifies chain, validity and EKU.
// DNS-name checking is replaced only because these certificates use URI identity.
func (m *Manager) Client(peerSAN string, mutual bool) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return m.verify(cs.PeerCertificates, peerSAN, x509.ExtKeyUsageServerAuth)
		}}
	if mutual {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return m.Certificate() }
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func (m *Manager) Refresh(ctx context.Context) error {
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
	peerSAN := m.IdentityServerSAN
	if peerSAN == "" {
		peerSAN = IdentitySAN
	}
	res, err := m.Client(peerSAN, false).Do(req)
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
	if err = m.verify(chain, m.SAN, x509.ExtKeyUsageServerAuth); err != nil {
		return err
	}
	leaf := chain[0]
	if leaf.IsCA || leaf.NotAfter.Sub(leaf.NotBefore) > 24*time.Hour+5*time.Minute || !leaf.NotAfter.Equal(reply.ExpiresAt) {
		return errors.New("invalid issued lifetime")
	}
	pair.Leaf = leaf
	m.current.Store(&pair)
	return nil
}
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
func (m *Manager) ServerTLS() (*tls.Config, error) {
	load := func() (*tls.Config, error) {
		c, err := m.Certificate()
		if err != nil {
			return nil, err
		}
		r, err := roots(m.CAFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*c}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: r, NextProtos: []string{"http/1.1"}}, nil
	}
	cfg, err := load()
	if err != nil {
		return nil, err
	}
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return load() }
	return cfg, nil
}
