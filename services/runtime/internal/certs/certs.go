// Package certs obtains and renews the runtime workload certificate through
// the gateway relay (TASK-03 3.3.2, COMMON Workload certificate bootstrap
// wire format). The private key is generated in memory and never written.
// packages/workloadcert (#218) is not used: it verifies the identity service
// SAN directly and a service (serverAuth) profile, while a runtime talks to
// the gateway and gets a clientAuth-only Pod certificate.
package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/gwclient"
)

// Bootstrapper posts one CSR (gwclient.Client.Bootstrap).
type Bootstrapper interface {
	Bootstrap(ctx context.Context, r gwclient.CertRequest) (gwclient.CertResponse, error)
}

// Manager holds the current certificate.
type Manager struct {
	TokenFile string // projected token, audience agentarium-identity
	Roots     *x509.CertPool
	// Namespace and KSA the issued SAN must name (agent-exec/agent-runtime).
	Namespace, KSA string
	Now            func() time.Time

	mu   sync.RWMutex
	cert *tls.Certificate
	leaf *x509.Certificate
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// GetClientCertificate is the tls.Config hook.
func (m *Manager) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, errors.New("certs: no workload certificate yet")
	}
	return m.cert, nil
}

// SAN returns the current certificate's URI SAN.
func (m *Manager) SAN() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.leaf == nil {
		return ""
	}
	return m.leaf.URIs[0].String()
}

// Refresh requests a new certificate with a fresh key and swaps it in.
func (m *Manager) Refresh(ctx context.Context, b Bootstrapper) error {
	tok, err := os.ReadFile(m.TokenFile)
	if err != nil {
		return fmt.Errorf("certs: read projected token: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	res, err := b.Bootstrap(ctx, gwclient.CertRequest{CSR: csr, Token: strings.TrimSpace(string(tok))})
	if err != nil {
		return fmt.Errorf("certs: bootstrap: %w", err)
	}
	chain, err := parseChain(res)
	if err != nil {
		return err
	}
	if err := m.verify(chain, key); err != nil {
		return err
	}
	tc := &tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	m.mu.Lock()
	m.cert, m.leaf = tc, chain[0]
	m.mu.Unlock()
	return nil
}

func parseChain(res gwclient.CertResponse) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for i, p := range append([]string{res.Certificate}, res.CertificateChain...) {
		b, rest := pem.Decode([]byte(p))
		if b == nil || b.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, fmt.Errorf("certs: certificate %d is not one PEM certificate", i)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certs: certificate %d: %w", i, err)
		}
		chain = append(chain, c)
	}
	return chain, nil
}

// verify checks the issued leaf: chains to Roots for clientAuth, is a
// clientAuth-only leaf for this key, is currently valid, and has exactly one
// URI SAN spiffe://agentarium.internal/ns/<Namespace>/sa/<KSA>/pod/<uid>.
func (m *Manager) verify(chain []*x509.Certificate, key *ecdsa.PrivateKey) error {
	leaf := chain[0]
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	now := m.now()
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: m.Roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("certs: verify issued chain: %w", err)
	}
	if leaf.IsCA || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		return errors.New("certs: issued certificate is not a clientAuth-only leaf")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("certs: issued certificate does not hold the requested key")
	}
	if len(leaf.URIs) != 1 || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return errors.New("certs: issued certificate must have exactly one URI SAN")
	}
	prefix := "spiffe://agentarium.internal/ns/" + m.Namespace + "/sa/" + m.KSA + "/pod/"
	if uid, ok := strings.CutPrefix(leaf.URIs[0].String(), prefix); !ok || uid == "" || strings.Contains(uid, "/") {
		return fmt.Errorf("certs: issued SAN %s is not a %s/%s Pod identity", leaf.URIs[0], m.Namespace, m.KSA)
	}
	if !now.Before(leaf.NotAfter) {
		return errors.New("certs: issued certificate already expired")
	}
	return nil
}

// RenewAt is 50% of the current certificate's lifetime (COMMON: runtime
// certificates renew at 50% of their lifetime).
func (m *Manager) RenewAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.leaf == nil {
		return m.now()
	}
	return m.leaf.NotBefore.Add(m.leaf.NotAfter.Sub(m.leaf.NotBefore) / 2)
}

// Run renews at RenewAt until ctx ends, retrying every retry on failure.
// onFail is called when the current certificate expires without renewal.
func (m *Manager) Run(ctx context.Context, b Bootstrapper, retry time.Duration, onFail func(error)) {
	for {
		wait := time.Until(m.RenewAt())
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := m.Refresh(ctx, b); err != nil {
			m.mu.RLock()
			expired := m.leaf == nil || !m.now().Before(m.leaf.NotAfter)
			m.mu.RUnlock()
			if expired && onFail != nil {
				onFail(err)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
			}
		}
	}
}
