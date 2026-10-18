package workload

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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Timeout is the COMMON external call timeout.
const Timeout = 10 * time.Second

const maxResponse = 64 << 10

// BootstrapPath is the certificate path on identity and on the gateway relay.
const BootstrapPath = "/internal/workload-certificates"

// Roots parses the trust bundle PEM text.
func Roots(bundle string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(bundle)) {
		return nil, errors.New("workload: trust bundle has no certificate")
	}
	return pool, nil
}

// Origin checks an https origin (no path, query, user or fragment).
func Origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("workload: %q is not an https origin", raw)
	}
	return strings.TrimSuffix(raw, "/"), nil
}

// VerifyServer accepts a peer whose leaf chains to roots for serverAuth, is
// a non-CA serverAuth leaf and has exactly one URI SAN equal to want and no
// other SAN (COMMON service PKI: URI identity, no DNS name check).
func VerifyServer(chain []*x509.Certificate, roots *x509.CertPool, want string, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("workload: server presented no certificate")
	}
	leaf := chain[0]
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("workload: verify server chain: %w", err)
	}
	if leaf.IsCA || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return errors.New("workload: server certificate is not a serverAuth leaf")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != want || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return fmt.Errorf("workload: server SAN is not %s", want)
	}
	return nil
}

// NewClient is an HTTP client to one service: exact server SAN, TLS 1.3, no
// redirects, keep-alive or HTTP/2. clientCert nil sends no certificate.
func NewClient(roots *x509.CertPool, serverSAN string, clientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) *http.Client {
	if clientCert == nil {
		clientCert = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	}
	cfg := &tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: clientCert,
		InsecureSkipVerify:   true, // replaced by VerifyConnection: URI SAN identity
		VerifyConnection: func(cs tls.ConnectionState) error {
			return VerifyServer(cs.PeerCertificates, roots, serverSAN, time.Now())
		},
	}
	return &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			TLSClientConfig:   cfg,
			DisableKeepAlives: true,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
			Proxy:             nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Certs holds the runner's current Pod-bound certificate.
type Certs struct {
	TokenFile string
	Roots     *x509.CertPool
	// URL is the bootstrap origin: the gateway relay for agent-exec, the
	// identity service for agent-adapters (TASK-06 call allow table).
	URL    string
	Client *http.Client // NewClient(roots, bootstrap server SAN, nil)
	// SAN is the exact Pod SAN the issued leaf must carry (Self.SAN).
	SAN string
	Now func() time.Time

	mu   sync.RWMutex
	cert *tls.Certificate
}

func (c *Certs) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// GetClientCertificate is the tls.Config hook.
func (c *Certs) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cert == nil || !c.now().Before(c.cert.Leaf.NotAfter) {
		return nil, errors.New("workload: no current certificate")
	}
	return c.cert, nil
}

// RenewAt is 50% of the current lifetime (COMMON: probe certificates renew at 50% of their lifetime).
func (c *Certs) RenewAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cert == nil {
		return c.now()
	}
	l := c.cert.Leaf
	return l.NotBefore.Add(l.NotAfter.Sub(l.NotBefore) / 2)
}

// Refresh posts one CSR with the projected token and swaps in the verified
// result.
func (c *Certs) Refresh(ctx context.Context) error {
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return fmt.Errorf("workload: read projected token: %w", err)
	}
	token := strings.TrimSpace(string(tok))
	if token == "" || len(token) > 16384 {
		return errors.New("workload: invalid projected token")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), "token": token})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+BootstrapPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("workload: certificate bootstrap: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse {
		return errors.New("workload: invalid certificate response")
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("workload: certificate bootstrap HTTP %d", res.StatusCode)
	}
	var reply struct {
		Certificate string    `json:"certificate"`
		Chain       []string  `json:"certificate_chain"`
		Serial      string    `json:"serial"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&reply) != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("workload: invalid certificate response")
	}
	chain, err := parseChain(append([]string{reply.Certificate}, reply.Chain...))
	if err != nil {
		return err
	}
	if err := c.verify(chain, key, reply.ExpiresAt); err != nil {
		return err
	}
	tc := &tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, cert := range chain {
		tc.Certificate = append(tc.Certificate, cert.Raw)
	}
	c.mu.Lock()
	c.cert = tc
	c.mu.Unlock()
	return nil
}

func parseChain(pems []string) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for i, p := range pems {
		b, rest := pem.Decode([]byte(p))
		if b == nil || b.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
			return nil, fmt.Errorf("workload: certificate %d is not one PEM certificate", i)
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("workload: certificate %d: %w", i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// verify checks the issued leaf: chains to Roots for clientAuth, is a
// clientAuth-only non-CA leaf for this key, carries exactly the Pod SAN,
// expires when the reply says and is currently valid.
func (c *Certs) verify(chain []*x509.Certificate, key *ecdsa.PrivateKey, expires time.Time) error {
	leaf := chain[0]
	inter := x509.NewCertPool()
	for _, cert := range chain[1:] {
		inter.AddCert(cert)
	}
	now := c.now()
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: c.Roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("workload: verify issued chain: %w", err)
	}
	if leaf.IsCA || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		return errors.New("workload: issued certificate is not a clientAuth-only leaf")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("workload: issued certificate does not hold the requested key")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != c.SAN || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return fmt.Errorf("workload: issued certificate is not %s", c.SAN)
	}
	if !leaf.NotAfter.Equal(expires) || !now.Before(leaf.NotAfter) {
		return errors.New("workload: issued certificate lifetime does not match")
	}
	return nil
}

// Run renews at RenewAt until ctx ends, retrying every retry on failure.
// onExpired is called once the current certificate has expired unrenewed.
func (c *Certs) Run(ctx context.Context, retry time.Duration, onError func(error), onExpired func()) {
	for {
		wait := time.Until(c.RenewAt())
		select {
		case <-ctx.Done():
			return
		case <-time.After(max(wait, 0)):
		}
		if err := c.Refresh(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			onError(err)
			if _, err := c.GetClientCertificate(nil); err != nil {
				onExpired()
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
