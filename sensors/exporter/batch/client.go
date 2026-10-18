package batch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	origin string
	http   *http.Client
}

// NewClient requires a trusted HTTPS origin and a workload certificate (or
// renewal callback). Redirects and environment proxies are disabled. The
// collector uses an exact service URI identity, with chain/EKU/time verification.
func NewClient(origin string, config *tls.Config) (*Client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, errors.New("collector must be an HTTPS origin")
	}
	if config == nil || config.InsecureSkipVerify || config.RootCAs == nil || (len(config.Certificates) == 0 && config.GetClientCertificate == nil) {
		return nil, errors.New("verified mTLS configuration required")
	}
	cfg := config.Clone()
	cfg.MinVersion = max(cfg.MinVersion, tls.VersionTLS13)
	roots := config.RootCAs.Clone()
	extraVerify := cfg.VerifyConnection
	// Service certificates have URI SANs and no DNS/IP SAN. All certificate
	// verification is done here; InsecureSkipVerify only disables DNS matching.
	cfg.InsecureSkipVerify = true
	cfg.ClientSessionCache = nil
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("missing collector certificate")
		}
		leaf := cs.PeerCertificates[0]
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer" {
			return errors.New("incorrect collector service identity")
		}
		chain := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			chain.AddCert(cert)
		}
		verified, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: chain, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if err != nil {
			return err
		}
		if extraVerify != nil {
			cs.VerifiedChains = verified
			return extraVerify(cs)
		}
		return nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = cfg
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.DisableCompression = true
	transport.DisableKeepAlives = true
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	return &Client{origin: "https://" + u.Host, http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// ProtocolError means a 200 response failed the acknowledgement contract.
// It is not permission to discard or automatically replace any WAL record.
type ProtocolError struct{ Err error }

func (e *ProtocolError) Error() string { return "invalid collector acknowledgement: " + e.Err.Error() }
func (e *ProtocolError) Unwrap() error { return e.Err }

type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("collector HTTP status %d", e.Status) }
func (e *HTTPError) Retryable() bool {
	return e.Status == http.StatusRequestTimeout || e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// Send performs one attempt. On any error the caller retains all WAL bytes.
// Permanent individual rejections are returned for durable quarantine and a
// subsequent record_rejected range; this method never abandons them itself.
func (c *Client) Send(ctx context.Context, b *Batch) (Ack, error) {
	if b == nil || len(b.body) == 0 {
		return Ack{}, errors.New("missing batch")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/internal/"+string(b.stream)+"/events:batch", bytes.NewReader(b.body))
	if err != nil {
		return Ack{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return Ack{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Ack{}, &HTTPError{resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return Ack{}, err
	}
	ack, err := b.validate(raw)
	if err != nil {
		return Ack{}, &ProtocolError{Err: err}
	}
	return ack, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }
