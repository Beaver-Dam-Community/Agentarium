package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
)

// maxIdentityBody bounds an identity response relayed to the browser.
const maxIdentityBody = 4 << 20

// errToken marks a failure to obtain the ID token, before identity is called.
var errToken = errors.New("no ID token")

// identityClient calls the identity console APIs with the operator's ID
// token. The server is verified against the trust bundle and its exact URI
// SAN; the workload certificates carry no DNS name, so hostname verification
// is replaced, never skipped.
type identityClient struct {
	base   *url.URL
	http   *http.Client
	tokens *tokenSource
}

// sanTLSConfig verifies the server chain against roots, requires the leaf to
// carry exactly one URI SAN equal to san, and applies
// workloadcert.VerifyServiceLeaf.
func sanTLSConfig(roots *x509.CertPool, san string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Go's hostname check is replaced by VerifyConnection below, which
		// always runs and verifies the chain and the URI SAN.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			leaf := cs.PeerCertificates[0]
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return err
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != san {
				return fmt.Errorf("server SAN %v, want %s", leaf.URIs, san)
			}
			// The shared service profile check also rejects a CA leaf and
			// any DNS, IP or email SAN.
			return workloadcert.VerifyServiceLeaf(leaf, san, x509.ExtKeyUsageServerAuth)
		},
	}
}

func loadRoots(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s has no PEM certificate", path)
	}
	return roots, nil
}

// newIdentityClient builds the client. dialAddr replaces the network address
// of the identity host (the kubectl port-forward), while TLS still verifies
// the identity certificate. run requires it; the empty value is kept only for
// tests that dial the URL host directly.
func newIdentityClient(rawURL string, roots *x509.CertPool, san, dialAddr string, tokens *tokenSource) (*identityClient, error) {
	base, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if base.Scheme != "https" || base.Host == "" || (base.Path != "" && base.Path != "/") || base.RawQuery != "" {
		return nil, errors.New("-identity-url must be https://host[:port]")
	}
	base.Path = ""
	hostPort := base.Host
	if base.Port() == "" {
		hostPort = net.JoinHostPort(base.Hostname(), "443")
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: sanTLSConfig(roots, san),
		Proxy:           nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dialAddr != "" && addr == hostPort {
				addr = dialAddr
			}
			return d.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &identityClient{base: base, tokens: tokens, http: &http.Client{
		Timeout:   20 * time.Second,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

// do sends one request to identity and returns its status, content type and
// body. tokenMaxAge is passed to the token source.
func (c *identityClient) do(ctx context.Context, method, path string, query url.Values, body []byte, tokenMaxAge time.Duration) (int, string, []byte, error) {
	tok, err := c.tokens.Token(ctx, tokenMaxAge)
	if err != nil {
		return 0, "", nil, fmt.Errorf("%w: %w", errToken, err)
	}
	u := *c.base
	u.Path = path
	u.RawQuery = query.Encode()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), r)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxIdentityBody+1))
	if err != nil {
		return 0, "", nil, err
	}
	if len(raw) > maxIdentityBody {
		return 0, "", nil, errors.New("identity response too large")
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), raw, nil
}
