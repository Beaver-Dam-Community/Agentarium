package receipt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

const ReceiverSAN = "spiffe://agentarium.internal/ns/agent-targets/sa/receiver"
const CollectorSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/evidence-collector"

type Client struct {
	base string
	http *http.Client
}

// NewClient accepts only a trusted deployment origin. Receipt target/route fields
// are comparison data and are never used as a URL, redirect or TLS identity.
// The client certificate is re-read from the files for each connection.
func NewClient(origin, certFile, keyFile, caFile string) (*Client, error) {
	load := func() (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &c, nil
	}
	return NewClientWithCertificate(origin, caFile, load)
}

// NewClientWithCertificate uses cert (for example an in-memory
// packages/workloadcert Manager) for each connection. The certificate must
// identify the evidence collector with client-auth EKU.
func NewClientWithCertificate(origin, caFile string, cert func() (*tls.Certificate, error)) (*Client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("receipt endpoint must be an HTTPS origin")
	}
	if cert == nil {
		return nil, errors.New("receipt client certificate source is required")
	}
	load := func() (*tls.Certificate, error) {
		c, err := cert()
		if err != nil {
			return nil, err
		}
		if c == nil || len(c.Certificate) == 0 {
			return nil, errors.New("empty receipt client certificate")
		}
		leaf := c.Leaf
		if leaf == nil {
			if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
				return nil, err
			}
		}
		if err = serviceLeaf(leaf, CollectorSAN, x509.ExtKeyUsageClientAuth); err != nil {
			return nil, err
		}
		return c, nil
	}
	if _, err = load(); err != nil {
		return nil, err
	}
	roots := func() (*x509.CertPool, error) {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM(b) {
			return nil, errors.New("empty receipt trust bundle")
		}
		return p, nil
	}
	if _, err = roots(); err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return load() }, VerifyConnection: func(cs tls.ConnectionState) error {
		trust, err := roots()
		if err != nil {
			return err
		}
		if len(cs.PeerCertificates) == 0 {
			return errors.New("missing receiver certificate")
		}
		intermediate := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			intermediate.AddCert(c)
		}
		// URI-only service PKI: replace DNS verification with full chain/time/EKU
		// verification plus the exact receiver URI SAN, never skip authentication.
		leaf := cs.PeerCertificates[0]
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: trust, Intermediates: intermediate, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return err
		}
		return serviceLeaf(leaf, ReceiverSAN, x509.ExtKeyUsageServerAuth)
	}}
	transport := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	return &Client{base: origin, http: &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func serviceLeaf(c *x509.Certificate, san string, usage x509.ExtKeyUsage) error {
	if c == nil || c.IsCA || len(c.URIs) != 1 || c.URIs[0].String() != san || len(c.DNSNames) > 0 || len(c.IPAddresses) > 0 || len(c.EmailAddresses) > 0 {
		return errors.New("unexpected service certificate identity")
	}
	for _, u := range c.ExtKeyUsage {
		if u == usage {
			return nil
		}
	}
	return errors.New("missing service certificate EKU")
}

// Check reads independent receiver facts and returns only TASK-08 receiver
// classification. Network/auth/schema errors return no classification; callers
// must not turn them into 'none' or invent a successful effect.
func (c *Client) Check(ctx context.Context, want Expected) (Result, error) {
	if c == nil || c.http == nil || !validUUID(want.ActionID) || want.TargetID == "" || want.RouteID == "" || !validDigest(want.WireBodyDigest) {
		return Result{}, errors.New("incomplete receipt query context")
	}
	r, digest, err := c.fetch(ctx, want.ActionID)
	if err != nil {
		return Result{}, err
	}
	return classify(want, r, digest)
}

// Read fetches and strictly validates one receipt without classifying it. The
// destination-evidence probe uses it with a fixed probe action key; it never
// produces destination_observed evidence.
func (c *Client) Read(ctx context.Context, actionID string) (*Receipt, string, error) {
	if c == nil || c.http == nil || !validUUID(actionID) {
		return nil, "", errors.New("incomplete receipt query context")
	}
	r, digest, err := c.fetch(ctx, actionID)
	if err != nil {
		return nil, "", err
	}
	if r.ActionKey != actionID {
		return nil, "", errors.New("receipt action key differs from requested action")
	}
	return r, digest, nil
}

func (c *Client) fetch(ctx context.Context, actionID string) (*Receipt, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/test/v1/receipts/"+actionID, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("receipt HTTP status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, canonical.MaxBodyBytes+1))
	if err != nil {
		return nil, "", err
	}
	return decode(raw)
}
