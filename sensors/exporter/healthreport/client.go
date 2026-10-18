package healthreport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

const healthSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"

type Lease struct {
	SourceID             string    `json:"source_id"`
	Component            string    `json:"component"`
	Scope                string    `json:"scope"`
	ScopeID              string    `json:"scope_id"`
	ActiveVersion        *string   `json:"active_version"`
	ActiveBundleRevision *string   `json:"active_bundle_revision"`
	LoadedArtifactDigest *string   `json:"loaded_artifact_digest"`
	CanonicalVersion     *string   `json:"canonical_version"`
	SensorGeneration     *int64    `json:"sensor_generation"`
	LeaseUntil           time.Time `json:"lease_until"`
	ObservedState        string    `json:"observed_state"`
	ReportedAt           time.Time `json:"reported_at"`
}

type Hold struct {
	Scope        string   `json:"scope"`
	ScopeID      string   `json:"scope_id"`
	Reason       string   `json:"reason"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type Client struct {
	origin string
	http   *http.Client
}

// NewClient verifies the CA chain, serverAuth EKU, validity, and exact service
// URI. Service certificates use URI SANs rather than DNS SANs. A fresh TLS
// connection on each request also uses the latest in-memory client certificate.
func NewClient(origin string, roots *x509.CertPool, certificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) (*Client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || roots == nil || certificate == nil {
		return nil, errors.New("health origin, trust roots, and client certificate provider required")
	}
	trusted := roots.Clone()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13, GetClientCertificate: certificate,
		// Verification is fully implemented below for the service URI identity.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("missing health certificate")
			}
			leaf := cs.PeerCertificates[0]
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != healthSAN {
				return errors.New("incorrect health service identity")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range cs.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := leaf.Verify(x509.VerifyOptions{Roots: trusted, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		},
	}
	transport := &http.Transport{TLSClientConfig: cfg, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	return &Client{origin: "https://" + u.Host, http: &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) post(ctx context.Context, path string, input, output any) error {
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("health transport failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && !(path == "/internal/holds" && response.StatusCode == http.StatusCreated) {
		return fmt.Errorf("health HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return errors.New("invalid health response size")
	}
	if canonical.CheckJSONForJCS(body) != nil {
		return errors.New("invalid health response JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid health response JSON")
	}
	return nil
}

func (c *Client) ReportLease(ctx context.Context, lease Lease) error {
	var ack struct {
		LeaseUntil time.Time `json:"lease_until"`
		ScopeState string    `json:"scope_state"`
	}
	if err := c.post(ctx, "/internal/control-health/leases", lease, &ack); err != nil {
		return err
	}
	if !ack.LeaseUntil.After(lease.ReportedAt) || ack.LeaseUntil.After(lease.LeaseUntil) || (ack.ScopeState != "healthy" && ack.ScopeState != "unhealthy" && ack.ScopeState != "degraded") {
		return errors.New("invalid lease acknowledgement")
	}
	return nil
}

func (c *Client) RequestHold(ctx context.Context, hold Hold) error {
	var ack struct {
		HoldID      string   `json:"hold_id"`
		Decision    string   `json:"decision"`
		ReasonCodes []string `json:"reason_codes"`
	}
	if err := c.post(ctx, "/internal/holds", hold, &ack); err != nil {
		return err
	}
	id, err := uuid.Parse(ack.HoldID)
	if err != nil || id == uuid.Nil || id.String() != ack.HoldID || (ack.Decision != "created" && ack.Decision != "existing") || len(ack.ReasonCodes) != 0 {
		return errors.New("hold was not accepted")
	}
	return nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }
