// Package healthreport implements the TASK-07 audit-db heartbeat obligation.
package healthreport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
)

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
type Reporter struct {
	URL      string
	SourceID string
	Version  string
	Client   *http.Client
	Check    func(context.Context) error
}

func (r Reporter) Report(ctx context.Context) error {
	state := "healthy"
	if err := r.Check(ctx); err != nil {
		state = "unhealthy"
	}
	now := time.Now().UTC()
	lease := Lease{SourceID: r.SourceID, Component: "audit-db", Scope: "global", ScopeID: "*", ActiveVersion: &r.Version, LeaseUntil: now.Add(15 * time.Second), ObservedState: state, ReportedAt: now}
	return SendLease(ctx, r.Client, r.URL, lease)
}

// SendLease sends the existing ControlHealthLease wire contract.
func SendLease(ctx context.Context, client *http.Client, base string, lease Lease) error {
	if client == nil {
		return errors.New("health client required")
	}
	raw, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/internal/control-health/leases", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return errors.New("invalid health response")
	}
	if res.StatusCode != 200 {
		return errors.New("health lease not accepted")
	}
	var ack struct {
		LeaseUntil time.Time `json:"lease_until"`
		ScopeState string    `json:"scope_state"`
	}
	if json.Unmarshal(body, &ack) != nil || ack.LeaseUntil.IsZero() {
		return errors.New("invalid health ack")
	}
	return nil
}
func (r Reporter) Run(ctx context.Context, onError func()) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		call, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := r.Report(call)
		cancel()
		if err != nil && ctx.Err() == nil {
			onError()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func Client(base, certFile, keyFile, caFile string) (*http.Client, error) {
	return ServiceClient(base, certFile, keyFile, caFile, "spiffe://agentarium.internal/ns/agent-observe/sa/control-health")
}

// ServiceClient is the file-based mTLS client for an exact peer service SAN.
func ServiceClient(base, certFile, keyFile, caFile, peerSAN string) (*http.Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("health URL must be an HTTPS origin")
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		return &c, err
	},
		VerifyConnection: func(cs tls.ConnectionState) error {
			pem, err := os.ReadFile(caFile)
			if err != nil {
				return err
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return errors.New("invalid roots")
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			// Service certificates authenticate with a URI SAN, so explicitly verify
			// the chain/EKU and exact service identity instead of the DNS hostname.
			if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return err
			}
			return workloadcert.VerifyServiceLeaf(cs.PeerCertificates[0], peerSAN, x509.ExtKeyUsageServerAuth)
		}}
	return &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
