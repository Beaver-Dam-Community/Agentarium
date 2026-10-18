package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
)

// AdapterNamespace is the Namespace of the four adapter Deployments (COMMON
// Namespace table, TASK-06 KSA table).
const AdapterNamespace = "agent-adapters"

// adapterKSA maps each catalog adapter_id to the KSA of its Deployment
// (TASK-06 KSA table; identity registered_workloads seed). adapter_id model runs
// as KSA model-adapter; the other three use the adapter_id as the KSA.
var adapterKSA = map[string]string{
	"kubernetes-reader": "kubernetes-reader",
	"receiver-sender":   "receiver-sender",
	"model":             "model-adapter",
	"evidence-reader":   "evidence-reader",
}

// AdapterSAN is the service SAN the adapter of adapterID must present
// (COMMON service SAN spiffe://agentarium.internal/ns/<namespace>/sa/<ksa>).
// An adapter_id outside the catalog's four is unknown and has no SAN.
func AdapterSAN(adapterID string) (string, bool) {
	ksa, ok := adapterKSA[adapterID]
	if !ok {
		return "", false
	}
	return "spiffe://agentarium.internal/ns/" + AdapterNamespace + "/sa/" + ksa, true
}

// ServiceClientTLS is the client TLS config for a call to an internal service
// whose certificate is a TASK-03 service certificate: one URI SAN and no
// DNS, IP or email SAN.
//
// Go's default check matches the dialed host name against DNS and IP SANs,
// which such a certificate never has, so InsecureSkipVerify turns that check
// off and VerifyConnection does the whole verification instead (see
// verifyServiceCert). Nothing is skipped: a handshake succeeds only when
// verifyServiceCert accepts the peer.
func ServiceClientTLS(roots *x509.CertPool, wantSAN string,
	clientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) (*tls.Config, error) {
	if roots == nil {
		return nil, errors.New("gateway: trust bundle is required")
	}
	if wantSAN == "" {
		return nil, errors.New("gateway: expected server SAN is required")
	}
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: clientCert,
		InsecureSkipVerify:   true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyServiceCert(cs.PeerCertificates, roots, wantSAN, time.Now())
		},
	}, nil
}

// verifyServiceCert accepts chain only when
//   - the leaf chains to roots through the intermediates the peer presented,
//     is valid at now, and the chain allows serverAuth;
//   - the leaf itself lists serverAuth (a leaf without an EKU extension, which
//     x509 treats as any usage, is refused) and is not a CA;
//   - the leaf has exactly one URI SAN, equal to wantSAN, and no DNS, IP or
//     email SAN.
func verifyServiceCert(chain []*x509.Certificate, roots *x509.CertPool, wantSAN string, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("gateway: server presented no certificate")
	}
	leaf := chain[0]
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("gateway: verify server chain: %w", err)
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return errors.New("gateway: server certificate does not list serverAuth")
	}
	if leaf.IsCA {
		return errors.New("gateway: server certificate is a CA certificate")
	}
	if len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return errors.New("gateway: server certificate has a DNS, IP or email SAN")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != wantSAN {
		return fmt.Errorf("gateway: server certificate URI SAN is not exactly %q", wantSAN)
	}
	return nil
}

// NewAdapterClient returns the execute client of one adapter. Its TLS config
// presents the gateway certificate (clientCert) and accepts only a server
// certificate with the adapter's service SAN (AdapterSAN). An unknown
// adapter_id is an error, so no client exists for it.
//
// The client follows no redirects, keeps no connection alive and does not
// use HTTP/2 (COMMON implementation defaults: automatic redirect/retry/HTTP2/keep-alive
// disabled).
func NewAdapterClient(adapterID string, roots *x509.CertPool,
	clientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) (*http.Client, error) {
	san, ok := AdapterSAN(adapterID)
	if !ok {
		return nil, fmt.Errorf("gateway: unknown adapter_id %q", adapterID)
	}
	cfg, err := ServiceClientTLS(roots, san, clientCert)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   cfg,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}
