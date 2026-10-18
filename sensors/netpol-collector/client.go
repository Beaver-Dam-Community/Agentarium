package netpolcollector

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"
)

// HTTPSClient authenticates the exact URI SAN of the peer (receiver or
// control-health) with a verified chain and serverAuth, presents the
// collector's in-memory client certificate, and refuses proxies/redirects.
func HTTPSClient(peerSAN string, roots func() (*x509.CertPool, error), certificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, GetClientCertificate: certificate,
		// Verification is done below for the URI identity; DNS names are not used.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("missing peer certificate")
			}
			leaf := cs.PeerCertificates[0]
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != peerSAN {
				return errors.New("unexpected peer identity")
			}
			pool, err := roots()
			if err != nil {
				return err
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		}}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: cfg, DisableKeepAlives: true, DisableCompression: true, TLSHandshakeTimeout: 5 * time.Second, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
