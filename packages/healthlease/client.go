package healthlease

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"slices"
	"time"
)

// ControlHealthSAN is the TASK-10 control-health service identity.
const ControlHealthSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"

// FileClient is an mTLS client for control-health that presents the
// component's certificate from certFile/keyFile (re-read on every handshake,
// so a renewed certificate is used) and accepts only a server certificate
// that chains to the trust bundle in caFile, has serverAuth, and carries
// exactly the URI SAN serverSAN and no other name. Service certificates use
// URI identity, so hostname verification is replaced by that check.
//
// It is the file-mode client; the workload certificate manager
// (packages/workloadcert) provides the same check for bootstrapped
// certificates.
func FileClient(certFile, keyFile, caFile, serverSAN string) (*http.Client, error) {
	if serverSAN == "" {
		return nil, errors.New("healthlease: server SAN required")
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, err
	}
	if _, err := loadRoots(caFile); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The chain and identity are verified in VerifyConnection.
		InsecureSkipVerify: true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(certFile, keyFile)
			return &c, err
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			roots, err := loadRoots(caFile)
			if err != nil {
				return err
			}
			return VerifyServer(cs.PeerCertificates, roots, serverSAN)
		},
	}
	return &http.Client{
		Timeout: callTimeout,
		Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true,
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// VerifyServer checks the presented chain against roots and the leaf's
// identity: serverAuth, not a CA, exactly one URI SAN equal to san and no
// DNS, IP or email names.
func VerifyServer(chain []*x509.Certificate, roots *x509.CertPool, san string) error {
	if len(chain) == 0 {
		return errors.New("healthlease: no server certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	leaf := chain[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return err
	}
	if leaf.IsCA || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return errors.New("healthlease: invalid server certificate purpose")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != san ||
		len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return errors.New("healthlease: unexpected server identity")
	}
	return nil
}

func loadRoots(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("healthlease: trust bundle has no certificates")
	}
	return roots, nil
}
