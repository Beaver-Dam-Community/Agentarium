// Package controlhealth is the node-readiness client for the TASK-10
// control-health internal API (COMMON "internal API responsibilities").
package controlhealth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// DefaultServerSAN is the control-health service SAN (COMMON "service PKI and identifiers").
const DefaultServerSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"

// TLSFiles points at the mTLS material issued by TASK-03. Issuance is out of scope here.
type TLSFiles struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// LoadTLSConfig builds a client TLS config that presents the node-readiness
// certificate and accepts only a server whose chain verifies against the
// trust bundle and whose URI SAN equals serverSAN.
//
// The key pair is re-read on every handshake so rotation (24h lifetime,
// renewal at 50%) does not need a restart. The CA bundle is read once.
func LoadTLSConfig(files TLSFiles, serverSAN string) (*tls.Config, error) {
	if files.CertFile == "" || files.KeyFile == "" || files.CAFile == "" {
		return nil, errors.New("controlhealth: cert, key and CA file paths are required")
	}
	if serverSAN == "" {
		return nil, errors.New("controlhealth: server SAN is required")
	}
	caPEM, err := os.ReadFile(files.CAFile)
	if err != nil {
		return nil, fmt.Errorf("controlhealth: read CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("controlhealth: CA bundle has no PEM certificates")
	}
	if _, err := tls.LoadX509KeyPair(files.CertFile, files.KeyFile); err != nil {
		return nil, fmt.Errorf("controlhealth: load client key pair: %w", err)
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(files.CertFile, files.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("controlhealth: reload client key pair: %w", err)
			}
			return &c, nil
		},
		// Service identity is the SPIFFE URI SAN, not a DNS name, so the default
		// hostname check is replaced by VerifyConnection (chain + URI SAN).
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyServer(cs.PeerCertificates, roots, serverSAN)
		},
	}, nil
}

func verifyServer(chain []*x509.Certificate, roots *x509.CertPool, wantSAN string) error {
	if len(chain) == 0 {
		return errors.New("controlhealth: server presented no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("controlhealth: verify server chain: %w", err)
	}
	for _, u := range chain[0].URIs {
		if u.String() == wantSAN {
			return nil
		}
	}
	return fmt.Errorf("controlhealth: server SAN does not match %q", wantSAN)
}
