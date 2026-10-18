// Package issuer asks the CA for a workload certificate and checks that what
// came back is exactly what was asked for before anyone stores or returns it.
package issuer

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Request is a config-based issuance request (TASK-03 3.3.2 step 4): the
// public key comes from the client's CSR, the SAN and EKU from the server.
type Request struct {
	RequestID    string // idempotency key; also the CAS certificate ID
	PublicKeyDER []byte // PKIX SubjectPublicKeyInfo
	SAN          string
	ClientOnly   bool
	Lifetime     time.Duration
}

// Certificate is an issued leaf plus the chain up to the root.
type Certificate struct {
	LeafPEM   string
	ChainPEM  []string // issuer first
	Serial    string   // lower-case hex of the leaf serial number
	NotBefore time.Time
	NotAfter  time.Time
}

// Issuer issues one certificate. Implementations must be safe to retry with
// the same RequestID.
type Issuer interface {
	Issue(ctx context.Context, req Request) (Certificate, error)
}

// ClockSkew is the tolerance for the issued leaf's validity window.
const ClockSkew = 5 * time.Minute

// Verify parses the issued leaf and checks it against the request: the
// public key, the single URI SAN, the exact EKU set (no unknown EKUs), the
// lifetime bound and that the leaf is valid at now (within ClockSkew).
func Verify(req Request, leafPEM string, now time.Time) (Certificate, error) {
	block, _ := pem.Decode([]byte(leafPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return Certificate{}, errors.New("issued leaf is not a PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, fmt.Errorf("parse issued leaf: %w", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(pub, req.PublicKeyDER) {
		return Certificate{}, errors.New("issued leaf public key does not match the request")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != req.SAN || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return Certificate{}, fmt.Errorf("issued leaf SAN does not match %q", req.SAN)
	}
	if len(leaf.UnknownExtKeyUsage) != 0 || !ekuMatches(leaf.ExtKeyUsage, req.ClientOnly) {
		return Certificate{}, fmt.Errorf("issued leaf EKU %v does not match client_only=%v", leaf.ExtKeyUsage, req.ClientOnly)
	}
	if leaf.IsCA {
		return Certificate{}, errors.New("issued leaf is a CA certificate")
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > req.Lifetime+time.Minute {
		return Certificate{}, errors.New("issued leaf lifetime exceeds the request")
	}
	if leaf.NotBefore.After(now.Add(ClockSkew)) || !leaf.NotAfter.After(now.Add(ClockSkew)) {
		return Certificate{}, errors.New("issued leaf is not valid now")
	}
	return Certificate{
		LeafPEM:   leafPEM,
		Serial:    hex.EncodeToString(leaf.SerialNumber.Bytes()),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}, nil
}

// Templates must produce the exact verified profile. Keep this check strict
// even after template selection: configuration and mocked requests do not prove
// that the deployed pool/template combination issues a compliant certificate.
func ekuMatches(got []x509.ExtKeyUsage, clientOnly bool) bool {
	has := map[x509.ExtKeyUsage]bool{}
	for _, u := range got {
		has[u] = true
	}
	if clientOnly {
		return len(got) == 1 && has[x509.ExtKeyUsageClientAuth]
	}
	return len(got) == 2 && has[x509.ExtKeyUsageClientAuth] && has[x509.ExtKeyUsageServerAuth]
}
