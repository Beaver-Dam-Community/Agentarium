package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// MaxCSRBytes bounds the PEM CSR a client may submit.
const MaxCSRBytes = 8 << 10

const csrBegin = "-----BEGIN CERTIFICATE REQUEST-----"

// ParseCSR decodes one PEM CERTIFICATE REQUEST, checks its self-signature and
// returns only the DER SubjectPublicKeyInfo. Everything else in the CSR
// (subject, SAN, extensions) is ignored: TASK-03 3.3.2 step 4 says the SAN
// comes from what the server verified, never from the CSR.
//
// Only ECDSA P-256 keys are accepted. TASK-03 and COMMON do not name a key
// type; this follows the CA pool issuance policy in PR #13
// (platform/gcp/modules/shared-resources/pki.tf: allowed_key_types is
// elliptic_curve ECDSA_P256 only, and shared.tftest.hcl asserts no RSA), so
// any other key would be rejected by CAS anyway. SPEC-QUESTION in the PR
// description: name the allowed key type in TASK-03 3.3.1.
func ParseCSR(pemBytes []byte) ([]byte, error) {
	if len(pemBytes) == 0 || len(pemBytes) > MaxCSRBytes {
		return nil, errors.New("csr size out of range")
	}
	// pem.Decode skips any text before the first BEGIN line and, if a block
	// fails to decode, keeps scanning for a later one. Decode the trimmed
	// input, require it to start with the BEGIN line, and require that line to
	// be the only BEGIN marker. A decoded block always starts at a BEGIN
	// marker, so the block returned below is the one at offset 0 and nothing
	// before it was skipped. Valid PEM never has "-----BEGIN" inside the
	// base64 body ('-' is not a base64 character).
	trimmed := trimSpace(pemBytes)
	if !bytes.HasPrefix(trimmed, []byte(csrBegin)) {
		return nil, errors.New("csr does not start with a PEM CERTIFICATE REQUEST block")
	}
	if bytes.Count(trimmed, []byte("-----BEGIN")) != 1 {
		return nil, errors.New("csr has more than one PEM BEGIN line")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr is not a PEM CERTIFICATE REQUEST")
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("csr PEM block has headers")
	}
	if len(trimSpace(rest)) != 0 {
		return nil, errors.New("csr has trailing data")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("csr key must be ECDSA P-256")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return der, nil
}

// trimSpace removes leading and trailing space, tab, CR and LF. No other
// byte counts as whitespace.
func trimSpace(b []byte) []byte {
	for len(b) > 0 && isSpace(b[0]) {
		b = b[1:]
	}
	for len(b) > 0 && isSpace(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
