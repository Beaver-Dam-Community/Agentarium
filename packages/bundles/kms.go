package bundles

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// KMSSigner is a crypto.Signer backed by a Cloud KMS EC_SIGN_P256_SHA256 key
// version (TASK-14 3.2). Sign sends the SHA-256 digest, never the message,
// and returns KMS's DER signature unchanged; Sign in this package converts it.
type KMSSigner struct {
	ctx     context.Context
	client  *kms.KeyManagementClient
	version string // projects/.../cryptoKeyVersions/N
	pub     *ecdsa.PublicKey
	pubPEM  string
}

// NewKMSSigner loads the public key of keyVersion and checks that it is a
// P-256 key with the EC_SIGN_P256_SHA256 algorithm.
func NewKMSSigner(ctx context.Context, client *kms.KeyManagementClient, keyVersion string) (*KMSSigner, error) {
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyVersion})
	if err != nil {
		return nil, fmt.Errorf("bundles: kms public key: %w", err)
	}
	if resp.GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 {
		return nil, fmt.Errorf("bundles: kms key algorithm %s, want EC_SIGN_P256_SHA256", resp.GetAlgorithm())
	}
	if resp.GetPemCrc32C() != nil && int64(crc32c([]byte(resp.GetPem()))) != resp.GetPemCrc32C().GetValue() {
		return nil, errors.New("bundles: kms public key CRC32C mismatch")
	}
	block, _ := pem.Decode([]byte(resp.GetPem()))
	if block == nil {
		return nil, errors.New("bundles: kms public key is not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundles: kms public key: %w", err)
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("bundles: kms public key is not ECDSA P-256")
	}
	return &KMSSigner{ctx: ctx, client: client, version: keyVersion, pub: pub, pubPEM: resp.GetPem()}, nil
}

// Public returns the key version's public key.
func (s *KMSSigner) Public() crypto.PublicKey { return s.pub }

// PublicKeyPEM returns the public key as KMS gave it, for Verify and the
// agentarium-bundle-keys ConfigMap.
func (s *KMSSigner) PublicKeyPEM() string { return s.pubPEM }

// Sign asks KMS to sign a SHA-256 digest and returns the DER signature.
func (s *KMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("bundles: kms signer needs a SHA-256 digest")
	}
	resp, err := s.client.AsymmetricSign(s.ctx, &kmspb.AsymmetricSignRequest{
		Name:         s.version,
		Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}},
		DigestCrc32C: wrapperspb.Int64(int64(crc32c(digest))),
	})
	if err != nil {
		return nil, fmt.Errorf("bundles: kms sign: %w", err)
	}
	// Integrity checks from the KMS client guide: the request digest arrived
	// intact, the response names the key we asked for, the signature is intact.
	if !resp.GetVerifiedDigestCrc32C() {
		return nil, errors.New("bundles: kms sign: request CRC32C not verified")
	}
	if resp.GetName() != s.version {
		return nil, fmt.Errorf("bundles: kms sign: response key %q, want %q", resp.GetName(), s.version)
	}
	if int64(crc32c(resp.GetSignature())) != resp.GetSignatureCrc32C().GetValue() {
		return nil, errors.New("bundles: kms sign: response CRC32C mismatch")
	}
	return resp.GetSignature(), nil
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func crc32c(b []byte) uint32 { return crc32.Checksum(b, castagnoli) }
