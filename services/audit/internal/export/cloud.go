package export

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"hash/crc32"
	"io"

	"cloud.google.com/go/storage"
	kms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/googleapi"
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)
var ErrObjectConflict = errors.New("existing object bytes differ from fixed batch")

type KMS struct {
	Service    *kms.Service
	KeyVersion string
	PublicKey  *ecdsa.PublicKey
}

func (k KMS) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if k.Service == nil || k.KeyVersion == "" || len(digest) != 32 || k.PublicKey == nil || k.PublicKey.Curve != elliptic.P256() {
		return nil, errors.New("invalid KMS signer configuration")
	}
	result, e := k.Service.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricSign(k.KeyVersion, &kms.AsymmetricSignRequest{
		Digest: &kms.Digest{Sha256: base64.StdEncoding.EncodeToString(digest)}, DigestCrc32c: int64(crc32.Checksum(digest, crcTable)), ForceSendFields: []string{"DigestCrc32c"},
	}).Context(ctx).Do()
	if e != nil {
		return nil, e
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(result.Signature)
	if e != nil || result.Name != k.KeyVersion || !result.VerifiedDigestCrc32c || int64(crc32.Checksum(sig, crcTable)) != result.SignatureCrc32c || !ecdsa.VerifyASN1(k.PublicKey, digest, sig) {
		return nil, errors.New("KMS response integrity or signature mismatch")
	}
	return sig, nil
}

type GCS struct{ Bucket *storage.BucketHandle }

func (g GCS) Read(ctx context.Context, key string, generation int64) ([]byte, error) {
	if g.Bucket == nil || key == "" || generation < 1 || generation > MaxSequence {
		return nil, errors.New("invalid pinned object request")
	}
	reader, e := g.Bucket.Object(key).Generation(generation).NewReader(ctx)
	if e != nil {
		return nil, e
	}
	defer reader.Close()
	if reader.Attrs.Generation != generation || reader.Attrs.Size > MaxBatchBytes {
		return nil, errors.New("unexpected object generation or size")
	}
	b, e := io.ReadAll(io.LimitReader(reader, MaxBatchBytes+1))
	if e != nil {
		return nil, e
	}
	if len(b) > MaxBatchBytes {
		return nil, errors.New("object too large")
	}
	return b, nil
}

// CreateFixed is for byte-stable artifacts. It never overwrites an object and
// accepts a 412 only after reading that generation and comparing actual bytes.
// A freshly randomized signature is not byte-stable: preserve the signed
// envelope for retries or reconcile its validated existing manifest first.
func (g GCS) CreateFixed(ctx context.Context, key, contentType string, data []byte) (int64, error) {
	if g.Bucket == nil || key == "" || len(data) == 0 || len(data) > MaxBatchBytes {
		return 0, errors.New("invalid object upload")
	}
	uploadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := g.Bucket.Object(key).If(storage.Conditions{DoesNotExist: true}).NewWriter(uploadCtx)
	w.ContentType = contentType
	w.CRC32C = crc32.Checksum(data, crcTable)
	w.SendCRC32C = true
	_, writeErr := w.Write(data)
	if writeErr != nil {
		cancel()
		_ = w.Close()
		return 0, writeErr
	}
	err := w.Close()
	if err == nil {
		gen := w.Attrs().Generation
		if gen < 1 || gen > MaxSequence {
			return 0, errors.New("object generation outside canonical range")
		}
		return gen, nil
	}
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != 412 {
		return 0, err
	}
	attrs, e := g.Bucket.Object(key).Attrs(ctx)
	if e != nil {
		return 0, e
	}
	existing, e := g.Read(ctx, key, attrs.Generation)
	if e != nil {
		return 0, e
	}
	if Digest(existing) != Digest(data) {
		return attrs.Generation, ErrObjectConflict
	}
	return attrs.Generation, nil
}

// ReadManifest resolves metadata once and then pins that exact generation.
// Missing objects are distinguished from permission/network failures.
func (g GCS) ReadManifest(ctx context.Context, key string) ([]byte, error) {
	if g.Bucket == nil || key == "" {
		return nil, errors.New("invalid manifest object request")
	}
	attrs, err := g.Bucket.Object(key).Attrs(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil, ErrManifestObjectMissing
	}
	if err != nil {
		return nil, err
	}
	if attrs.Size > MaxManifestBytes {
		return nil, errors.New("manifest object too large")
	}
	return g.Read(ctx, key, attrs.Generation)
}
