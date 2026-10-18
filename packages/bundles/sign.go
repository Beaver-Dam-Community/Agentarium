package bundles

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/open-policy-agent/opa/v1/bundle"
)

// Algorithm is the only bundle signing algorithm (TASK-14 3.2).
const Algorithm = "ES256"

// Signed is a signed bundle ready to upload.
type Signed struct {
	Tarball         []byte
	CandidateDigest string
	ArtifactDigest  string
	KeyID           string
}

// Sign signs the bundle with signer under keyID and returns the signed
// tarball. signer must hold a P-256 key; its Sign must return an ASN.1 DER
// ECDSA signature for a SHA-256 digest, as crypto/ecdsa and Cloud KMS
// EC_SIGN_P256_SHA256 both do.
func Sign(u *Unsigned, signer crypto.Signer, keyID string) (*Signed, error) {
	if keyID == "" {
		return nil, errors.New("bundles: empty keyID")
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("bundles: signer key is not ECDSA P-256")
	}
	b := u.bundle
	if err := generateSignature(&b, signer, keyID); err != nil {
		return nil, err
	}
	tarball, err := writeTarball(b)
	if err != nil {
		return nil, err
	}
	// The signed tarball must hold the same files as the unsigned one.
	digest, err := CandidateDigest(tarball)
	if err != nil {
		return nil, err
	}
	if digest != u.CandidateDigest {
		return nil, fmt.Errorf("bundles: candidate_digest changed by signing: %s != %s", digest, u.CandidateDigest)
	}
	return &Signed{Tarball: tarball, CandidateDigest: digest, ArtifactDigest: ArtifactDigest(tarball), KeyID: keyID}, nil
}

// OPA computes the file list (and its hashing rules for data.json) inside
// Bundle.GenerateSignature and hands it to a registered bundle.Signer. The
// registry is global and holds no per-call state, so one shim is registered
// and the active crypto.Signer is passed through a variable guarded by mu.
const signerPluginID = "agentarium-es256"

var (
	mu     sync.Mutex
	active crypto.Signer
)

func init() {
	if err := bundle.RegisterSigner(signerPluginID, shim{}); err != nil {
		panic(err)
	}
}

func generateSignature(b *bundle.Bundle, signer crypto.Signer, keyID string) error {
	mu.Lock()
	defer mu.Unlock()
	active = signer
	defer func() { active = nil }()
	sc := &bundle.SigningConfig{Plugin: signerPluginID, Algorithm: Algorithm}
	if err := b.GenerateSignature(sc, keyID, false); err != nil {
		return fmt.Errorf("bundles: sign: %w", err)
	}
	// Loaders do not need the plugin name; leave it out of .signatures.json.
	b.Signatures.Plugin = ""
	return nil
}

type shim struct{}

func (shim) GenerateSignedToken(files []bundle.FileInfo, _ *bundle.SigningConfig, keyID string) (string, error) {
	if active == nil {
		return "", errors.New("bundles: no active signer")
	}
	return signJWT(active, keyID, map[string]any{"files": files, "keyid": keyID})
}

// signJWT returns a compact JWS (ES256) over claims.
func signJWT(signer crypto.Signer, keyID string, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": Algorithm, "kid": keyID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))
	der, err := signer.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("bundles: sign: %w", err)
	}
	raw, err := DERToJOSE(der)
	if err != nil {
		return "", err
	}
	return input + "." + enc.EncodeToString(raw), nil
}

// DERToJOSE converts an ASN.1 DER ECDSA P-256 signature into the fixed
// 64-byte R || S form that JWS ES256 requires (RFC 7518 3.4). Cloud KMS
// returns DER, so this conversion is mandatory before the JWS is built.
func DERToJOSE(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("bundles: DER signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("bundles: trailing bytes after DER signature")
	}
	n := elliptic.P256().Params().N
	out := make([]byte, 64)
	for i, v := range []*big.Int{sig.R, sig.S} {
		if v == nil || v.Sign() <= 0 || v.Cmp(n) >= 0 {
			return nil, errors.New("bundles: DER signature value out of range")
		}
		v.FillBytes(out[i*32 : (i+1)*32])
	}
	return out, nil
}
