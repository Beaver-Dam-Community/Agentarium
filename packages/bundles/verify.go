package bundles

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/bundle"
)

// Verify reads a signed tarball the way the gateway does (COMMON policy decision
// contract steps 3–4): v1/bundle with a verification config whose keyID is set,
// so a missing .signatures.json is rejected. publicKeyPEM is the ES256
// verification key. It returns the manifest revision.
//
// The gateway's own loader is packages/policyloader (TASK-04); this is the
// publisher's pre-upload check that the signature OPA will see is valid.
//
// OPA uses the configured keyID and ignores the token's "kid" header (v1
// bundle/verify.go), so trust rests on the public key alone. Verify also
// requires the token's kid to equal keyID, so a bundle signed under the
// wrong label is caught before upload.
func Verify(tarball []byte, publicKeyPEM, keyID string) (string, error) {
	if keyID == "" {
		return "", errors.New("bundles: empty keyID")
	}
	if len(tarball) > maxBundleBytes {
		return "", errors.New("bundles: tarball too large")
	}
	if err := checkTokenKeyID(tarball, keyID); err != nil {
		return "", err
	}
	keys := map[string]*bundle.KeyConfig{keyID: {Key: publicKeyPEM, Algorithm: Algorithm}}
	vc := bundle.NewVerificationConfig(keys, keyID, "", nil)
	b, err := bundle.NewCustomReader(bundle.NewTarballLoader(bytes.NewReader(tarball))).
		WithBundleVerificationConfig(vc).
		Read()
	if err != nil {
		return "", fmt.Errorf("bundles: verify: %w", err)
	}
	if b.Manifest.Revision == "" {
		return "", errors.New("bundles: verify: empty manifest revision")
	}
	return b.Manifest.Revision, nil
}

// checkTokenKeyID requires exactly one signature whose JWS header kid is keyID.
func checkTokenKeyID(tarball []byte, keyID string) error {
	files, err := tarFiles(tarball)
	if err != nil {
		return err
	}
	raw, ok := files["/"+SignaturesFile]
	if !ok {
		return fmt.Errorf("bundles: verify: no %s", SignaturesFile)
	}
	var sigs struct {
		Signatures []string `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &sigs); err != nil {
		return fmt.Errorf("bundles: verify: %w", err)
	}
	if len(sigs.Signatures) != 1 {
		return fmt.Errorf("bundles: verify: %d signatures, want 1", len(sigs.Signatures))
	}
	head, _, ok := strings.Cut(sigs.Signatures[0], ".")
	if !ok {
		return errors.New("bundles: verify: malformed signature")
	}
	hb, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return fmt.Errorf("bundles: verify: %w", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return fmt.Errorf("bundles: verify: %w", err)
	}
	if h.Alg != Algorithm || h.Kid != keyID {
		return fmt.Errorf("bundles: verify: token alg %q kid %q, want %s %q", h.Alg, h.Kid, Algorithm, keyID)
	}
	return nil
}
