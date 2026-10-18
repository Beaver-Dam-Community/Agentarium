package export

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
)

// LoadTrustedKeys reads trusted configuration mapping exact KMS key version
// names to PEM P-256 public keys. Manifests cannot choose or fetch keys.
func LoadTrustedKeys(path string) (map[string]*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read trusted key file")
	}
	var entries map[string]string
	if json.Unmarshal(raw, &entries) != nil || len(entries) == 0 {
		return nil, errors.New("invalid trusted key file")
	}
	keys := map[string]*ecdsa.PublicKey{}
	for version, value := range entries {
		block, rest := pem.Decode([]byte(value))
		if version == "" || block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
			return nil, errors.New("invalid pinned public key")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid pinned public key")
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return nil, errors.New("pinned key must be P-256")
		}
		keys[version] = key
	}
	return keys, nil
}
