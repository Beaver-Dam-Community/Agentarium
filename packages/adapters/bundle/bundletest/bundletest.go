// Package bundletest builds signed policy bundles for adapter tests: an OPA
// bundle signed with a fresh ES256 key under key ID prod-v1, as
// packages/policyloader verifies them.
package bundletest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/bundle"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

// KeyID is the bundle signing key ID the tests use (TASK-05 3.4: prod-v1).
const KeyID = "prod-v1"

// Signed is one signed bundle object and the key that verifies it.
type Signed struct {
	Object         []byte
	PublicKeyPEM   string
	BundleID       string
	ArtifactDigest string
	ObjectURI      string
}

// Build signs a bundle whose data is data.catalog = cat plus extra.
func Build(t testing.TB, bundleID string, cat canonical.Catalog, extra map[string]any) Signed {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalECPrivateKey(k)
	public, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	raw, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	var catalog any
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	data := map[string]any{"catalog": catalog}
	for k, v := range extra {
		data[k] = v
	}
	b := bundle.Bundle{Manifest: bundle.Manifest{Revision: "rev-" + bundleID}, Data: data}
	signing := bundle.NewSigningConfig(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})), "ES256", "")
	if err := b.GenerateSignature(signing, KeyID, false); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := bundle.NewWriter(&buf).Write(b); err != nil {
		t.Fatal(err)
	}
	digest := canonical.SHA256Hex(buf.Bytes())
	return Signed{
		Object: buf.Bytes(), PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})),
		BundleID: bundleID, ArtifactDigest: digest, ObjectURI: "gs://agentarium-test/bundles/" + digest + ".tar.gz",
	}
}

// Fetcher serves bundle objects by URI.
type Fetcher struct {
	mu      sync.Mutex
	Objects map[string][]byte
}

func (f *Fetcher) Put(s Signed) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Objects == nil {
		f.Objects = map[string][]byte{}
	}
	f.Objects[s.ObjectURI] = s.Object
}

func (f *Fetcher) Fetch(_ context.Context, uri string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.Objects[uri]
	if !ok {
		return nil, errors.New("bundletest: no object")
	}
	return b, nil
}

// StaticSource is a desired_bundle row that never changes.
type StaticSource struct{ Row policyloader.Desired }

func (s StaticSource) Desired(context.Context) (policyloader.Desired, error) { return s.Row, nil }

// Desired is the desired_bundle row of s.
func (s Signed) Desired() policyloader.Desired {
	return policyloader.Desired{BundleID: s.BundleID, ArtifactDigest: s.ArtifactDigest, ObjectURI: s.ObjectURI}
}
