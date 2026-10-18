package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/bundles"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

const (
	repoRoot   = "../../../.."
	testKeyID  = "prod-v1"
	testRev    = "rev-gw-1"
	testBundle = "bundle-gw-1"
)

// memStore is an in-memory desired_bundle row and bucket.
type memStore struct {
	mu      sync.Mutex
	desired policyloader.Desired
	objects map[string][]byte
}

func (m *memStore) Desired(context.Context) (policyloader.Desired, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.desired, nil
}

func (m *memStore) Fetch(_ context.Context, uri string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[uri]
	if !ok {
		return nil, errors.New("no object")
	}
	return b, nil
}

// testPolicy is a loaded snapshot of the real policies/gateway/decision.rego
// with the Rego test policy data and the canonical test catalog, signed with
// a fresh ES256 key and loaded through packages/policyloader.
type testPolicy struct {
	loader   *policyloader.Loader
	artifact string
	catalog  canonical.Catalog
	store    *memStore // the signed bundle object, for another Source
	pub      string    // PEM public key of testKeyID
}

func loadTestPolicy(t *testing.T, regoSrc string) *testPolicy {
	t.Helper()
	cat, err := canonical.LoadCatalogDir(filepath.Join(repoRoot, "packages/canonical/testdata/catalog"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if regoSrc == "" {
		b, err := os.ReadFile(filepath.Join(repoRoot, "policies/gateway/decision.rego"))
		if err != nil {
			t.Fatal(err)
		}
		regoSrc = string(b)
	}
	if err := os.WriteFile(filepath.Join(dir, "decision.rego"), []byte(regoSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	var pd map[string]json.RawMessage
	raw, err := os.ReadFile(filepath.Join(repoRoot, "policies/gateway/testdata/policy-data.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &pd); err != nil {
		t.Fatal(err)
	}
	delete(pd, "_comment")
	pdJSON, _ := json.Marshal(pd)
	u, err := bundles.Build(bundles.Input{PolicyDir: dir, Catalog: cat, PolicyData: pdJSON, Revision: testRev})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := bundles.Sign(u, key, testKeyID)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	uri := "gs://agentarium-bundle/bundles/" + signed.ArtifactDigest + ".tar.gz"
	st := &memStore{
		desired: policyloader.Desired{BundleID: testBundle, ArtifactDigest: signed.ArtifactDigest, ObjectURI: uri},
		objects: map[string][]byte{uri: signed.Tarball},
	}
	l, err := policyloader.New(policyloader.Config{Source: st, Fetcher: st, Keys: map[string]string{testKeyID: pub},
		KeyID: testKeyID, Query: policyloader.GatewayQuery})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &testPolicy{loader: l, artifact: signed.ArtifactDigest, catalog: cat, store: st, pub: pub}
}
