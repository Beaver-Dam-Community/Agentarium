package policyloader

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

const fixtureRego = `package agentarium.gateway

result := {"verdict": "allow", "catalog": data.catalog.catalog_digest} if input.ok
`

// --- fixtures ----------------------------------------------------------------

type keyPair struct {
	priv string // PEM EC PRIVATE KEY, for OPA's default signer
	pub  string // PEM PUBLIC KEY
}

func newKey(t *testing.T) keyPair {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(k)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return keyPair{
		priv: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
		pub:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})),
	}
}

func catalogData(t *testing.T) any {
	t.Helper()
	cat, err := canonical.LoadCatalogDir("../canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cat)
	var v any
	_ = json.Unmarshal(b, &v)
	return v
}

type spec struct {
	revision string
	rego     string
	catalog  any
	key      *keyPair // nil = unsigned
	keyID    string
}

func makeBundle(t *testing.T, s spec) []byte {
	t.Helper()
	parsed, err := ast.ParseModuleWithOpts("/gateway.rego", s.rego, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{"catalog": s.catalog}
	b := bundle.Bundle{
		Manifest: bundle.Manifest{Revision: s.revision},
		Data:     data,
		Modules:  []bundle.ModuleFile{{URL: "/gateway.rego", Path: "/gateway.rego", Raw: []byte(s.rego), Parsed: parsed}},
	}
	if s.key != nil {
		if err := b.GenerateSignature(bundle.NewSigningConfig(s.key.priv, "ES256", ""), s.keyID, false); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := bundle.NewWriter(&buf).DisableFormat(true).Write(b); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// store is an in-memory desired_bundle row and bucket.
type store struct {
	mu      sync.Mutex
	desired Desired
	objects map[string][]byte
	// onFetch runs after each fetch (to change desired mid-load).
	onFetch func()
	fetches int
	err     error
}

func (s *store) Desired(context.Context) (Desired, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.desired, s.err
}

func (s *store) Fetch(_ context.Context, uri string) ([]byte, error) {
	s.mu.Lock()
	s.fetches++
	b, ok := s.objects[uri]
	f := s.onFetch
	s.mu.Unlock()
	if f != nil {
		f()
	}
	if !ok {
		return nil, errors.New("no object")
	}
	return b, nil
}

func (s *store) put(bundleID string, obj []byte) Desired {
	d := canonical.SHA256Hex(obj)
	uri := "gs://agentarium-bundle/bundles/" + d + ".tar.gz"
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.objects == nil {
		s.objects = map[string][]byte{}
	}
	s.objects[uri] = obj
	s.desired = Desired{BundleID: bundleID, ArtifactDigest: d, ObjectURI: uri}
	return s.desired
}

func newLoader(t *testing.T, st *store, key keyPair, mod func(*Config)) *Loader {
	t.Helper()
	cfg := Config{Source: st, Fetcher: st, Keys: map[string]string{"prod-v1": key.pub}, KeyID: "prod-v1", Query: GatewayQuery}
	if mod != nil {
		mod(&cfg)
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func good(t *testing.T, k keyPair, rev string) []byte {
	return makeBundle(t, spec{revision: rev, rego: fixtureRego, catalog: catalogData(t), key: &k, keyID: "prod-v1"})
}

// --- tests -------------------------------------------------------------------

func TestLoadAndEvaluate(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	st := &store{}
	d := st.put("bundle-1", good(t, k, "rev-1"))
	var loaded []Status
	l := newLoader(t, st, k, func(c *Config) { c.OnLoaded = func(s Status) error { loaded = append(loaded, s); return nil } })

	if l.Current() != nil {
		t.Fatal("snapshot before first poll")
	}
	if err := l.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	s := l.Current()
	if s == nil || s.Revision() != "rev-1" || s.ArtifactDigest() != d.ArtifactDigest || s.BundleID() != "bundle-1" {
		t.Fatalf("snapshot %+v", s)
	}
	cat, err := s.Catalog()
	if err != nil || cat.CatalogDigest == "" || len(cat.Operations) == 0 {
		t.Fatalf("catalog not loaded: %v", err)
	}
	// Changing the returned catalog does not change the snapshot.
	for id := range cat.Operations {
		delete(cat.Operations, id)
	}
	cat.CatalogDigest = "changed"
	if again, _ := s.Catalog(); again.CatalogDigest == "changed" || len(again.Operations) == 0 {
		t.Fatal("snapshot catalog was modified through the returned value")
	}
	rs, err := s.Prepared().Eval(ctx, rego.EvalInput(map[string]any{"ok": true}))
	if err != nil || len(rs) != 1 {
		t.Fatalf("eval %v %v", rs, err)
	}
	if got := rs[0].Expressions[0].Value.(map[string]any)["catalog"]; got != mustCatalog(t, s).CatalogDigest {
		t.Fatalf("query sees catalog %v", got)
	}
	if st := l.Status(); st.Loaded != d || st.LastError != "" || st.Revision != "rev-1" {
		t.Fatalf("status %+v", st)
	}
	if len(loaded) != 1 {
		t.Fatalf("OnLoaded called %d times", len(loaded))
	}

	// Same tuple: no download.
	n := st.fetches
	if err := l.Poll(ctx); err != nil || st.fetches != n {
		t.Fatalf("reloaded same tuple: %v fetches %d→%d", err, n, st.fetches)
	}
	// Same artifact under another bundle_id: reloaded with the new id.
	st.mu.Lock()
	st.desired.BundleID = "bundle-1b"
	st.mu.Unlock()
	if err := l.Poll(ctx); err != nil || l.Current().BundleID() != "bundle-1b" {
		t.Fatalf("bundle_id change not applied: %v %s", err, l.Current().BundleID())
	}

	// A new bundle replaces the snapshot.
	st.put("bundle-2", good(t, k, "rev-2"))
	if err := l.Poll(ctx); err != nil || l.Current().Revision() != "rev-2" {
		t.Fatalf("rev-2 not loaded: %v", err)
	}
}

func TestBadBundlesKeepPreviousSnapshot(t *testing.T) {
	ctx := context.Background()
	k, other := newKey(t), newKey(t)
	cat := catalogData(t)
	forged := catalogData(t).(map[string]any)
	forged["catalog_digest"] = strings.Repeat("0", 64)

	cases := map[string]func(st *store){
		"unsigned": func(st *store) { st.put("b", makeBundle(t, spec{revision: "r", rego: fixtureRego, catalog: cat})) },
		"other key": func(st *store) {
			st.put("b", makeBundle(t, spec{revision: "r", rego: fixtureRego, catalog: cat, key: &other, keyID: "prod-v1"}))
		},
		"empty revision": func(st *store) {
			st.put("b", makeBundle(t, spec{revision: "", rego: fixtureRego, catalog: cat, key: &k, keyID: "prod-v1"}))
		},
		"forged catalog": func(st *store) {
			st.put("b", makeBundle(t, spec{revision: "r", rego: fixtureRego, catalog: forged, key: &k, keyID: "prod-v1"}))
		},
		"no catalog": func(st *store) {
			st.put("b", makeBundle(t, spec{revision: "r", rego: fixtureRego, catalog: nil, key: &k, keyID: "prod-v1"}))
		},
		"query fails": func(st *store) {
			st.put("b", makeBundle(t, spec{revision: "r", rego: "package agentarium.gateway\n\nresult := undefined_function(1)\n", catalog: cat, key: &k, keyID: "prod-v1"}))
		},
		"digest mismatch": func(st *store) {
			d := st.put("b", good(t, k, "r"))
			st.objects[d.ObjectURI] = append([]byte{}, good(t, k, "r2")...)
		},
		"uri not digest": func(st *store) {
			st.put("b", good(t, k, "r"))
			st.desired.ObjectURI = "gs://agentarium-bundle/bundles/" + strings.Repeat("e", 64) + ".tar.gz"
		},
		"uri other prefix": func(st *store) {
			d := st.put("b", good(t, k, "r"))
			st.desired.ObjectURI = "gs://agentarium-bundle/other/" + d.ArtifactDigest + ".tar.gz"
		},
		"empty bundle_id": func(st *store) { st.put("", good(t, k, "r")) },
		"missing object":  func(st *store) { st.put("b", good(t, k, "r")); st.objects = nil },
		"source error":    func(st *store) { st.err = errors.New("db down") },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			st := &store{}
			first := st.put("bundle-1", good(t, k, "rev-1"))
			var failures int
			l := newLoader(t, st, k, func(c *Config) { c.OnFailed = func(Status, error) error { failures++; return nil } })
			if err := l.Poll(ctx); err != nil {
				t.Fatal(err)
			}
			breakIt(st)
			if err := l.Poll(ctx); err == nil {
				t.Fatal("bad bundle loaded")
			}
			s := l.Current()
			if s == nil || s.ArtifactDigest() != first.ArtifactDigest || s.Revision() != "rev-1" {
				t.Fatalf("previous snapshot not kept: %+v", s)
			}
			stt := l.Status()
			if stt.Loaded != first || stt.LastError == "" {
				t.Fatalf("status %+v", stt)
			}
			if failures != 1 {
				t.Fatalf("OnFailed called %d times", failures)
			}
		})
	}
}

func TestDesiredChangedDuringLoad(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	st := &store{}
	st.put("bundle-a", good(t, k, "rev-a"))
	bObj := good(t, k, "rev-b")
	once := true
	st.onFetch = func() {
		if once {
			once = false
			st.put("bundle-b", bObj)
		}
	}
	l := newLoader(t, st, k, nil)
	if err := l.Poll(ctx); !errors.Is(err, ErrDesiredChanged) {
		t.Fatalf("got %v, want ErrDesiredChanged", err)
	}
	if l.Current() != nil {
		t.Fatal("bundle A was published after desired moved to B")
	}
	if err := l.Poll(ctx); err != nil || l.Current().Revision() != "rev-b" {
		t.Fatalf("B not loaded on the next poll: %v", err)
	}
}

func TestObserverErrorsDoNotUndoLoad(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	st := &store{}
	st.put("bundle-1", good(t, k, "rev-1"))
	l := newLoader(t, st, k, func(c *Config) { c.OnLoaded = func(Status) error { return errors.New("audit down") } })
	err := l.Poll(ctx)
	if err == nil || !strings.Contains(err.Error(), "OnLoaded") {
		t.Fatalf("observer error not reported: %v", err)
	}
	if l.Current() == nil || l.Current().Revision() != "rev-1" {
		t.Fatal("observer error undid the load")
	}
	n := st.fetches
	if err := l.Poll(ctx); err != nil || st.fetches != n {
		t.Fatal("observer error caused a reload")
	}
}

func TestNewRejectsBadKeys(t *testing.T) {
	k := newKey(t)
	rsa := "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL6Vj7Q0mYhR0w8w9pJm8Qy3cX7V1aH5\nZbXqk7x1+3g9cH8k1aFZq2c9h8b1aQmQ8m3q1aB5x8c9H1aQ8m3q1aBECAwEAAQ==\n-----END PUBLIC KEY-----\n"
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	p384pem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	st := &store{}
	for name, cfg := range map[string]Config{
		"empty keyID": {Source: st, Fetcher: st, Keys: map[string]string{"prod-v1": k.pub}},
		"missing key": {Source: st, Fetcher: st, Keys: map[string]string{"regression-v1": k.pub}, KeyID: "prod-v1"},
		"not PEM":     {Source: st, Fetcher: st, Keys: map[string]string{"prod-v1": "x"}, KeyID: "prod-v1"},
		"private key": {Source: st, Fetcher: st, Keys: map[string]string{"prod-v1": k.priv}, KeyID: "prod-v1"},
		"rsa key":     {Source: st, Fetcher: st, Keys: map[string]string{"prod-v1": rsa}, KeyID: "prod-v1"},
		"p384 key":    {Source: st, Fetcher: st, Keys: map[string]string{"prod-v1": p384pem}, KeyID: "prod-v1"},
		"no source":   {Fetcher: st, Keys: map[string]string{"prod-v1": k.pub}, KeyID: "prod-v1"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// The key map is copied: changing it later has no effect.
	keys := map[string]string{"prod-v1": k.pub}
	l, err := New(Config{Source: st, Fetcher: st, Keys: keys, KeyID: "prod-v1"})
	if err != nil {
		t.Fatal(err)
	}
	keys["prod-v1"] = "changed"
	if l.keys["prod-v1"].Key != k.pub {
		t.Fatal("key map not copied")
	}
}

func TestArchiveLimits(t *testing.T) {
	big := func(n int, size int64) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		chunk := make([]byte, 1<<20)
		for i := 0; i < n; i++ {
			tw.WriteHeader(&tar.Header{Name: "/f" + strings.Repeat("x", i%5) + string(rune('a'+i%26)), Mode: 0o600, Size: size, Typeflag: tar.TypeReg})
			for w := int64(0); w < size; w += int64(len(chunk)) {
				m := min(int64(len(chunk)), size-w)
				tw.Write(chunk[:m])
			}
		}
		tw.Close()
		zw.Close()
		return buf.Bytes()
	}
	if err := checkArchive(big(1, MaxEntryBytes+1)); err == nil {
		t.Error("oversize entry accepted")
	}
	if err := checkArchive(big(MaxEntries+1, 0)); err == nil {
		t.Error("too many entries accepted")
	}
	if err := checkArchive(big(5, MaxEntryBytes)); err == nil {
		t.Error("oversize expansion accepted")
	}
	if err := checkArchive(big(3, 1<<20)); err != nil {
		t.Errorf("small archive rejected: %v", err)
	}
}

func TestConcurrentReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k := newKey(t)
	st := &store{}
	st.put("bundle-1", good(t, k, "rev-1"))
	l := newLoader(t, st, k, nil)
	if err := l.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	objs := [][]byte{good(t, k, "rev-2"), good(t, k, "rev-3")}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s := l.Current()
				if s == nil || s.Revision() == "" {
					t.Error("empty snapshot")
					return
				}
				_ = l.Status()
			}
		}()
	}
	for i, o := range objs {
		st.put("bundle-n", o)
		if err := l.Poll(ctx); err != nil {
			t.Fatal(i, err)
		}
	}
	wg.Wait()
}

func mustCatalog(t *testing.T, s *Snapshot) canonical.Catalog {
	t.Helper()
	c, err := s.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRollbackToLoadedBundleClearsFailure(t *testing.T) {
	ctx := context.Background()
	k, other := newKey(t), newKey(t)
	st := &store{}
	a := st.put("bundle-a", good(t, k, "rev-a"))
	l := newLoader(t, st, k, nil)
	if err := l.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	// B is signed with an untrusted key and fails.
	st.put("bundle-b", makeBundle(t, spec{revision: "rev-b", rego: fixtureRego, catalog: catalogData(t), key: &other, keyID: "prod-v1"}))
	if err := l.Poll(ctx); err == nil {
		t.Fatal("B loaded")
	}
	if l.Status().LastError == "" {
		t.Fatal("failure not recorded")
	}
	// desired_bundle is rolled back to A: status is healthy again, no download.
	st.mu.Lock()
	st.desired = a
	st.mu.Unlock()
	n := st.fetches
	if err := l.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if got := l.Status(); got.LastError != "" || got.LastAttempt != a || got.Loaded != a || got.Revision != "rev-a" {
		t.Fatalf("status after rollback %+v", got)
	}
	if st.fetches != n {
		t.Fatal("rollback to the loaded bundle downloaded it again")
	}
}

func TestConcurrentCatalogUse(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	st := &store{}
	st.put("bundle-1", good(t, k, "rev-1"))
	l := newLoader(t, st, k, nil)
	if err := l.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				c := mustCatalog(t, l.Current())
				for id := range c.Operations {
					delete(c.Operations, id) // each caller mutates its own copy
				}
			}
		}()
	}
	wg.Wait()
	if len(mustCatalog(t, l.Current()).Operations) == 0 {
		t.Fatal("snapshot catalog changed")
	}
}
