//go:build integration

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/bundles"
)

// Run with the release migration applied:
// DATABASE_URL=postgres://... go test -tags integration ./tools/first-bundle/
//
// Postgres is real; KMS and GCS are replaced by a local ECDSA key (randomized
// signatures, like KMS) and an in-memory bucket.

const (
	changeA = "0b4e7f8a-3c2d-4e5f-8a9b-0c1d2e3f4a5b"
	changeB = "7d1c2b3a-4e5f-4a6b-9c8d-1e2f3a4b5c6d"
	bucketA = "agentarium-bundle"
)

// localKey counts Sign calls.
type localKey struct {
	*ecdsa.PrivateKey
	pem   string
	signs atomic.Int32
}

func newLocalKey(t *testing.T) *localKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &localKey{PrivateKey: k, pem: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
}

func (k *localKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.signs.Add(1)
	return k.PrivateKey.Sign(r, digest, opts)
}

func (k *localKey) PublicKeyPEM() string { return k.pem }

// memStore is an in-memory bucket. With barrier set, createIfAbsent waits
// until every publisher sharing it has reached the upload step.
type memStore struct {
	mu      sync.Mutex
	objs    map[string][]byte
	creates atomic.Int32
	barrier *sync.WaitGroup
}

func newMemStore() *memStore { return &memStore{objs: map[string][]byte{}} }

func (m *memStore) createIfAbsent(_ context.Context, bucket, name string, body []byte) (bool, error) {
	m.creates.Add(1)
	if m.barrier != nil {
		m.barrier.Done()
		m.barrier.Wait()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objs[bucket+"/"+name]; ok {
		return true, nil
	}
	m.objs[bucket+"/"+name] = bytes.Clone(body)
	return false, nil
}

func (m *memStore) read(_ context.Context, bucket, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objs[bucket+"/"+name]
	if !ok {
		return nil, fmt.Errorf("gs://%s/%s: object not found", bucket, name)
	}
	return bytes.Clone(b), nil
}

func (m *memStore) put(bucket, digest string, b []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objs[bucket+"/"+objectName(digest)] = b
}

func connect(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) })
	return conn
}

// environment returns a fresh environment name and deletes its row after
// the test.
func environment(t *testing.T, conn *pgx.Conn) string {
	t.Helper()
	env := "it-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	ctx := context.Background()
	del := func() {
		if _, err := conn.Exec(ctx, `DELETE FROM release.desired_bundle WHERE environment = $1`, env); err != nil {
			t.Fatal(err)
		}
	}
	del()
	t.Cleanup(del)
	return env
}

// fixture builds the test bundle. The policy dir has the gateway result rule
// that -publish requires; policyData edits the policy data JSON.
func fixture(t *testing.T, revision string, policyData func([]byte) []byte) *bundles.Unsigned {
	t.Helper()
	return fixtureRego(t, revision, "package agentarium.gateway\n\nresult := {\"allow\": false}\n", policyData)
}

func fixtureRego(t *testing.T, revision, rego string, policyData func([]byte) []byte) *bundles.Unsigned {
	t.Helper()
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policy")
	if err := os.MkdirAll(filepath.Join(policyDir, "agentarium"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "agentarium", "gateway.rego"), []byte(rego), 0o644); err != nil {
		t.Fatal(err)
	}
	pd, err := os.ReadFile("../../packages/bundles/testdata/policy-data.json")
	if err != nil {
		t.Fatal(err)
	}
	if policyData != nil {
		pd = policyData(pd)
	}
	pdPath := filepath.Join(dir, "policy-data.json")
	if err := os.WriteFile(pdPath, pd, 0o644); err != nil {
		t.Fatal(err)
	}
	u, err := buildBundle(policyDir, "../../packages/canonical/testdata/catalog", pdPath, revision, true)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func baseParams(env string) publishParams {
	return publishParams{
		BundleID: "first", Revision: "rev-1", KeyID: "prod-v1",
		Bucket: bucketA, Environment: env, ChangeID: changeA,
	}
}

func readRow(t *testing.T, conn *pgx.Conn, env string) desiredRow {
	t.Helper()
	r, err := readDesired(context.Background(), conn, env)
	if err != nil || r == nil {
		t.Fatalf("row %v %v", r, err)
	}
	return *r
}

func TestRepublishReusesExistingBundle(t *testing.T) {
	conn := connect(t)
	env := environment(t, conn)
	ctx := context.Background()
	key, store := newLocalKey(t), newMemStore()
	p := publisher{key: key, store: store, db: conn}

	first, firstTar, err := p.publish(ctx, fixture(t, "rev-1", nil), baseParams(env))
	if err != nil {
		t.Fatal(err)
	}
	if key.signs.Load() != 1 || store.creates.Load() != 1 || !first.Published {
		t.Fatalf("first run: signs %d uploads %d %+v", key.signs.Load(), store.creates.Load(), first)
	}
	// Same inputs again: a fresh build, no signing and no upload, the stored
	// bundle comes back (main writes these bytes to -out).
	second, secondTar, err := p.publish(ctx, fixture(t, "rev-1", nil), baseParams(env))
	if err != nil {
		t.Fatal(err)
	}
	if key.signs.Load() != 1 || store.creates.Load() != 1 {
		t.Fatalf("second run signed %d or uploaded %d times", key.signs.Load()-1, store.creates.Load()-1)
	}
	if second != first {
		t.Fatalf("second result %+v, want %+v", second, first)
	}
	if stored, _ := store.read(ctx, bucketA, objectName(first.ArtifactDigest)); !bytes.Equal(secondTar, firstTar) || !bytes.Equal(secondTar, stored) {
		t.Fatal("second run did not return the stored tarball")
	}
	if r := readRow(t, conn, env); r.ArtifactDigest != first.ArtifactDigest || r.SetByChangeID != changeA {
		t.Fatalf("row %+v", r)
	}
}

// tamperSignature flips a bit of the JWS signature in .signatures.json.
func tamperSignature(t *testing.T, tb []byte) []byte {
	t.Helper()
	return rewriteTar(t, tb, "/"+bundles.SignaturesFile, func(b []byte) []byte {
		var sigs struct {
			Signatures []string `json:"signatures"`
		}
		if err := json.Unmarshal(b, &sigs); err != nil || len(sigs.Signatures) != 1 {
			t.Fatalf("signatures %s %v", b, err)
		}
		i := strings.LastIndex(sigs.Signatures[0], ".")
		raw, err := base64.RawURLEncoding.DecodeString(sigs.Signatures[0][i+1:])
		if err != nil {
			t.Fatal(err)
		}
		raw[10] ^= 1
		sigs.Signatures[0] = sigs.Signatures[0][:i+1] + base64.RawURLEncoding.EncodeToString(raw)
		out, err := json.Marshal(sigs)
		if err != nil {
			t.Fatal(err)
		}
		return out
	})
}

func rewriteTar(t *testing.T, tb []byte, name string, f func([]byte) []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(tb))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == name {
			body = f(body)
		}
		h.Size = int64(len(body))
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestReuseRefused(t *testing.T) {
	key := newLocalKey(t)
	otherKey := newLocalKey(t)
	// seedRow stores tarball under its SHA-256 and points the row at it, as
	// if an earlier run had published it.
	seedRow := func(t *testing.T, conn *pgx.Conn, store *memStore, env string, tarball []byte) {
		d := bundles.ArtifactDigest(tarball)
		store.put(bucketA, d, tarball)
		if ok, err := insertDesired(context.Background(), conn, desiredRow{
			Environment: env, BundleID: "first", ArtifactDigest: d,
			ObjectURI: objectURI(bucketA, d), SetByChangeID: changeA,
		}); err != nil || !ok {
			t.Fatalf("seed: %v %v", ok, err)
		}
	}
	signed := func(t *testing.T, u *bundles.Unsigned) []byte {
		s, err := bundles.Sign(u, key.PrivateKey, "prod-v1")
		if err != nil {
			t.Fatal(err)
		}
		return s.Tarball
	}
	cases := map[string]struct {
		// seed sets up the existing row; nil means a normal first publish.
		seed func(t *testing.T, conn *pgx.Conn, store *memStore, env string)
		// change alters the second run or the stored object.
		change func(t *testing.T, store *memStore, first result, u **bundles.Unsigned, p *publisher, pp *publishParams)
	}{
		"candidate": {change: func(t *testing.T, _ *memStore, _ result, u **bundles.Unsigned, _ *publisher, _ *publishParams) {
			*u = fixture(t, "rev-1", func(b []byte) []byte {
				return bytes.Replace(b, []byte(`"session_budget": 100`), []byte(`"session_budget": 99`), 1)
			})
		}},
		"policy": {change: func(t *testing.T, _ *memStore, _ result, u **bundles.Unsigned, _ *publisher, _ *publishParams) {
			*u = fixtureRego(t, "rev-1", "package agentarium.gateway\n\nresult := {\"allow\": true}\n", nil)
		}},
		"bundle_id": {change: func(_ *testing.T, _ *memStore, _ result, _ **bundles.Unsigned, _ *publisher, pp *publishParams) {
			pp.BundleID = "second"
		}},
		"set_by_change_id": {change: func(_ *testing.T, _ *memStore, _ result, _ **bundles.Unsigned, _ *publisher, pp *publishParams) {
			pp.ChangeID = changeB
		}},
		"bucket": {change: func(_ *testing.T, store *memStore, first result, _ **bundles.Unsigned, _ *publisher, pp *publishParams) {
			// Even with the same object in the other bucket.
			b, _ := store.read(context.Background(), bucketA, objectName(first.ArtifactDigest))
			store.put("other-bucket", first.ArtifactDigest, b)
			pp.Bucket = "other-bucket"
		}},
		"key-id": {change: func(_ *testing.T, _ *memStore, _ result, _ **bundles.Unsigned, _ *publisher, pp *publishParams) {
			pp.KeyID = "regression-v1"
		}},
		"key": {change: func(_ *testing.T, _ *memStore, _ result, _ **bundles.Unsigned, p *publisher, _ *publishParams) {
			p.key = otherKey
		}},
		"object missing": {change: func(_ *testing.T, store *memStore, first result, _ **bundles.Unsigned, _ *publisher, _ *publishParams) {
			store.mu.Lock()
			delete(store.objs, bucketA+"/"+objectName(first.ArtifactDigest))
			store.mu.Unlock()
		}},
		"object digest": {change: func(t *testing.T, store *memStore, first result, _ **bundles.Unsigned, _ *publisher, _ *publishParams) {
			// Another valid signing of the same bundle under the old name.
			store.put(bucketA, first.ArtifactDigest, signed(t, fixture(t, "rev-1", nil)))
		}},
		"bad signature": {seed: func(t *testing.T, conn *pgx.Conn, store *memStore, env string) {
			seedRow(t, conn, store, env, tamperSignature(t, signed(t, fixture(t, "rev-1", nil))))
		}},
		"revision": {seed: func(t *testing.T, conn *pgx.Conn, store *memStore, env string) {
			seedRow(t, conn, store, env, signed(t, fixture(t, "rev-0", nil)))
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			conn := connect(t)
			env := environment(t, conn)
			ctx := context.Background()
			store := newMemStore()
			p := publisher{key: key, store: store, db: conn}
			pp := baseParams(env)
			var first result
			if c.seed != nil {
				c.seed(t, conn, store, env)
			} else {
				var err error
				if first, _, err = p.publish(ctx, fixture(t, "rev-1", nil), pp); err != nil {
					t.Fatal(err)
				}
			}
			before := readRow(t, conn, env)
			u := fixture(t, "rev-1", nil)
			if c.change != nil {
				c.change(t, store, first, &u, &p, &pp)
			}
			signs, creates := key.signs.Load()+otherKey.signs.Load(), store.creates.Load()
			res, _, err := p.publish(ctx, u, pp)
			if err == nil {
				t.Fatalf("reused: %+v", res)
			}
			// Each case must fail for its own reason, not an earlier one.
			reason := map[string]string{
				"candidate": "candidate_digest", "policy": "candidate_digest",
				"bundle_id": "bundle_id", "set_by_change_id": "set_by_change_id",
				"bucket": "object_uri", "key-id": "kid", "key": "signature",
				"object missing": "not found", "object digest": "object has SHA-256",
				"bad signature": "signature", "revision": "revision",
			}[name]
			if !strings.Contains(err.Error(), reason) {
				t.Fatalf("refused for another reason (want %q): %v", reason, err)
			}
			if key.signs.Load()+otherKey.signs.Load() != signs || store.creates.Load() != creates {
				t.Fatal("refused run signed or uploaded")
			}
			if after := readRow(t, conn, env); after != before {
				t.Fatalf("row changed: %+v -> %+v", before, after)
			}
		})
	}
}

func TestConcurrentFirstPublish(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(fmt.Sprintf("same=%v", same), func(t *testing.T) {
			conn := connect(t)
			env := environment(t, conn)
			ctx := context.Background()
			key := newLocalKey(t)
			store := newMemStore()
			// Both runs read the empty table before either inserts.
			store.barrier = new(sync.WaitGroup)
			store.barrier.Add(2)
			params := []publishParams{baseParams(env), baseParams(env)}
			if !same {
				params[1].BundleID = "second"
			}
			type outcome struct {
				res result
				tar []byte
				err error
			}
			out := make([]outcome, 2)
			var wg sync.WaitGroup
			conns := []*pgx.Conn{connect(t), connect(t)}
			for i := range 2 {
				u := fixture(t, "rev-1", nil)
				wg.Go(func() {
					var o outcome
					o.res, o.tar, o.err = publisher{key: key, store: store, db: conns[i]}.publish(ctx, u, params[i])
					out[i] = o
				})
			}
			wg.Wait()
			if key.signs.Load() != 2 || store.creates.Load() != 2 {
				t.Fatalf("signs %d uploads %d, want 2 each", key.signs.Load(), store.creates.Load())
			}
			row := readRow(t, conn, env)
			var n int
			if err := conn.QueryRow(ctx, `SELECT count(*) FROM release.desired_bundle WHERE environment = $1`, env).Scan(&n); err != nil || n != 1 {
				t.Fatalf("rows %d %v", n, err)
			}
			if same {
				for i, o := range out {
					if o.err != nil {
						t.Fatalf("run %d: %v", i, o.err)
					}
					if o.res.ArtifactDigest != row.ArtifactDigest || o.res.ObjectURI != row.ObjectURI {
						t.Fatalf("run %d result %+v, row %+v", i, o.res, row)
					}
				}
				if out[0].res != out[1].res || !bytes.Equal(out[0].tar, out[1].tar) {
					t.Fatal("winner and loser disagree")
				}
				return
			}
			var ok []outcome
			for _, o := range out {
				if o.err == nil {
					ok = append(ok, o)
				} else {
					t.Log(o.err)
				}
			}
			if len(ok) != 1 || ok[0].res.BundleID != row.BundleID || ok[0].res.ArtifactDigest != row.ArtifactDigest {
				t.Fatalf("successes %+v, row %+v", ok, row)
			}
		})
	}
}

func TestDesiredBundleRow(t *testing.T) {
	conn := connect(t)
	env := environment(t, conn)
	ctx := context.Background()
	row := func(d string) desiredRow {
		return desiredRow{Environment: env, BundleID: "b-" + d[:1], ArtifactDigest: d, ObjectURI: objectURI(bucketA, d), SetByChangeID: changeA}
	}
	first := row(strings.Repeat("a", 64))
	if ok, err := insertDesired(ctx, conn, first); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	// An existing row is never replaced.
	if ok, err := insertDesired(ctx, conn, row(strings.Repeat("b", 64))); err != nil || ok {
		t.Fatalf("replaced desired_bundle: %v %v", ok, err)
	}
	if got := readRow(t, conn, env); got != first {
		t.Fatalf("row %+v, want %+v", got, first)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM release.desired_bundle WHERE environment = $1`, env); err != nil {
		t.Fatal(err)
	}
	bad := row(strings.Repeat("c", 64))
	bad.ObjectURI = objectURI(bucketA, strings.Repeat("d", 64))
	if _, err := insertDesired(ctx, conn, bad); err == nil {
		t.Fatal("object_uri that does not match artifact_digest was accepted")
	}
	bad = row(strings.Repeat("c", 64))
	bad.SetByChangeID = "bootstrap"
	if _, err := insertDesired(ctx, conn, bad); err == nil {
		t.Fatal("non-UUID set_by_change_id was accepted by the table")
	}
	// The publisher refuses non-canonical change ids before touching anything.
	key, store := newLocalKey(t), newMemStore()
	for _, id := range []string{"bootstrap", strings.ToUpper(changeA)} {
		pp := baseParams(env)
		pp.ChangeID = id
		if _, _, err := (publisher{key: key, store: store, db: conn}).publish(ctx, fixture(t, "rev-1", nil), pp); err == nil {
			t.Fatalf("change id %q accepted", id)
		}
	}
	if key.signs.Load() != 0 || store.creates.Load() != 0 {
		t.Fatal("invalid change id reached signing or upload")
	}
	if r, err := readDesired(ctx, conn, env); err != nil || r != nil {
		t.Fatalf("row %+v %v", r, err)
	}
}
