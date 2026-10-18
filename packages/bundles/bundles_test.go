package bundles

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

func testInput(t *testing.T) Input {
	t.Helper()
	cat, err := canonical.LoadCatalogDir("../canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	pd, err := os.ReadFile("testdata/policy-data.json")
	if err != nil {
		t.Fatal(err)
	}
	return Input{PolicyDir: "testdata/policy", Catalog: cat, PolicyData: pd, Revision: "rev-1"}
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func build(t *testing.T, in Input) *Unsigned {
	t.Helper()
	u, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSignedBundleVerifiesWithOPA(t *testing.T) {
	key, pub := newKey(t)
	s, err := Sign(build(t, testInput(t)), key, "prod-v1")
	if err != nil {
		t.Fatal(err)
	}
	rev, err := Verify(s.Tarball, pub, "prod-v1")
	if err != nil {
		t.Fatal(err)
	}
	if rev != "rev-1" {
		t.Fatalf("revision %q", rev)
	}
	if s.ArtifactDigest != canonical.SHA256Hex(s.Tarball) {
		t.Fatal("artifact_digest is not the tarball SHA-256")
	}
}

func TestVerifiedBundleEvaluates(t *testing.T) {
	// The gateway prepares a query from the parsed bundle; check data and
	// modules survive the round trip.
	key, pub := newKey(t)
	s, err := Sign(build(t, testInput(t)), key, "prod-v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(s.Tarball, pub, "prod-v1"); err != nil {
		t.Fatal(err)
	}
	b, err := readBundle(s.Tarball)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pq, err := rego.New(rego.Query("data.agentarium.fixture.allowed"), rego.ParsedBundle("b", b)).PrepareForEval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := pq.Eval(ctx, rego.EvalInput(map[string]any{"ok": true}))
	if err != nil || len(rs) != 1 || rs[0].Expressions[0].Value != true {
		t.Fatalf("eval: %v %v", rs, err)
	}
	if b.Data["data_class_rank"] == nil || b.Data["catalog"].(map[string]any)["catalog_digest"] == "" {
		t.Fatal("data_class_rank or catalog missing from data")
	}
}

func TestVerifyRejects(t *testing.T) {
	key, pub := newKey(t)
	_, otherPub := newKey(t)
	u := build(t, testInput(t))
	s, err := Sign(u, key, "prod-v1")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() ([]byte, string, string){
		"unsigned":    func() ([]byte, string, string) { return u.Tarball, pub, "prod-v1" },
		"wrong key":   func() ([]byte, string, string) { return s.Tarball, otherPub, "prod-v1" },
		"wrong keyID": func() ([]byte, string, string) { return s.Tarball, pub, "regression-v1" },
		"changed file": func() ([]byte, string, string) {
			return editTar(t, s.Tarball, "/data.json", func(b []byte) []byte { return bytes.Replace(b, []byte("100"), []byte("101"), 1) }), pub, "prod-v1"
		},
		"changed rev": func() ([]byte, string, string) {
			return editTar(t, s.Tarball, "/.manifest", func(b []byte) []byte { return bytes.Replace(b, []byte("rev-1"), []byte("rev-2"), 1) }), pub, "prod-v1"
		},
		"added file": func() ([]byte, string, string) {
			return addTar(t, s.Tarball, "/agentarium/extra.rego", "package agentarium.extra\n"), pub, "prod-v1"
		},
		"renamed module": func() ([]byte, string, string) {
			return renameTar(t, s.Tarball, "/agentarium/fixture.rego", "/agentarium/other.rego"), pub, "prod-v1"
		},
		"removed module": func() ([]byte, string, string) {
			return dropTar(t, s.Tarball, "/agentarium/fixture.rego"), pub, "prod-v1"
		},
		"empty signature": func() ([]byte, string, string) { return dropTar(t, s.Tarball, "/"+SignaturesFile), pub, "prod-v1" },
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tb, k, id := c()
			if _, err := Verify(tb, k, id); err == nil {
				t.Fatal("verified")
			}
		})
	}
}

func TestDeterministic(t *testing.T) {
	a, b := build(t, testInput(t)), build(t, testInput(t))
	if !bytes.Equal(a.Tarball, b.Tarball) || a.CandidateDigest != b.CandidateDigest {
		t.Fatal("same input gave different unsigned bundles")
	}
	key, _ := newKey(t)
	sa, err := Sign(a, key, "prod-v1")
	if err != nil {
		t.Fatal(err)
	}
	// ECDSA signatures are randomized, so artifact_digest differs between
	// signings while candidate_digest stays the same.
	sb, err := Sign(b, key, "prod-v1")
	if err != nil {
		t.Fatal(err)
	}
	if sa.CandidateDigest != sb.CandidateDigest || sa.CandidateDigest != a.CandidateDigest {
		t.Fatal("candidate_digest changed")
	}
	// Every tar header carries zero time and fixed mode.
	for name, h := range tarHeaders(t, sa.Tarball) {
		if !h.ModTime.IsZero() && h.ModTime.Unix() != 0 || h.Mode != 0o600 || h.Uid != 0 || h.Gid != 0 {
			t.Fatalf("%s: non-deterministic header %+v", name, h)
		}
	}
	zr, err := gzip.NewReader(bytes.NewReader(sa.Tarball))
	if err != nil {
		t.Fatal(err)
	}
	if !zr.ModTime.IsZero() || zr.Name != "" || zr.Comment != "" {
		t.Fatalf("gzip header not fixed: %+v", zr.Header)
	}
}

func TestCandidateDigestTracksContent(t *testing.T) {
	in := testInput(t)
	base := build(t, in).CandidateDigest
	in.Revision = "rev-2"
	if build(t, in).CandidateDigest == base {
		t.Fatal("revision change kept candidate_digest")
	}
	in = testInput(t)
	in.PolicyData = bytes.Replace(in.PolicyData, []byte(`"session_budget": 100`), []byte(`"session_budget": 99`), 1)
	if build(t, in).CandidateDigest == base {
		t.Fatal("data change kept candidate_digest")
	}
}

func TestSignedCandidateDigest(t *testing.T) {
	u := build(t, testInput(t))
	key, pub := newKey(t)
	sa, err := Sign(u, key, "prod-v1")
	if err != nil {
		t.Fatal(err)
	}
	// Re-signing, even with another key, changes artifact_digest only.
	other, _ := newKey(t)
	sb, err := Sign(u, other, "regression-v1")
	if err != nil {
		t.Fatal(err)
	}
	if sa.ArtifactDigest == sb.ArtifactDigest {
		t.Fatal("re-signing gave the same artifact_digest")
	}
	for _, s := range []*Signed{sa, sb} {
		got, err := SignedCandidateDigest(s.Tarball)
		if err != nil || got != u.CandidateDigest {
			t.Fatalf("got %s %v, want %s", got, err, u.CandidateDigest)
		}
	}
	if _, err := SignedCandidateDigest(u.Tarball); err == nil {
		t.Fatal("unsigned tarball accepted")
	}

	// A changed file changes the digest; Verify rejects the same tarball.
	changed := editTar(t, sa.Tarball, "/data.json", func(b []byte) []byte { return bytes.Replace(b, []byte("100"), []byte("101"), 1) })
	if got, err := SignedCandidateDigest(changed); err != nil || got == u.CandidateDigest {
		t.Fatalf("changed data.json: %s %v", got, err)
	}
	if _, err := Verify(changed, pub, "prod-v1"); err == nil {
		t.Fatal("changed data.json verified")
	}

	sigs := readEntries(t, sa.Tarball)
	var sigBody []byte
	for _, e := range sigs {
		if e.name == "/"+SignaturesFile {
			sigBody = e.body
		}
	}
	cases := map[string][]byte{
		"duplicate entry":      addTar(t, sa.Tarball, "/data.json", "{}"),
		"relative path":        renameTar(t, sa.Tarball, "/agentarium/fixture.rego", "agentarium/fixture.rego"),
		"dot-dot path":         renameTar(t, sa.Tarball, "/agentarium/fixture.rego", "/agentarium/../fixture.rego"),
		"unclean path":         renameTar(t, sa.Tarball, "/agentarium/fixture.rego", "/agentarium//fixture.rego"),
		"backslash path":       renameTar(t, sa.Tarball, "/agentarium/fixture.rego", "/agentarium\\fixture.rego"),
		"nested signatures":    addTar(t, sa.Tarball, "/agentarium/"+SignaturesFile, string(sigBody)),
		"too large compressed": append(append([]byte{}, sa.Tarball...), make([]byte, maxBundleBytes)...),
		"too large unpacked":   addTar(t, sa.Tarball, "/big.json", string(make([]byte, maxBundleBytes))),
		"not gzip":             []byte("not a tarball"),
	}
	for name, tb := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := SignedCandidateDigest(tb); err == nil {
				t.Fatalf("accepted: %s", got)
			}
		})
	}
}

func TestBuildRejects(t *testing.T) {
	cases := map[string]func(*Input){
		"empty revision": func(in *Input) { in.Revision = " " },
		"unknown data key": func(in *Input) {
			in.PolicyData = bytes.Replace(in.PolicyData, []byte(`"receiver"`), []byte(`"catalog": {}, "receiver"`), 1)
		},
		"missing data key": func(in *Input) {
			in.PolicyData = bytes.Replace(in.PolicyData, []byte(`"sensor_rules": {},`), nil, 1)
		},
		"rule id mismatch": func(in *Input) {
			in.PolicyData = bytes.Replace(in.PolicyData, []byte(`"standing_rule_id": "standing.k8s_read.v1"`), []byte(`"standing_rule_id": "x"`), 1)
		},
		"unsorted disclosure": func(in *Input) {
			in.PolicyData = bytes.Replace(in.PolicyData, []byte(`["summary"]},`), []byte(`["summary", "body"]},`), 1)
		},
		"duplicate key": func(in *Input) {
			in.PolicyData = bytes.Replace(in.PolicyData, []byte(`"sensor_rules": {},`), []byte(`"sensor_rules": {}, "sensor_rules": {},`), 1)
		},
		"no catalog digest": func(in *Input) { in.Catalog.CatalogDigest = "" },
		"non-rego file": func(in *Input) {
			in.PolicyDir = t.TempDir()
			os.WriteFile(filepath.Join(in.PolicyDir, "a.rego"), []byte("package a\n"), 0o644)
			os.WriteFile(filepath.Join(in.PolicyDir, "notes.txt"), []byte("x"), 0o644)
		},
		"signatures input": func(in *Input) {
			in.PolicyDir = t.TempDir()
			os.WriteFile(filepath.Join(in.PolicyDir, SignaturesFile), []byte("{}"), 0o644)
		},
		"symlink": func(in *Input) {
			in.PolicyDir = t.TempDir()
			os.WriteFile(filepath.Join(in.PolicyDir, "a.rego"), []byte("package a\n"), 0o644)
			os.Symlink("a.rego", filepath.Join(in.PolicyDir, "b.rego"))
		},
		"empty dir": func(in *Input) { in.PolicyDir = t.TempDir() },
		"rego v0 syntax": func(in *Input) {
			in.PolicyDir = t.TempDir()
			os.WriteFile(filepath.Join(in.PolicyDir, "a.rego"), []byte("package a\np { true }\n"), 0o644)
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			in := testInput(t)
			mod(&in)
			if _, err := Build(in); err == nil {
				t.Fatal("built")
			}
		})
	}
}

func TestSignRejectsNonP256(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(build(t, testInput(t)), k, "prod-v1"); err == nil {
		t.Fatal("signed with P-384")
	}
}

func TestDERToJOSE(t *testing.T) {
	key, _ := newKey(t)
	sum := sha256.Sum256([]byte("m"))
	der, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := DERToJOSE(der)
	if err != nil || len(raw) != 64 {
		t.Fatalf("%x %v", raw, err)
	}
	r, s := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
	if !ecdsa.Verify(&key.PublicKey, sum[:], r, s) {
		t.Fatal("converted signature does not verify")
	}
	// Short R and S are left-padded to 32 bytes.
	small, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), big.NewInt(2)})
	raw, err = DERToJOSE(small)
	if err != nil || raw[31] != 1 || raw[63] != 2 || !bytes.Equal(raw[:31], make([]byte, 31)) {
		t.Fatalf("padding: %x %v", raw, err)
	}
	for name, bad := range map[string][]byte{
		"zero":     mustDER(t, big.NewInt(0), big.NewInt(1)),
		"over N":   mustDER(t, elliptic.P256().Params().N, big.NewInt(1)),
		"trailing": append(append([]byte{}, der...), 0),
		"garbage":  []byte{1, 2, 3},
	} {
		if _, err := DERToJOSE(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func mustDER(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- tar helpers ---------------------------------------------------------------

type entry struct {
	name string
	body []byte
}

func readEntries(t *testing.T, tb []byte) []entry {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(tb))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var out []entry
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out = append(out, entry{h.Name, b})
	}
}

func writeEntries(t *testing.T, es []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range es {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Typeflag: tar.TypeReg, Size: int64(len(e.body))}); err != nil {
			t.Fatal(err)
		}
		tw.Write(e.body)
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func editTar(t *testing.T, tb []byte, name string, f func([]byte) []byte) []byte {
	es := readEntries(t, tb)
	for i := range es {
		if es[i].name == name {
			es[i].body = f(es[i].body)
		}
	}
	return writeEntries(t, es)
}

func addTar(t *testing.T, tb []byte, name, body string) []byte {
	return writeEntries(t, append(readEntries(t, tb), entry{name, []byte(body)}))
}

// readBundle parses an already verified tarball for evaluation.
func readBundle(tb []byte) (*bundle.Bundle, error) {
	b, err := bundle.NewCustomReader(bundle.NewTarballLoader(bytes.NewReader(tb))).WithSkipBundleVerification(true).Read()
	return &b, err
}

func renameTar(t *testing.T, tb []byte, from, to string) []byte {
	es := readEntries(t, tb)
	for i := range es {
		if es[i].name == from {
			es[i].name = to
		}
	}
	return writeEntries(t, es)
}

func dropTar(t *testing.T, tb []byte, name string) []byte {
	var keep []entry
	for _, e := range readEntries(t, tb) {
		if e.name != name {
			keep = append(keep, e)
		}
	}
	return writeEntries(t, keep)
}

func tarHeaders(t *testing.T, tb []byte) map[string]*tar.Header {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(tb))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string]*tar.Header{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = h
	}
}

func TestDefinesRule(t *testing.T) {
	u := build(t, testInput(t))
	if !u.DefinesRule("agentarium.fixture", "allowed") {
		t.Fatal("fixture rule not found")
	}
	if u.DefinesRule("agentarium.gateway", "result") {
		t.Fatal("gateway rule reported in fixture bundle")
	}
}
