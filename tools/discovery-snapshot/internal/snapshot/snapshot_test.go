package snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/format"
)

func fakeDigest(calls *[]string) Digester {
	return func(_ context.Context, doc []byte) (string, error) {
		*calls = append(*calls, string(doc))
		return strings.Repeat("ab", 32), nil
	}
}

// shaDigest stands in for canonical-digest: distinct documents get distinct ids.
func shaDigest(_ context.Context, doc []byte) (string, error) {
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:]), nil
}

var emptySites = format.CallSites{Language: "python", Tool: "python-ast", CallSites: []format.CallSite{}, Imports: []format.ImportAlias{}, Limitations: []string{}}

func srcTree(t *testing.T) (string, format.Manifest) {
	t.Helper()
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "a.py"), []byte("a"), 0o644)
	m, err := BuildManifest(src)
	if err != nil {
		t.Fatal(err)
	}
	return src, m
}

func TestWriteLayoutAndIdempotence(t *testing.T) {
	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, "pkg", ".git"), 0o755)
	os.WriteFile(filepath.Join(src, "pkg", "b.py"), []byte("b"), 0o644)
	os.WriteFile(filepath.Join(src, "a.py"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(src, "pkg", ".git", "HEAD"), []byte("x"), 0o644)

	m, err := BuildManifest(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 2 || m.Files[0].Path != "a.py" || m.Files[1].Path != "pkg/b.py" {
		t.Fatalf("manifest: %+v", m.Files)
	}
	// sha256("a")
	if m.Files[0].SHA256 != "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" {
		t.Fatalf("sha256: %s", m.Files[0].SHA256)
	}

	out := t.TempDir()
	var calls []string
	id, reused, err := Write(context.Background(), DirStore{out}, src, m, format.Callgraph{"a": {"b"}}, emptySites, fakeDigest(&calls))
	if err != nil || reused {
		t.Fatalf("write: reused=%v err=%v", reused, err)
	}
	dir := filepath.Join(out, "snapshots", id)
	for _, f := range []string{"manifest.json", "callgraph.json", "call_sites.json", "src/a.py", "src/pkg/b.py"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if string(raw) != calls[0] {
		t.Fatal("snapshot_id must be the digest of the stored manifest.json bytes")
	}
	var back format.Manifest
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Files) != 2 {
		t.Fatalf("manifest round trip: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 4 { // no leftover temp files
		t.Fatalf("snapshot dir entries: %v", ents)
	}

	// A complete snapshot is reused, never rewritten.
	os.WriteFile(filepath.Join(src, "a.py"), []byte("changed"), 0o644)
	if _, reused, err := Write(context.Background(), DirStore{out}, src, m, nil, emptySites, fakeDigest(&calls)); err != nil || !reused {
		t.Fatalf("rerun: reused=%v err=%v", reused, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "src", "a.py")); string(b) != "a" {
		t.Fatal("existing snapshot was modified")
	}
}

func TestWriteRejectsFileChangedAfterManifest(t *testing.T) {
	src, m := srcTree(t)
	os.WriteFile(filepath.Join(src, "a.py"), []byte("tampered"), 0o644)
	var calls []string
	if _, _, err := Write(context.Background(), DirStore{t.TempDir()}, src, m, nil, format.CallSites{}, fakeDigest(&calls)); err == nil {
		t.Fatal("want error")
	}
}

// writeOnceCases runs the same write-once behaviour against any Store.
func writeOnceCases(t *testing.T, newStore func(t *testing.T) Store, tamper func(t *testing.T, st Store, key string, data []byte)) {
	ctx := context.Background()

	t.Run("create_only_never_replaces", func(t *testing.T) {
		st := newStore(t)
		if err := st.CreateOnly(ctx, "snapshots/x/a", []byte("one")); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateOnly(ctx, "snapshots/x/a", []byte("two")); !errors.Is(err, ErrExists) {
			t.Fatalf("second create: %v", err)
		}
		if b, err := st.Get(ctx, "snapshots/x/a"); err != nil || string(b) != "one" {
			t.Fatalf("get: %q %v", b, err)
		}
		if _, err := st.Get(ctx, "snapshots/x/missing"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("missing: %v", err)
		}
	})

	t.Run("reuse_same_manifest", func(t *testing.T) {
		st := newStore(t)
		src, m := srcTree(t)
		id, reused, err := Write(ctx, st, src, m, format.Callgraph{}, emptySites, shaDigest)
		if err != nil || reused {
			t.Fatalf("first: %v %v", reused, err)
		}
		id2, reused, err := Write(ctx, st, src, m, format.Callgraph{}, emptySites, shaDigest)
		if err != nil || !reused || id2 != id {
			t.Fatalf("second: id=%s reused=%v err=%v", id2, reused, err)
		}
	})

	t.Run("existing_manifest_digest_mismatch_fails", func(t *testing.T) {
		st := newStore(t)
		src, m := srcTree(t)
		id, _, err := Write(ctx, st, src, m, format.Callgraph{}, emptySites, shaDigest)
		if err != nil {
			t.Fatal(err)
		}
		tamper(t, st, "snapshots/"+id+"/manifest.json", []byte(`{"files":[]}`))
		if _, _, err := Write(ctx, st, src, m, format.Callgraph{}, emptySites, shaDigest); err == nil || !strings.Contains(err.Error(), "digest") {
			t.Fatalf("want digest mismatch, got %v", err)
		}
	})

	t.Run("partial_object_with_same_bytes_is_completed", func(t *testing.T) {
		st := newStore(t)
		src, m := srcTree(t)
		b, _ := json.Marshal(m)
		id, _ := shaDigest(ctx, b)
		if err := st.CreateOnly(ctx, "snapshots/"+id+"/src/a.py", []byte("a")); err != nil {
			t.Fatal(err)
		}
		if _, reused, err := Write(ctx, st, src, m, format.Callgraph{}, emptySites, shaDigest); err != nil || reused {
			t.Fatalf("complete partial: reused=%v err=%v", reused, err)
		}
		if _, err := st.Get(ctx, "snapshots/"+id+"/manifest.json"); err != nil {
			t.Fatal("manifest not written")
		}
	})

	t.Run("partial_object_with_other_bytes_fails", func(t *testing.T) {
		st := newStore(t)
		src, m := srcTree(t)
		b, _ := json.Marshal(m)
		id, _ := shaDigest(ctx, b)
		if err := st.CreateOnly(ctx, "snapshots/"+id+"/src/a.py", []byte("other")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Write(ctx, st, src, m, format.Callgraph{}, emptySites, shaDigest); err == nil {
			t.Fatal("want error for a differing existing object")
		}
		if _, err := st.Get(ctx, "snapshots/"+id+"/manifest.json"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("manifest must not be written over a differing object")
		}
		if got, _ := st.Get(ctx, "snapshots/"+id+"/src/a.py"); string(got) != "other" {
			t.Fatal("existing object was overwritten")
		}
	})
}

func TestDirStoreWriteOnce(t *testing.T) {
	writeOnceCases(t,
		func(t *testing.T) Store { return DirStore{t.TempDir()} },
		func(t *testing.T, st Store, key string, data []byte) {
			if err := os.WriteFile(st.(DirStore).path(key), data, 0o644); err != nil {
				t.Fatal(err)
			}
		})
}

func TestOpenStoreRoots(t *testing.T) {
	st, closeFn, err := OpenStore(context.Background(), "/tmp/x")
	if err != nil || closeFn() != nil {
		t.Fatal(err)
	}
	if _, ok := st.(DirStore); !ok {
		t.Fatalf("local root: %T", st)
	}
	for _, bad := range []string{"gs://", "gs://bucket/path", "gs://UPPER"} {
		if _, _, err := OpenStore(context.Background(), bad); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
}

func TestCLIDigesterValidatesOutput(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte("#!/bin/sh\ncat >/dev/null\necho "+strings.Repeat("0f", 32)+"\n"), 0o755)
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("#!/bin/sh\necho NOTHEX\n"), 0o755)
	if d, err := CLIDigester(good)(context.Background(), []byte(`{}`)); err != nil || d != strings.Repeat("0f", 32) {
		t.Fatalf("good: %q %v", d, err)
	}
	if _, err := CLIDigester(bad)(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("bad output must fail")
	}
}
