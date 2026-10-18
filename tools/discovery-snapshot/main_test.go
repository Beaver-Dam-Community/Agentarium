package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/format"
	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/snapshot"
)

func archiveDir(t *testing.T, dir, prefix string) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, _ := os.ReadFile(p)
		tw.WriteHeader(&tar.Header{Name: prefix + filepath.ToSlash(rel), Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		tw.Write(b)
		return nil
	})
	tw.Close()
	gz.Close()
	p := filepath.Join(t.TempDir(), "src.tar.gz")
	os.WriteFile(p, buf.Bytes(), 0o644)
	sum := sha256.Sum256(buf.Bytes())
	return "file://" + p, hex.EncodeToString(sum[:])
}

func fixedDigest(_ context.Context, doc []byte) (string, error) {
	return strings.Repeat("cd", 32), nil
}

func readSites(t *testing.T, out, id string) format.CallSites {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(out, "snapshots", id, format.CallSitesFile))
	if err != nil {
		t.Fatal(err)
	}
	var cs format.CallSites
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestRunPythonSnapshot(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	uri, digest := archiveDir(t, "testdata/pylib", "mylib-1.0/")
	out := t.TempDir()
	res, err := run(context.Background(), config{Language: "python", SourceURI: uri, SourceDigest: digest, OutRoot: out, Python: py}, snapshot.DirStore{Root: out}, fixedDigest)
	if err != nil {
		t.Fatal(err)
	}
	if res.SnapshotID != strings.Repeat("cd", 32) || res.FileCount != 3 || res.CallSiteCount == 0 {
		t.Fatalf("result: %+v", res)
	}
	cs := readSites(t, out, res.SnapshotID)
	if cs.Tool != "python-ast" || cs.CallSites[0].Path == "" {
		t.Fatalf("call sites: %+v", cs)
	}
}

func TestRunGoSnapshot(t *testing.T) {
	uri, digest := archiveDir(t, "internal/goscan/testdata/mod", "example.com/scanfixture@v1.0.0/")
	out := t.TempDir()
	res, err := run(context.Background(), config{Language: "go", SourceURI: uri, SourceDigest: digest, OutRoot: out}, snapshot.DirStore{Root: out}, fixedDigest)
	if err != nil {
		t.Fatal(err)
	}
	cs := readSites(t, out, res.SnapshotID)
	found := false
	for _, s := range cs.CallSites {
		if s.Callee == "(*net/http.Client).Do" && s.Path == "client/client.go" {
			found = true
		}
	}
	if !found {
		t.Fatalf("VTA call site missing: %+v", cs.CallSites)
	}
}

func TestRunRejectsUnknownLanguage(t *testing.T) {
	if _, err := run(context.Background(), config{Language: "rust", SourceURI: "file:///x.tar.gz", OutRoot: "/tmp"}, snapshot.DirStore{Root: "/tmp"}, fixedDigest); err == nil {
		t.Fatal("want error")
	}
}

// writeModule writes files into a fresh directory and archives it as a Go
// module zip-like tree ("<module>@<version>/...").
func writeModule(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return archiveDir(t, dir, "example.com/untrusted@v1.0.0/")
}

const fetchGo = "package lib\n\nimport \"net/http\"\n\nfunc Fetch() { http.Get(\"https://x.example/\") }\n"

func runGo(t *testing.T, uri, digest string) (format.Result, error) {
	t.Helper()
	out := t.TempDir()
	return run(context.Background(), config{Language: "go", SourceURI: uri, SourceDigest: digest, OutRoot: out}, snapshot.DirStore{Root: out}, fixedDigest)
}

// The scanned module must never reach a C toolchain: `go list -compiled` runs
// cgo, and cgo runs $CC on the module's sources.
func TestRunGoSnapshotNeverRunsCgo(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "cc-ran")
	cc := filepath.Join(t.TempDir(), "cc.sh")
	if err := os.WriteFile(cc, []byte("#!/bin/sh\ntouch "+marker+"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CGO_ENABLED", "1")
	t.Setenv("CC", cc)
	uri, digest := writeModule(t, map[string]string{
		"go.mod":   "module example.com/untrusted\n\ngo 1.22\n",
		"fetch.go": fetchGo,
		"c.go":     "package lib\n\n/*\nint x(void) { return 1; }\n*/\nimport \"C\"\n\nfunc X() int { return int(C.x()) }\n",
	})
	res, err := runGo(t, uri, digest)
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("scanner invoked the C compiler on the scanned module")
	}
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.CallSiteCount == 0 {
		t.Fatalf("pure-Go call site missing: %+v", res)
	}
}

// A go/toolchain line must not switch to (or download) another toolchain.
func TestRunGoSnapshotKeepsLocalToolchain(t *testing.T) {
	t.Setenv("GOTOOLCHAIN", "auto")
	t.Setenv("GOPROXY", "off") // keeps the run offline even without the fix
	uri, digest := writeModule(t, map[string]string{
		"go.mod":   "module example.com/untrusted\n\ngo 1.99.0\n\ntoolchain go1.99.0\n",
		"fetch.go": fetchGo,
	})
	_, err := runGo(t, uri, digest)
	if err == nil || !strings.Contains(err.Error(), "GOTOOLCHAIN=local") {
		t.Fatalf("want a GOTOOLCHAIN=local refusal, got %v", err)
	}
}

// Requirements named by the scanned go.mod are never fetched, whatever
// GOPROXY/GOFLAGS the Job environment carries.
func TestRunGoSnapshotDownloadsNothing(t *testing.T) {
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer proxy.Close()
	t.Setenv("GOPROXY", proxy.URL)
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOSUMDB", "off")
	uri, digest := writeModule(t, map[string]string{
		"go.mod":   "module example.com/untrusted\n\ngo 1.22\n\nrequire evil.example/dep v1.0.0\n",
		"fetch.go": fetchGo,
		"dep.go":   "package lib\n\nimport _ \"evil.example/dep\"\n",
	})
	if _, err := runGo(t, uri, digest); err == nil {
		t.Fatal("want an error for an unavailable requirement")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("scanner fetched %d module URLs for the scanned go.mod", n)
	}
}

// A directory replace in the scanned go.mod must not pull Go code from outside
// the fetched source into the snapshot.
func TestRunGoSnapshotRejectsReplaceOutsideSource(t *testing.T) {
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "go.mod"), []byte("module example.com/dep\n\ngo 1.22\n"), 0o644)
	os.WriteFile(filepath.Join(outside, "dep.go"), []byte("package dep\n\nfunc D() {}\n"), 0o644)
	uri, digest := writeModule(t, map[string]string{
		"go.mod": "module example.com/untrusted\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => " +
			filepath.ToSlash(outside) + "\n",
		"fetch.go": fetchGo,
		"dep.go":   "package lib\n\nimport \"example.com/dep\"\n\nfunc UseDep() { dep.D() }\n",
	})
	_, err := runGo(t, uri, digest)
	if err == nil || !strings.Contains(err.Error(), "outside the source root") {
		t.Fatalf("want replace-outside-root refusal, got %v", err)
	}
}

// A vendored copy of a directory replacement loads from inside the source and
// stays accepted, even though go.mod still names the outside directory.
func TestRunGoSnapshotAcceptsVendoredReplace(t *testing.T) {
	gone := filepath.ToSlash(filepath.Join(t.TempDir(), "outside"))
	uri, digest := writeModule(t, map[string]string{
		"go.mod":                        "module example.com/untrusted\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => " + gone + "\n",
		"fetch.go":                      fetchGo,
		"dep.go":                        "package lib\n\nimport \"example.com/dep\"\n\nfunc UseDep() { dep.D() }\n",
		"vendor/modules.txt":            "# example.com/dep v1.0.0 => " + gone + "\n## explicit; go 1.22\nexample.com/dep\n# example.com/dep => " + gone + "\n",
		"vendor/example.com/dep/dep.go": "package dep\n\nfunc D() {}\n",
	})
	if _, err := runGo(t, uri, digest); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func shaDocDigest(_ context.Context, doc []byte) (string, error) {
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:]), nil
}

// The same archive scanned as go and as python must give two snapshots; the
// python request must never reuse the go snapshot (PR #12 review).
func TestSnapshotIDDependsOnLanguage(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	uri, digest := archiveDir(t, "internal/goscan/testdata/mod", "example.com/scanfixture@v1.0.0/")
	out := t.TempDir()
	st := snapshot.DirStore{Root: out}
	goRes, err := run(context.Background(), config{Language: "go", SourceURI: uri, SourceDigest: digest, OutRoot: out}, st, shaDocDigest)
	if err != nil {
		t.Fatal(err)
	}
	pyRes, err := run(context.Background(), config{Language: "python", SourceURI: uri, SourceDigest: digest, OutRoot: out, Python: py}, st, shaDocDigest)
	if err != nil {
		t.Fatal(err)
	}
	if goRes.SnapshotID == pyRes.SnapshotID || pyRes.Reused {
		t.Fatalf("python reused the go snapshot: go=%+v python=%+v", goRes, pyRes)
	}
	for id, lang := range map[string]string{goRes.SnapshotID: "go", pyRes.SnapshotID: "python"} {
		b, err := os.ReadFile(filepath.Join(out, "snapshots", id, format.ManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		var m format.Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m.Language != lang || m.ScannerVersion != format.ScannerVersion || m.SourceDigest != digest {
			t.Fatalf("%s manifest: %+v", lang, m)
		}
	}
	// Rerunning the same language reuses its own snapshot.
	again, err := run(context.Background(), config{Language: "python", SourceURI: uri, SourceDigest: digest, OutRoot: out, Python: py}, st, shaDocDigest)
	if err != nil || !again.Reused || again.SnapshotID != pyRes.SnapshotID {
		t.Fatalf("rerun: %+v %v", again, err)
	}
}

// An archive that breaks a limit fails the run, writes no snapshot object,
// and the termination message names the limit (TASK-02 3.4).
func TestLimitFailureWritesNothingAndNamesTheLimit(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "lib-1.0/a.py", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	tw.Write([]byte("x"))
	tw.WriteHeader(&tar.Header{Name: "lib-1.0/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	tw.Close()
	gz.Close()
	p := filepath.Join(t.TempDir(), "src.tar.gz")
	os.WriteFile(p, buf.Bytes(), 0o644)
	sum := sha256.Sum256(buf.Bytes())
	out := t.TempDir()
	_, err := run(context.Background(), config{Language: "python", SourceURI: "file://" + p, SourceDigest: hex.EncodeToString(sum[:]),
		OutRoot: out, Python: "python3"}, snapshot.DirStore{Root: out}, fixedDigest)
	if err == nil {
		t.Fatal("want failure")
	}
	if ents, _ := os.ReadDir(out); len(ents) != 0 {
		t.Fatalf("snapshot objects written on failure: %v", ents)
	}
	msg := failure(err)
	if msg["limit"] != "entry_type" || !strings.Contains(msg["error"], "entry_type") {
		t.Fatalf("termination message: %v", msg)
	}
	if got := failure(errors.New("other")); got["limit"] != "" || got["error"] != "other" {
		t.Fatalf("non-limit failure: %v", got)
	}
}

// The extracted tree is scanned in place: no second copy under the work dir.
func TestScanRunsOnTheExtractedTreeWithoutACopy(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	uri, digest := archiveDir(t, "testdata/pylib", "mylib-1.0/")
	out, work := t.TempDir(), t.TempDir()
	if _, err := run(context.Background(), config{Language: "python", SourceURI: uri, SourceDigest: digest, OutRoot: out,
		WorkDir: work, Python: py}, snapshot.DirStore{Root: out}, fixedDigest); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(work)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "tree" {
		t.Fatalf("work dir holds %v; want only the extracted tree", names)
	}
}
