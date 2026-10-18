// Command discovery-snapshot is the discovery snapshot Job (TASK-02 3.4).
//
// It reads the operator-staged source archive
// gs://<discovery-bucket>/sources/<source_digest>.<ext>, checks source_digest,
// scans it (Go: VTA call graph, Python: ast call sites), and writes the
// snapshot under <out-root>/snapshots/<snapshot_id>/. In GKE out-root is the
// same bucket, read and written through the Cloud Storage API with the
// `discovery-snapshot` KSA (TASK-02 3.4, PR #8); there is no https or VCS
// fetch. The result JSON goes to stdout and to the Kubernetes termination
// message so services/discovery can read snapshot_id.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/format"
	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/goscan"
	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/pyscan"
	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/snapshot"
	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/source"
)

//go:embed pyscan/scan.py
var pyScript []byte

type config struct {
	Language       string
	SourceURI      string
	SourceDigest   string
	OutRoot        string
	WorkDir        string
	DigestBin      string
	Python         string
	TerminationLog string
}

func main() {
	var c config
	var library, version string
	flag.StringVar(&library, "library", "", "library name (logged only)")
	flag.StringVar(&version, "library-version", "", "library version (logged only)")
	flag.StringVar(&c.Language, "language", "", "go | python")
	flag.StringVar(&c.SourceURI, "source-uri", "", "gs://<out-root bucket>/sources/<source_digest>.<ext> (file:// for local runs)")
	flag.StringVar(&c.SourceDigest, "source-digest", "", "SHA-256 of the fetched source bytes")
	flag.StringVar(&c.OutRoot, "out-root", "", "gs://<bucket> (Cloud Storage API) or a local directory")
	flag.StringVar(&c.WorkDir, "work-dir", "", "scratch directory (default: temp)")
	flag.StringVar(&c.DigestBin, "canonical-digest-bin", "canonical-digest", "path to packages/canonical/cmd/canonical-digest")
	flag.StringVar(&c.Python, "python", "python3", "python interpreter for the ast scanner")
	flag.StringVar(&c.TerminationLog, "termination-log", "/dev/termination-log", "file for the result JSON; empty to skip")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "discovery-snapshot: library=%q version=%q language=%s\n", library, version, c.Language)
	st, closeStore, err := snapshot.OpenStore(ctx, c.OutRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "discovery-snapshot:", err)
		writeTermination(c.TerminationLog, map[string]string{"error": err.Error()})
		os.Exit(1)
	}
	res, err := run(ctx, c, st, snapshot.CLIDigester(c.DigestBin))
	if cerr := closeStore(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "discovery-snapshot:", err)
		writeTermination(c.TerminationLog, failure(err))
		os.Exit(1)
	}
	b, _ := json.Marshal(res)
	fmt.Println(string(b))
	writeTermination(c.TerminationLog, res)
}

func run(ctx context.Context, c config, st snapshot.Store, digest snapshot.Digester) (format.Result, error) {
	if c.Language != format.LanguageGo && c.Language != format.LanguagePython {
		return format.Result{}, fmt.Errorf("language must be go or python")
	}
	if c.SourceURI == "" || c.OutRoot == "" {
		return format.Result{}, fmt.Errorf("source-uri and out-root are required")
	}
	work := c.WorkDir
	if work == "" {
		d, err := os.MkdirTemp("", "discovery-snapshot-")
		if err != nil {
			return format.Result{}, err
		}
		defer os.RemoveAll(d)
		work = d
	}
	// A gs:// source is read only from the out-root bucket (TASK-02 3.4).
	objs, _ := st.(source.Objects)
	root, err := source.Fetch(ctx, c.SourceURI, c.SourceDigest, work, objs)
	if err != nil {
		return format.Result{}, err
	}
	// The manifest is taken before scanning so build artefacts never enter it.
	m, err := snapshot.BuildManifest(root)
	if err != nil {
		return format.Result{}, err
	}
	m.Language, m.ScannerVersion, m.SourceDigest = c.Language, format.ScannerVersion, c.SourceDigest
	// The extracted tree is scanned in place; no second copy (it would not fit
	// the emptyDir budget, TASK-02 3.4). Nothing a scanner writes can reach the
	// snapshot: snapshot.Write uploads only manifest files and re-hashes each
	// against the manifest. Neither scanner writes into the tree: the Python
	// scanner only parses with `ast`, and `go list` runs with the default
	// -mod=readonly (or -mod=vendor) and keeps its caches under the work dir
	// (goEnv), so the Go scan does not need a writable module directory.
	scanRoot := root
	var cg format.Callgraph
	var cs format.CallSites
	switch c.Language {
	case format.LanguageGo:
		var env []string
		if env, err = goEnv(work); err != nil {
			return format.Result{}, err
		}
		cg, cs, err = goscan.Scan(scanRoot, env)
	case format.LanguagePython:
		cg, cs, err = pyscan.Scan(ctx, c.Python, pyScript, scanRoot)
	}
	if err != nil {
		return format.Result{}, err
	}
	id, reused, err := snapshot.Write(ctx, st, root, m, cg, cs, digest)
	if err != nil {
		return format.Result{}, err
	}
	return format.Result{SnapshotID: id, Reused: reused, FileCount: len(m.Files), CallSiteCount: len(cs.CallSites)}, nil
}

// goEnv is the complete environment of the `go list` run behind
// packages.Load. The scanned module is untrusted input (TASK-02 5): nothing it
// declares may download, switch toolchains or hand its sources to a C
// toolchain, and nothing from the Job environment (GOFLAGS, GOPROXY,
// GOINSECURE, CC, ...) changes that.
//
// SPEC-QUESTION: TASK-02 3.4 does not say where the Job gets a Go library's
// dependencies. With GOPROXY=off they resolve only from vendor/ or a module
// cache pre-populated in the image (GOMODCACHE/GOPATH); otherwise the scan
// fails closed.
func goEnv(work string) ([]string, error) {
	home := filepath.Join(work, "home")
	cache := filepath.Join(work, "gocache")
	for _, d := range []string{home, cache} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	env := []string{
		"HOME=" + home,
		"GOCACHE=" + cache,
		"GOENV=off",         // no user go.env file
		"GOWORK=off",        // no go.work
		"GOTOOLCHAIN=local", // a go/toolchain line never downloads or runs another toolchain
		"GOPROXY=off",       // no module downloads, neither proxy nor direct VCS
		"CGO_ENABLED=0",     // cgo files are excluded; no CC, pkg-config or swig
	}
	for _, k := range []string{"PATH", "GOROOT", "GOPATH", "GOMODCACHE", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env, nil
}

// failure is the termination-message JSON of a failed run. An archive limit
// adds the limit name (TASK-02 3.4) so the service can record which limit was
// exceeded.
func failure(err error) map[string]string {
	out := map[string]string{"error": err.Error()}
	var le *source.LimitError
	if errors.As(err, &le) {
		out["limit"] = le.Limit
	}
	return out
}

func writeTermination(path string, v any) {
	if path == "" {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	// Kubernetes keeps at most 4096 bytes of the termination message.
	if len(b) > 4096 {
		b = b[:4096]
	}
	_ = os.WriteFile(path, b, 0o644)
}
