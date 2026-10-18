// Package snapshot writes the immutable snapshot layout described in
// internal/format and computes snapshot_id through the canonical-digest CLI.
package snapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/format"
)

// Digester returns the canonical digest of a JSON document.
type Digester func(ctx context.Context, doc []byte) (string, error)

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CLIDigester runs packages/canonical/cmd/canonical-digest.
//
// SPEC-QUESTION: the CLI interface is not fixed in COMMON or TASK-02. This
// assumes JSON on stdin and the lowercase hex digest on stdout.
func CLIDigester(bin string) Digester {
	return func(ctx context.Context, doc []byte) (string, error) {
		cmd := exec.CommandContext(ctx, bin)
		cmd.Stdin = bytes.NewReader(doc)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("canonical-digest: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		d := strings.TrimSpace(string(out))
		if !hexRe.MatchString(d) {
			return "", fmt.Errorf("canonical-digest returned %q", d)
		}
		return d, nil
	}
}

// BuildManifest lists every regular file under root (except .git) with its
// SHA-256, sorted by path bytes.
func BuildManifest(root string) (format.Manifest, error) {
	var files []format.ManifestEntry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files = append(files, format.ManifestEntry{Path: filepath.ToSlash(rel), SHA256: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return format.Manifest{}, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if files == nil {
		files = []format.ManifestEntry{}
	}
	return format.Manifest{Files: files}, nil
}

// Write stores the snapshot under snapshots/<snapshot_id>/ in st and returns
// the snapshot_id and whether an existing snapshot was reused (TASK-02 3.4).
//
// Every object is created once (ifGenerationMatch=0 on Cloud Storage) and
// manifest.json is written last, so it marks a complete snapshot. If
// manifest.json already exists, its digest must equal snapshot_id and the
// snapshot is reused without writing anything; a different digest fails. An
// object left by an interrupted earlier run is accepted only if its bytes
// equal the new ones (the layout is content-addressed); otherwise Write fails
// instead of overwriting it.
func Write(ctx context.Context, st Store, srcRoot string, m format.Manifest, cg format.Callgraph, cs format.CallSites, digest Digester) (string, bool, error) {
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		return "", false, err
	}
	id, err := digest(ctx, manifestBytes)
	if err != nil {
		return "", false, err
	}
	prefix := "snapshots/" + id + "/"
	manifestKey := prefix + format.ManifestFile
	reuse := func(existing []byte) (string, bool, error) {
		d, err := digest(ctx, existing)
		if err != nil {
			return "", false, err
		}
		if d != id {
			return "", false, fmt.Errorf("existing %s has digest %s, want %s", manifestKey, d, id)
		}
		return id, true, nil
	}
	if existing, err := st.Get(ctx, manifestKey); err == nil {
		return reuse(existing)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", false, err
	}
	putOnce := func(key string, data []byte) error {
		err := st.CreateOnly(ctx, key, data)
		if !errors.Is(err, ErrExists) {
			return err
		}
		prev, gerr := st.Get(ctx, key)
		if gerr != nil {
			return gerr
		}
		if !bytes.Equal(prev, data) {
			return fmt.Errorf("%s already exists with different content", key)
		}
		return nil
	}
	for _, f := range m.Files {
		data, err := os.ReadFile(filepath.Join(srcRoot, filepath.FromSlash(f.Path)))
		if err != nil {
			return "", false, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return "", false, fmt.Errorf("file changed after manifest: %s", f.Path)
		}
		if err := putOnce(prefix+format.SourceDir+"/"+f.Path, data); err != nil {
			return "", false, err
		}
	}
	cgBytes, err := json.Marshal(cg)
	if err != nil {
		return "", false, err
	}
	csBytes, err := json.Marshal(cs)
	if err != nil {
		return "", false, err
	}
	if err := putOnce(prefix+format.CallgraphFile, cgBytes); err != nil {
		return "", false, err
	}
	if err := putOnce(prefix+format.CallSitesFile, csBytes); err != nil {
		return "", false, err
	}
	if err := st.CreateOnly(ctx, manifestKey, manifestBytes); err != nil {
		if !errors.Is(err, ErrExists) {
			return "", false, err
		}
		// Another run completed the same snapshot first.
		existing, gerr := st.Get(ctx, manifestKey)
		if gerr != nil {
			return "", false, gerr
		}
		return reuse(existing)
	}
	return id, false, nil
}
