package bundles

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// fileDigest is one entry of the candidate_digest input.
// SPEC-QUESTION: COMMON only says "canonical digest of the file list and each
// file's SHA-256". This package fixes the form as a JSON array of
// {path, sha256} sorted by path, with the path exactly as stored in the
// tarball ("/data.json", "/.manifest", "/policies/x.rego") and sha256 as
// lower-case hex of the file bytes.
type fileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// maxBundleBytes bounds what CandidateDigest and Verify read from a tarball.
const maxBundleBytes = 64 << 20

// CandidateDigest returns candidate_digest for a bundle tarball, signed or
// not: the canonical digest of every regular file except .signatures.json.
func CandidateDigest(tarball []byte) (string, error) {
	files, err := tarFiles(tarball)
	if err != nil {
		return "", err
	}
	return digestFiles(files)
}

// SignedCandidateDigest returns candidate_digest of a signed tarball, for
// example one read back from the bundle bucket. It is CandidateDigest plus
// one rule: the tarball must hold /.signatures.json. ECDSA signatures are
// randomized, so artifact_digest differs between signings of the same
// bundle; candidate_digest does not, so a publisher uses it to recognize a
// bundle it has already signed.
//
// It does not check the signature. Call it only on a tarball that Verify
// has accepted.
func SignedCandidateDigest(tarball []byte) (string, error) {
	files, err := tarFiles(tarball)
	if err != nil {
		return "", err
	}
	if _, ok := files["/"+SignaturesFile]; !ok {
		return "", fmt.Errorf("bundles: no %s", SignaturesFile)
	}
	return digestFiles(files)
}

// digestFiles is the candidate_digest of files without /.signatures.json.
// tarFiles allows a .signatures.json only at the root.
func digestFiles(files map[string][]byte) (string, error) {
	list := make([]fileDigest, 0, len(files))
	for p, body := range files {
		if p == "/"+SignaturesFile {
			continue
		}
		sum := sha256.Sum256(body)
		list = append(list, fileDigest{Path: p, SHA256: hex.EncodeToString(sum[:])})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	return canonical.CanonicalDigest(list)
}

// ArtifactDigest returns artifact_digest: SHA-256 of the tarball bytes.
func ArtifactDigest(tarball []byte) string {
	return canonical.SHA256Hex(tarball)
}

// tarFiles reads a gzip tarball into path → bytes. It rejects anything that is
// not a regular file, duplicate paths, paths that are not clean absolute
// slash paths ("/data.json", "/agentarium/x.rego"), a .signatures.json
// anywhere but the root, and more than maxBundleBytes compressed or not.
func tarFiles(tarball []byte) (map[string][]byte, error) {
	if len(tarball) > maxBundleBytes {
		return nil, errors.New("bundles: tarball too large")
	}
	zr, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("bundles: gzip: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(io.LimitReader(zr, maxBundleBytes+1))
	files := map[string][]byte{}
	total := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundles: tar: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("bundles: tar entry %q is not a regular file", h.Name)
		}
		if err := checkTarPath(h.Name); err != nil {
			return nil, err
		}
		if _, dup := files[h.Name]; dup {
			return nil, fmt.Errorf("bundles: duplicate tar entry %q", h.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("bundles: tar: %w", err)
		}
		if total += len(body); total > maxBundleBytes {
			return nil, errors.New("bundles: tarball too large")
		}
		files[h.Name] = body
	}
	if len(files) == 0 {
		return nil, errors.New("bundles: empty tarball")
	}
	return files, nil
}

// checkTarPath accepts the paths OPA's bundle writer produces.
func checkTarPath(name string) error {
	if !strings.HasPrefix(name, "/") || name == "/" || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00") {
		return fmt.Errorf("bundles: bad tar path %q", name)
	}
	if path.Base(name) == SignaturesFile && name != "/"+SignaturesFile {
		return fmt.Errorf("bundles: %s outside the bundle root: %q", SignaturesFile, name)
	}
	return nil
}
