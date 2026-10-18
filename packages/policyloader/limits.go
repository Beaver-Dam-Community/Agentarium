package policyloader

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

// Limits on a bundle before OPA reads it into memory. MaxObjectBytes bounds
// the compressed object; the rest bound what it expands to.
// SPEC-QUESTION: the specs give no bundle size limits; these are this
// package's values.
const (
	MaxObjectBytes       = 64 << 20
	MaxUncompressedBytes = 256 << 20
	MaxEntryBytes        = 64 << 20
	MaxEntries           = 10000
)

// checkArchive walks the tar.gz once within the limits, so OPA's reader is
// only given archives whose expansion is bounded.
func checkArchive(obj []byte) error {
	zr, err := gzip.NewReader(bytes.NewReader(obj))
	if err != nil {
		return fmt.Errorf("policyloader: gzip: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(io.LimitReader(zr, MaxUncompressedBytes+1))
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("policyloader: tar: %w", err)
		}
		if n >= MaxEntries {
			return fmt.Errorf("policyloader: more than %d entries", MaxEntries)
		}
		if h.Size > MaxEntryBytes {
			return fmt.Errorf("policyloader: entry %q larger than %d bytes", h.Name, MaxEntryBytes)
		}
		w, err := io.Copy(io.Discard, io.LimitReader(tr, MaxEntryBytes+1))
		if err != nil {
			return fmt.Errorf("policyloader: tar: %w", err)
		}
		if w > MaxEntryBytes {
			return fmt.Errorf("policyloader: entry %q larger than %d bytes", h.Name, MaxEntryBytes)
		}
		if total += w; total > MaxUncompressedBytes {
			return fmt.Errorf("policyloader: archive expands past %d bytes", MaxUncompressedBytes)
		}
	}
}
