package netpolcollector

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/tailer"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

var ErrSourceLoss = errors.New("policy-action source checkpoint was lost or truncated")
var ErrInventory = errors.New("invalid policy-action file inventory")
var ErrInventoryChanged = errors.New("policy-action file inventory changed during rotation")

// Inventory supplies a verified oldest-backup-to-live ordering. Anetd rotation
// naming/compression is still a Q0 gap; this code never infers order from mtime,
// inode numbers, or Tetragon's different writer convention.
type Inventory func() ([]string, error)
type fileIdentity struct {
	Path          string
	Device, Inode uint64
}

func snapshot(paths []string, maxFiles int) ([]fileIdentity, error) {
	if len(paths) == 0 || len(paths) > maxFiles {
		return nil, ErrInventory
	}
	files := make([]fileIdentity, 0, len(paths))
	seen := map[[2]uint64]bool{}
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, ErrInventory
		}
		info, e := os.Lstat(p)
		if e != nil {
			return nil, e
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() {
			return nil, ErrInventory
		}
		key := [2]uint64{uint64(stat.Dev), uint64(stat.Ino)}
		if seen[key] {
			return nil, ErrInventory
		}
		seen[key] = true
		files = append(files, fileIdentity{p, key[0], key[1]})
	}
	return files, nil
}

type Reader struct {
	Inventory              Inventory
	MaxFiles, MaxLineBytes int
}

// Next reads at most one complete bounded line. The caller durably commits its
// checkpoint with the WAL payload. A rotation race never commits that candidate.
func (r Reader) Next(cp wal.Checkpoint) (tailer.Line, error) {
	if r.Inventory == nil || r.MaxFiles < 1 || r.MaxFiles > 64 || r.MaxLineBytes < 1 || r.MaxLineBytes > wal.MaxRecordBytes {
		return tailer.Line{}, ErrInventory
	}
	for attempt := 0; attempt < 3; attempt++ {
		paths, e := r.Inventory()
		if e != nil {
			return tailer.Line{}, e
		}
		paths = append([]string(nil), paths...)
		before, e := snapshot(paths, r.MaxFiles)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return tailer.Line{}, e
		}
		line, readErr := tailer.Next(paths, cp, r.MaxLineBytes)
		afterPaths, e := r.Inventory()
		if e != nil {
			return tailer.Line{}, e
		}
		after, e := snapshot(afterPaths, r.MaxFiles)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return tailer.Line{}, e
		}
		if !reflect.DeepEqual(before, after) || os.IsNotExist(readErr) {
			continue
		}
		if errors.Is(readErr, tailer.ErrRotationLoss) || errors.Is(readErr, tailer.ErrTruncated) || errors.Is(readErr, tailer.ErrIncompleteRotatedRecord) {
			return tailer.Line{}, ErrSourceLoss
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return tailer.Line{}, readErr
		}
		return line, readErr
	}
	return tailer.Line{}, ErrInventoryChanged
}
