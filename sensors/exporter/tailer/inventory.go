package tailer

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

var ErrInventoryChanged = errors.New("export rotation inventory changed or live file is not yet present")
var ErrInventoryLimit = errors.New("export rotation inventory exceeds configured bound")
var ErrInventoryFormat = errors.New("unsupported export rotation file or permissions")

const backupTimeFormat = "2006-01-02T15-04-05.000"

type inventoryFile struct {
	Path          string
	Device, Inode uint64
}

// inventory follows cilium/lumberjack v2.4.2's UTC timestamp backup names, as
// used by Tetragon v1.7.1 with compression disabled. It never guesses order from
// mtime or an inode number, and never reads unrelated files or symbolic links.
func inventory(live string, maxFiles int) ([]inventoryFile, error) {
	if !filepath.IsAbs(live) || filepath.Clean(live) != live || filepath.Base(live) == "." || maxFiles < 1 || maxFiles > 1024 {
		return nil, errors.New("invalid export inventory configuration")
	}
	dir, err := os.Open(filepath.Dir(live))
	if err != nil {
		return nil, err
	}
	entries, err := dir.ReadDir(4097)
	closeErr := dir.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > 4096 {
		return nil, ErrInventoryLimit
	}
	base := filepath.Base(live)
	ext := filepath.Ext(base)
	prefix := strings.TrimSuffix(base, ext) + "-"
	backups := []inventoryFile{}
	var current *inventoryFile
	seen := map[[2]uint64]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if name != base {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			uncompressed := strings.TrimSuffix(strings.TrimSuffix(name, ".tmp"), ".gz")
			if !strings.HasSuffix(uncompressed, ext) {
				continue
			}
			stamp := strings.TrimSuffix(strings.TrimPrefix(uncompressed, prefix), ext)
			timestamp, err := time.Parse(backupTimeFormat, stamp)
			if err != nil || timestamp.Format(backupTimeFormat) != stamp || name != uncompressed {
				return nil, ErrInventoryFormat
			}
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, ErrInventoryFormat
		}
		key := [2]uint64{uint64(stat.Dev), uint64(stat.Ino)}
		if seen[key] {
			return nil, ErrInventoryFormat
		}
		seen[key] = true
		file := inventoryFile{filepath.Join(filepath.Dir(live), name), key[0], key[1]}
		if name == base {
			current = &file
		} else {
			backups = append(backups, file)
		}
		if len(seen) > maxFiles {
			return nil, ErrInventoryLimit
		}
	}
	if current == nil {
		return nil, ErrInventoryChanged
	}
	sort.Slice(backups, func(a, b int) bool { return backups[a].Path < backups[b].Path })
	return append(backups, *current), nil
}

// NextFile checks the inventory before and after reading. If rotation changed a
// path's inode or added/removed a backup, discard the candidate and resume from
// the same durable checkpoint with a fresh inventory. This prevents silently
// jumping over a file rotated between listing and opening the live path.
// Frequent rotation is bounded to three attempts per call, then reported to the
// cancellable acquisition loop as ErrInventoryChanged. Loss is never reset.
func NextFile(live string, checkpoint wal.Checkpoint, maxBytes, maxFiles int) (Line, error) {
	return nextFile(live, checkpoint, maxBytes, maxFiles, Next)
}
func nextFile(live string, checkpoint wal.Checkpoint, maxBytes, maxFiles int, read func([]string, wal.Checkpoint, int) (Line, error)) (Line, error) {
	for attempt := 0; attempt < 3; attempt++ {
		before, err := inventory(live, maxFiles)
		if err != nil {
			var pathErr *os.PathError
			if errors.Is(err, os.ErrNotExist) && errors.As(err, &pathErr) && pathErr.Path != filepath.Dir(live) {
				continue
			}
			return Line{}, err
		}
		paths := make([]string, len(before))
		for n, f := range before {
			paths[n] = f.Path
		}
		line, readErr := read(paths, checkpoint, maxBytes)
		after, err := inventory(live, maxFiles)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrInventoryChanged) {
				continue
			}
			return Line{}, err
		}
		if !reflect.DeepEqual(before, after) {
			continue
		}
		if readErr != nil {
			return Line{}, readErr
		}
		return line, nil
	}
	return Line{}, ErrInventoryChanged
}
