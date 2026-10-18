package tailer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

func TestPinnedInventoryOrderAndPermissions(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "tetragon.log")
	oldest := filepath.Join(dir, "tetragon-2026-10-16T01-02-03.004.log")
	newest := filepath.Join(dir, "tetragon-2026-10-16T01-02-04.005.log")
	write(t, newest, "newer\n")
	write(t, oldest, "oldest\n")
	write(t, live, "live\n")
	write(t, filepath.Join(dir, "other.log"), "unrelated\n")
	line, err := NextFile(live, wal.Checkpoint{}, 100, 6)
	if err != nil || string(line.Bytes) != "oldest\n" {
		t.Fatalf("oldest: %q %v", line.Bytes, err)
	}
	line, err = NextFile(live, line.Checkpoint, 100, 6)
	if err != nil || string(line.Bytes) != "newer\n" {
		t.Fatalf("newer: %q %v", line.Bytes, err)
	}
	line, err = NextFile(live, line.Checkpoint, 100, 6)
	if err != nil || string(line.Bytes) != "live\n" {
		t.Fatalf("live: %q %v", line.Bytes, err)
	}
	if _, err := NextFile(live, wal.Checkpoint{}, 100, 2); !errors.Is(err, ErrInventoryLimit) {
		t.Fatalf("missing count bound: %v", err)
	}
	if err := os.Chmod(oldest, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NextFile(live, wal.Checkpoint{}, 100, 6); !errors.Is(err, ErrInventoryFormat) {
		t.Fatalf("accepted broad export permissions: %v", err)
	}
}

func TestRotationBetweenInventoryAndReadNeverSkipsOldLive(t *testing.T) {
	for _, rotateAfterRead := range []bool{false, true} {
		t.Run(fmt.Sprint(rotateAfterRead), func(t *testing.T) {
			dir := t.TempDir()
			live := filepath.Join(dir, "tetragon.log")
			write(t, live, "old\n")
			backup := filepath.Join(dir, "tetragon-2026-10-16T01-02-03.004.log")
			calls := 0
			rotate := func() {
				if err := os.Rename(live, backup); err != nil {
					t.Fatal(err)
				}
				write(t, live, "new\n")
			}
			line, err := nextFile(live, wal.Checkpoint{}, 100, 6, func(paths []string, cp wal.Checkpoint, max int) (Line, error) {
				calls++
				if calls == 1 && !rotateAfterRead {
					rotate()
				}
				line, err := Next(paths, cp, max)
				if calls == 1 && rotateAfterRead {
					rotate()
				}
				return line, err
			})
			if err != nil || calls != 2 || string(line.Bytes) != "old\n" {
				t.Fatalf("skipped rotated data: calls=%d line=%q err=%v", calls, line.Bytes, err)
			}
			line, err = NextFile(live, line.Checkpoint, 100, 6)
			if err != nil || string(line.Bytes) != "new\n" {
				t.Fatalf("new live: %q %v", line.Bytes, err)
			}
		})
	}
}

func TestUnstableInventoryIsBoundedAndLossNeverResets(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "tetragon.log")
	write(t, live, "original\n")
	first, err := NextFile(live, wal.Checkpoint{}, 100, 16)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err = nextFile(live, wal.Checkpoint{}, 100, 16, func(paths []string, cp wal.Checkpoint, max int) (Line, error) {
		calls++
		backup := filepath.Join(dir, fmt.Sprintf("tetragon-2026-10-16T01-02-%02d.000.log", calls))
		if err := os.Rename(live, backup); err != nil {
			t.Fatal(err)
		}
		write(t, live, "replacement\n")
		return Next(paths, cp, max)
	})
	if !errors.Is(err, ErrInventoryChanged) || calls != 3 {
		t.Fatalf("unbounded rotation: %d %v", calls, err)
	}
	if err := os.Remove(filepath.Join(dir, "tetragon-2026-10-16T01-02-01.000.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := NextFile(live, first.Checkpoint, 100, 16); !errors.Is(err, ErrRotationLoss) {
		t.Fatalf("reset a lost checkpoint: %v", err)
	}
}

func TestInventoryRejectsUnsupportedFiles(t *testing.T) {
	for _, mode := range []string{"compressed", "symlink", "hardlink", "timestamp", "fifo"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			live := filepath.Join(dir, "tetragon.log")
			write(t, live, "live\n")
			backup := filepath.Join(dir, "tetragon-2026-10-16T01-02-03.004.log")
			switch mode {
			case "compressed":
				write(t, backup+".gz", "compressed")
			case "symlink":
				if err := os.Symlink(live, backup); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(live, backup); err != nil {
					t.Fatal(err)
				}
			case "timestamp":
				write(t, filepath.Join(dir, "tetragon-invalid.log"), "unknown\n")
			case "fifo":
				if err := syscall.Mkfifo(backup, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NextFile(live, wal.Checkpoint{}, 100, 6); !errors.Is(err, ErrInventoryFormat) {
				t.Fatalf("accepted %s: %v", mode, err)
			}
		})
	}
}

func TestNextDoesNotFollowSymlinkOrBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "actual")
	write(t, real, "not an export\n")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Next([]string{link}, wal.Checkpoint{}, 100); err == nil {
		t.Fatal("followed symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Next([]string{fifo}, wal.Checkpoint{}, 100); err == nil {
		t.Fatal("read a FIFO")
	}
}

func TestMissingDirectoryIsNotAnIdleRotation(t *testing.T) {
	if _, err := NextFile(filepath.Join(t.TempDir(), "missing", "tetragon.log"), wal.Checkpoint{}, 100, 6); !errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrInventoryChanged) {
		t.Fatalf("missing mount treated as rotation: %v", err)
	}
}
