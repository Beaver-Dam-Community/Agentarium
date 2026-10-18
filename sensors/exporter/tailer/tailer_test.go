package tailer

import (
	"errors"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if e := os.WriteFile(p, []byte(s), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestRotationResumeAndIncompleteLiveLine(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "export.json")
	backup := filepath.Join(dir, "backup.json")
	write(t, live, "{\"a\":1}\n{\"b\"")
	first, e := Next([]string{live}, wal.Checkpoint{}, 100)
	if e != nil || string(first.Bytes) != "{\"a\":1}\n" {
		t.Fatalf("%v %v", first, e)
	}
	if _, e = Next([]string{live}, first.Checkpoint, 100); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	f, e := os.OpenFile(live, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteString(":2}\n")
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(live, backup); e != nil {
		t.Fatal(e)
	}
	write(t, live, "{\"c\":3}\n")
	second, e := Next([]string{backup, live}, first.Checkpoint, 100)
	if e != nil || string(second.Bytes) != "{\"b\":2}\n" || second.Checkpoint.Inode != first.Checkpoint.Inode {
		t.Fatalf("%v %v", second, e)
	}
	third, e := Next([]string{backup, live}, second.Checkpoint, 100)
	if e != nil || string(third.Bytes) != "{\"c\":3}\n" || third.Checkpoint.Inode == second.Checkpoint.Inode {
		t.Fatalf("%v %v", third, e)
	}
	if e = os.Remove(backup); e != nil {
		t.Fatal(e)
	}
	if _, e = Next([]string{live}, second.Checkpoint, 100); !errors.Is(e, ErrRotationLoss) {
		t.Fatal(e)
	}
}
func TestTailerNeverSkipsBadInput(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old")
	live := filepath.Join(dir, "live")
	write(t, old, "ok\npartial")
	write(t, live, "next\n")
	first, e := Next([]string{old, live}, wal.Checkpoint{}, 100)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Next([]string{old, live}, first.Checkpoint, 100); !errors.Is(e, ErrIncompleteRotatedRecord) {
		t.Fatal(e)
	}
	if _, e = Next([]string{old}, wal.Checkpoint{}, 2); !errors.Is(e, ErrRecordTooLarge) {
		t.Fatal(e)
	}
	write(t, old, "")
	if _, e = Next([]string{old}, first.Checkpoint, 100); !errors.Is(e, ErrTruncated) {
		t.Fatal(e)
	}
}

func TestCheckpointRejectsReusedInodeAndLegacyIdentity(t *testing.T) {
	file := filepath.Join(t.TempDir(), "export.json")
	write(t, file, "first\nsecond\n")
	first, err := Next([]string{file}, wal.Checkpoint{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if first.Checkpoint.Device == 0 || len(first.Checkpoint.PrefixDigest) != 64 {
		t.Fatal("missing durable file identity")
	}
	// Rewrite the same inode to deterministically reproduce identity reuse.
	write(t, file, "other\nsecond\n")
	if _, err = Next([]string{file}, first.Checkpoint, 100); !errors.Is(err, ErrRotationLoss) {
		t.Fatalf("reused inode resumed at stale offset: %v", err)
	}
	write(t, file, "first\nsecond\n")
	cp := first.Checkpoint
	cp.Device++
	if _, err = Next([]string{file}, cp, 100); !errors.Is(err, ErrRotationLoss) {
		t.Fatalf("wrong device accepted: %v", err)
	}
	cp = first.Checkpoint
	cp.PrefixDigest = ""
	if _, err = Next([]string{file}, cp, 100); !errors.Is(err, ErrRotationLoss) {
		t.Fatalf("legacy checkpoint silently trusted: %v", err)
	}
}
