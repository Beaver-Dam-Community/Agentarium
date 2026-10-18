package wal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func damagedSegment(t *testing.T, mode string) (dir, path string, original []byte, offset int64) {
	t.Helper()
	dir = t.TempDir()
	j := openTest(t, dir, "old", 0)
	first := appendTest(t, j, 1)
	appendTest(t, j, 2)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "wal-*.seg"))
	path = paths[0]
	original, _ = os.ReadFile(path)
	offset = int64(12 + len(first.Payload))
	switch mode {
	case "partial_header":
		original = original[:offset+5]
	case "partial_payload":
		original = original[:len(original)-7]
	case "crc_mismatch":
		original[len(original)-1] ^= 1
	default:
		t.Fatal("unknown damage")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	return
}

func damageFile(t *testing.T, dir string) (string, []byte, damage) {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(dir, "damaged-*.bin"))
	if len(paths) != 1 {
		t.Fatalf("expected one damage evidence file, got %d", len(paths))
	}
	raw, d, err := readDamage(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	return paths[0], raw, d
}

func TestDamagedTailPreservedBeforeTrimAndAfterAck(t *testing.T) {
	for _, mode := range []string{"partial_header", "partial_payload", "crc_mismatch"} {
		t.Run(mode, func(t *testing.T) {
			dir, path, original, offset := damagedSegment(t, mode)
			j := openTest(t, dir, "new", 0)
			_, raw, d := damageFile(t, dir)
			if d.Epoch != "old" || d.First != 1 || d.Sequence != 2 || d.Offset != offset || d.Reason != mode {
				t.Fatalf("wrong recovery metadata %+v", d)
			}
			n := int(binary.BigEndian.Uint32(raw[4:8]))
			if !bytes.Equal(raw[8+n:], original[offset:]) {
				t.Fatal("did not preserve exact damaged bytes")
			}
			trimmed, _ := os.ReadFile(path)
			if !bytes.Equal(trimmed, original[:offset]) {
				t.Fatal("changed good prefix")
			}
			gaps, err := j.RecoveryGaps()
			if err != nil || len(gaps) != 1 || gaps[0] != (Gap{"old", 2, 2}) {
				t.Fatalf("gap %+v %v", gaps, err)
			}
			if j.used != offset+int64(len(raw)) {
				t.Fatal("damage omitted from spool usage")
			}
			if err := j.Ack("old", 2); err != nil {
				t.Fatal(err)
			}
			if j.used != int64(len(raw)) {
				t.Fatal("ack removed retained damage accounting")
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			j = openTest(t, dir, "restart", 0)
			_, after, _ := damageFile(t, dir)
			if !bytes.Equal(after, raw) || j.used != int64(len(raw)) {
				t.Fatal("restart changed evidence or accounting")
			}
		})
	}
}

func TestFullRecoveryPreservesOriginalSegment(t *testing.T) {
	dir, path, original, _ := damagedSegment(t, "partial_payload")
	if _, err := Open(dir, "next", int64(len(original))); !errors.Is(err, ErrFull) {
		t.Fatalf("recovery exceeded capacity: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, original) {
		t.Fatal("trimmed before evidence could be preserved")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "damaged-*.bin"))
	if len(files) != 0 {
		t.Fatal("published evidence beyond capacity")
	}
	j := openTest(t, dir, "next", 0)
	if _, err := j.RecoveryGaps(); err != nil {
		t.Fatal(err)
	}
	damageFile(t, dir)
}

func TestPublishedDamageSurvivesTruncateFailureAndRetriesIdempotently(t *testing.T) {
	dir, path, original, offset := damagedSegment(t, "crc_mismatch")
	// Recovery can read and preserve evidence, but this descriptor cannot
	// truncate. This exercises the actual failure between publication and trim.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	j := &Journal{dir: dir, capacity: DefaultCapacity, used: int64(len(original)), state: state{Epochs: map[string]position{"old": {Reserved: 2}}}}
	_, _, err = scan(f, "old", 1, func(off, total int64, seq uint64, reason string) error {
		return j.preserveDamage(f, "old", 1, seq, off, total, reason)
	})
	f.Close()
	if err == nil {
		t.Fatal("read-only descriptor unexpectedly truncated")
	}
	_, saved, _ := damageFile(t, dir)
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, original) {
		t.Fatal("failed truncate changed original")
	}
	j = openTest(t, dir, "new", 0)
	_, retried, _ := damageFile(t, dir)
	if !bytes.Equal(saved, retried) || j.used != offset+int64(len(saved)) {
		t.Fatal("retry duplicated or changed damage evidence")
	}
}

func TestInvalidDamageStopsRecoveryBeforeTruncation(t *testing.T) {
	for _, mode := range []string{"payload", "metadata", "permissions", "symlink", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			dir, path, original, _ := damagedSegment(t, "partial_payload")
			j := openTest(t, dir, "new", 0)
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			artifact, raw, _ := damageFile(t, dir)
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "payload":
				raw[len(raw)-1] ^= 1
				if err := os.WriteFile(artifact, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "metadata":
				raw[8] = '!'
				if err := os.WriteFile(artifact, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(artifact, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other := filepath.Join(dir, "other.bin")
				if err := os.Rename(artifact, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, artifact); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.Truncate(artifact, damageLimit+1); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Open(dir, "retry", 0); err == nil {
				t.Fatal("accepted invalid recovery evidence")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, original) {
				t.Fatal("trimmed despite invalid evidence")
			}
		})
	}
}

func TestPendingDamageCountsButCannotAuthorizeTrim(t *testing.T) {
	dir, path, original, _ := damagedSegment(t, "partial_header")
	pending := filepath.Join(dir, "damage-pending-interrupted")
	if err := os.WriteFile(pending, []byte("partial copy"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, "next", int64(len(original))+12); !errors.Is(err, ErrFull) {
		t.Fatalf("pending copy authorized trim: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, original) {
		t.Fatal("discarded original for unpublished copy")
	}
	j := openTest(t, dir, "next", 0)
	_, raw, d := damageFile(t, dir)
	if j.used != d.Offset+int64(len(raw))+12 {
		t.Fatalf("pending bytes not accounted: %d", j.used)
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatal("pending copy deleted without review")
	}
}
