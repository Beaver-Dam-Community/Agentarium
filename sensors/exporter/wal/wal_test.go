package wal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func build(epoch string, seq uint64) ([]byte, error) {
	return json.Marshal(map[string]any{"source_epoch": epoch, "source_sequence": seq, "source_event_id": "stable-test-id", "safe_attributes": map[string]any{"binary": "/bin/test"}})
}
func openTest(t *testing.T, dir, epoch string, cap int64) *Journal {
	t.Helper()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	j, e := Open(dir, epoch, cap)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}
func appendTest(t *testing.T, j *Journal, n int) Record {
	t.Helper()
	r, e := j.Append(build, Checkpoint{Inode: 11, Offset: int64(n)})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestReplayKeepsEpochBytesAndCheckpoint(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "boot_instance_a", 0)
	r := appendTest(t, j, 42)
	if j.Checkpoint() != (Checkpoint{Inode: 11, Offset: 42}) {
		t.Fatal("checkpoint missing")
	}
	_ = j.Close()
	next := openTest(t, dir, "boot_instance_b", 0)
	records, e := next.Pending()
	if e != nil || len(records) != 1 || !bytes.Equal(r.Payload, records[0].Payload) || records[0].Epoch != "boot_instance_a" {
		t.Fatalf("%+v %v", records, e)
	}
	newRecord := appendTest(t, next, 84)
	if newRecord.Sequence != 1 || newRecord.Epoch != "boot_instance_b" {
		t.Fatal("new process reused epoch sequence")
	}
	if gaps, e := next.RecoveryGaps(); e != nil || len(gaps) != 0 {
		t.Fatalf("%v %v", gaps, e)
	}
}
func TestFramingAndUnackedRetention(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "epoch", 0)
	r := appendTest(t, j, 1)
	appendTest(t, j, 2)
	paths, _ := filepath.Glob(filepath.Join(dir, "*.seg"))
	raw, e := os.ReadFile(paths[0])
	if e != nil {
		t.Fatal(e)
	}
	if string(raw[:4]) != "AGW1" || binary.BigEndian.Uint32(raw[4:8]) != uint32(len(r.Payload)) {
		t.Fatal("framing mismatch")
	}
	if e = j.Ack("epoch", 1); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(paths[0]); e != nil {
		t.Fatal("partially acked segment deleted")
	}
	pending, _ := j.Pending()
	if len(pending) != 1 || pending[0].Sequence != 2 {
		t.Fatal("wrong pending")
	}
	if e = j.Ack("epoch", 2); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(paths[0]); !os.IsNotExist(e) {
		t.Fatal("fully acked segment retained")
	}
	_ = j.Close()
	j = openTest(t, dir, "epoch", 0)
	if got := appendTest(t, j, 3); got.Sequence != 3 {
		t.Fatal("ack reset sequence")
	}
}
func TestPartialLastFrameAndCRCBecomeExactGap(t *testing.T) {
	for _, mode := range []string{"partial", "crc"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			j := openTest(t, dir, "epoch", 0)
			first := appendTest(t, j, 1)
			appendTest(t, j, 2)
			_ = j.Close()
			paths, _ := filepath.Glob(filepath.Join(dir, "*.seg"))
			b, _ := os.ReadFile(paths[0])
			if mode == "partial" {
				b = b[:len(b)-7]
			} else {
				b[len(b)-1] ^= 1
			}
			if e := os.WriteFile(paths[0], b, 0600); e != nil {
				t.Fatal(e)
			}
			j = openTest(t, dir, "next", 0)
			r, e := j.Pending()
			if e != nil || len(r) != 1 || !bytes.Equal(r[0].Payload, first.Payload) {
				t.Fatalf("%v %v", r, e)
			}
			gaps, e := j.RecoveryGaps()
			if e != nil || len(gaps) != 1 || gaps[0] != (Gap{"epoch", 2, 2}) {
				t.Fatalf("%v %v", gaps, e)
			}
			if e = j.Ack("epoch", 2); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestMiddleCorruptionNeverSilentlyTruncated(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "epoch", 0)
	appendTest(t, j, 1)
	appendTest(t, j, 2)
	_ = j.Close()
	paths, _ := filepath.Glob(filepath.Join(dir, "*.seg"))
	b, _ := os.ReadFile(paths[0])
	b[12] ^= 1
	_ = os.WriteFile(paths[0], b, 0600)
	if _, e := Open(dir, "next", 0); !errors.Is(e, ErrCorrupt) {
		t.Fatalf("%v", e)
	}
	after, _ := os.ReadFile(paths[0])
	if !bytes.Equal(after, b) {
		t.Fatal("middle corruption discarded later evidence")
	}
}
func TestCrashAfterReservationAndCapacityBoundary(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "epoch", 0)
	appendTest(t, j, 1)
	j.state.Epochs["epoch"] = position{Reserved: 2}
	if e := j.persist(); e != nil {
		t.Fatal(e)
	}
	_ = j.Close()
	j = openTest(t, dir, "next", 0)
	gaps, e := j.RecoveryGaps()
	if e != nil || len(gaps) != 1 || gaps[0].From != 2 || gaps[0].To != 2 {
		t.Fatalf("%v %v", gaps, e)
	}
	other := openTest(t, t.TempDir(), "epoch", 1)
	if _, e = other.Append(build, Checkpoint{}); !errors.Is(e, ErrFull) {
		t.Fatal(e)
	}
	if other.state.Epochs["epoch"].Reserved != 0 {
		t.Fatal("full spool consumed sequence")
	}
}
func TestExclusiveAndInvalidInputs(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "epoch", 0)
	if _, e := Open(dir, "second", 0); e == nil {
		t.Fatal("concurrent spool opened")
	}
	if _, e := Open(t.TempDir(), "../escape", 0); e == nil {
		t.Fatal("unsafe epoch")
	}
	if _, e := j.Append(func(string, uint64) ([]byte, error) {
		return []byte(`{"source_epoch":"wrong","source_sequence":1}`), nil
	}, Checkpoint{}); e == nil {
		t.Fatal("wrong identity appended")
	}
	if e := j.Ack("epoch", 1); e == nil {
		t.Fatal("unreserved ack")
	}
	if got := appendTest(t, j, 1); got.Sequence != 1 {
		t.Fatal("invalid record consumed sequence")
	}
}

func TestLostStateAfterFullAckFailsClosed(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "epoch", 0)
	appendTest(t, j, 1)
	if err := j.Ack("epoch", 1); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	if err := os.Remove(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, "next", 0); err == nil {
		t.Fatal("lost sequence state silently reset")
	}
}

func TestCheckpointRecoveryAcrossFrameCommit(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(map[bool]string{false: "reservation-only", true: "frame-durable"}[durable], func(t *testing.T) {
			dir := t.TempDir()
			j := openTest(t, dir, "epoch", 0)
			appendTest(t, j, 10)
			if durable {
				appendTest(t, j, 20)
			}
			// Persist the state visible between the reservation and checkpoint commit.
			j.state.Epochs["epoch"] = position{Reserved: 2}
			j.state.Checkpoint = Checkpoint{Inode: 11, Offset: 10}
			j.state.Pending = &reservation{"epoch", 2, Checkpoint{Inode: 11, Offset: 20}}
			if err := j.persist(); err != nil {
				t.Fatal(err)
			}
			_ = j.Close()
			j = openTest(t, dir, "next", 0)
			want := int64(10)
			if durable {
				want = 20
			}
			if j.Checkpoint().Offset != want {
				t.Fatalf("checkpoint=%v want=%d", j.Checkpoint(), want)
			}
			gaps, err := j.RecoveryGaps()
			if err != nil {
				t.Fatal(err)
			}
			if durable && len(gaps) != 0 || !durable && (len(gaps) != 1 || gaps[0] != (Gap{"epoch", 2, 2})) {
				t.Fatal(gaps)
			}
		})
	}
}

func TestCheckpointCannotRegressWithinInode(t *testing.T) {
	j := openTest(t, t.TempDir(), "epoch", 0)
	appendTest(t, j, 10)
	if _, err := j.Append(build, Checkpoint{Inode: 11, Offset: 9}); err == nil {
		t.Fatal("checkpoint regressed")
	}
	if r, err := j.Append(build, Checkpoint{Inode: 12, Offset: 0}); err != nil || r.Sequence != 2 {
		t.Fatalf("rotation: %v %v", r, err)
	}
}

func TestFilteredCheckpointDoesNotAllocateSequence(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "epoch", 0)
	if err := j.AdvanceFiltered(Checkpoint{Inode: 11, Offset: 100}); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	j = openTest(t, dir, "epoch", 0)
	if j.Checkpoint() != (Checkpoint{Inode: 11, Offset: 100}) {
		t.Fatal(j.Checkpoint())
	}
	if r := appendTest(t, j, 200); r.Sequence != 1 {
		t.Fatal("filtered record allocated a sequence")
	}
}

func TestWorldReadableSpoolRejected(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(dir, "epoch", 0); e == nil {
		t.Fatal("insecure spool accepted")
	}
}

func TestCheckpointIdentitySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "epoch", 0)
	cp := Checkpoint{Inode: 11, Offset: 42, Device: 3, PrefixDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	if _, err := j.Append(build, cp); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openTest(t, dir, "next", 0)
	if got := j.Checkpoint(); got != cp {
		t.Fatalf("checkpoint after restart=%+v want=%+v", got, cp)
	}
	cp.Device = 4
	cp.Offset = 1
	if _, err := j.Append(build, cp); err != nil {
		t.Fatalf("new device rejected: %v", err)
	}
	cp.Offset = 0
	if err := j.AdvanceFiltered(cp); err == nil {
		t.Fatal("same identity regressed")
	}
	cp.PrefixDigest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if err := j.AdvanceFiltered(cp); err != nil {
		t.Fatalf("new file identity rejected: %v", err)
	}
}

func TestAtomicHealthSnapshotTracksDurableProgressAcrossEpochs(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "old", 0)
	appendTest(t, j, 1)
	_ = j.Close()
	j = openTest(t, dir, "new", 0)
	appendTest(t, j, 2)
	check := func(pending bool, progress uint64) {
		t.Helper()
		s, err := j.HealthSnapshot()
		if err != nil || s.Pending != pending || s.AckProgress != progress || s.Capacity != DefaultCapacity || s.Used < 0 {
			t.Fatalf("snapshot=%+v error=%v", s, err)
		}
	}
	check(true, 0)
	if err := j.Ack("old", 1); err != nil {
		t.Fatal(err)
	}
	check(true, 1)
	if err := j.Ack("old", 1); err != nil {
		t.Fatal(err)
	}
	check(true, 1)
	if err := j.Ack("new", 1); err != nil {
		t.Fatal(err)
	}
	check(false, 2)
	_ = j.Close()
	if _, err := j.HealthSnapshot(); err == nil {
		t.Fatal("closed journal appeared healthy")
	}
}

func TestHealthSnapshotIncludesRecoveredGapAndFailedState(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "old", 0)
	appendTest(t, j, 1)
	// Simulate a durable reservation without its frame. Recovery must keep the gap pending.
	j.state.Epochs["old"] = position{Reserved: 2}
	if err := j.persist(); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	j = openTest(t, dir, "new", 0)
	if err := j.Ack("old", 1); err != nil {
		t.Fatal(err)
	}
	s, err := j.HealthSnapshot()
	if err != nil || !s.Pending || s.AckProgress != 1 {
		t.Fatalf("gap disappeared: %+v %v", s, err)
	}
	j.failed = true
	if _, err := j.HealthSnapshot(); err == nil {
		t.Fatal("failed journal appeared healthy")
	}
}
