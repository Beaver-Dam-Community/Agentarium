package netpolcollector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/tailer"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

const clusterUID = "11111111-1111-4111-8111-111111111111"
const nodeUID = "22222222-2222-4222-8222-222222222222"

func q0(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("../../evidence/gcp/runs/20261014-task01-q0-min/raw/netpol-policy_action.log")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func open(t *testing.T, dir, epoch string, capacity int64) *wal.Journal {
	t.Helper()
	j, e := wal.Open(dir, epoch, capacity)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}
func capture(t *testing.T, j *wal.Journal, inventory Inventory) *Capture {
	t.Helper()
	line := bytes.Split(q0(t), []byte("\n"))[0]
	ob, e := Normalize(line)
	if e != nil {
		t.Fatal(e)
	}
	c, e := New(Config{Journal: j, Reader: Reader{inventory, 64, wal.MaxRecordBytes}, ClusterUID: clusterUID, NodeUID: nodeUID, NodeName: ob.NodeName, NormalizationVersion: "local-q0-v1"})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestQ0CaptureRestartKeepsSourceAndPending(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_action.log")
	raw := q0(t)
	write(t, path, raw)
	inv := func() ([]string, error) { return []string{path}, nil }
	spool := filepath.Join(dir, "netpol-spool")
	j := open(t, spool, "boot_instance_1", 0)
	c := capture(t, j, inv)
	first, e := c.Step(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	j = open(t, spool, "boot_instance_2", 0)
	c = capture(t, j, inv)
	if e = c.Run(context.Background(), false); e != nil {
		t.Fatal(e)
	}
	pending, e := j.Pending()
	if e != nil {
		t.Fatal(e)
	}
	if len(pending) != 5 || !bytes.Equal(first.Payload, pending[0].Payload) {
		t.Fatalf("wrong recovered records: %d", len(pending))
	}
	counts := int64(0)
	allow, deny := 0, 0
	for n, r := range pending {
		var local Captured
		if e = json.Unmarshal(r.Payload, &local); e != nil {
			t.Fatal(e)
		}
		if local.ClusterUID != clusterUID || local.NodeUID != nodeUID || local.SourceEpoch != r.Epoch || local.SourceSequence != r.Sequence {
			t.Fatal("identity lost")
		}
		if n == 0 && r.Epoch != "boot_instance_1" || n > 0 && (r.Epoch != "boot_instance_2" || r.Sequence != uint64(n)) {
			t.Fatal("epoch/sequence rewritten")
		}
		original, e := Normalize(bytes.Split(raw, []byte("\n"))[n])
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(local.Observation, original) {
			t.Fatal("source fields changed")
		}
		counts += local.Observation.Count
		if local.Observation.Disposition == "allow" {
			allow++
		} else {
			deny++
		}
		if bytes.Contains(r.Payload, []byte(`"record_id"`)) || bytes.Contains(r.Payload, []byte(`"received_at"`)) {
			t.Fatal("invented server/wire identity")
		}
	}
	if counts != 12 || allow != 3 || deny != 2 {
		t.Fatalf("unexpected measured Q0 counts: %d/%d/%d", counts, allow, deny)
	}
	if j.Checkpoint().Offset != int64(len(raw)) {
		t.Fatal("checkpoint did not reach source EOF")
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	j = open(t, spool, "boot_instance_3", 0)
	c = capture(t, j, inv)
	if _, e = c.Step(context.Background()); !errors.Is(e, io.EOF) {
		t.Fatalf("replayed source: %v", e)
	}
	again, e := j.Pending()
	if e != nil || !reflect.DeepEqual(pending, again) {
		t.Fatal("unacknowledged payload was lost/rewritten")
	}
}
func TestVerifiedRotationAndLostHistory(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "policy_action.log")
	backup := filepath.Join(dir, "verified-backup")
	lines := bytes.SplitAfter(q0(t), []byte("\n"))
	write(t, live, append(append([]byte(nil), lines[0]...), lines[1]...))
	paths := []string{live}
	j := open(t, filepath.Join(dir, "spool"), "epoch", 0)
	c := capture(t, j, func() ([]string, error) { return paths, nil })
	if _, e := c.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(live, backup); e != nil {
		t.Fatal(e)
	}
	write(t, live, lines[2])
	paths = []string{backup, live}
	for range 2 {
		if _, e := c.Step(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := c.Step(context.Background()); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	cp := j.Checkpoint()
	if e := os.Rename(live, filepath.Join(dir, "deleted-history")); e != nil {
		t.Fatal(e)
	}
	write(t, live, lines[3])
	paths = []string{live}
	if _, e := c.Step(context.Background()); !errors.Is(e, ErrSourceLoss) {
		t.Fatalf("lost history silently reset: %v", e)
	}
	if j.Checkpoint() != cp {
		t.Fatal("loss advanced cursor")
	}
}
func TestRotationDuringReadRetriesOldestVerifiedFile(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "policy_action.log")
	backup := filepath.Join(dir, "verified-backup")
	lines := bytes.SplitAfter(q0(t), []byte("\n"))
	write(t, live, lines[0])
	calls := 0
	inventory := func() ([]string, error) {
		calls++
		if calls == 2 {
			if e := os.Rename(live, backup); e != nil {
				return nil, e
			}
			if e := os.WriteFile(live, lines[1], 0600); e != nil {
				return nil, e
			}
		}
		if calls == 1 {
			return []string{live}, nil
		}
		return []string{backup, live}, nil
	}
	j := open(t, filepath.Join(dir, "spool"), "epoch", 0)
	c := capture(t, j, inventory)
	r, e := c.Step(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	var got Captured
	_ = json.Unmarshal(r.Payload, &got)
	want, _ := Normalize(lines[0])
	if !reflect.DeepEqual(got.Observation, want) || calls < 4 {
		t.Fatal("rotation skipped an input candidate")
	}
}
func TestPartialOversizeAndFullNeverSkip(t *testing.T) {
	line := bytes.SplitAfter(q0(t), []byte("\n"))[0]
	for _, scenario := range []string{"partial", "oversize", "full", "wrong-node", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy_action.log")
			raw := line
			capacity := int64(0)
			switch scenario {
			case "partial":
				raw = line[:len(line)-1]
			case "oversize":
				raw = append(bytes.Repeat([]byte("x"), wal.MaxRecordBytes), '\n')
			case "full":
				capacity = 1
			}
			write(t, path, raw)
			j := open(t, filepath.Join(dir, "spool"), "epoch", capacity)
			c := capture(t, j, func() ([]string, error) { return []string{path}, nil })
			if scenario == "wrong-node" {
				c.config.NodeName = "another-node"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "canceled" {
				cancel()
			}
			_, e := c.Step(ctx)
			if e == nil {
				t.Fatal("expected rejection")
			}
			if scenario == "full" && !errors.Is(e, wal.ErrFull) {
				t.Fatal(e)
			}
			if scenario == "oversize" && !errors.Is(e, tailer.ErrRecordTooLarge) {
				t.Fatal(e)
			}
			if j.Checkpoint() != (wal.Checkpoint{}) {
				t.Fatal("failed input advanced checkpoint")
			}
			if count, err := j.SchemaRejections(); err != nil || count != 0 {
				t.Fatalf("non-schema failure was counted: %d, %v", count, err)
			}
			pending, _ := j.Pending()
			if len(pending) != 0 {
				t.Fatal("failed input allocated record")
			}
			if scenario == "partial" {
				f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.Write([]byte("\n"))
				_ = f.Close()
				if e != nil {
					t.Fatal(e)
				}
				if _, e = c.Step(ctx); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
func TestInventoryRejectsAliasesAndNonRegular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_action.log")
	write(t, path, q0(t))
	link := filepath.Join(dir, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	for _, paths := range [][]string{{path, path}, {link}, {dir}, {"relative"}} {
		r := Reader{func() ([]string, error) { return paths, nil }, 64, wal.MaxRecordBytes}
		if _, e := r.Next(wal.Checkpoint{}); !errors.Is(e, ErrInventory) {
			t.Fatalf("accepted %v: %v", paths, e)
		}
	}
}
func TestFollowIsCancelableAtEOF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_action.log")
	write(t, path, nil)
	j := open(t, filepath.Join(dir, "spool"), "epoch", 0)
	c := capture(t, j, func() ([]string, error) { return []string{path}, nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, true) }()
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("follow ignored cancellation")
	}
}

func TestRotationMissingLiveFileRetriesWithoutSkipping(t *testing.T) {
	dir := t.TempDir()
	live, backup := filepath.Join(dir, "policy_action.log"), filepath.Join(dir, "backup")
	lines := bytes.SplitAfter(q0(t), []byte("\n"))
	write(t, live, lines[0])
	j := open(t, filepath.Join(dir, "spool"), "epoch", 0)
	paths := []string{live}
	c := capture(t, j, func() ([]string, error) { return paths, nil })
	if _, err := c.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkpoint := j.Checkpoint()
	if err := os.Rename(live, backup); err != nil {
		t.Fatal(err)
	}
	paths = []string{backup, live}
	if _, err := c.Step(context.Background()); !errors.Is(err, ErrInventoryChanged) {
		t.Fatalf("rotation gap: %v", err)
	}
	if j.Checkpoint() != checkpoint {
		t.Fatal("missing live path advanced checkpoint")
	}
	write(t, live, lines[1])
	if _, err := c.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending, err := j.Pending()
	if err != nil || len(pending) != 2 {
		t.Fatalf("lost/repeated records: %v %v", pending, err)
	}
}

func TestFollowWaitsForRotationGapAndKeepsCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing-live")
	j := open(t, filepath.Join(dir, "spool"), "epoch", 0)
	c := capture(t, j, func() ([]string, error) { return []string{path}, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := c.Run(ctx, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("follow stopped during transient rotation: %v", err)
	}
	if j.Checkpoint() != (wal.Checkpoint{}) {
		t.Fatal("missing file advanced checkpoint")
	}
	if err := c.Run(context.Background(), false); !errors.Is(err, ErrInventoryChanged) {
		t.Fatalf("one-shot hid incomplete inventory: %v", err)
	}
}
