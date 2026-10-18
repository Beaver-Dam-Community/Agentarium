package acquire

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/tailer"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

func open(t *testing.T, dir, epoch string, capacity int64) *wal.Journal {
	t.Helper()
	j, err := wal.Open(dir, epoch, capacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}
func record(epoch string, seq uint64) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"source_epoch":%q,"source_sequence":%d,"safe":true}`, epoch, seq)), nil
}
func collector(t *testing.T, j *wal.Journal, live string, n Normalize) *Collector {
	t.Helper()
	c, err := New(Config{Journal: j, LiveFile: live, MaxFiles: 6, MaxLineBytes: 1024, Normalize: n})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func normalize(_ context.Context, raw []byte) (Prepared, error) {
	if string(raw) == "filter\n" {
		return Prepared{Excluded: true}, nil
	}
	return Prepared{Build: record}, nil
}

func TestAcquireFilterPartialLineRotationAndRestart(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "tetragon.log")
	writeFile(t, live, "one\nfilter\npartial")
	spool := filepath.Join(dir, "spool")
	j := open(t, spool, "old", 0)
	c := collector(t, j, live, normalize)
	first, err := c.Step(context.Background())
	if err != nil || first.Record == nil || first.Record.Sequence != 1 {
		t.Fatalf("first %+v %v", first, err)
	}
	second, err := c.Step(context.Background())
	if err != nil || !second.Filtered {
		t.Fatalf("filter %+v %v", second, err)
	}
	cp := j.Checkpoint()
	pending, err := j.Pending()
	if err != nil || len(pending) != 1 || pending[0].Sequence != 1 {
		t.Fatal("filter allocated sequence")
	}
	idle, err := c.Step(context.Background())
	if err != nil || !idle.Idle || j.Checkpoint() != cp {
		t.Fatal("consumed partial input")
	}
	f, err := os.OpenFile(live, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("-complete\n")
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "tetragon-2026-10-16T01-02-03.004.log")
	if err := os.Rename(live, backup); err != nil {
		t.Fatal(err)
	}
	writeFile(t, live, "new\n")
	_ = j.Close()
	j = open(t, spool, "new", 0)
	var seen []string
	c = collector(t, j, live, func(ctx context.Context, raw []byte) (Prepared, error) {
		seen = append(seen, string(raw))
		return normalize(ctx, raw)
	})
	for i := 0; i < 2; i++ {
		if result, err := c.Step(context.Background()); err != nil || result.Record == nil {
			t.Fatalf("resume %+v %v", result, err)
		}
	}
	if fmt.Sprint(seen) != "[partial-complete\n new\n]" {
		t.Fatalf("replayed or skipped input: %q", seen)
	}
	pending, err = j.Pending()
	if err != nil || len(pending) != 3 {
		t.Fatalf("WAL records %d %v", len(pending), err)
	}
}

func TestFailuresNeverBecomePolicyExclusion(t *testing.T) {
	for _, mode := range []string{"normalize", "builder", "empty", "both", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			live := filepath.Join(dir, "tetragon.log")
			writeFile(t, live, "sensitive input\n")
			j := open(t, filepath.Join(dir, "spool"), "ep", 0)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := collector(t, j, live, func(context.Context, []byte) (Prepared, error) {
				switch mode {
				case "normalize":
					return Prepared{}, errors.New("sensitive input")
				case "builder":
					return Prepared{Build: func(string, uint64) ([]byte, error) { return nil, errors.New("bad schema") }}, nil
				case "both":
					return Prepared{Excluded: true, Build: record}, nil
				case "cancel":
					cancel()
					return Prepared{Build: record}, nil
				default:
					return Prepared{}, nil
				}
			})
			if _, err := c.Step(ctx); err == nil || strings.Contains(err.Error(), "sensitive input") {
				t.Fatalf("bad error %v", err)
			}
			if j.Checkpoint() != (wal.Checkpoint{}) {
				t.Fatal("advanced failed input checkpoint")
			}
			pending, err := j.Pending()
			if err != nil || len(pending) != 0 {
				t.Fatal("spooled failed input")
			}
		})
	}
}

func TestSpoolPressureLeavesInputForRetry(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "tetragon.log")
	writeFile(t, live, "new\n")
	j := open(t, filepath.Join(dir, "spool"), "ep", 100)
	if _, err := j.Append(record, wal.Checkpoint{}); err != nil {
		t.Fatal(err)
	}
	c := collector(t, j, live, normalize)
	if _, err := c.Step(context.Background()); !errors.Is(err, wal.ErrFull) {
		t.Fatalf("expected full: %v", err)
	}
	if j.Checkpoint() != (wal.Checkpoint{}) {
		t.Fatal("advanced input on full spool")
	}
	// This local boundary test supplies an already verified watermark; the real
	// delivery tests separately prove the mTLS response-to-Ack validation path.
	if err := j.Ack("ep", 1); err != nil {
		t.Fatal(err)
	}
	result, err := c.Step(context.Background())
	if err != nil || result.Record == nil || result.Record.Sequence != 2 {
		t.Fatalf("retry %+v %v", result, err)
	}
}

func TestLossReturnsWithoutResetAndIdleRunCancels(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "tetragon.log")
	writeFile(t, live, "one\n")
	j := open(t, filepath.Join(dir, "spool"), "ep", 0)
	c := collector(t, j, live, normalize)
	if _, err := c.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	cp := j.Checkpoint()
	backup := filepath.Join(dir, "tetragon-2026-10-16T01-02-03.004.log")
	if err := os.Rename(live, backup); err != nil {
		t.Fatal(err)
	}
	writeFile(t, live, "new\n")
	if err := os.Remove(backup); err != nil {
		t.Fatal(err)
	}
	if err := c.Run(context.Background()); !errors.Is(err, tailer.ErrRotationLoss) {
		t.Fatalf("lost source did not stop: %v", err)
	}
	if j.Checkpoint() != cp {
		t.Fatal("reset missing checkpoint")
	}
	empty := filepath.Join(dir, "empty.log")
	writeFile(t, empty, "")
	j2 := open(t, filepath.Join(dir, "empty-spool"), "ep", 0)
	c2 := collector(t, j2, empty, normalize)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c2.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
