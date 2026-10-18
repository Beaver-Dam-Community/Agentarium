package walread

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

// The reader must decode exactly what the real journal fsynced, while the
// journal still holds its lock, and tolerate a torn tail written after it.
func TestReadsRealJournalSegmentsWithoutLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	j, err := wal.Open(dir, "epoch_a", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for i := 1; i <= 3; i++ {
		_, err := j.Append(func(epoch string, seq uint64) ([]byte, error) {
			return canonical.JCS([]byte(`{"source_epoch":"` + epoch + `","source_sequence":` + string(rune('0'+seq)) + `,"n":` + string(rune('0'+i)) + `}`))
		}, wal.Checkpoint{Inode: 7, Offset: int64(i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	var got []map[string]any
	read := func() error {
		got = nil
		return Each(dir, func(_ string, p []byte) error {
			var m map[string]any
			if err := json.Unmarshal(p, &m); err != nil {
				return err
			}
			got = append(got, m)
			return nil
		})
	}
	if err := read(); err != nil || len(got) != 3 || got[2]["source_sequence"].(float64) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	segs, _ := filepath.Glob(filepath.Join(dir, "wal-*.seg"))
	f, err := os.OpenFile(segs[0], os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("AGW1\x00\x00\x00\x10\x00\x00")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := read(); err != nil || len(got) != 3 {
		t.Fatalf("torn tail: %v %v", len(got), err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wal-zz-1.seg"), []byte("XXXX\x00\x00\x00\x01\x00\x00\x00\x00a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := read(); err != ErrCorrupt {
		t.Fatalf("bad magic must be reported, got %v", err)
	}
}
