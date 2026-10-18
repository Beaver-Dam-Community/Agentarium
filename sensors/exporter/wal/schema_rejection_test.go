package wal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func rejectedCount(t *testing.T, j *Journal, want uint64) {
	t.Helper()
	got, err := j.SchemaRejections()
	if err != nil || got != want {
		t.Fatalf("rejection count = %d, %v; want %d", got, err, want)
	}
}

func TestSchemaRejectionAtomicReplayAndCAS(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "epoch", 0)
	original := appendTest(t, j, 10)
	previous := j.Checkpoint()
	next := previous
	next.Offset = 20
	if err := j.RejectSchema(previous, next); err != nil {
		t.Fatal(err)
	}
	rejectedCount(t, j, 1)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openTest(t, dir, "next_epoch", 0)
	if err := j.RejectSchema(previous, next); err != nil {
		t.Fatal(err)
	}
	rejectedCount(t, j, 1)
	if j.Checkpoint() != next {
		t.Fatal("rejection cursor lost")
	}
	pending, err := j.Pending()
	if err != nil || !reflect.DeepEqual(pending, []Record{original}) {
		t.Fatalf("pending changed: %+v %v", pending, err)
	}
	further := next
	further.Offset = 30
	if err := j.RejectSchema(previous, further); err == nil {
		t.Fatal("stale CAS accepted")
	}
	if err := j.RejectSchema(next, previous); err == nil {
		t.Fatal("regressing cursor accepted")
	}
	if err := j.RejectSchema(next, next); err == nil {
		t.Fatal("empty input counted")
	}
	if err := j.RejectSchema(next, Checkpoint{}); err == nil {
		t.Fatal("invalid cursor accepted")
	}
	rejectedCount(t, j, 1)
	// Rotation changes identity; offset may restart, but count remains spool-wide.
	rotated := Checkpoint{Inode: 22, Device: 3, PrefixDigest: "next-file", Offset: 2}
	if err := j.RejectSchema(next, rotated); err != nil {
		t.Fatal(err)
	}
	rejectedCount(t, j, 2)
	rotated.Offset++
	r, err := j.Append(build, rotated)
	if err != nil || r.Sequence != 1 {
		t.Fatalf("rejections allocated sequences: %+v %v", r, err)
	}
	gaps, err := j.RecoveryGaps()
	if err != nil || len(gaps) != 0 {
		t.Fatalf("rejections became reserved gaps: %v %v", gaps, err)
	}
}

func TestSchemaRejectionPersistenceFailure(t *testing.T) {
	for _, stage := range []string{"before-rename", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			j := openTest(t, dir, "epoch", 0)
			original := appendTest(t, j, 10)
			previous := j.Checkpoint()
			next := previous
			next.Offset = 20
			var restore func()
			if stage == "before-rename" {
				// Keep the real durable state safely aside, then obstruct its rename target.
				statePath := filepath.Join(dir, "state.json")
				backup := filepath.Join(dir, "saved-state")
				if err := os.Rename(statePath, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(statePath, 0700); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if err := os.Remove(statePath); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(backup, statePath); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				j.syncStateDir = func(string) error { return errors.New("injected directory fsync failure after rename") }
				restore = func() {}
			}
			if err := j.RejectSchema(previous, next); err == nil {
				t.Fatal("persistence failure succeeded")
			}
			if j.Checkpoint() != previous || j.state.SchemaRejected != 0 {
				t.Fatal("speculative state exposed")
			}
			if _, err := j.SchemaRejections(); err == nil {
				t.Fatal("failed journal reported durable count")
			}
			if err := j.RejectSchema(previous, next); err == nil {
				t.Fatal("uncertain commit converted to successful retry")
			}
			if _, err := j.Append(build, next); err == nil {
				t.Fatal("failed journal appended")
			}
			if err := j.AdvanceFiltered(next); err == nil {
				t.Fatal("failed journal advanced cursor")
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			restore()
			j = openTest(t, dir, "epoch", 0)
			want := uint64(0)
			if stage == "after-rename" {
				want = 1
			}
			rejectedCount(t, j, want)
			expected := previous
			if want == 1 {
				expected = next
			}
			if j.Checkpoint() != expected {
				t.Fatal("recovered mixed count/cursor")
			}
			if err := j.RejectSchema(previous, next); err != nil {
				t.Fatal(err)
			}
			rejectedCount(t, j, 1)
			pending, err := j.Pending()
			if err != nil || !reflect.DeepEqual(pending, []Record{original}) {
				t.Fatal("original pending changed")
			}
		})
	}
}

func TestSchemaRejectionLegacyStateAndBounds(t *testing.T) {
	dir := t.TempDir()
	j := openTest(t, dir, "epoch", 0)
	path := filepath.Join(dir, "state.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]json.RawMessage
	if err = json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	if _, exists := legacy["schema_rejected"]; exists {
		t.Fatal("zero count should preserve legacy state encoding")
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openTest(t, dir, "epoch", 0)
	rejectedCount(t, j, 0)
	j.state.SchemaRejected = MaxSequence
	if err = j.persist(); err != nil {
		t.Fatal(err)
	}
	if err = j.RejectSchema(Checkpoint{}, Checkpoint{Inode: 1, Offset: 1}); err == nil {
		t.Fatal("count overflow accepted")
	}
	if j.Checkpoint() != (Checkpoint{}) {
		t.Fatal("overflow advanced cursor")
	}
	rejectedCount(t, j, MaxSequence)
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	legacy["schema_rejected"] = json.RawMessage("9007199254740992")
	raw, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if unexpected, err := Open(dir, "epoch", 0); err == nil {
		_ = unexpected.Close()
		t.Fatal("invalid persisted count accepted")
	}
}
