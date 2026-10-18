package wal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func deliveryRecord(epoch string, seq uint64) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"source_epoch":%q,"source_sequence":%d,"value":"preserved"}`, epoch, seq)), nil
}
func deliveryJournal(t *testing.T, dir, epoch string, capacity int64) *Journal {
	t.Helper()
	j, err := Open(dir, epoch, capacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}
func TestDeliveryWindowBoundsAndEpochOrder(t *testing.T) {
	dir := t.TempDir() + "/spool"
	j := deliveryJournal(t, dir, "z_old", 0)
	for n := 0; n < 5; n++ {
		if _, err := j.Append(deliveryRecord, Checkpoint{}); err != nil {
			t.Fatal(err)
		}
	}
	_ = j.Close()
	j = deliveryJournal(t, dir, "a_new", 0)
	if _, err := j.Append(deliveryRecord, Checkpoint{}); err != nil {
		t.Fatal(err)
	}
	w, err := j.Next(2, MaxRecordBytes)
	if err != nil || w.Epoch != "z_old" || len(w.Records) != 2 || w.End != 2 || w.Acked != 0 {
		t.Fatalf("window %+v %v", w, err)
	}
	if err := j.Ack("z_old", 2); err != nil {
		t.Fatal(err)
	}
	w, err = j.Next(100, len(w.Records[0].Payload))
	if err != nil || len(w.Records) != 1 || w.Records[0].Sequence != 3 || w.End != 3 {
		t.Fatalf("bounded window %+v %v", w, err)
	}
	if err := j.Ack("z_old", 5); err != nil {
		t.Fatal(err)
	}
	w, err = j.Next(100, MaxRecordBytes)
	if err != nil || w.Epoch != "a_new" {
		t.Fatalf("current epoch %+v %v", w, err)
	}
}

func TestQuarantineSurvivesAckAndRestart(t *testing.T) {
	dir := t.TempDir() + "/spool"
	j := deliveryJournal(t, dir, "old", 0)
	r, err := j.Append(deliveryRecord, Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.QuarantineSchemaRejected("old", 1); err != nil {
		t.Fatal(err)
	}
	used, _ := j.Usage()
	if err := j.QuarantineSchemaRejected("old", 1); err != nil {
		t.Fatal(err)
	}
	again, _ := j.Usage()
	if again != used {
		t.Fatal("idempotent quarantine duplicated disk accounting")
	}
	_ = j.Close()
	j = deliveryJournal(t, dir, "new", 0)
	w, err := j.Next(100, MaxRecordBytes)
	if err != nil || !w.Rejected[1] {
		t.Fatalf("lost rejection %+v %v", w, err)
	}
	if err := j.Ack("old", 1); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "wal-*.seg"))
	if len(paths) != 0 {
		t.Fatal("acked segment retained")
	}
	raw, err := os.ReadFile(filepath.Join(dir, quarantineName("old", 1)))
	if err != nil {
		t.Fatal(err)
	}
	var q quarantine
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	if string(q.Payload) != string(r.Payload) || q.Reason != "SCHEMA_INVALID" {
		t.Fatal("original rejection evidence changed")
	}
	_ = j.Close()
	j = deliveryJournal(t, dir, "next", 0)
	retained, _ := j.Usage()
	if retained != int64(len(raw)) {
		t.Fatalf("quarantine capacity accounting %d != %d", retained, len(raw))
	}
	w, err = j.Next(100, MaxRecordBytes)
	if err != nil || w.Epoch != "" {
		t.Fatal("replayed already committed rejection")
	}
}

func TestQuarantineFullNeverAbandonsRecord(t *testing.T) {
	j := deliveryJournal(t, t.TempDir()+"/spool", "ep", 100)
	if _, err := j.Append(deliveryRecord, Checkpoint{}); err != nil {
		t.Fatal(err)
	}
	if err := j.QuarantineSchemaRejected("ep", 1); !errors.Is(err, ErrFull) {
		t.Fatalf("want capacity error, got %v", err)
	}
	w, err := j.Next(100, MaxRecordBytes)
	if err != nil || w.Rejected[1] || len(w.Records) != 1 || w.Acked != 0 {
		t.Fatalf("discarded on full: %+v %v", w, err)
	}
}

func TestQuarantineCorruptionFailsRecovery(t *testing.T) {
	dir := t.TempDir() + "/spool"
	j := deliveryJournal(t, dir, "ep", 0)
	if _, err := j.Append(deliveryRecord, Checkpoint{}); err != nil {
		t.Fatal(err)
	}
	if err := j.QuarantineSchemaRejected("ep", 1); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	path := filepath.Join(dir, quarantineName("ep", 1))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), "preserved", "tampered", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if recovered, err := Open(dir, "new", 0); err == nil {
		recovered.Close()
		t.Fatal("accepted corrupt quarantine")
	}
}

func TestWindowRetainsMissingTailAsGap(t *testing.T) {
	dir := t.TempDir() + "/spool"
	j := deliveryJournal(t, dir, "ep", 0)
	first, err := j.Append(deliveryRecord, Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(deliveryRecord, Checkpoint{}); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	paths, _ := filepath.Glob(filepath.Join(dir, "wal-*.seg"))
	if err := os.Truncate(paths[0], int64(12+len(first.Payload)+5)); err != nil {
		t.Fatal(err)
	}
	j = deliveryJournal(t, dir, "new", 0)
	w, err := j.Next(100, MaxRecordBytes)
	if err != nil || w.End != 2 || len(w.Records) != 1 || w.Records[0].Sequence != 1 {
		t.Fatalf("gap window %+v %v", w, err)
	}
}

func TestWindowFailsClosedIfOpenSegmentDisappears(t *testing.T) {
	dir := t.TempDir() + "/spool"
	j := deliveryJournal(t, dir, "ep", 0)
	if _, err := j.Append(deliveryRecord, Checkpoint{}); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "wal-*.seg"))
	if err := os.Truncate(paths[0], 0); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Next(100, MaxRecordBytes); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing pending frame was not corruption: %v", err)
	}
}
