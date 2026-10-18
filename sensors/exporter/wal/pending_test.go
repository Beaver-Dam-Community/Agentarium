package wal

import (
	"errors"
	"strings"
	"testing"
)

func TestCursorCapacityRefusalPreservesDrainedState(t *testing.T) {
	j := openTest(t, t.TempDir(), "epoch", 500)
	if err := j.BindWatchScope("namespace/agent-exec"); err != nil {
		t.Fatal(err)
	}
	used, _ := j.Usage()
	err := j.StoreDelivery(PendingDelivery{SourceID: "source", Stream: "lifecycle", Epoch: "epoch", Body: []byte(`{"scope":"namespace/agent-exec","records":[],"sequence_range_abandoned":[],"cursor":{"resource_version":"` + strings.Repeat("a", 550) + `"}}`)})
	if !errors.Is(err, ErrFull) {
		t.Fatalf("expected pending capacity rejection: %v", err)
	}
	pending, err := j.Delivery()
	if err != nil || pending != nil {
		t.Fatal("failed request became pending", err)
	}
	records, err := j.Pending()
	if err != nil || len(records) != 0 {
		t.Fatal("WAL lost", err)
	}
	after, _ := j.Usage()
	if after != used {
		t.Fatal("failed capacity check changed accounting")
	}
}
func TestLegacyWatcherScopeCannotBeInferred(t *testing.T) {
	j := openTest(t, t.TempDir(), "legacy", 0)
	appendTest(t, j, 1)
	if err := j.BindWatchScope("namespace/agent-exec"); err == nil {
		t.Fatal("unknown legacy scope adopted current configuration")
	}
	records, err := j.Pending()
	if err != nil || len(records) != 1 {
		t.Fatal("legacy WAL not retained", err)
	}
}
