package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

func lifecycleRecordWire(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	id, _ := canonical.LifecycleEventID("source-a", "epoch", 1)
	m := map[string]any{"lifecycle_event_id": id, "source_id": "source-a", "source_epoch": "epoch", "source_sequence": 1,
		"cluster_uid": "17d3e81e-65f8-462e-b681-670a14d57f88", "pod_uid": "c9ac8ee3-c88c-49a7-adc5-83cc0dadc453",
		"namespace": "agent-exec", "pod_name": "worker-1", "transition": "create", "mapping_version": 1, "evidence_refs": []string{}}
	if mutate != nil {
		mutate(m)
	}
	raw, _ := json.Marshal(m)
	digest, err := canonical.DigestWithoutKeys(raw, "record_digest", "received_at")
	if err != nil {
		t.Fatal(err)
	}
	m["record_digest"] = digest
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestLifecycleRecord(t *testing.T) {
	raw := lifecycleRecordWire(t, nil)
	record, err := DecodeLifecycleRecord(raw, "source-a", "epoch")
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"wrong UUID":            func(m map[string]any) { m["lifecycle_event_id"] = uuid.NewString() },
		"wrong source":          func(m map[string]any) { m["source_id"] = "source-b" },
		"wrong epoch":           func(m map[string]any) { m["source_epoch"] = "other" },
		"zero sequence":         func(m map[string]any) { m["source_sequence"] = 0 },
		"unknown field":         func(m map[string]any) { m["session_id"] = "inferred" },
		"caller timestamp":      func(m map[string]any) { m["received_at"] = "2026-10-16T12:00:00Z" },
		"null caller timestamp": func(m map[string]any) { m["received_at"] = nil },
		"caller source kind":    func(m map[string]any) { m["source_kind"] = "runtime" },
		"bad cluster":           func(m map[string]any) { m["cluster_uid"] = "bad" },
		"bad node":              func(m map[string]any) { m["node_uid"] = "bad" },
		"bad timestamp":         func(m map[string]any) { m["source_time"] = "2026-10-16" },
		"missing mapping":       func(m map[string]any) { delete(m, "mapping_version") },
		"null mapping":          func(m map[string]any) { m["mapping_version"] = nil },
		"overflow mapping":      func(m map[string]any) { m["mapping_version"] = int64(1) << 32 },
		"null evidence":         func(m map[string]any) { m["evidence_refs"] = nil },
		"case alias":            func(m map[string]any) { m["Pod_UID"] = m["pod_uid"]; delete(m, "pod_uid") },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLifecycleRecord(lifecycleRecordWire(t, mutate), "source-a", "epoch"); !errors.Is(err, ErrSchema) {
				t.Fatalf("accepted invalid record: %v", err)
			}
		})
	}
	if _, err := DecodeLifecycleRecord(bytes.Replace(raw, []byte(record.Digest), []byte(strings.ToUpper(record.Digest)), 1), "source-a", "epoch"); err == nil {
		t.Fatal("uppercase digest accepted")
	}
	if _, err := DecodeLifecycleRecord(bytes.Replace(raw, []byte(`"pod_name":"worker-1"`), []byte(`"pod_name":"worker-2"`), 1), "source-a", "epoch"); err == nil {
		t.Fatal("mutation accepted")
	}
	nullable := lifecycleRecordWire(t, func(m map[string]any) { m["node_uid"] = nil; m["source_time"] = nil })
	other, err := DecodeLifecycleRecord(nullable, "source-a", "epoch")
	if err != nil {
		t.Fatal(err)
	}
	if record.Digest == other.Digest {
		t.Fatal("absent and explicit null were collapsed")
	}
	nullable = bytes.Replace(nullable, []byte(other.Digest), []byte(record.Digest), 1)
	if _, err := DecodeLifecycleRecord(nullable, "source-a", "epoch"); err == nil {
		t.Fatal("used normalized struct digest instead of original wire digest")
	}
}

// TASK-07 applies its JSON collection/string limits to the entire request,
// including otherwise opaque record evidence. Valid digests cannot waive them.
func TestLifecycleJSONLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		value func(int) any
	}{
		{"string bytes", 16384, func(n int) any { return strings.Repeat("a", n) }},
		{"object keys", 256, func(n int) any {
			m := map[string]any{}
			for i := 0; i < n; i++ {
				m[fmt.Sprintf("key_%d", i)] = true
			}
			return m
		}},
		{"array entries", 1000, func(n int) any { return make([]any, n) }},
	} {
		for _, excess := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, tc.limit+excess), func(t *testing.T) {
				record := lifecycleRecordWire(t, func(m map[string]any) {
					m["evidence_refs"] = []any{map[string]any{"evidence": tc.value(tc.limit + excess)}}
				})
				batch := lifecycleWire(t, func(m map[string]any) {
					m["records"] = []any{json.RawMessage(record)}
				})
				_, recordErr := DecodeLifecycleRecord(record, "source-a", "epoch")
				_, batchErr := DecodeLifecycleEnvelope(batch)
				if excess == 0 {
					if recordErr != nil || batchErr != nil {
						t.Fatalf("boundary rejected: record %v, batch %v", recordErr, batchErr)
					}
				} else if !errors.Is(recordErr, ErrSchema) || !errors.Is(batchErr, ErrSchema) {
					t.Fatalf("oversized JSON accepted: record %v, batch %v", recordErr, batchErr)
				}
			})
		}
	}
}
