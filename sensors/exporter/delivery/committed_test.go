package delivery

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
)

// Committed sees exactly the records at or below the acknowledged watermark,
// never an accepted ID above it, a schema-rejected one, or one before the ack.
func TestCommittedReceivesOnlyAcknowledgedRecords(t *testing.T) {
	j := journal(t, t.TempDir()+"/spool", "ep", 4)
	through := 0
	s, tlsConfig := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in envelope
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")
		accepted, rejected := []string{}, []any{}
		if through > 0 {
			accepted = []string{observationID("ep", 1), observationID("ep", 3)}
			rejected = []any{map[string]any{"id": observationID("ep", 2), "reason_codes": []string{"SCHEMA_INVALID"}}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"batch_id": in.ID, "accepted_ids": accepted, "duplicate_ids": []string{},
			"rejected": rejected, "watermarks": []any{map[string]any{"source_epoch": "ep", "acked_through": through}}})
	}))
	c, err := batch.NewClient(s.URL, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	var got []uint64
	p, err := New(Config{Journal: j, Client: c, SourceID: "sensor", Stream: batch.Kernel, RecoveryReason: "wal_segment_corrupt", Committed: func(payload []byte) {
		var v struct {
			Seq uint64 `json:"source_sequence"`
		}
		_ = json.Unmarshal(payload, &v)
		got = append(got, v.Seq)
	}})
	if err != nil {
		t.Fatal(err)
	}
	// Stagnant watermark: no record is committed yet.
	if _, err := p.Flush(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("committed before ack: %v %v", got, err)
	}
	through = 1
	if _, err := p.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 3 is accepted but above the watermark; 2 is quarantined.
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("committed %v, want [1]", got)
	}
}
