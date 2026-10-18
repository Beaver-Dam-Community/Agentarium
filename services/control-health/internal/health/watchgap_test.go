package health

import (
	"strings"
	"testing"
)

func TestDecodeWatchGap(t *testing.T) {
	valid := `{"scope":"s","gap":{"gap_id":"6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f","stage":"lifecycle_capture","reason":"WATCH_HISTORY_EXPIRED","source_epoch":"e_1","start_at":"2026-10-17T00:00:00Z","end_at":"2026-10-17T00:01:00Z","loss_count":null,"count_quality":"unknown","recovery_state":"unrecoverable","evidence_refs":[]}}`
	r, err := DecodeWatchGap([]byte(valid))
	if err != nil || len(r.Digest) != 64 {
		t.Fatalf("%+v %v", r, err)
	}
	// JCS: key order and spacing do not change the digest.
	reordered := `{ "gap":{"evidence_refs":[],"recovery_state":"unrecoverable","count_quality":"unknown","loss_count":null,"end_at":"2026-10-17T00:01:00Z","start_at":"2026-10-17T00:00:00Z","source_epoch":"e_1","reason":"WATCH_HISTORY_EXPIRED","stage":"lifecycle_capture","gap_id":"6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f"}, "scope":"s"}`
	if r2, err := DecodeWatchGap([]byte(reordered)); err != nil || r2.Digest != r.Digest {
		t.Fatalf("canonical digest differs: %v", err)
	}
	for name, change := range map[string][2]string{
		"other stage":      {`"stage":"lifecycle_capture"`, `"stage":"kernel_sensor_export"`},
		"other reason":     {`"reason":"WATCH_HISTORY_EXPIRED"`, `"reason":"RUNTIME_RECORD_MISSING"`},
		"loss count":       {`"loss_count":null`, `"loss_count":3`},
		"count quality":    {`"count_quality":"unknown"`, `"count_quality":"exact"`},
		"recovery":         {`"recovery_state":"unrecoverable"`, `"recovery_state":"open"`},
		"start after end":  {`"start_at":"2026-10-17T00:00:00Z"`, `"start_at":"2026-10-17T00:02:00Z"`},
		"sequence range":   {`"evidence_refs":[]`, `"evidence_refs":[],"sequence_from":1`},
		"node identity":    {`"evidence_refs":[]`, `"evidence_refs":[],"node_uid":"6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f"`},
		"body source":      {`"scope":"s"`, `"scope":"s","source_id":"x"`},
		"missing loss":     {`"loss_count":null,`, ``},
		"empty scope":      {`"scope":"s"`, `"scope":""`},
		"non canonical id": {`6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f`, `6F1C2B8E-1D2A-4C3B-9E8F-0A1B2C3D4E5F`},
	} {
		if _, err := DecodeWatchGap([]byte(strings.Replace(valid, change[0], change[1], 1))); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
