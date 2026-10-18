package export

import (
	"encoding/json"
	"errors"
)

// recordID extracts the stored primary identifier for a wrapped record.
func recordID(r Record) (string, error) {
	field := map[string]string{"audit_event": "event_id", "kernel_event": "source_event_id", "lifecycle_event": "lifecycle_event_id"}[r.Kind]
	var fields map[string]json.RawMessage
	var id string
	if field == "" || json.Unmarshal(r.Body, &fields) != nil || json.Unmarshal(fields[field], &id) != nil || !validUUID(id) {
		return "", errors.New("record identifier missing")
	}
	return id, nil
}

// A source range describes actual sequenced records in this batch, not a claim
// that every intermediate sequence exists. Gaps remain the ingest watermark's job.
func recordSources(records []Record) ([]Source, error) {
	sources := []Source{}
	positions := map[[2]string]int{}
	for _, record := range records {
		var r struct {
			ID       string `json:"source_id"`
			Epoch    string `json:"source_epoch"`
			Sequence *int64 `json:"source_sequence"`
		}
		if json.Unmarshal(record.Body, &r) != nil || r.ID == "" || r.Epoch == "" {
			return nil, errors.New("record source identity missing")
		}
		// Business events may be unsequenced (COMMON): they are covered by the
		// manifest outbox_range, never by an invented sequence. Kernel and
		// lifecycle rows always carry a stored sequence.
		if r.Sequence == nil && record.Kind == "audit_event" {
			continue
		}
		if r.Sequence == nil || *r.Sequence < 1 || *r.Sequence > MaxSequence {
			return nil, ErrUnsupportedRecord
		}
		pair := [2]string{r.ID, r.Epoch}
		i, ok := positions[pair]
		if !ok {
			positions[pair] = len(sources)
			sources = append(sources, Source{ID: r.ID, Epoch: r.Epoch, First: *r.Sequence, Last: *r.Sequence})
			continue
		}
		if *r.Sequence < sources[i].First {
			sources[i].First = *r.Sequence
		}
		if *r.Sequence > sources[i].Last {
			sources[i].Last = *r.Sequence
		}
	}
	return sources, nil
}

func sameSources(a, b []Source) bool {
	if len(a) != len(b) {
		return false
	}
	byID := map[[2]string]Source{}
	for _, s := range a {
		key := [2]string{s.ID, s.Epoch}
		if _, exists := byID[key]; exists {
			return false
		}
		byID[key] = s
	}
	for _, s := range b {
		if byID[[2]string{s.ID, s.Epoch}] != s {
			return false
		}
	}
	return true
}
