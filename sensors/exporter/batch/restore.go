package batch

import (
	"bytes"
	"errors"
)

// Restore validates a persisted immutable request, including its original digest.
// It never attaches a newly fetched revision to a historical cursor.
func Restore(stream Stream, source, epoch string, previous uint64, body []byte) (*Batch, error) {
	var r request
	if len(body) > MaxBytes || strictDecode(body, &r) != nil || r.Epoch != epoch {
		return nil, errors.New("invalid durable batch")
	}
	b, err := New(Input{Stream: stream, SourceID: source, Epoch: r.Epoch, BatchID: r.BatchID, Scope: r.Scope, PreviousAck: previous, Records: r.Records, Abandoned: r.Abandoned, Cursor: r.Cursor})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(body, b.body) {
		return nil, errors.New("durable batch digest or bytes changed")
	}
	return b, nil
}
func (b *Batch) HasCursor() bool { return b.cursor != nil }
func (b *Batch) Epoch() string   { return b.epoch }

func (b *Batch) Scope() string { return b.scope }

func (b *Batch) IsCursorOnly() bool {
	return b.cursor != nil && len(b.records) == 0 && len(b.ranges) == 0
}
