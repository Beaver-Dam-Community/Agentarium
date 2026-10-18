package wal

import (
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// PendingDelivery preserves an immutable cursor-only request before its first send.
// The transport validates Body against source, stream, epoch and PreviousAck.
type PendingDelivery struct {
	SourceID    string `json:"source_id"`
	Stream      string `json:"stream"`
	Epoch       string `json:"epoch"`
	PreviousAck uint64 `json:"previous_ack"`
	Body        []byte `json:"body"`
}
type WatchCheckpoint struct {
	Scope           string `json:"scope"`
	ResourceVersion string `json:"resource_version"`
	Revision        uint64 `json:"checkpoint_revision"`
}
type WatchState struct {
	Scope           string           `json:"scope"`
	RefreshRequired bool             `json:"refresh_required"`
	Checkpoint      *WatchCheckpoint `json:"checkpoint,omitempty"`
}

func (j *Journal) persistDelivery() error {
	if err := j.persist(); err != nil {
		j.failed = true
		return err
	}
	return nil
}
func (j *Journal) Delivery() (*PendingDelivery, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed {
		return nil, errors.New("spool unavailable")
	}
	if j.state.Delivery == nil {
		return nil, nil
	}
	p := *j.state.Delivery
	p.Body = append([]byte(nil), p.Body...)
	return &p, nil
}
func (j *Journal) StoreDelivery(p PendingDelivery) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed || j.state.Delivery != nil {
		return errors.New("spool unavailable or request already pending")
	}
	if len(p.Body) == 0 || len(p.Body) > MaxRecordBytes || canonical.CheckStrictJSON(p.Body) != nil || p.SourceID == "" || (p.Stream != "kernel" && p.Stream != "lifecycle") || !epochPattern.MatchString(p.Epoch) {
		return errors.New("invalid pending delivery")
	}
	var envelope struct {
		Cursor  json.RawMessage   `json:"cursor"`
		Records []json.RawMessage `json:"records"`
		Ranges  []json.RawMessage `json:"sequence_range_abandoned"`
		Scope   string            `json:"scope"`
	}
	if err := json.Unmarshal(p.Body, &envelope); err != nil {
		return err
	}
	if len(envelope.Cursor) == 0 || string(envelope.Cursor) == "null" || len(envelope.Records) != 0 || len(envelope.Ranges) != 0 || j.state.Watch == nil || envelope.Scope != j.state.Watch.Scope || p.Stream != "lifecycle" {
		return errors.New("durable delivery requires a bound cursor-only request")
	}
	for _, position := range j.state.Epochs {
		if position.Acked != position.Reserved {
			return errors.New("cursor crossed unacknowledged WAL")
		}
	}
	position, ok := j.state.Epochs[p.Epoch]
	if !ok && p.Epoch == j.epoch && p.PreviousAck == 0 {
		j.state.Epochs[p.Epoch] = position
		ok = true
	}
	if !ok || position.Acked != p.PreviousAck {
		return errors.New("pending request watermark mismatch")
	}
	if j.used+deliveryBytes(&p) > j.capacity {
		return ErrFull
	}
	p.Body = append([]byte(nil), p.Body...)
	j.state.Delivery = &p
	j.used += deliveryBytes(&p)
	return j.persistDelivery()
}

// FinishDelivery clears a completed request and its checkpoint outcome atomically.
// A stale cursor requires explicit GET/restart; it cannot inherit a fresh revision.
func (j *Journal) FinishDelivery(checkpoint *WatchCheckpoint) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed || j.state.Delivery == nil {
		return errors.New("no available pending request")
	}
	if j.state.Watch == nil {
		return errors.New("watcher not bound")
	}
	if checkpoint != nil && (checkpoint.Scope != j.state.Watch.Scope || checkpoint.ResourceVersion == "" || checkpoint.Revision == 0 || checkpoint.Revision > MaxSequence) {
		return errors.New("invalid committed checkpoint")
	}
	j.state.Watch.RefreshRequired = checkpoint == nil
	if checkpoint != nil {
		cp := *checkpoint
		j.state.Watch.Checkpoint = &cp
	}
	j.used -= deliveryBytes(j.state.Delivery)
	j.state.Delivery = nil
	return j.persistDelivery()
}

// BindWatchScope must run before the first watcher record. Existing unbound WAL
// has unknown provenance and must not silently adopt today's configured scope.
func (j *Journal) BindWatchScope(scope string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed || scope == "" || len(scope) > 16384 || !utf8.ValidString(scope) {
		return errors.New("invalid watcher binding")
	}
	if j.state.Watch != nil {
		if j.state.Watch.Scope != scope {
			return errors.New("watch scope changed")
		}
		return nil
	}
	for _, p := range j.state.Epochs {
		if p.Reserved != 0 {
			return errors.New("existing WAL has no durable watch scope")
		}
	}
	if j.state.Delivery != nil {
		return errors.New("pending request has no watch scope")
	}
	j.state.Watch = &WatchState{Scope: scope, RefreshRequired: true}
	return j.persistDelivery()
}
func (j *Journal) Watch() (WatchState, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed || j.state.Watch == nil {
		return WatchState{}, errors.New("watcher unavailable")
	}
	s := *j.state.Watch
	if s.Checkpoint != nil {
		cp := *s.Checkpoint
		s.Checkpoint = &cp
	}
	return s, nil
}

// ResumeWatch records the authenticated GET result. The caller must restart
// LIST/WATCH from the returned server checkpoint before queuing another cursor.
func (j *Journal) ResumeWatch(checkpoint *WatchCheckpoint) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed || j.state.Watch == nil || j.state.Delivery != nil {
		return errors.New("watcher unavailable or delivery pending")
	}
	if checkpoint != nil && (checkpoint.Scope != j.state.Watch.Scope || checkpoint.ResourceVersion == "" || checkpoint.Revision == 0 || checkpoint.Revision > MaxSequence) {
		return errors.New("invalid server checkpoint")
	}
	j.state.Watch.Checkpoint = nil
	if checkpoint != nil {
		cp := *checkpoint
		j.state.Watch.Checkpoint = &cp
	}
	j.state.Watch.RefreshRequired = false
	return j.persistDelivery()
}

// DrainedPosition permits cursor-only requests only after every earlier record
// in every epoch was acknowledged. No sequence is allocated for a bookmark.
func (j *Journal) DrainedPosition() (string, uint64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed || j.state.Pending != nil || j.state.Delivery != nil {
		return "", 0, errors.New("WAL is not drained")
	}
	for _, p := range j.state.Epochs {
		if p.Acked != p.Reserved {
			return "", 0, errors.New("WAL is not drained")
		}
	}
	return j.epoch, j.state.Epochs[j.epoch].Acked, nil
}

func deliveryBytes(p *PendingDelivery) int64 { raw, _ := json.Marshal(p); return int64(len(raw)) }
