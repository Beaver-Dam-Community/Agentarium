package delivery

import (
	"context"
	"errors"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

var ErrCheckpointRefresh = errors.New("restart LIST/WATCH from server checkpoint before queuing a cursor")

// ResumeCheckpoint retrieves the authoritative checkpoint and durably records
// its revision. Call on initial start or after a stale response, with no pending
// request. The caller must restart LIST/WATCH from the returned resourceVersion;
// it must not reuse an old observed cursor with this newly fetched revision.
func (p *Pump) ResumeCheckpoint(ctx context.Context) (*batch.CheckpointResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.config.WatchScope == "" || p.pending != nil {
		return nil, errors.New("watcher unavailable or request pending")
	}
	cp, err := p.config.Client.GetCheckpoint(ctx, p.config.WatchScope)
	if err != nil {
		return nil, err
	}
	var saved *wal.WatchCheckpoint
	if cp != nil {
		saved = &wal.WatchCheckpoint{Scope: cp.Scope, ResourceVersion: cp.ResourceVersion, Revision: cp.Revision}
	}
	if err = p.config.Journal.ResumeWatch(saved); err != nil {
		return nil, err
	}
	return cp, nil
}

// QueueCursor is called only after every LIST page/prior event was durably
// delivered. It persists an empty bookmark with no synthetic record/sequence.
// The caller supplies an observed opaque RV, never a guessed numeric successor.
func (p *Pump) QueueCursor(resourceVersion string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.config.WatchScope == "" || p.pending != nil {
		return errors.New("watcher unavailable or request pending")
	}
	state, err := p.config.Journal.Watch()
	if err != nil {
		return err
	}
	if state.RefreshRequired {
		return ErrCheckpointRefresh
	}
	epoch, acked, err := p.config.Journal.DrainedPosition()
	if err != nil {
		return err
	}
	var expected uint64
	if state.Checkpoint != nil {
		expected = state.Checkpoint.Revision
	}
	id, err := newBatchID()
	if err != nil {
		return err
	}
	b, err := batch.New(batch.Input{Stream: batch.Lifecycle, SourceID: p.config.SourceID, Scope: state.Scope, Epoch: epoch, BatchID: id, PreviousAck: acked, Cursor: &batch.Cursor{Scope: state.Scope, ResourceVersion: resourceVersion, ExpectedRevision: expected}})
	if err != nil {
		return err
	}
	return p.save(&inFlight{batch: b, previous: acked, records: map[string]uint64{}})
}
