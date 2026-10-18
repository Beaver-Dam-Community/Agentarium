// Package delivery drains fsynced WAL prefixes through the authenticated batch
// client. It never treats an HTTP failure as an acknowledgement or abandonment.
package delivery

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

type Config struct {
	Journal    *wal.Journal
	Client     *batch.Client
	SourceID   string
	Stream     batch.Stream
	WatchScope string
	// RecoveryReason is the producer's recorded reason for incomplete WAL frames.
	// The reviewed installation adapter supplies it; it is not a COMMON enum.
	RecoveryReason string
	// Committed, when set, receives each record payload after the collector
	// acknowledged its sequence as committed and the WAL watermark was
	// persisted. Schema-rejected records are not committed. It must not block.
	Committed func(payload []byte)
}

type inFlight struct {
	batch    *batch.Batch
	previous uint64
	records  map[string]uint64
	payloads map[uint64][]byte
}

type Pump struct {
	mu      sync.Mutex
	config  Config
	pending *inFlight
}

func New(c Config) (*Pump, error) {
	if c.Journal == nil || c.Client == nil || c.SourceID == "" || c.RecoveryReason == "" || (c.Stream != batch.Kernel && c.Stream != batch.Lifecycle) {
		return nil, errors.New("delivery requires a journal, authenticated client, source, stream and recovery reason")
	}
	if c.SourceID == batch.PodWatcherSource {
		if c.Stream != batch.Lifecycle || c.WatchScope == "" {
			return nil, errors.New("watcher requires lifecycle stream and scope")
		}
		if err := c.Journal.BindWatchScope(c.WatchScope); err != nil {
			return nil, err
		}
	} else if c.WatchScope != "" {
		return nil, errors.New("runtime cannot have watch scope")
	} else if _, err := c.Journal.Watch(); err == nil {
		return nil, errors.New("watcher WAL cannot become a runtime spool")
	}
	p := &Pump{config: c}
	saved, err := c.Journal.Delivery()
	if err != nil {
		return nil, err
	}
	if saved != nil {
		if saved.SourceID != c.SourceID || saved.Stream != string(c.Stream) {
			return nil, errors.New("durable batch source changed")
		}
		b, err := batch.Restore(c.Stream, c.SourceID, saved.Epoch, saved.PreviousAck, saved.Body)
		if err != nil {
			return nil, err
		}
		if !b.IsCursorOnly() {
			return nil, errors.New("durable request must be cursor-only")
		}
		if b.Scope() != c.WatchScope {
			return nil, errors.New("durable batch scope changed")
		}
		p.pending = &inFlight{batch: b, previous: saved.PreviousAck, records: map[string]uint64{}}
	}
	return p, nil
}

type Result struct {
	Idle        bool
	Acked       uint64
	Quarantined int
}

type attemptError struct{ cause error }

func (e *attemptError) Error() string { return e.cause.Error() }
func (e *attemptError) Unwrap() error { return e.cause }

// Flush attempts one batch, keeping its exact bytes on transport failure or ack
// stagnation. The caller must have one pump per spool. Accepted IDs by themselves
// cannot delete bytes. Cursor-only requests are fsynced with their original
// expected revision; record-only envelopes are rebuilt from WAL after restart.
func (p *Pump) Flush(ctx context.Context) (Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if p.pending == nil {
		w, err := p.config.Journal.Next(batch.MaxRecords, batch.MaxBytes)
		if err != nil {
			return Result{}, err
		}
		if w.Epoch == "" {
			return Result{Idle: true}, nil
		}
		pending, err := p.build(w)
		if err != nil {
			return Result{}, err
		}
		if err = p.save(pending); err != nil {
			return Result{}, err
		}
	}
	current := p.pending
	ack, err := p.config.Client.Send(ctx, current.batch)
	if err != nil {
		return Result{}, &attemptError{err}
	}
	// Validate the entire rejection set before changing the durable local state.
	// A range rejection, ID conflict, or unknown reason requires investigation.
	for _, rejection := range ack.Rejected {
		if _, ok := current.records[rejection.ID]; !ok || len(rejection.ReasonCodes) != 1 || rejection.ReasonCodes[0] != "SCHEMA_INVALID" {
			return Result{}, errors.New("collector rejection requires intervention; WAL retained")
		}
	}
	result := Result{}
	for _, rejection := range ack.Rejected {
		if err := p.config.Journal.QuarantineSchemaRejected(ack.Epoch, current.records[rejection.ID]); err != nil {
			return Result{}, fmt.Errorf("persist rejected record: %w", err)
		}
		result.Quarantined++
	}
	if ack.Through > current.previous {
		if err := p.config.Journal.Ack(ack.Epoch, ack.Through); err != nil {
			return Result{}, fmt.Errorf("persist committed watermark: %w", err)
		}
		result.Acked = ack.Through - current.previous
		if p.config.Committed != nil {
			rejected := map[uint64]bool{}
			for _, rejection := range ack.Rejected {
				rejected[current.records[rejection.ID]] = true
			}
			for _, sequence := range slices.Sorted(maps.Keys(current.payloads)) {
				if sequence > current.previous && sequence <= ack.Through && !rejected[sequence] {
					p.config.Committed(current.payloads[sequence])
				}
			}
		}
	}
	if result.Acked > 0 || result.Quarantined > 0 || current.batch.HasCursor() {
		var cp *wal.WatchCheckpoint
		if ack.Checkpoint != nil {
			cp = &wal.WatchCheckpoint{Scope: ack.Checkpoint.Scope, ResourceVersion: ack.Checkpoint.ResourceVersion, Revision: ack.Checkpoint.Revision}
		}
		if current.batch.HasCursor() {
			if err := p.config.Journal.FinishDelivery(cp); err != nil {
				return Result{}, err
			}
		}
		p.pending = nil
		if current.batch.HasCursor() && ack.Checkpoint == nil {
			return result, ErrCheckpointRefresh
		}
	}
	return result, nil
}

type item struct {
	record   *wal.Record
	from, to uint64
	reason   string
}

func (p *Pump) build(w wal.Window) (*inFlight, error) {
	var items []item
	next := w.Acked + 1
	for n := range w.Records {
		r := &w.Records[n]
		if r.Sequence > next {
			items = append(items, item{from: next, to: r.Sequence - 1, reason: p.config.RecoveryReason})
		}
		if w.Rejected[r.Sequence] {
			items = append(items, item{from: r.Sequence, to: r.Sequence, reason: "record_rejected"})
		} else {
			items = append(items, item{record: r})
		}
		next = r.Sequence + 1
	}
	if next <= w.End {
		items = append(items, item{from: next, to: w.End, reason: p.config.RecoveryReason})
	}
	if len(items) > batch.MaxRecords {
		items = items[:batch.MaxRecords]
	}
	id, err := newBatchID()
	if err != nil {
		return nil, err
	}
	for len(items) > 0 {
		input := batch.Input{Stream: p.config.Stream, SourceID: p.config.SourceID, Epoch: w.Epoch, BatchID: id, PreviousAck: w.Acked, Scope: p.config.WatchScope}
		records := map[string]uint64{}
		payloads := map[uint64][]byte{}
		for _, i := range items {
			if i.record != nil {
				input.Records = append(input.Records, i.record.Payload)
				payloads[i.record.Sequence] = i.record.Payload
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(i.record.Payload, &fields); err != nil {
					return nil, err
				}
				key := "source_event_id"
				if p.config.Stream == batch.Lifecycle {
					key = "lifecycle_event_id"
				}
				var recordID string
				if err := json.Unmarshal(fields[key], &recordID); err != nil {
					return nil, err
				}
				records[recordID] = i.record.Sequence
			} else {
				digest, err := canonical.AbandonedRangeDigest(p.config.SourceID, string(p.config.Stream), w.Epoch, int64(i.from), int64(i.to), i.reason)
				if err != nil {
					return nil, err
				}
				input.Abandoned = append(input.Abandoned, batch.Range{From: i.from, To: i.to, Reason: i.reason, Digest: digest})
			}
		}
		b, err := batch.New(input)
		if err == nil {
			return &inFlight{batch: b, previous: w.Acked, records: records, payloads: payloads}, nil
		}
		if !errors.Is(err, batch.ErrTooLarge) {
			return nil, err
		}
		items = items[:len(items)-1]
	}
	return nil, errors.New("first WAL item cannot fit the batch envelope; WAL retained")
}

// Run flushes idle spools at most one second after data arrives and immediately
// drains a backlog in batches of at most 100. One in-flight request prevents
// overlapping retries. Retry delays cap at 30 seconds and are cancellable.
// Local durability failures, permanent HTTP errors, and invalid acknowledgements
// stop the loop; the supervisor must report unhealthy/hold rather than restart
// it blindly. A transport retry never clears an existing hold.
func (p *Pump) Run(ctx context.Context) error {
	delay := time.Second
	for {
		result, err := p.Flush(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait := time.Duration(0)
		if err != nil {
			var attempt *attemptError
			var status *batch.HTTPError
			var protocol *batch.ProtocolError
			if !errors.As(err, &attempt) || errors.As(err, &protocol) || (errors.As(err, &status) && !status.Retryable()) {
				return err
			}
			wait = delay
			delay = min(2*delay, 30*time.Second)
		} else if result.Idle {
			wait = time.Second
			delay = time.Second
		} else if result.Acked == 0 && result.Quarantined == 0 {
			wait = delay
			delay = min(2*delay, 30*time.Second)
		} else {
			delay = time.Second
		}
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}

func newBatchID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func (p *Pump) save(current *inFlight) error {
	if !current.batch.HasCursor() {
		p.pending = current
		return nil
	}
	err := p.config.Journal.StoreDelivery(wal.PendingDelivery{SourceID: p.config.SourceID, Stream: string(p.config.Stream), Epoch: current.batch.Epoch(), PreviousAck: current.previous, Body: current.batch.Bytes()})
	if err == nil {
		p.pending = current
	}
	return err
}
