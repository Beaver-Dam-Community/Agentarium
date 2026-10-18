package netpolcollector

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	"github.com/google/uuid"
)

// CollectorSAN is the netpol-collector KSA identity (TASK-06 3.1).
const CollectorSAN = "spiffe://agentarium.internal/ns/agent-sensors/sa/netpol-collector"

// ReceiverSAN is the TASK-10 connector that owns records:batch.
const ReceiverSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/correlation"

const batchPath = "/internal/network-policy/records:batch"
const maxBatchBytes = 1 << 20
const recoveryReason = "wal_segment_corrupt"

// Record is the NetworkPolicyRecord wire object (COMMON), without the
// server-owned received_at.
type Record struct {
	RecordID             string    `json:"record_id"`
	ClusterUID           string    `json:"cluster_uid"`
	NodeUID              string    `json:"node_uid"`
	SourceEpoch          string    `json:"source_epoch"`
	SourceSequence       uint64    `json:"source_sequence"`
	NodeName             string    `json:"node_name"`
	SourceTime           string    `json:"source_time"`
	Disposition          string    `json:"disposition"`
	Direction            string    `json:"direction"`
	Protocol             string    `json:"protocol"`
	SrcIP                string    `json:"src_ip"`
	SrcPort              *int      `json:"src_port"`
	DestIP               string    `json:"dest_ip"`
	DestPort             *int      `json:"dest_port"`
	SrcEndpoint          *Endpoint `json:"src_endpoint"`
	DestEndpoint         *Endpoint `json:"dest_endpoint"`
	Policies             []Policy  `json:"policies"`
	Count                int64     `json:"count"`
	NormalizationVersion string    `json:"normalization_version"`
}

// WireRecord derives the wire record from the immutable spooled capture.
// It is a pure function of the WAL payload, so a replay sends identical bytes.
func WireRecord(payload []byte, epoch string, sequence uint64) (Record, error) {
	var c Captured
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || c.CaptureVersion != 1 || c.SourceEpoch != epoch || c.SourceSequence != sequence {
		return Record{}, errors.New("spooled capture does not match its WAL position")
	}
	id, err := canonical.NetworkPolicyRecordID(c.ClusterUID, c.NodeUID, epoch, int64(sequence))
	if err != nil {
		return Record{}, err
	}
	o := c.Observation
	return Record{id, c.ClusterUID, c.NodeUID, epoch, sequence, o.NodeName, o.SourceTime, o.Disposition, o.Direction, o.Protocol, o.SrcIP, o.SrcPort, o.DestIP, o.DestPort, o.SrcEndpoint, o.DestEndpoint, o.Policies, o.Count, c.NormalizationVersion}, nil
}

type rangeItem struct {
	From   uint64 `json:"from_seq"`
	To     uint64 `json:"to_seq"`
	Reason string `json:"reason"`
	Digest string `json:"range_digest"`
}
type FinalFlush struct {
	Through    uint64 `json:"through_sequence"`
	CaughtUpAt string `json:"caught_up_at"`
}
type RotationLoss struct {
	DetectedAt string `json:"detected_at"`
	After      uint64 `json:"after_sequence"`
}
type envelope struct {
	BatchID      string            `json:"batch_id"`
	Epoch        string            `json:"source_epoch"`
	Records      []json.RawMessage `json:"records"`
	Abandoned    []rangeItem       `json:"sequence_range_abandoned"`
	CaughtUpAt   *string           `json:"caught_up_at,omitempty"`
	FinalFlush   *FinalFlush       `json:"final_flush,omitempty"`
	RotationLoss *RotationLoss     `json:"rotation_loss,omitempty"`
	Digest       string            `json:"batch_digest,omitempty"`
}
type response struct {
	BatchID    string   `json:"batch_id"`
	Accepted   []string `json:"accepted_ids"`
	Duplicates []string `json:"duplicate_ids"`
	Rejected   []struct {
		ID          string   `json:"id"`
		ReasonCodes []string `json:"reason_codes"`
	} `json:"rejected"`
	Watermarks []struct {
		Epoch   string `json:"source_epoch"`
		Through uint64 `json:"acked_through"`
	} `json:"watermarks"`
	FinalFlushRecorded bool `json:"final_flush_recorded"`
}

// Signals are the optional TASK-10 3.7 fields for the next batch. CaughtUpAt
// and FinalFlush are attached only when the batch carries every pending
// sequence, so the receiver never treats an unsent backlog as read.
type Signals struct {
	CaughtUpAt   *time.Time
	FinalFlush   bool
	RotationLoss *time.Time
}

type Result struct {
	Idle, FinalRecorded, Complete bool
	Epoch                         string
	Acked                         uint64
	Quarantined                   int
	// CaughtUpSent/RotationLossSent report what the acknowledged batch
	// actually carried, so callers do not mistake an older batch for it.
	CaughtUpSent, RotationLossSent bool
}

// RejectedError is a permanent per-record rejection other than SCHEMA_INVALID.
type RejectedError struct {
	ID      string
	Reasons []string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("receiver rejected %s: %v; WAL retained for investigation", e.ID, e.Reasons)
}

type inFlight struct {
	body           []byte
	id, epoch      string
	previous, last uint64
	ids            map[string]bool
	seqs           map[string]uint64
	final, signal  bool
	caughtUp, loss bool
}

// Sender delivers the netpol WAL. It is not safe for concurrent Send calls.
type Sender struct {
	Journal *wal.Journal
	// Epoch is the journal's current process epoch (wal.Open argument).
	Epoch   string
	Client  *http.Client
	Origin  string
	pending *inFlight
}

func (s *Sender) build(sig Signals) (*inFlight, bool, error) {
	w, err := s.Journal.Next(100, maxBatchBytes/2)
	if err != nil {
		return nil, false, err
	}
	pending, err := s.Journal.Pending()
	if err != nil {
		return nil, false, err
	}
	epoch := w.Epoch
	if epoch == "" {
		// Nothing pending: use the journal's real position, never zero.
		epoch = s.Epoch
		w.Acked, _, _ = s.Journal.Position(epoch)
		w.End = w.Acked
	}
	if len(w.Records) == 0 && w.End <= w.Acked && sig.CaughtUpAt == nil && !sig.FinalFlush && sig.RotationLoss == nil {
		return nil, true, nil
	}
	env := envelope{Epoch: epoch, Records: []json.RawMessage{}, Abandoned: []rangeItem{}}
	f := &inFlight{epoch: epoch, previous: w.Acked, last: w.Acked, ids: map[string]bool{}, seqs: map[string]uint64{}}
	next := w.Acked + 1
	addRange := func(from, to uint64, reason string) error {
		digest, err := canonical.AbandonedRangeDigest(CollectorSAN, "network_policy", epoch, int64(from), int64(to), reason)
		if err != nil {
			return err
		}
		env.Abandoned = append(env.Abandoned, rangeItem{from, to, reason, digest})
		f.last = to
		return nil
	}
	for _, r := range w.Records {
		if r.Sequence > next {
			if err := addRange(next, r.Sequence-1, recoveryReason); err != nil {
				return nil, false, err
			}
		}
		if w.Rejected[r.Sequence] {
			if err := addRange(r.Sequence, r.Sequence, "record_rejected"); err != nil {
				return nil, false, err
			}
		} else {
			rec, err := WireRecord(r.Payload, epoch, r.Sequence)
			if err != nil {
				return nil, false, err
			}
			raw, err := canonical.CanonicalJSON(rec)
			if err != nil {
				return nil, false, err
			}
			env.Records = append(env.Records, raw)
			f.ids[rec.RecordID] = true
			f.seqs[rec.RecordID] = r.Sequence
			f.last = r.Sequence
		}
		next = r.Sequence + 1
	}
	if next <= w.End {
		if err := addRange(next, w.End, recoveryReason); err != nil {
			return nil, false, err
		}
	}
	// The batch covers everything pending only if this is the current epoch
	// and no record outside this window remains.
	complete := epoch == s.Epoch && len(pending) == len(w.Records) && w.End == f.last
	if complete && sig.CaughtUpAt != nil {
		t := sig.CaughtUpAt.UTC().Format(time.RFC3339Nano)
		env.CaughtUpAt = &t
		f.signal, f.caughtUp = true, true
		if sig.FinalFlush {
			// The last sequence this epoch allocated (#170).
			_, reserved, _ := s.Journal.Position(epoch)
			env.FinalFlush = &FinalFlush{Through: reserved, CaughtUpAt: t}
			f.final = true
		}
	}
	if sig.RotationLoss != nil && complete {
		_, reserved, _ := s.Journal.Position(epoch)
		env.RotationLoss = &RotationLoss{DetectedAt: sig.RotationLoss.UTC().Format(time.RFC3339Nano), After: reserved}
		f.signal, f.loss = true, true
	}
	if len(env.Records)+len(env.Abandoned) == 0 && !f.signal {
		return nil, true, nil
	}
	id, err := uuid.NewRandomFromReader(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	env.BatchID, f.id = id.String(), id.String()
	unsigned, err := canonical.CanonicalJSON(env)
	if err != nil {
		return nil, false, err
	}
	env.Digest = canonical.SHA256Hex(unsigned)
	f.body, err = canonical.CanonicalJSON(env)
	if err != nil || len(f.body) > maxBatchBytes {
		return nil, false, errors.New("batch envelope exceeds 1 MiB; WAL retained")
	}
	return f, false, nil
}

type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("receiver HTTP status %d", e.Status) }
func (e *HTTPError) Retryable() bool {
	return e.Status == http.StatusRequestTimeout || e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// Send delivers at most one batch. A failed attempt keeps the same batch
// bytes for the next call; only a validated watermark is applied to the WAL.
func (s *Sender) Send(ctx context.Context, sig Signals) (Result, error) {
	// A batch carrying records or ranges is resent with identical bytes until
	// acknowledged. A signal-only batch may be rebuilt with newer signals.
	if s.pending != nil && len(s.pending.ids) == 0 && s.pending.last == s.pending.previous {
		s.pending = nil
	}
	if s.pending == nil {
		f, idle, err := s.build(sig)
		if err != nil {
			return Result{}, err
		}
		if idle {
			acked, _, _ := s.Journal.Position(s.Epoch)
			return Result{Idle: true, Complete: true, Epoch: s.Epoch, Acked: acked}, nil
		}
		s.pending = f
	}
	f := s.pending
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Origin+batchPath, bytes.NewReader(f.body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, &HTTPError{resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBatchBytes+1))
	if err != nil || len(raw) > maxBatchBytes || canonical.CheckJSONForJCS(raw) != nil {
		return Result{}, errors.New("invalid receiver response")
	}
	var r response
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.BatchID != f.id || len(r.Watermarks) != 1 || r.Watermarks[0].Epoch != f.epoch {
		return Result{}, errors.New("invalid receiver acknowledgement")
	}
	// COMMON batch API: a record permanently rejected as SCHEMA_INVALID is
	// quarantined with its original bytes and replaced by a record_rejected
	// range in the next batch. Any other rejection stops delivery.
	quarantined := 0
	for _, rej := range r.Rejected {
		seq, ok := f.seqs[rej.ID]
		if !ok || len(rej.ReasonCodes) != 1 || rej.ReasonCodes[0] != "SCHEMA_INVALID" {
			return Result{}, &RejectedError{ID: rej.ID, Reasons: rej.ReasonCodes}
		}
		if err := s.Journal.QuarantineSchemaRejected(f.epoch, seq); err != nil {
			return Result{}, err
		}
		quarantined++
	}
	seen := map[string]bool{}
	for _, list := range [][]string{r.Accepted, r.Duplicates} {
		for _, id := range list {
			if !f.ids[id] || seen[id] {
				return Result{}, errors.New("acknowledgement names an unsent or repeated record")
			}
			seen[id] = true
		}
	}
	through := min(r.Watermarks[0].Through, f.last)
	if r.Watermarks[0].Through < f.previous || (r.FinalFlushRecorded && (!f.final || through < f.last)) {
		return Result{}, errors.New("invalid watermark or final flush acknowledgement")
	}
	if through > f.previous {
		if err := s.Journal.Ack(f.epoch, through); err != nil {
			return Result{}, err
		}
	}
	complete := through == f.last
	if complete || quarantined > 0 {
		s.pending = nil // rebuild: the next batch carries the record_rejected range
	} else {
		f.previous = through
	}
	return Result{Epoch: f.epoch, Acked: through, FinalRecorded: r.FinalFlushRecorded, Complete: complete, Quarantined: quarantined, CaughtUpSent: complete && f.caughtUp, RotationLossSent: complete && f.loss}, nil
}
