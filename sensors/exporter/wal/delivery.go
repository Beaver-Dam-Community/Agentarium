package wal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Window is a bounded durable prefix from one epoch. Missing sequences through
// End are recovery gaps; nothing after End may be inferred to be missing.
// Old epochs are drained before the current process's epoch.
type Window struct {
	Epoch      string
	Acked, End uint64
	Records    []Record
	Rejected   map[uint64]bool
}

func (j *Journal) Next(count, byteLimit int) (Window, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed {
		return Window{}, errors.New("spool unavailable")
	}
	if count < 1 || count > 100 || byteLimit < 1 || byteLimit > MaxRecordBytes {
		return Window{}, errors.New("invalid delivery bounds")
	}
	var epochs []string
	for ep, p := range j.state.Epochs {
		if p.Acked < p.Reserved {
			epochs = append(epochs, ep)
		}
	}
	sort.Slice(epochs, func(a, b int) bool {
		if epochs[a] == j.epoch {
			return false
		}
		if epochs[b] == j.epoch {
			return true
		}
		return epochs[a] < epochs[b]
	})
	if len(epochs) == 0 {
		return Window{}, nil
	}
	ep := epochs[0]
	p := j.state.Epochs[ep]
	w := Window{Epoch: ep, Acked: p.Acked, End: p.Reserved, Rejected: map[uint64]bool{}}
	used := 0
	for _, seg := range j.segments {
		if seg.Epoch != ep || seg.Last <= p.Acked {
			continue
		}
		f, err := os.Open(seg.Path)
		if err != nil {
			return Window{}, err
		}
		records, size, err := scanWindow(f, ep, seg.First, nil, p.Acked, count-len(w.Records), byteLimit-used)
		_ = f.Close()
		if err != nil {
			return Window{}, err
		}
		if len(records) == 0 {
			// Metadata said this segment contained unacked records. A file lost
			// after Open is corruption, not a newly inferred recovery gap.
			return Window{}, ErrCorrupt
		}
		for _, r := range records {
			// scanWindow returns an oversized first record so the caller can report it
			// without guessing a gap or silently discarding it.
			if len(w.Records) > 0 && used+len(r.Payload) > byteLimit {
				w.End = w.Records[len(w.Records)-1].Sequence
				return w, nil
			}
			w.Records = append(w.Records, r)
			used += len(r.Payload)
			if j.quarantined[ep][r.Sequence] {
				w.Rejected[r.Sequence] = true
			}
		}
		if size < seg.Size || len(w.Records) >= count || used >= byteLimit {
			w.End = w.Records[len(w.Records)-1].Sequence
			return w, nil
		}
	}
	return w, nil
}

type quarantine struct {
	Version       int             `json:"version"`
	Epoch         string          `json:"epoch"`
	Sequence      uint64          `json:"sequence"`
	Reason        string          `json:"reason"`
	PayloadDigest string          `json:"payload_digest"`
	Payload       json.RawMessage `json:"payload"`
}

func quarantineName(ep string, seq uint64) string { return fmt.Sprintf("rejected-%s-%d.json", ep, seq) }

func (j *Journal) loadQuarantine() error {
	j.quarantined = map[string]map[uint64]bool{}
	paths, err := filepath.Glob(filepath.Join(j.dir, "rejected-*.json"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			f.Close()
			return errors.New("quarantine must be an owner-only regular file")
		}
		raw, err := io.ReadAll(io.LimitReader(f, MaxRecordBytes+4097))
		_ = f.Close()
		if err != nil {
			return err
		}
		if len(raw) > MaxRecordBytes+4096 || canonical.CheckStrictJSON(raw) != nil {
			return errors.New("invalid quarantine JSON")
		}
		var q quarantine
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&q) != nil || q.Version != 1 || q.Reason != "SCHEMA_INVALID" || !epochPattern.MatchString(q.Epoch) || q.Sequence == 0 || filepath.Base(path) != quarantineName(q.Epoch, q.Sequence) {
			return errors.New("invalid quarantine record")
		}
		p, ok := j.state.Epochs[q.Epoch]
		if !ok || q.Sequence > p.Reserved {
			return errors.New("unreserved quarantine record")
		}
		payload, err := canonical.JCS(q.Payload)
		var id struct {
			Epoch    string `json:"source_epoch"`
			Sequence uint64 `json:"source_sequence"`
		}
		if err != nil || len(payload) > MaxRecordBytes || canonical.SHA256Hex(payload) != q.PayloadDigest || json.Unmarshal(payload, &id) != nil || id.Epoch != q.Epoch || id.Sequence != q.Sequence {
			return errors.New("quarantine payload mismatch")
		}
		if j.quarantined[q.Epoch] == nil {
			j.quarantined[q.Epoch] = map[uint64]bool{}
		}
		j.quarantined[q.Epoch][q.Sequence] = true
		j.used += int64(len(raw))
	}
	return nil
}

// QuarantineSchemaRejected durably preserves the original normalized record
// before delivery may replace it with a record_rejected range. Only an explicit,
// authenticated, validated per-record SCHEMA_INVALID response permits this call.
// HTTP failures, ID conflicts, and unknown rejection reasons never authorize it.
// Quarantine files survive ack/segment deletion and count toward spool capacity.
func (j *Journal) QuarantineSchemaRejected(epoch string, sequence uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed {
		return errors.New("spool unavailable")
	}
	p, ok := j.state.Epochs[epoch]
	if !ok || sequence <= p.Acked || sequence > p.Reserved {
		return errors.New("invalid rejection sequence")
	}
	if j.quarantined[epoch][sequence] {
		return nil
	}
	var payload []byte
	for _, seg := range j.segments {
		if seg.Epoch != epoch || sequence < seg.First || sequence > seg.Last {
			continue
		}
		f, err := os.Open(seg.Path)
		if err != nil {
			return err
		}
		records, _, err := scanWindow(f, epoch, seg.First, nil, sequence-1, 1, MaxRecordBytes)
		_ = f.Close()
		if err != nil {
			return err
		}
		if len(records) != 1 || records[0].Sequence != sequence {
			return errors.New("rejected record missing")
		}
		payload = records[0].Payload
		break
	}
	if payload == nil {
		return errors.New("cannot quarantine a missing record")
	}
	q := quarantine{1, epoch, sequence, "SCHEMA_INVALID", canonical.SHA256Hex(payload), payload}
	raw, err := canonical.CanonicalJSON(q)
	if err != nil {
		return err
	}
	if j.used+int64(len(raw)) > j.capacity {
		return ErrFull
	}
	tmp, err := os.CreateTemp(j.dir, "quarantine-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(j.dir, quarantineName(epoch, sequence)))
	}
	if err == nil {
		err = syncDir(j.dir)
	}
	if err != nil {
		j.failed = true
		return err
	}
	if j.quarantined[epoch] == nil {
		j.quarantined[epoch] = map[uint64]bool{}
	}
	j.quarantined[epoch][sequence] = true
	j.used += int64(len(raw))
	return nil
}
