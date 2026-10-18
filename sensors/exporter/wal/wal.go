// Package wal implements TASK-09's AGW1 durability boundary. Only fsynced
// records are exposed to transport. A spool is owned by exactly one process.
package wal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"syscall"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

const MaxSegmentBytes int64 = 64 << 20
const DefaultCapacity int64 = 256 << 20
const MaxRecordBytes = 1 << 20
const MaxSequence uint64 = 9007199254740991

var ErrFull = errors.New("spool capacity reached")
var ErrCorrupt = errors.New("WAL corruption before final frame")
var epochPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var crcTable = crc32.MakeTable(crc32.Castagnoli)

type Checkpoint struct {
	Inode        uint64 `json:"inode"`
	Offset       int64  `json:"offset"`
	Device       uint64 `json:"device,omitempty"`
	PrefixDigest string `json:"prefix_digest,omitempty"`
}
type position struct {
	Reserved uint64 `json:"reserved"`
	Acked    uint64 `json:"acked"`
}
type reservation struct {
	Epoch      string     `json:"epoch"`
	Sequence   uint64     `json:"sequence"`
	Checkpoint Checkpoint `json:"checkpoint"`
}
type state struct {
	SchemaRejected uint64              `json:"schema_rejected,omitempty"`
	Delivery       *PendingDelivery    `json:"delivery,omitempty"`
	Watch          *WatchState         `json:"watch,omitempty"`
	Version        int                 `json:"version"`
	Pending        *reservation        `json:"pending,omitempty"`
	Epochs         map[string]position `json:"epochs"`
	Checkpoint     Checkpoint          `json:"checkpoint"`
}
type Record struct {
	Epoch    string
	Sequence uint64
	Payload  []byte
}
type Gap struct {
	Epoch    string
	From, To uint64
}
type segment struct {
	Path, Epoch string
	First, Last uint64
	Size        int64
}
type Journal struct {
	mu             sync.Mutex
	dir, epoch     string
	capacity, used int64
	ackProgress    uint64
	lock           *os.File
	state          state
	segments       []segment
	failed, closed bool
	quarantined    map[string]map[uint64]bool
	syncStateDir   func(string) error // defaults to syncDir; permits deterministic I/O failure tests
}

func syncDir(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (j *Journal) persist() error {
	raw, e := json.Marshal(j.state)
	if e != nil {
		return e
	}
	tmp, e := os.CreateTemp(j.dir, "state-")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	if _, e = tmp.Write(raw); e == nil {
		e = tmp.Sync()
	}
	closeErr := tmp.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(tmp.Name(), filepath.Join(j.dir, "state.json")); e != nil {
		return e
	}
	if j.syncStateDir != nil {
		return j.syncStateDir(j.dir)
	}
	return syncDir(j.dir)
}
func Open(dir, epoch string, capacity int64) (j *Journal, err error) {
	if !epochPattern.MatchString(epoch) {
		return nil, errors.New("unsafe epoch")
	}
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("spool directory must be owner-only")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("spool in use")
	}
	j = &Journal{dir: dir, epoch: epoch, capacity: capacity, lock: lock, state: state{Version: 1, Epochs: map[string]position{}}}
	success := false
	defer func() {
		if !success {
			_ = j.Close()
		}
	}()
	b, e := os.ReadFile(filepath.Join(dir, "state.json"))
	if e == nil {
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if d.Decode(&j.state) != nil || d.Decode(new(any)) != io.EOF || j.state.Version != 1 || j.state.Epochs == nil {
			return j, errors.New("invalid spool state")
		}
	} else if !os.IsNotExist(e) {
		return j, e
	} else {
		entries, _ := filepath.Glob(filepath.Join(dir, "wal-*.seg"))
		_, markerErr := os.Stat(filepath.Join(dir, "initialized"))
		if markerErr != nil && !os.IsNotExist(markerErr) {
			return j, markerErr
		}
		if len(entries) != 0 || markerErr == nil {
			return j, errors.New("missing spool state")
		}
	}
	for ep, p := range j.state.Epochs {
		if !epochPattern.MatchString(ep) || p.Reserved > MaxSequence || p.Acked > p.Reserved {
			return j, errors.New("invalid sequence state")
		}
	}
	if j.state.SchemaRejected > MaxSequence {
		return j, errors.New("invalid schema rejection count")
	}
	if j.state.Checkpoint.Offset < 0 {
		return j, errors.New("invalid checkpoint state")
	}
	if r := j.state.Pending; r != nil {
		p, ok := j.state.Epochs[r.Epoch]
		if !ok || r.Sequence == 0 || r.Sequence != p.Reserved || r.Sequence <= p.Acked || r.Checkpoint.Offset < 0 {
			return j, errors.New("invalid pending reservation")
		}
	}
	files, e := filepath.Glob(filepath.Join(dir, "wal-*.seg"))
	if e != nil {
		return j, e
	}
	// Count all retained bytes before recovery writes another durable copy.
	if e = j.loadQuarantine(); e != nil {
		return j, e
	}
	if e = j.loadDamage(); e != nil {
		return j, e
	}
	for _, path := range files {
		info, e := os.Lstat(path)
		if e != nil {
			return j, e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > MaxSegmentBytes {
			return j, errors.New("segment must be an owner-only regular file within its size limit")
		}
		j.used += info.Size()
	}
	for _, path := range files {
		var seg segment
		name := filepath.Base(path)
		base := name[4 : len(name)-4]
		split := -1
		for n := len(base) - 1; n >= 0; n-- {
			if base[n] == '-' {
				split = n
				break
			}
		}
		if split < 1 {
			return j, errors.New("invalid segment name")
		}
		seg.Epoch = base[:split]
		seg.First, e = strconv.ParseUint(base[split+1:], 10, 53)
		seg.Path = path
		p, ok := j.state.Epochs[seg.Epoch]
		if e != nil || seg.First == 0 || !ok || seg.First > p.Reserved {
			return j, errors.New("unreserved segment")
		}
		f, e := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return j, e
		}
		info, e := f.Stat()
		if e != nil {
			f.Close()
			return j, e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > MaxSegmentBytes {
			f.Close()
			return j, errors.New("segment changed to an invalid file during recovery")
		}
		records, size, e := scan(f, seg.Epoch, seg.First, func(offset, total int64, sequence uint64, reason string) error {
			return j.preserveDamage(f, seg.Epoch, seg.First, sequence, offset, total, reason)
		})
		_ = f.Close()
		if e != nil {
			return j, e
		}
		seg.Size = size
		if len(records) > 0 {
			seg.Last = records[len(records)-1].Sequence
		}
		if seg.Last > p.Reserved {
			return j, errors.New("unreserved record")
		}
		if r := j.state.Pending; r != nil && r.Epoch == seg.Epoch {
			for _, record := range records {
				if record.Sequence == r.Sequence {
					j.state.Checkpoint = r.Checkpoint
				}
			}
		}
		j.used -= info.Size() - size
		j.segments = append(j.segments, seg)
	}
	sort.Slice(j.segments, func(a, b int) bool {
		if j.segments[a].Epoch != j.segments[b].Epoch {
			return j.segments[a].Epoch < j.segments[b].Epoch
		}
		return j.segments[a].First < j.segments[b].First
	})
	for i := 1; i < len(j.segments); i++ {
		a, b := j.segments[i-1], j.segments[i]
		if a.Epoch == b.Epoch && a.Last >= b.First {
			return j, errors.New("overlapping segments")
		}
	}
	if d := j.state.Delivery; d != nil {
		p, ok := j.state.Epochs[d.Epoch]
		if !ok || d.PreviousAck > p.Acked || len(d.Body) == 0 || len(d.Body) > MaxRecordBytes || canonical.CheckStrictJSON(d.Body) != nil {
			return j, errors.New("invalid pending delivery state")
		}
		j.used += deliveryBytes(d)
	}
	if w := j.state.Watch; w != nil {
		if w.Scope == "" {
			return j, errors.New("invalid durable watch scope")
		}
		if cp := w.Checkpoint; cp != nil && (cp.Scope != w.Scope || cp.ResourceVersion == "" || cp.Revision == 0 || cp.Revision > MaxSequence) {
			return j, errors.New("invalid durable watch checkpoint")
		}
	}
	j.state.Pending = nil
	if e = j.persist(); e != nil {
		return j, e
	}
	marker, e := os.OpenFile(filepath.Join(dir, "initialized"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return j, e
	}
	e = marker.Sync()
	closeErr := marker.Close()
	if e != nil {
		return j, e
	}
	if closeErr != nil {
		return j, closeErr
	}
	if e = syncDir(dir); e != nil {
		return j, e
	}
	success = true
	return j, nil
}

type repairTail func(offset, total int64, sequence uint64, reason string) error

func scan(f *os.File, epoch string, first uint64, repair repairTail) ([]Record, int64, error) {
	return scanWindow(f, epoch, first, repair, 0, 0, 0)
}

// Limits bound pending payload memory; recovery uses the unlimited scan wrapper.
func scanWindow(f *os.File, epoch string, first uint64, repair repairTail, after uint64, count, byteLimit int) (records []Record, size int64, err error) {
	payloadBytes := 0
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	total := info.Size()
	seq := first
	trim := func(reason string) ([]Record, int64, error) {
		if repair == nil {
			return nil, size, io.ErrUnexpectedEOF
		}
		if e := repair(size, total, seq, reason); e != nil {
			return nil, size, e
		}
		if e := f.Truncate(size); e != nil {
			return nil, size, e
		}
		return records, size, f.Sync()
	}
	for size < total {
		if count > 0 && len(records) >= count {
			return records, size, nil
		}
		header := make([]byte, 12)
		if _, err = io.ReadFull(f, header); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, size, err
			}
			return trim("partial_header")
		}
		length := int64(binary.BigEndian.Uint32(header[4:8]))
		if string(header[:4]) != "AGW1" || length == 0 || length > MaxRecordBytes {
			return nil, size, ErrCorrupt
		}
		if size+12+length > total {
			return trim("partial_payload")
		}
		payload := make([]byte, length)
		if _, err = io.ReadFull(f, payload); err != nil {
			return nil, size, err
		}
		if crc32.Checksum(payload, crcTable) != binary.BigEndian.Uint32(header[8:12]) {
			if size+12+length == total {
				return trim("crc_mismatch")
			}
			return nil, size, ErrCorrupt
		}
		var id struct {
			Epoch    string `json:"source_epoch"`
			Sequence uint64 `json:"source_sequence"`
		}
		canonicalPayload, e := canonical.JCS(payload)
		if e != nil || canonical.CheckStrictJSON(payload) != nil || !bytes.Equal(payload, canonicalPayload) || json.Unmarshal(payload, &id) != nil || id.Epoch != epoch || id.Sequence != seq {
			return nil, size, ErrCorrupt
		}
		if seq > after {
			if byteLimit > 0 && len(records) > 0 && payloadBytes+len(payload) > byteLimit {
				return records, size, nil
			}
			records = append(records, Record{epoch, seq, payload})
			payloadBytes += len(payload)
		}
		seq++
		size += 12 + length
	}
	return records, size, nil
}

// Append reserves the sequence durably before writing its frame. If a process
// dies between reservation and fsync, RecoveryGaps reports that exact sequence.
// Checkpoint advances only after frame fsync, so upstream file bytes are replayable.
func (j *Journal) Append(build func(string, uint64) ([]byte, error), checkpoint Checkpoint) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed {
		return Record{}, errors.New("spool unavailable")
	}
	p := j.state.Epochs[j.epoch]
	if p.Reserved >= MaxSequence {
		return Record{}, errors.New("sequence exhausted")
	}
	seq := p.Reserved + 1
	payload, e := build(j.epoch, seq)
	if e != nil {
		return Record{}, e
	}
	if e = canonical.CheckStrictJSON(payload); e != nil {
		return Record{}, e
	}
	payload, e = canonical.JCS(payload)
	if e != nil {
		return Record{}, e
	}
	var id struct {
		Epoch    string `json:"source_epoch"`
		Sequence uint64 `json:"source_sequence"`
	}
	if json.Unmarshal(payload, &id) != nil || id.Epoch != j.epoch || id.Sequence != seq {
		return Record{}, errors.New("record sequence mismatch")
	}
	if len(payload) > MaxRecordBytes {
		return Record{}, errors.New("record too large")
	}
	size := int64(12 + len(payload))
	if j.used+size > j.capacity {
		return Record{}, ErrFull
	}
	if checkpoint.Offset < 0 || (checkpoint.Inode == j.state.Checkpoint.Inode && checkpoint.Device == j.state.Checkpoint.Device && checkpoint.PrefixDigest == j.state.Checkpoint.PrefixDigest && checkpoint.Offset < j.state.Checkpoint.Offset) {
		return Record{}, errors.New("invalid checkpoint")
	}
	p.Reserved = seq
	j.state.Epochs[j.epoch] = p
	j.state.Pending = &reservation{j.epoch, seq, checkpoint}
	if e = j.persist(); e != nil {
		j.failed = true
		return Record{}, e
	}
	index := -1
	for n := len(j.segments) - 1; n >= 0; n-- {
		seg := j.segments[n]
		if seg.Epoch == j.epoch && seg.Last+1 == seq && seg.Size+size <= MaxSegmentBytes {
			index = n
			break
		}
	}
	if index < 0 {
		j.segments = append(j.segments, segment{Path: filepath.Join(j.dir, fmt.Sprintf("wal-%s-%d.seg", j.epoch, seq)), Epoch: j.epoch, First: seq})
		index = len(j.segments) - 1
	}
	seg := &j.segments[index]
	f, e := os.OpenFile(seg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		j.failed = true
		return Record{}, e
	}
	frame := make([]byte, 12+len(payload))
	copy(frame, "AGW1")
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
	binary.BigEndian.PutUint32(frame[8:12], crc32.Checksum(payload, crcTable))
	copy(frame[12:], payload)
	n, e := f.Write(frame)
	if e == nil && n != len(frame) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		j.failed = true
		return Record{}, e
	}
	if e = syncDir(j.dir); e != nil {
		j.failed = true
		return Record{}, e
	}
	seg.Last = seq
	seg.Size += size
	j.used += size
	j.state.Checkpoint = checkpoint
	j.state.Pending = nil
	if e = j.persist(); e != nil {
		j.failed = true
		return Record{}, e
	}
	return Record{j.epoch, seq, payload}, nil
}
func (j *Journal) Pending() ([]Record, error) { j.mu.Lock(); defer j.mu.Unlock(); return j.pending() }
func (j *Journal) pending() ([]Record, error) {
	if j.closed || j.failed {
		return nil, errors.New("spool unavailable")
	}
	var result []Record
	for _, s := range j.segments {
		f, e := os.Open(s.Path)
		if e != nil {
			return nil, e
		}
		records, _, e := scan(f, s.Epoch, s.First, nil)
		_ = f.Close()
		if e != nil {
			return nil, e
		}
		for _, r := range records {
			if r.Sequence > j.state.Epochs[r.Epoch].Acked {
				result = append(result, r)
			}
		}
	}
	return result, nil
}
func (j *Journal) RecoveryGaps() ([]Gap, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	records, e := j.pending()
	if e != nil {
		return nil, e
	}
	byEpoch := map[string][]uint64{}
	for _, r := range records {
		byEpoch[r.Epoch] = append(byEpoch[r.Epoch], r.Sequence)
	}
	gaps := []Gap{}
	for ep, p := range j.state.Epochs {
		seqs := byEpoch[ep]
		sort.Slice(seqs, func(a, b int) bool { return seqs[a] < seqs[b] })
		next := p.Acked + 1
		for _, seq := range seqs {
			if seq > next {
				gaps = append(gaps, Gap{ep, next, seq - 1})
			}
			next = seq + 1
		}
		if next <= p.Reserved {
			gaps = append(gaps, Gap{ep, next, p.Reserved})
		}
	}
	sort.Slice(gaps, func(a, b int) bool {
		if gaps[a].Epoch != gaps[b].Epoch {
			return gaps[a].Epoch < gaps[b].Epoch
		}
		return gaps[a].From < gaps[b].From
	})
	return gaps, nil
}
func (j *Journal) Ack(epoch string, through uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed {
		return errors.New("spool unavailable")
	}
	p, ok := j.state.Epochs[epoch]
	if !ok || through < p.Acked || through > p.Reserved {
		return errors.New("invalid watermark")
	}
	delta := through - p.Acked
	if ^uint64(0)-j.ackProgress < delta {
		j.failed = true
		return errors.New("ack progress overflow")
	}
	p.Acked = through
	j.state.Epochs[epoch] = p
	if e := j.persist(); e != nil {
		j.failed = true
		return e
	}
	// Only the fsynced watermark counts as progress, including abandoned ranges.
	j.ackProgress += delta
	kept := []segment{}
	for _, seg := range j.segments {
		if seg.Epoch == epoch && seg.Last <= through && seg.First <= through {
			if e := os.Remove(seg.Path); e != nil {
				j.failed = true
				return e
			}
			j.used -= seg.Size
		} else {
			kept = append(kept, seg)
		}
	}
	j.segments = kept
	if err := syncDir(j.dir); err != nil {
		j.failed = true
		return err
	}
	return nil
}

// AdvanceFiltered checkpoints an upstream record excluded before sequence
// allocation. The caller must not use this to skip malformed or lost records.
func (j *Journal) AdvanceFiltered(checkpoint Checkpoint) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed {
		return errors.New("spool unavailable")
	}
	if checkpoint.Offset < 0 || (checkpoint.Inode == j.state.Checkpoint.Inode && checkpoint.Device == j.state.Checkpoint.Device && checkpoint.PrefixDigest == j.state.Checkpoint.PrefixDigest && checkpoint.Offset < j.state.Checkpoint.Offset) {
		return errors.New("invalid checkpoint")
	}
	j.state.Checkpoint = checkpoint
	if err := j.persist(); err != nil {
		j.failed = true
		return err
	}
	return nil
}

func (j *Journal) Checkpoint() Checkpoint {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state.Checkpoint
}

// HealthSnapshot is an atomic view for the sensor health supervisor. Pending
// includes reserved gaps and rejected records until the collector commits them.
// AckProgress counts durable contiguous advances during this process only.
type HealthSnapshot struct {
	Used, Capacity int64
	Pending        bool
	AckProgress    uint64
}

func (j *Journal) HealthSnapshot() (HealthSnapshot, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed {
		return HealthSnapshot{}, errors.New("spool unavailable")
	}
	s := HealthSnapshot{Used: j.used, Capacity: j.capacity, AckProgress: j.ackProgress, Pending: j.state.Delivery != nil}
	for _, p := range j.state.Epochs {
		if p.Reserved > p.Acked {
			s.Pending = true
			break
		}
	}
	return s, nil
}

func (j *Journal) Usage() (int64, int64) { j.mu.Lock(); defer j.mu.Unlock(); return j.used, j.capacity }
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	_ = syscall.Flock(int(j.lock.Fd()), syscall.LOCK_UN)
	return j.lock.Close()
}

// Position returns the durable acknowledged watermark and the last reserved
// sequence of an epoch. ok is false for an epoch with no state.
func (j *Journal) Position(epoch string) (acked, reserved uint64, ok bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	p, found := j.state.Epochs[epoch]
	if !found {
		return 0, 0, false
	}
	return p.Acked, p.Reserved, true
}
