// Package batch implements the TASK-07 producer wire boundary. It never
// deletes WAL records: callers may apply only a successfully validated Ack.
package batch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

var ErrTooLarge = errors.New("batch exceeds 1 MiB")

const MaxBytes = 1 << 20
const MaxRecords = 100
const maxSequence uint64 = 1<<53 - 1

const PodWatcherSource = "spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher"

type Stream string

const (
	Kernel    Stream = "kernel"
	Lifecycle Stream = "lifecycle"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Cursor struct {
	Scope            string `json:"scope"`
	ResourceVersion  string `json:"resource_version"`
	ExpectedRevision uint64 `json:"expected_checkpoint_revision"`
}
type Checkpoint struct {
	Scope           string `json:"scope"`
	ResourceVersion string `json:"resource_version"`
	Revision        uint64 `json:"checkpoint_revision"`
}
type Range struct {
	From   uint64 `json:"from_seq"`
	To     uint64 `json:"to_seq"`
	Reason string `json:"reason"`
	Digest string `json:"range_digest"`
}

type Input struct {
	Stream                   Stream
	SourceID, Epoch, BatchID string
	// Scope is required for the pod watcher and forbidden for runtime sources.
	Scope string
	// PreviousAck is the last durable watermark, never a guessed max sequence.
	PreviousAck uint64
	Records     []json.RawMessage
	Abandoned   []Range
	Cursor      *Cursor
}

type request struct {
	BatchID   string            `json:"batch_id"`
	Epoch     string            `json:"source_epoch"`
	Scope     string            `json:"scope,omitempty"`
	Records   []json.RawMessage `json:"records"`
	Abandoned []Range           `json:"sequence_range_abandoned"`
	Cursor    *Cursor           `json:"cursor,omitempty"`
	Digest    string            `json:"batch_digest,omitempty"`
}
type interval struct{ from, to uint64 }

// Batch is immutable, including its ID, digest and original epoch. Retrying
// Send on the same Batch sends identical bytes, even if the input is mutated.
type Batch struct {
	stream           Stream
	id, epoch, scope string
	body             []byte
	previous, last   uint64
	records          map[string]uint64
	ranges           map[string]interval
	cursor           *Cursor
}

func New(in Input) (*Batch, error) {
	if (in.Stream != Kernel && in.Stream != Lifecycle) || !uuidPattern.MatchString(in.BatchID) || !validText(in.SourceID) || !validText(in.Epoch) || in.PreviousAck > maxSequence {
		return nil, errors.New("invalid batch identity")
	}
	if (len(in.Records)+len(in.Abandoned) == 0 && in.Cursor == nil) || len(in.Records)+len(in.Abandoned) > MaxRecords {
		return nil, errors.New("invalid batch count")
	}
	watcher := in.SourceID == PodWatcherSource
	if watcher && (in.Stream != Lifecycle || !validText(in.Scope)) || !watcher && in.Scope != "" {
		return nil, errors.New("invalid watcher scope")
	}
	if in.Cursor != nil && (!watcher || in.Cursor.Scope != in.Scope || !validText(in.Cursor.ResourceVersion) || in.Cursor.ExpectedRevision > maxSequence) {
		return nil, errors.New("invalid lifecycle cursor")
	}
	b := &Batch{stream: in.Stream, id: in.BatchID, epoch: in.Epoch, scope: in.Scope, previous: in.PreviousAck, records: map[string]uint64{}, ranges: map[string]interval{}}
	r := request{BatchID: in.BatchID, Epoch: in.Epoch, Scope: in.Scope, Records: []json.RawMessage{}, Abandoned: append([]Range{}, in.Abandoned...)}
	if in.Cursor != nil {
		c := *in.Cursor
		b.cursor = &c
		r.Cursor = &c
	}
	var spans []interval
	for _, raw := range in.Records {
		if len(raw) > MaxBytes || canonical.CheckStrictJSON(raw) != nil {
			return nil, errors.New("invalid record JSON")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return nil, errors.New("record must be an object")
		}
		idKey, sourceKey := "source_event_id", "sensor_id"
		if in.Stream == Lifecycle {
			idKey, sourceKey = "lifecycle_event_id", "source_id"
		}
		var id, epoch, source string
		var sequence uint64
		if watcher && strings.HasPrefix(in.Scope, "namespace/") {
			var namespace string
			if json.Unmarshal(fields["namespace"], &namespace) != nil || namespace == "" || namespace != strings.TrimPrefix(in.Scope, "namespace/") {
				return nil, errors.New("record namespace does not match watcher scope")
			}
		}
		if json.Unmarshal(fields[idKey], &id) != nil || !uuidPattern.MatchString(id) || json.Unmarshal(fields[sourceKey], &source) != nil || source != in.SourceID || json.Unmarshal(fields["source_epoch"], &epoch) != nil || epoch != in.Epoch || json.Unmarshal(fields["source_sequence"], &sequence) != nil || sequence <= in.PreviousAck || sequence > maxSequence {
			return nil, errors.New("record identity does not match batch")
		}
		expectedID, err := canonical.KernelEventID(source, epoch, int64(sequence))
		if in.Stream == Lifecycle {
			expectedID, err = canonical.LifecycleEventID(source, epoch, int64(sequence))
		}
		if err != nil || expectedID != id {
			return nil, errors.New("record ID does not match canonical observation identity")
		}
		if _, exists := b.records[id]; exists {
			return nil, errors.New("duplicate record ID")
		}
		b.records[id] = sequence
		spans = append(spans, interval{sequence, sequence})
		r.Records = append(r.Records, append(json.RawMessage(nil), raw...))
	}
	for _, a := range in.Abandoned {
		if a.From <= in.PreviousAck || a.To < a.From || a.To > maxSequence || !validText(a.Reason) || !digestPattern.MatchString(a.Digest) {
			return nil, errors.New("invalid abandoned range")
		}
		digest, err := canonical.AbandonedRangeDigest(in.SourceID, string(in.Stream), in.Epoch, int64(a.From), int64(a.To), a.Reason)
		if err != nil || digest != a.Digest {
			return nil, errors.New("abandoned range digest mismatch")
		}
		key := fmt.Sprintf("%s:%d-%d", in.Epoch, a.From, a.To)
		b.ranges[key] = interval{a.From, a.To}
		spans = append(spans, interval{a.From, a.To})
	}
	// This transport accepts only the next contiguous WAL prefix. It cannot
	// authorize deletion across an unsent hole, including a recovered gap.
	sort.Slice(spans, func(i, j int) bool { return spans[i].from < spans[j].from })
	next := in.PreviousAck + 1
	for _, s := range spans {
		if s.from != next {
			return nil, errors.New("batch overlaps or skips an unacknowledged sequence")
		}
		next = s.to + 1
	}
	b.last = next - 1
	preimage, err := canonical.CanonicalJSON(r)
	if err != nil {
		return nil, err
	}
	r.Digest, err = canonical.BatchDigest(preimage)
	if err != nil {
		return nil, err
	}
	b.body, err = canonical.CanonicalJSON(r)
	if err != nil {
		return nil, err
	}
	if len(b.body) > MaxBytes {
		return nil, ErrTooLarge
	}
	return b, nil
}

func (b *Batch) Bytes() []byte { return append([]byte(nil), b.body...) }

func validText(s string) bool { return s != "" && len(s) <= 16384 && utf8.ValidString(s) }

type Rejection struct {
	ID          string   `json:"id"`
	ReasonCodes []string `json:"reason_codes"`
}
type watermark struct {
	Epoch   string `json:"source_epoch"`
	Through uint64 `json:"acked_through"`
}
type response struct {
	BatchID    string      `json:"batch_id"`
	Accepted   []string    `json:"accepted_ids"`
	Duplicates []string    `json:"duplicate_ids"`
	Rejected   []Rejection `json:"rejected"`
	Watermarks []watermark `json:"watermarks"`
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
}
type Ack struct {
	Epoch string
	// Through is bounded by the verified contiguous prefix in this batch.
	// accepted_ids alone never authorize WAL deletion.
	Through              uint64
	Accepted, Duplicates []string
	Rejected             []Rejection
	Checkpoint           *Checkpoint
}

func (b *Batch) validate(raw []byte) (Ack, error) {
	var r response
	if len(raw) > MaxBytes || strictDecode(raw, &r) != nil || r.BatchID != b.id {
		return Ack{}, errors.New("invalid batch response")
	}
	if len(r.Watermarks) != 1 || r.Watermarks[0].Epoch != b.epoch || r.Watermarks[0].Through < b.previous || r.Watermarks[0].Through > maxSequence {
		return Ack{}, errors.New("invalid watermark")
	}
	through := min(r.Watermarks[0].Through, b.last)
	for _, gap := range b.ranges {
		if gap.from <= through && through < gap.to {
			return Ack{}, errors.New("watermark splits an atomic abandoned range")
		}
	}
	seen := map[string]bool{}
	stored := map[string]bool{}
	known := func(id string) bool { _, record := b.records[id]; _, gap := b.ranges[id]; return record || gap }
	for _, ids := range [][]string{r.Accepted, r.Duplicates} {
		for _, id := range ids {
			if !known(id) || seen[id] {
				return Ack{}, errors.New("unknown or repeated response ID")
			}
			seen[id], stored[id] = true, true
		}
	}
	for _, rejection := range r.Rejected {
		if !known(rejection.ID) || seen[rejection.ID] || len(rejection.ReasonCodes) == 0 {
			return Ack{}, errors.New("invalid rejection")
		}
		seen[rejection.ID] = true
		for _, reason := range rejection.ReasonCodes {
			if reason == "" {
				return Ack{}, errors.New("empty rejection reason")
			}
		}
		if seq, ok := b.records[rejection.ID]; ok && seq <= through {
			return Ack{}, errors.New("watermark crosses rejected record")
		}
		if gap, ok := b.ranges[rejection.ID]; ok && gap.from <= through {
			return Ack{}, errors.New("watermark crosses rejected range")
		}
	}
	for id, seq := range b.records {
		if seq <= through && !stored[id] {
			return Ack{}, errors.New("watermark crosses unconfirmed record")
		}
	}
	if r.Checkpoint != nil && (b.cursor == nil || r.Checkpoint.Scope != b.cursor.Scope || r.Checkpoint.ResourceVersion != b.cursor.ResourceVersion || r.Checkpoint.Revision != b.cursor.ExpectedRevision+1 || r.Checkpoint.Revision > maxSequence || through != b.last || len(r.Rejected) > 0) {
		return Ack{}, errors.New("invalid checkpoint")
	}
	return Ack{b.epoch, through, r.Accepted, r.Duplicates, r.Rejected, r.Checkpoint}, nil
}

// encoding/json's case-insensitive keys and null scalar coercion are not part
// of COMMON. Validate exact field names, presence and nullability first.
func strictDecode(raw []byte, out any) error {
	if err := canonical.CheckStrictJSON(raw); err != nil {
		return err
	}
	if err := shape(raw, reflect.TypeOf(out).Elem()); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
func shape(raw []byte, t reflect.Type) error {
	if t == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return shape(raw, t.Elem())
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("null required value")
	}
	switch t.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil || obj == nil {
			return errors.New("expected object")
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			v, exists := obj[tag[0]]
			if !exists {
				if len(tag) > 1 && tag[1] == "omitempty" {
					continue
				}
				return errors.New("missing field")
			}
			if err := shape(v, f.Type); err != nil {
				return err
			}
			delete(obj, tag[0])
		}
		if len(obj) != 0 {
			return errors.New("unknown field")
		}
	case reflect.Slice:
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return errors.New("expected array")
		}
		for _, item := range items {
			if err := shape(item, t.Elem()); err != nil {
				return err
			}
		}
	default:
		return json.Unmarshal(raw, reflect.New(t).Interface())
	}
	return nil
}
