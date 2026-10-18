// Package receivertest is a TASK-10 records:batch fixture for tests. It
// enforces the wire of TASK-10 3.7 "collector batch wire" (PR #170) and records
// violations instead of silently accepting malformed batches.
package receivertest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

const CollectorSAN = "spiffe://agentarium.internal/ns/agent-sensors/sa/netpol-collector"

type Receiver struct {
	ClusterUID string
	mu         sync.Mutex
	Available  bool
	DropNext   bool
	Records    map[string]map[string]any // record_id -> record
	content    map[string]string
	seqs       map[string]map[uint64]bool
	Acked      map[string]uint64
	CaughtUp   []string
	Final      map[string]uint64 // epoch -> recorded through
	Rotation   []map[string]any
	Violations []string
	Batches    int
	// RejectSequence answers SCHEMA_INVALID for that record sequence once,
	// as the COMMON batch API allows for a permanently invalid record.
	RejectSequence uint64
	RejectReason   string // default SCHEMA_INVALID
	Rejections     int
	RejectedRanges int
}

func New(cluster string) *Receiver {
	return &Receiver{ClusterUID: cluster, Records: map[string]map[string]any{}, content: map[string]string{}, seqs: map[string]map[uint64]bool{}, Acked: map[string]uint64{}, Final: map[string]uint64{}}
}

func (r *Receiver) Lock()   { r.mu.Lock() }
func (r *Receiver) Unlock() { r.mu.Unlock() }

func (r *Receiver) bad(f string, a ...any) { r.Violations = append(r.Violations, fmt.Sprintf(f, a...)) }

func strict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing")
	}
	return nil
}

func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.URL.Path != "/internal/network-policy/records:batch" || req.Method != http.MethodPost {
		r.bad("path %s %s", req.Method, req.URL.Path)
		w.WriteHeader(404)
		return
	}
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 || len(req.TLS.PeerCertificates[0].URIs) != 1 || req.TLS.PeerCertificates[0].URIs[0].String() != CollectorSAN {
		r.bad("unregistered caller")
		w.WriteHeader(403)
		return
	}
	if !r.Available {
		w.WriteHeader(503)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 1<<20))
	if err != nil {
		r.bad("oversized")
		w.WriteHeader(413)
		return
	}
	var env struct {
		BatchID   string            `json:"batch_id"`
		Epoch     string            `json:"source_epoch"`
		Records   []json.RawMessage `json:"records"`
		Abandoned []struct {
			From   int64  `json:"from_seq"`
			To     int64  `json:"to_seq"`
			Reason string `json:"reason"`
			Digest string `json:"range_digest"`
		} `json:"sequence_range_abandoned"`
		CaughtUpAt *string `json:"caught_up_at"`
		FinalFlush *struct {
			Through    uint64 `json:"through_sequence"`
			CaughtUpAt string `json:"caught_up_at"`
		} `json:"final_flush"`
		RotationLoss map[string]any `json:"rotation_loss"`
		Digest       string         `json:"batch_digest"`
	}
	if strict(raw, &env) != nil || uuid.Validate(env.BatchID) != nil || len(env.Records)+len(env.Abandoned) > 100 || env.Records == nil || env.Abandoned == nil {
		r.bad("envelope schema")
		w.WriteHeader(422)
		return
	}
	var body map[string]json.RawMessage
	_ = json.Unmarshal(raw, &body)
	delete(body, "batch_digest")
	unsigned, _ := json.Marshal(body)
	jcs, err := canonical.JCS(unsigned)
	if err != nil || canonical.SHA256Hex(jcs) != env.Digest {
		r.bad("batch_digest")
		w.WriteHeader(422)
		return
	}
	if len(env.Epoch) != 128 {
		r.bad("epoch encoding %q", env.Epoch)
		w.WriteHeader(422)
		return
	}
	nodeBytes, err := hex.DecodeString(env.Epoch[:32])
	node, uerr := uuid.FromBytes(nodeBytes)
	if err != nil || uerr != nil {
		r.bad("epoch node")
		w.WriteHeader(422)
		return
	}
	r.Batches++
	if r.seqs[env.Epoch] == nil {
		r.seqs[env.Epoch] = map[uint64]bool{}
	}
	var accepted, dups []string
	rejected := []any{}
	last := uint64(0)
	for _, rec := range env.Records {
		var m map[string]any
		d := json.NewDecoder(bytes.NewReader(rec))
		d.UseNumber()
		if d.Decode(&m) != nil {
			r.bad("record JSON")
			continue
		}
		for _, k := range []string{"record_id", "cluster_uid", "node_uid", "source_epoch", "source_sequence", "node_name", "source_time", "disposition", "direction", "protocol", "src_ip", "src_port", "dest_ip", "dest_port", "src_endpoint", "dest_endpoint", "policies", "count", "normalization_version"} {
			if _, ok := m[k]; !ok {
				r.bad("record missing %s", k)
			}
		}
		if len(m) != 19 {
			r.bad("record has extra fields (received_at is server-owned)")
		}
		seq, _ := m["source_sequence"].(json.Number).Int64()
		id, _ := canonical.NetworkPolicyRecordID(r.ClusterUID, node.String(), env.Epoch, seq)
		if m["record_id"] != id || m["cluster_uid"] != r.ClusterUID || m["node_uid"] != node.String() || m["source_epoch"] != env.Epoch {
			r.bad("record identity %v", m["record_id"])
			continue
		}
		if r.RejectSequence != 0 && uint64(seq) == r.RejectSequence {
			r.RejectSequence = 0
			r.Rejections++
			reason := r.RejectReason
			if reason == "" {
				reason = "SCHEMA_INVALID"
			}
			rejected = append(rejected, map[string]any{"id": id, "reason_codes": []string{reason}})
			continue
		}
		c := string(rec)
		if old, ok := r.content[id]; ok {
			if old != c {
				r.bad("EVENT_ID_CONFLICT %s", id)
			}
			dups = append(dups, id)
		} else {
			r.content[id], r.Records[id] = c, m
			r.seqs[env.Epoch][uint64(seq)] = true
			accepted = append(accepted, id)
		}
		last = max(last, uint64(seq))
	}
	for _, a := range env.Abandoned {
		digest, err := canonical.AbandonedRangeDigest(CollectorSAN, "network_policy", env.Epoch, a.From, a.To, a.Reason)
		if err != nil || digest != a.Digest {
			r.bad("range_digest")
			continue
		}
		if a.Reason == "record_rejected" {
			r.RejectedRanges++
		}
		for s := a.From; s <= a.To; s++ {
			r.seqs[env.Epoch][uint64(s)] = true
		}
		last = max(last, uint64(a.To))
	}
	for r.seqs[env.Epoch][r.Acked[env.Epoch]+1] {
		r.Acked[env.Epoch]++
	}
	if env.CaughtUpAt != nil {
		r.CaughtUp = append(r.CaughtUp, *env.CaughtUpAt)
	}
	recorded := false
	if env.RotationLoss != nil && env.CaughtUpAt != nil {
		r.bad("rotation_loss batch must not claim caught_up_at")
	}
	if f := env.FinalFlush; f != nil {
		// through_sequence is the last allocated sequence (#170): it can be
		// below this batch only if the batch is empty, never zero after acks.
		if (len(env.Records)+len(env.Abandoned) > 0 && f.Through != last) || f.Through < r.Acked[env.Epoch] || env.CaughtUpAt == nil || f.CaughtUpAt != *env.CaughtUpAt {
			r.bad("final_flush must cover the last allocated sequence")
		} else if r.Acked[env.Epoch] >= f.Through {
			r.Final[env.Epoch], recorded = f.Through, true
		}
	}
	if env.RotationLoss != nil {
		r.Rotation = append(r.Rotation, env.RotationLoss)
	}
	if r.DropNext {
		r.DropNext = false
		w.WriteHeader(502)
		return
	}
	nonNil := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	resp, _ := json.Marshal(map[string]any{"batch_id": env.BatchID, "accepted_ids": nonNil(accepted), "duplicate_ids": nonNil(dups), "rejected": rejected, "watermarks": []any{map[string]any{"source_epoch": env.Epoch, "acked_through": r.Acked[env.Epoch]}}, "final_flush_recorded": recorded})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}
