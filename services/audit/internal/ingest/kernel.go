package ingest

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// KernelRecord is the COMMON producer wire object. source_id and received_at
// are server-owned storage fields; neither is accepted from the producer.
// Optional fields preserve absent-versus-null semantics through the original
// bytes used for digest verification, not by re-marshalling this value.
type KernelRecord struct {
	ID                   string                     `json:"source_event_id"`
	SensorID             string                     `json:"sensor_id"`
	Epoch                string                     `json:"source_epoch"`
	Sequence             int64                      `json:"source_sequence"`
	ExporterInstanceID   string                     `json:"exporter_instance_id"`
	SensorGeneration     int64                      `json:"sensor_generation"`
	NodeUID              string                     `json:"node_uid"`
	BootID               string                     `json:"boot_id"`
	SourceTime           string                     `json:"source_time"`
	SpooledAt            string                     `json:"spooled_at"`
	ProcessExecID        *string                    `json:"process_exec_id"`
	ParentExecID         *string                    `json:"parent_exec_id"`
	ProcessStart         *string                    `json:"process_start"`
	HostPID              *int32                     `json:"host_pid"`
	ContainerID          *string                    `json:"container_id"`
	DockerIDPrefix       *string                    `json:"docker_id_prefix"`
	PodUID               *string                    `json:"pod_uid"`
	NetNSInode           *int64                     `json:"netns_inode"`
	SocketTuple          *KernelSocketTuple         `json:"socket_tuple"`
	SockPtr              *string                    `json:"sock_ptr"`
	TCPNewState          *int16                     `json:"tcp_new_state"`
	LifecycleRecordID    *string                    `json:"lifecycle_record_id"`
	MetadataStatus       string                     `json:"metadata_status"`
	NormalizationVersion string                     `json:"normalization_version"`
	UpstreamEventRef     *string                    `json:"upstream_event_ref"`
	EventType            string                     `json:"event_type"`
	SafeAttributes       map[string]json.RawMessage `json:"safe_attributes"`
	RuleHash             string                     `json:"rule_hash"`
	Coverage             string                     `json:"coverage"`
	Digest               string                     `json:"record_digest"`
}

type KernelSocketTuple struct {
	SAddr string `json:"saddr"`
	SPort uint16 `json:"sport"`
	DAddr string `json:"daddr"`
	DPort uint16 `json:"dport"`
}

// DecodeKernelRecord validates one record, independently of batch storage.
// sensorID must be resolved from trusted source registration; epoch comes from
// the validated batch envelope. This does not authorize node/boot provenance,
// producer grants or historical replay, and cannot itself produce a DB ACK.
// Record validation failures become individual SCHEMA_INVALID rejections.
func DecodeKernelRecord(raw []byte, sensorID, epoch string) (KernelRecord, error) {
	var r KernelRecord
	if len(raw) > canonical.MaxBodyBytes || canonical.CheckStrictJSON(raw) != nil {
		return r, ErrSchema
	}
	var value any
	scan := json.NewDecoder(bytes.NewReader(raw))
	scan.UseNumber()
	if scan.Decode(&value) != nil || limits(value) != nil {
		return r, ErrSchema
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return r, ErrSchema
	}
	// encoding/json accepts case-insensitive names and null scalar values.
	// Require exact COMMON field names and non-null required values first.
	shape, _ := json.Marshal(KernelRecord{})
	var allowed map[string]json.RawMessage
	_ = json.Unmarshal(shape, &allowed)
	for key := range fields {
		if _, ok := allowed[key]; !ok {
			return r, ErrSchema
		}
	}
	for _, key := range []string{"source_event_id", "sensor_id", "source_epoch", "source_sequence", "exporter_instance_id", "sensor_generation", "node_uid", "boot_id", "source_time", "spooled_at", "metadata_status", "normalization_version", "event_type", "safe_attributes", "rule_hash", "coverage", "record_digest"} {
		if v, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return r, ErrSchema
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return r, ErrSchema
	}
	id, err := canonical.KernelEventID(sensorID, epoch, r.Sequence)
	if err != nil || r.ID != id || r.SensorID != sensorID || r.Epoch != epoch || !validUUID(r.NodeUID) || r.SensorGeneration < 1 {
		return r, ErrSchema
	}
	for _, s := range []string{r.ExporterInstanceID, r.BootID, r.MetadataStatus, r.NormalizationVersion, r.Coverage} {
		if s == "" {
			return r, ErrSchema
		}
	}
	for _, s := range []string{r.SourceTime, r.SpooledAt} {
		if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
			return r, ErrSchema
		}
	}
	if r.ProcessStart != nil {
		if _, err := time.Parse(time.RFC3339Nano, *r.ProcessStart); err != nil {
			return r, ErrSchema
		}
	}
	switch r.EventType {
	case "process_exec", "process_exit", "tcp_connect", "file_open", "openat":
		if r.ProcessExecID == nil || *r.ProcessExecID == "" || r.TCPNewState != nil {
			return r, ErrSchema
		}
	case "tcp_state":
		if r.ProcessExecID != nil && *r.ProcessExecID == "" || r.TCPNewState == nil || (*r.TCPNewState != 1 && *r.TCPNewState != 7) {
			return r, ErrSchema
		}
	default:
		return r, ErrSchema
	}
	if r.HostPID != nil && *r.HostPID <= 0 {
		return r, ErrSchema
	}
	if r.NetNSInode != nil && *r.NetNSInode < 0 {
		return r, ErrSchema
	}
	for _, id := range []*string{r.PodUID, r.LifecycleRecordID} {
		if id != nil && !validUUID(*id) {
			return r, ErrSchema
		}
	}
	if r.SockPtr != nil && !kernelHex(*r.SockPtr, 16) {
		return r, ErrSchema
	}
	if r.DockerIDPrefix != nil && !kernelHex(*r.DockerIDPrefix, 15) {
		return r, ErrSchema
	}
	if r.SocketTuple != nil {
		var tuple map[string]json.RawMessage
		if json.Unmarshal(fields["socket_tuple"], &tuple) != nil || len(tuple) != 4 {
			return r, ErrSchema
		}
		for _, key := range []string{"saddr", "sport", "daddr", "dport"} {
			if v, ok := tuple[key]; !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				return r, ErrSchema
			}
		}
		for _, s := range []string{r.SocketTuple.SAddr, r.SocketTuple.DAddr} {
			a, err := netip.ParseAddr(s)
			if err != nil || a.Zone() != "" {
				return r, ErrSchema
			}
		}
	}
	digest, err := canonical.DigestWithoutKeys(raw, "record_digest", "received_at")
	if err != nil || !validDigest(r.RuleHash) || !validDigest(r.Digest) || digest != r.Digest {
		return r, ErrSchema
	}
	return r, nil
}

func kernelHex(s string, size int) bool {
	return len(s) == size && strings.IndexFunc(s, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) == -1
}

// KernelEnvelope is TASK-07's kernel batch variant. Lifecycle-only scope and
// cursor are absent. Records stay raw so per-record failures do not erase valid
// siblings or alter the submitted bytes before digest verification.
type KernelEnvelope struct {
	BatchID   string            `json:"batch_id"`
	Epoch     string            `json:"source_epoch"`
	Records   []json.RawMessage `json:"records"`
	Abandoned []KernelRange     `json:"sequence_range_abandoned"`
	Digest    string            `json:"batch_digest"`
}
type KernelRange struct {
	From   int64  `json:"from_seq"`
	To     int64  `json:"to_seq"`
	Reason string `json:"reason"`
	Digest string `json:"range_digest"`
}

// DecodeKernelEnvelope checks request-wide syntax/digest/limits. Record IDs,
// record digests and abandoned-range identities are individual rejections and
// must be checked by the receiver separately, inside its storage transaction.
func DecodeKernelEnvelope(raw []byte) (KernelEnvelope, error) {
	var b KernelEnvelope
	if len(raw) > canonical.MaxBodyBytes || canonical.CheckStrictJSON(raw) != nil {
		return b, ErrSchema
	}
	var value any
	scan := json.NewDecoder(bytes.NewReader(raw))
	scan.UseNumber()
	if scan.Decode(&value) != nil || limits(value) != nil {
		return b, ErrSchema
	}
	if !kernelRequiredKeys(raw, "batch_id", "source_epoch", "records", "sequence_range_abandoned", "batch_digest") {
		return b, ErrSchema
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || !validUUID(b.BatchID) || b.Epoch == "" || strings.Contains(b.Epoch, "/") || len(b.Records)+len(b.Abandoned) > 100 {
		return b, ErrSchema
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	var ranges []json.RawMessage
	_ = json.Unmarshal(fields["sequence_range_abandoned"], &ranges)
	for _, a := range ranges {
		if !kernelRequiredKeys(a, "from_seq", "to_seq", "reason", "range_digest") {
			return b, ErrSchema
		}
	}
	digest, err := canonical.BatchDigest(raw)
	if err != nil || digest != b.Digest {
		return b, ErrSchema
	}
	return b, nil
}

func kernelRequiredKeys(raw []byte, keys ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if v, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
	}
	return true
}

// CheckKernelRange verifies a single range against the authenticated source and
// batch epoch. Overlap and persisted watermark checks remain the SQL receiver's
// responsibility; invalid digests must not turn into abandoned stored ranges.
func CheckKernelRange(a KernelRange, sourceID, epoch string) error {
	digest, err := canonical.AbandonedRangeDigest(sourceID, "kernel", epoch, a.From, a.To, a.Reason)
	if err != nil || digest != a.Digest {
		return ErrSchema
	}
	return nil
}
