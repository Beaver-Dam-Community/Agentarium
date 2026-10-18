package ingest

import (
	"encoding/json"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// LifecycleRecord is the producer wire object, not a storage row. received_at
// belongs to the server (TASK-07 3.1); source_kind is derived from the registered
// caller, so neither can be supplied by the producer.
type LifecycleRecord struct {
	ID                  string            `json:"lifecycle_event_id"`
	SourceID            string            `json:"source_id"`
	Epoch               string            `json:"source_epoch"`
	Sequence            int64             `json:"source_sequence"`
	ClusterUID          string            `json:"cluster_uid"`
	PodUID              string            `json:"pod_uid"`
	Namespace           string            `json:"namespace"`
	PodName             string            `json:"pod_name"`
	NodeUID             *string           `json:"node_uid,omitempty"`
	BootID              *string           `json:"boot_id,omitempty"`
	ContainerID         *string           `json:"container_id,omitempty"`
	CgroupsPath         *string           `json:"cgroups_path,omitempty"`
	CgroupInode         *int64            `json:"cgroup_inode,omitempty"`
	ContainerName       *string           `json:"container_name,omitempty"`
	RestartInstance     *int32            `json:"restart_instance,omitempty"`
	ImageID             *string           `json:"image_id,omitempty"`
	ImageManifestDigest *string           `json:"image_manifest_digest,omitempty"`
	Transition          string            `json:"transition"`
	SourceTime          *string           `json:"source_time,omitempty"`
	ResourceVersion     *string           `json:"resource_version,omitempty"`
	MappingVersion      int32             `json:"mapping_version"`
	EvidenceRefs        []json.RawMessage `json:"evidence_refs"`
	MissingReason       *string           `json:"missing_reason,omitempty"`
	Digest              string            `json:"record_digest"`
}

// DecodeLifecycleRecord verifies fields, UUID and the owner-approved digest
// rule: SHA256(JCS(record without record_digest and received_at)). It does not
// re-marshal the struct for hashing: absent and explicit null fields differ.
// Callers turn ErrSchema into an individual SCHEMA_INVALID result, not a
// batch-wide HTTP 422. Producer grants and current node/boot require DB checks.
func DecodeLifecycleRecord(raw []byte, source, epoch string) (LifecycleRecord, error) {
	var r LifecycleRecord
	if len(raw) > canonical.MaxBodyBytes || strictObject(raw, &r) != nil {
		return r, ErrSchema
	}
	id, err := canonical.LifecycleEventID(source, epoch, r.Sequence)
	if err != nil || r.ID != id || r.SourceID != source || r.Epoch != epoch || !canonicalUUID(r.ClusterUID) || !canonicalUUID(r.PodUID) ||
		!validLifecycleText(r.Namespace) || !validLifecycleText(r.PodName) || !validLifecycleText(r.Transition) {
		return r, ErrSchema
	}
	if r.NodeUID != nil && !canonicalUUID(*r.NodeUID) {
		return r, ErrSchema
	}
	if r.SourceTime != nil {
		if _, err := time.Parse(time.RFC3339Nano, *r.SourceTime); err != nil {
			return r, ErrSchema
		}
	}
	// Transition vocabulary and evidence reference content are not narrowed
	// beyond COMMON here; inventing enums would reject valid watcher records.
	digest, err := canonical.DigestWithoutKeys(raw, "record_digest", "received_at")
	if err != nil || digest != r.Digest {
		return r, ErrSchema
	}
	return r, nil
}
