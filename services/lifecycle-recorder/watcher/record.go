package watcher

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// PodEvent distinguishes a LIST snapshot from a watch transition. Neither an
// ADDED event nor Pod deletion is proof of process creation/exit.
type PodEvent struct {
	Pod      *corev1.Pod
	Type     watch.EventType
	Snapshot bool
}

// Facts contains only COMMON LifecycleRecord fields. No Pod spec/argv/env is
// persisted. An owner-approved normalizer must define transition/mapping/time
// semantics; there is deliberately no production default for those choices.
type Facts struct {
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
	MappingVersion      int32             `json:"mapping_version"`
	EvidenceRefs        []json.RawMessage `json:"evidence_refs"`
	MissingReason       *string           `json:"missing_reason,omitempty"`
}
type lifecycleRecord struct {
	Facts
	ID              string `json:"lifecycle_event_id"`
	SourceID        string `json:"source_id"`
	Epoch           string `json:"source_epoch"`
	Sequence        uint64 `json:"source_sequence"`
	ClusterUID      string `json:"cluster_uid"`
	PodUID          string `json:"pod_uid"`
	Namespace       string `json:"namespace"`
	PodName         string `json:"pod_name"`
	ResourceVersion string `json:"resource_version"`
	Digest          string `json:"record_digest,omitempty"`
}

func prepareRecord(f Facts, cluster, source string, pod *corev1.Pod) (func(string, uint64) ([]byte, error), error) {
	if f.Transition == "" || len(f.Transition) > 16384 || f.EvidenceRefs == nil {
		return nil, errors.New("normalizer returned incomplete lifecycle facts")
	}
	if f.SourceTime != nil {
		if _, err := time.Parse(time.RFC3339Nano, *f.SourceTime); err != nil {
			return nil, errors.New("invalid lifecycle source time")
		}
	}
	if f.NodeUID != nil && !validUUID(*f.NodeUID) {
		return nil, errors.New("invalid observed node UID")
	}
	// Snapshot the callback's mutable memory before handing it to WAL framing.
	raw, err := canonical.CanonicalJSON(f)
	if err != nil {
		return nil, err
	}
	if canonical.CheckStrictJSON(raw) != nil {
		return nil, errors.New("invalid lifecycle facts JSON")
	}
	var frozen Facts
	if err = json.Unmarshal(raw, &frozen); err != nil {
		return nil, err
	}
	uid, namespace, name, rv := string(pod.UID), pod.Namespace, pod.Name, pod.ResourceVersion
	return func(epoch string, sequence uint64) ([]byte, error) {
		id, err := canonical.LifecycleEventID(source, epoch, int64(sequence))
		if err != nil {
			return nil, err
		}
		record := lifecycleRecord{Facts: frozen, ID: id, SourceID: source, Epoch: epoch, Sequence: sequence, ClusterUID: cluster, PodUID: uid, Namespace: namespace, PodName: name, ResourceVersion: rv}
		raw, err := canonical.CanonicalJSON(record)
		if err != nil {
			return nil, err
		}
		record.Digest, err = canonical.DigestWithoutKeys(raw, "record_digest", "received_at")
		if err != nil {
			return nil, err
		}
		return canonical.CanonicalJSON(record)
	}, nil
}
