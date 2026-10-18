package watcher

import (
	"context"
	"encoding/json"
	"errors"

	"k8s.io/apimachinery/pkg/watch"
)

// MappingVersion is the version of the source mapping below (#109, #178).
const MappingVersion = 1

// MissingReason marks Pod-level records whose node/boot/container fields the
// watcher does not resolve; the watcher host is never substituted.
const MissingReason = "not_resolved_by_watcher"

// Normalize is the mapping_version 1 Pod mapping (TASK-09 3.6, COMMON
// LifecycleRecord): pod_snapshot for the initial LIST, pod_added /
// pod_modified / pod_deleted for WATCH events. source_time stays null because
// the actual occurrence time is unknown (creationTimestamp is not used) and
// evidence_refs is empty because no durable external reference exists.
// Deletion is not a runtime exit and a snapshot is not process creation.
func Normalize(_ context.Context, e PodEvent) ([]Facts, error) {
	if e.Pod == nil {
		return nil, errors.New("missing Pod")
	}
	transition := ""
	switch {
	case e.Snapshot:
		transition = "pod_snapshot"
	case e.Type == watch.Added:
		transition = "pod_added"
	case e.Type == watch.Modified:
		transition = "pod_modified"
	case e.Type == watch.Deleted:
		transition = "pod_deleted"
	default:
		return nil, errors.New("unsupported Pod event type")
	}
	reason := MissingReason
	return []Facts{{Transition: transition, MappingVersion: MappingVersion, EvidenceRefs: []json.RawMessage{}, MissingReason: &reason}}, nil
}
