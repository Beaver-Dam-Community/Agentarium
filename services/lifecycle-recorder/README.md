# Lifecycle Pod watcher driver (TASK-09 section 3.6)

`watcher` connects the pinned client-go typed Pod API to the existing exporter WAL
and checkpoint Pump. It is a producer driver library, with real LIST/WATCH and
on-disk delivery behavior. `cmd/pod-watcher` is the production command: it
bootstraps its certificate from the identity service, runs one producer while it
holds the `agent-observe/pod-watcher` Lease (client-go leader election), and
exits when leadership is lost so the next leader resumes from the TASK-07
checkpoint. The Deployment is `deploy/gcp/sensors/pod-watcher.yaml`.

The implementation is based on merged #107 and shared specs #93/#94. The Pod
mapping and the WATCH_HISTORY_EXPIRED route follow the #109 owner decision as
written in shared-spec PR #178:

- `Normalize` is the mapping_version 1 normalizer: `pod_snapshot` for the
  initial LIST, `pod_added`/`pod_modified`/`pod_deleted` for WATCH events,
  `source_time` null (never creationTimestamp), empty `evidence_refs`, and
  `missing_reason = "not_resolved_by_watcher"` with no node/boot/container
  fields. Bookmarks and unknown event types are not records.
- `HTTPGapSink.Report` is the production GapSink. It fsyncs the complete
  `POST /internal/control-health/observation-gaps` body with a new `gap_id` in
  the watcher directory before the first attempt, resends the same bytes on
  transport/5xx failures and after a restart, and returns nil only after a
  201 `created` or 200 `existing` acknowledgement naming that `gap_id`.
  403/409/invalid acknowledgements are permanent and keep the request on disk.
  `start_at` is a lower bound of the last committed checkpoint (TASK-07
  `committed_at` on resume, otherwise the time the cursor request was sent, or
  the producer start), clamped to `end_at` on clock skew. On a 410 the driver
  first reads and sends the new LIST, then reports the gap with `end_at` = LIST
  completion, and commits the LIST cursor only after the gap ACK, and the gap is
  `count_quality = unknown`, `recovery_state = unrecoverable` with no sequence
  range. `NewControlHealthClient` pins the control-health URI SAN.

`Open(Config)` requires a typed CoreV1 client, authenticated collector client,
trusted installation cluster UID, one namespace, owner-only durable directory,
and non-nil normalizer and gap sink. The driver chooses `Pods(namespace)` itself
and rejects events outside that namespace. Current support is one namespace per
spool and one producer process; it does not implement cluster-wide scopes or HA.

The normalizer receives a Pod event with an explicit LIST-snapshot flag and must
return a bounded nonempty set of typed COMMON facts. It decides the unresolved
source semantics only when an owner-approved implementation is supplied. The
driver adds Pod identity/resourceVersion, source SAN, durable epoch/sequence,
canonical UUIDv5 and record digest. It does not copy Pod spec/command/env into WAL.
The adapter remains responsible for safe content within the facts it supplies;
there is no production default that silently classifies Pod deletion as process
exit or LIST presence as process creation. Missing/failed normalization stops
progress before committing that event's cursor.

The `GapSink` callback must durably record a watch-history observation before
returning nil. A missing/failed sink stops the loop; no successful relist is
claimed. Unknown watch-history loss is never converted to an invented producer
sequence range/count.

## Durable identity and ordering

The owner-only instance journal stores UUID, scope, trusted cluster UID, restart counter and a checksum.
An exclusive lock covers the producer lifetime. Each open increments and fsyncs
the counter before opening the new WAL epoch `<instance_uuid_32hex>_<counter>`.
A missing initialized journal, changed scope/cluster UID, unsafe file, malformed/checksum-
mismatched state or counter exhaustion fails closed. A counter is never truncated
or reset to recover. The checksum detects accidental changes, not a malicious
storage owner rewriting the checksum. Restore only a complete consistent spool
backup; this does not defend against deliberate filesystem rollback.

`Run(ctx)` first drains historical WAL and any exact pending cursor request, then
loads the collector's authoritative checkpoint. Initial LIST follows every page,
checks that page snapshots agree, and commits only the final snapshot RV after
all prior records are acknowledged. Item RVs never become partial LIST cursors.
Empty LIST creates only a cursor request. Page error, repeated continuation token
or inconsistent snapshot leaves the checkpoint unchanged; already stored facts
are retained. A process restart resumes the server checkpoint after old WAL replay.

WATCH processes each Pod event and its cursor serially. ResourceVersions remain
opaque strings. EOF/recoverable reconnects resume only after preceding observations
are durable. Bookmarks commit cursor-only requests, without synthetic records.
A stale cursor response restarts from server current state; it does not attach a
new revision to the historical cursor.

## Pinned RetryWatcher behavior

[client-go v0.37.1 RetryWatcher](https://github.com/kubernetes/client-go/blob/v0.37.1/tools/watch/retrywatcher.go)
consumes bookmarks without forwarding them, and treats initial HTTP410 differently
from stream Error410. A narrow WatchWithContext wrapper processes/commits events
before forwarding them to RetryWatcher. Thus bookmark persistence finishes before
its internal RV advances. An initial HTTP410 is exposed as the existing Error410
status path, which reaches the mandatory gap sink. No new public event type or
wire field is introduced. The wrapper stops reading after a stream error, and
cancellation joins its workers before returning control to the caller.

After a durable WATCH_HISTORY_EXPIRED report the driver performs a new LIST and
starts WATCH from that completed snapshot. If the gap sink fails, it returns the
error instead. Other HTTP/stream retry behavior remains client-go's; this driver
does not claim to exhaustively classify every Kubernetes error or cache condition.
A real watch-cache eviction/410 test in the target cluster remains required.

## Verification and remaining work

`go test -race ./services/lifecycle-recorder/...` uses actual typed client-go HTTP
requests, real collector mTLS and on-disk WAL/identity files. Test-only adapters
provide explicit fixture facts and a local fsynced gap record. Tests cover paged
LIST, page failure/snapshot change, empty LIST, foreign namespace, durable counter
restart/scope/corruption/overflow, replay of unacked old-epoch records before new
LIST, bookmark ordering, EOF reconnect, initial HTTP410 and stream410, durable-gap-
before-relist, gap failure, stale CAS recovery and cancellation. A direct pinned
RetryWatcher fixture also confirms that its ResultChan omits bookmarks.

`gapsink_test.go` adds a control-health fixture that enforces the #178 contract
(exact pod-watcher SAN, scope allowlist, only ObservationGap fields with the
fixed values, `gap_id` idempotency by body digest, 409 on a changed body) and
covers 503 retry, a committed-but-lost ACK, restart resend of the same `gap_id`,
permanent refusal, the mapping, and a full Run where the relist happens only
after the gap ACK.

The collector is a CAS fixture, not PostgreSQL production ingestion. No live
Kubernetes cluster, real control-health receiver, containerd runtime recorder,
PKI loading, lease publisher, GKE deployment, complete M2-3 or M3 observation was
implemented or verified here. The caller owns client credentials and must stop
Run before Close. This slice does not release holds or declare a node ready.

`go test -race ./services/lifecycle-recorder/cmd/pod-watcher` builds the command
and runs it as a process against mTLS fixtures for identity, TASK-07 (strict:
SAN, mandatory scope, `batch_digest`, canonical `lifecycle_event_id` and
`record_digest`, the #178 mapping values, checkpoint CAS) and control-health
gaps, plus a fake Kubernetes API (Pod LIST/WATCH with a 410, coordination
Lease). It checks the leader lease, the seven transitions in order, no Pod spec
content in records, and that the gap arrives after the relist and before its
cursor commit.
