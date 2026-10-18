# Sensor exporter durability (TASK-09 section 3.3)

`wal` and `tailer` implement the local JSON-file-to-WAL durability boundary;
`batch` implements the producer's HTTPS request and acknowledgement boundary,
`acquire.Collector` checkpoints prepared input, and `delivery.Pump` runs bounded
WAL delivery and retry.
This is a library checkpoint, not a deployed or complete node sensor.

The single-process journal holds a filesystem lock, reserves each sequence in
fsynced state, appends an AGW1/length/CRC32C/JCS frame, fsyncs it, and commits the
input device/inode, first-line SHA-256 and offset. Recovery completes an interrupted checkpoint commit only if
the corresponding valid frame exists. Otherwise the reserved sequence becomes
an exact `RecoveryGaps` interval. Incomplete final frames and final CRC failures
are truncated only after the exact damaged tail is durably quarantined.
Corruption before another frame, invalid magic or impossible length stops
recovery and preserves the segment.

A `damaged-<metadata SHA-256>.bin` file stores `AGQ1`, a big-endian uint32 JSON
metadata length, bounded metadata and the unchanged damaged bytes. The metadata
records epoch, segment first sequence, affected sequence, byte offset, local
cause, byte count and SHA-256 of the tail. These are local recovery fields, not
new wire fields or reason enums. The file is 0600 and is fsynced before atomic
publication and directory fsync; only then is the original segment truncated
and fsynced. A published copy is reused after a crash or failed truncation.

Recovery validates retained evidence and counts it toward spool capacity even
after the corresponding gap has been acknowledged and its segment deleted.
Capacity includes both the original segment and the new copy during recovery;
insufficient capacity leaves the original untouched. Unpublished
`damage-pending-*` files left by a crash are retained and counted too, but cannot
authorize truncation. Quarantine is not automatically deleted by ack or TTL.
Malformed metadata, payload hash mismatches, broad permissions and symlinked
evidence stop recovery. This preserves available bytes on the local volume;
loss of the volume itself remains outside this guarantee.

Old epochs and canonical payload bytes survive restart unchanged. Start a new
process with a new boot/instance epoch; replay the old pending epochs first.
The journal accepts positive JSON-safe sequence values up to 2^53-1. Its default
capacity is 256 MiB, segment limit 64 MiB, and record limit 1 MiB. Current appends
fsync each record, which is within the specified one-second/100-record maximum
flush interval; throughput and disk pressure need measurement on the target node.

Call `Ack` only with a verified TASK-07 committed watermark. It persists the
watermark before deleting segments and never deletes a partly acknowledged
segment. The library itself cannot authenticate server acknowledgements.
`AdvanceFiltered` is only for successfully policy-excluded input: it commits the
cursor without allocating a sequence. Malformed records must not use it.

`tailer.NextFile` discovers the pinned writer's UTC timestamp backup names,
orders backups before the live file, and checks the path/device/inode inventory
before and after each read. A rotation race discards the uncommitted candidate
and retries from the durable checkpoint, at most three times per call. Appending
to the same live inode is allowed. It never orders backups by arbitrary mtime or
inode values. Symlinks, nonregular files, broad file permissions, compressed
backups, malformed backup names and configured inventory overflow stop reading.

This adapter follows [Tetragon v1.7.1's writer](https://github.com/cilium/tetragon/blob/v1.7.1/cmd/tetragon/main.go)
and [cilium/lumberjack v2.4.2's rotation naming](https://github.com/cilium/lumberjack/blob/v2.4.2/lumberjack.go).
The chart's export directory and disabled compression are pinned explicitly in
our values. Backup ordering inherits the upstream timestamp convention; it does
not prove recovery across clock rollback, upstream same-name rotation overwrite,
or adversarial reuse that preserves the first line. Changed first-line bytes at
a reused inode are rejected before the saved offset is used. These limits and actual rotation retention need Q0
measurement.

The reader returns complete newline-terminated bytes and leaves partial live
lines unconsumed. A missing checkpoint inode returns `ErrRotationLoss`;
a changed device or first-line fingerprint also returns loss. Legacy checkpoints
without this identity retain their WAL records but cannot resume input silently.
A durable gap and operator/supervisor recovery are needed before restarting
collection from another cursor. Truncation, oversized input, and an incomplete rotated record are explicit
errors. Reads use no-follow/nonblocking opens, so a replaced symlink/FIFO is not
silently consumed. Gap and unhealthy reports remain the supervisor's job.

`acquire.Collector` prepares each line through the normalizer adapter before
allocating a sequence. A successful policy exclusion advances only the input
checkpoint. Other input is appended/fsynced before checkpoint advancement.
Parse/normalization errors, invalid adapter results, cancellation before append,
and spool pressure leave the input checkpoint intact. An idle or concurrently
rotating inventory is polled at 100 ms; real loss stops the loop instead of
resetting its cursor. Normalizer error details and raw input are omitted from
the collector's error string. Event normalization itself remains a separate,
adapter supplied by [normalize](normalize/README.md), pending shared spec PR
#87 and authoritative metadata wiring. It does not infer scope from raw Pod labels.

Use an owner-only persistent spool directory. A marker makes loss of sequence
state fail closed even after every segment was acknowledged and deleted. Loss
of the entire node volume is outside this local durability guarantee.

Validation: `go test -race ./sensors/exporter/...` and `go vet ./sensors/exporter/...`.
Tests use real temporary files and simulate interruption between reservation,
frame durability and checkpoint commit; they do not power-cycle a disk. They
cover replay bytes, partial-tail/CRC recovery, preservation of middle corruption,
capacity rejection, locking, state loss, rotation, and input bounds.

`batch.New` takes only the next contiguous prefix after the durable watermark,
including explicitly abandoned ranges. It freezes the batch ID, original
epoch, record bytes, cursor and JCS digest. It limits the complete request to
1 MiB and 100 combined records/ranges. Record IDs, epoch, source and sequences
are checked; full event schema validation remains the normalizer/receiver's
responsibility. The merged [PR #60 contract](https://github.com/Beaver-Dam-Community/Agentarium/pull/60)
is enforced directly through `packages/canonical`: kernel/lifecycle IDs must
match their fixed namespace and source/epoch/sequence, and each range digest
binds source, stream, epoch, endpoints and reason. There is no configurable
digest override.

`batch.Client` verifies TLS 1.3 with a trusted chain, serverAuth EKU, validity
period and exactly one URI SAN identifying the audit-writer service. DNS/IP SANs
are not required by the workload certificate contract. New connections disable
session resumption and recheck identity/expiry; a workload client certificate is
required. The client refuses
redirects, ignores environment proxies and performs one bounded attempt.
Callers can retry the same immutable batch after a transport failure. An ack
must match the batch and epoch, name only submitted IDs, and cannot acknowledge
rejected or unconfirmed records, split an abandoned range, or advance a watcher
cursor before the whole batch is committed. Returned watermarks are capped at
the contiguous prefix this batch submitted. Only then may the caller pass
`Ack.Epoch` and `Ack.Through` to `wal.Ack`. Accepted IDs alone do not delete WAL.

Local tests run a real mTLS handshake and real on-disk WAL recovery while a
contract-fixture receiver drops the first response and returns duplicate IDs
on retry. They also reject malformed/oversized responses, wrong epochs,
unsafe watermarks, cursor changes, redirects and untrusted server certificates.
The fixture does not prove a TASK-07 database commit or deployed ingestion.

`delivery.Pump.Run` drains durable prefixes immediately, polls idle spools every
second, and retries transport failures/408/429/5xx with bounded 1, 2, 4, 8, 16,
30-second delays. Cancellation interrupts waits and requests. An unchanged
watermark is backoff-worthy even with accepted IDs. The same in-flight batch
bytes survive retries within a process. Record-only envelopes may be rebuilt
after restart while preserving every record's original ID/epoch/sequence/bytes.
They do not reserve a second durable copy of the payload: a full WAL must still
be able to drain, and durable quarantine must determine what is replayed.
Cursor-only requests separately preserve their original envelope across restart,
as described below. Old pending epochs drain before new data.
The bounded journal window loads at most 100 records and a 1 MiB payload prefix;
the pump also accounts for envelope overhead before sending. An individual
record that cannot fit an envelope stops delivery without deleting it.

An authenticated, validated per-record `SCHEMA_INVALID` rejection is fsynced
into an owner-only quarantine file with the original normalized payload and its
local SHA-256. Only afterward does the pump replace that sequence with a
`record_rejected` range. The file survives restart and subsequent WAL segment
deletion. Quarantine bytes count against spool capacity and are never removed by
TTL or ack. Disk/capacity failure stops the transition and retains the WAL.
Other reasons, ID conflicts, range rejection, permanent HTTP errors, and invalid
acks stop delivery for investigation; none authorize automatic abandonment.
Recovery and rejected ranges use the same canonical implementation as batch
validation.

Tests exercise these transitions through real mTLS and disk files: dropped ack,
503 retry, partial ack/rejection, process restart, recovered partial frame,
bounded backlog/envelope splitting, cancellation, and rejection evidence surviving
segment deletion. The receiver remains a contract fixture, not the audit DB.

The [health reporter supervisor](healthreport/README.md) connects this pump and
acquisition worker to the atomic WAL snapshot, pinned Tetragon loss metrics,
30-second ACK stagnation and 80% spool detection. It translates terminal worker
failures into unhealthy/hold reporting while the reporting loop stays alive.
The [normalizer](normalize/README.md) implements the pinned Tetragon parsing
boundary. Remaining integration includes authoritative lifecycle/scope resolution,
capture/probe verification, production lifecycle and Pod watcher adapters,
authenticated client identity loading, the service binary/deployment and actual
cluster observation. The pump does not auto-release holds or claim node readiness.
Operator handling of
retained quarantine data is still needed when it consumes the configured spool.

`Journal.HealthSnapshot` supplies one mutex-protected view of spool usage,
capacity, pending records/ranges and process-local durable ACK progress.
Reserved-but-missing records remain pending; duplicate ACKs do not count as
progress. A failed or closed journal returns an error instead of a usable health
sample. `healthreport.Sampler` consumes this atomic view; it never derives ACK
progress from a filtered event or an HTTP response. The local integration tests
exercise real WAL recovery but do not establish deployed sensor readiness.

## Durable Pod watcher checkpoints (TASK-09 section 3.6)

This producer implementation depends on shared spec PRs #93/#94. It adds no
receiver DB function or new wire fields. The existing `delivery.Pump`,
`batch.Client`, and on-disk WAL execute the request/recovery path; Kubernetes
client-go LIST/WATCH collection and the production audit CAS receiver remain
separate integrations.

Create the Pump with lifecycle stream, the exact pod-watcher source SAN, and
`WatchScope`. The scope is fsynced into journal metadata before its first record
and cannot change on reopen. Existing WAL without known scope fails closed;
its scope is never inferred from current configuration. Known-scope records
without a saved cursor are replayed without inventing one.

The collection adapter uses this sequence:

1. Recover and flush any existing pending request with its original bytes.
2. Call `ResumeCheckpoint(ctx)` and start LIST/WATCH from the returned opaque
   resourceVersion (404 means no accessible checkpoint, logical revision zero).
3. Complete every LIST page and all preceding events; append lifecycle records
   and flush them until the WAL is drained.
4. Call `QueueCursor(observedResourceVersion)` to persist a cursor-only request.
   This uses the durable expected revision and allocates no event or sequence.
5. Flush the request. On success, checkpoint state and removal of the pending
   request are saved atomically. A lost response retries identical bytes even
   across process restart. A current-request retry keeps its original revision.
6. A stale `checkpoint=null` persists `RefreshRequired`, clears the completed
   request, and returns `ErrCheckpointRefresh` to stop the delivery loop. Call
   `ResumeCheckpoint` and restart LIST/WATCH from the **server's current** cursor.
   Never submit an old cursor with the newly fetched revision.

`QueueCursor` refuses undrained WAL, concurrent pending requests and unresolved
checkpoint refresh. It does not prove that the caller read every Kubernetes
LIST page; that remains the collection adapter's responsibility. The producer
never orders resourceVersions or implements HA election. One Pump owns a spool.

Only the cursor-only pending body is stored as bytes in owner-only journal metadata so JSON string
escaping cannot change its original canonical representation. Its serialized
size counts toward spool capacity and the atomic health snapshot reports it as
pending even for an empty bookmark. Record ACK progress remains a record counter;
a bookmark does not manufacture record progress. A local persistence error stops
sending. Metadata fsync currently rewrites the bounded pending body with journal
state; throughput/disk amplification still needs target-volume measurement.

Local tests reopen real journal files and use a real mTLS HTTP server with an
explicit CAS fixture: cursor restart, ACK loss after fixture commit, same-current
retry, empty bookmark, delayed A after B, stale recovery persistence,
record-before-cursor draining, changed scope, corrupt batch digest, invalid GET
schemas and failed local publication. Regressions additionally fill a real WAL
to capacity and prove it still drains, and simulate a crash after durable schema
quarantine to prove replay sends only the record_rejected range. These tests establish producer behavior, not PostgreSQL CAS,
actual Kubernetes watch continuity, GKE deployment, or complete M2/M3 observation.

Older binaries reject the added watcher journal metadata fields. Preserve the spool and
run this version or a compatible reader after first use; do not downgrade a live
spool by deleting pending requests, scope or checkpoint metadata. AGW1 record
framing is unchanged. A rollback requires a separately reviewed offline metadata
migration or restoration of a complete consistent spool backup.

## Sidecar command

`cmd/exporter` wires the libraries above into the Tetragon DaemonSet sidecar.
Build it with the shared template:
`docker build -f build/docker/go-service.Dockerfile --build-arg CMD=./sensors/exporter/cmd/exporter .`

- Configuration is one strict JSON file (`--config`); `NODE_NAME` comes from
  the downward API. Unknown keys and relative paths are rejected.
- Node identity: Node `metadata.uid` from the read-only API, kernel boot ID from
  `/proc/sys/kernel/random/boot_id`, which must equal Node `status.nodeInfo.bootID`.
  The source epoch is node UUID 32hex + SHA-256(boot ID) 64hex + a new process
  instance UUID 32hex, the same encoding as the runtime lifecycle source.
  `sensor_id` is the exporter SAN `spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon`.
- `podmeta` is the trusted resolver: a node-scoped Pod informer
  (`fieldSelector=spec.nodeName`). A Tetragon docker prefix that matches a
  container of an observed Namespace keeps the event with the full container
  ID and Pod UID from the API; a match elsewhere, or a host process, is excluded.
  `tcp_state` is kept when its tuple contains an observed Pod IP (deleted Pods
  are retained for `pod_retention_seconds`). An endpoint inside the node's Pod
  CIDRs (Node `spec.podCIDRs`) that no cached Pod owns waits up to the grace
  period for a late IP and is then kept as `unresolved`; an endpoint owned by an
  observed hostNetwork Pod is kept as `unresolved`. Only tuples whose endpoints
  are all owned by non-observed Pods or outside the node Pod ranges are excluded. An unmatched prefix waits up to
  `metadata_grace_seconds` from the event time and is then **kept** with null IDs
  as `unresolved` instead of being dropped (sandbox containers never appear in
  Pod status).
- `metadata_status` (`resolved`, `tuple_scoped`, `unresolved`) and `coverage`
  (`complete`, `partial`) are the COMMON enums of PR #185. The normalizer rejects
  a status whose fields do not match it and computes `coverage` per event from
  the TASK-09 4 identity field table.
- Client identity is bootstrapped from `POST /internal/workload-certificates`
  with the projected token; the key stays in memory. Only clientAuth is required.
  As a hostNetwork node component the sidecar bootstraps through the gateway
  relay (TASK-03 3.3): `identity_peer_san` is the gateway SAN, and only the
  gateway or identity-service SAN is accepted.
- `capture.Verifier` is the CaptureVerifier (TASK-09 3.5, PR #185). Each check
  compares the mounted `tetragon-config` with `tetragon_settings` as an exact
  set over the export/filter keys (any extra `export-*` or `*filter*` key, a
  changed value, a missing key, or an `export-filename` other than the tailed
  file is a mismatch; the TASK-09 invariants such as `export-rate-limit = -1`
  are enforced even if the expectation were edited), recomputes `rule_hash`
  from the `agentarium-*` TracingPolicy/TracingPolicyNamespaced objects (with
  the pinned 1.7.1 CRD defaults from `capture/crd_defaults.json` applied, the
  same file `deploy/gcp/sensors/render.py` uses, so explicit and API-filled
  defaults hash alike), and
  reads Tetragon's loopback policy metrics: the `agentarium-*` rows of
  `tetragon_tracingpolicy_kernel_memory_bytes` must equal the declared set and
  `tetragon_tracingpolicy_loaded` must have an `enabled` row and no duplicate
  state row, every state other than `enabled` (including unknown future
  states) must be zero, and `enabled` must be at least the number of declared
  policies. The exporter is not given Tetragon's gRPC socket because it
  also serves policy changes. Any mismatch or failed read keeps the lease
  unhealthy. Hold requests still follow the 3.5 conditions.
- `exporter inspect-wal <spool>` prints fsynced, unacknowledged KernelEvents as
  NDJSON without the journal lock; `tests/kernel/probes` uses it.

`go test -race ./sensors/exporter/cmd/exporter` builds the binary and runs it as
a process against the real Q0 export lines, a real on-disk spool, mTLS fixture
servers for identity/TASK-07/TASK-10 and a fake Kubernetes API (LIST and
WatchList). The TASK-07 fixture enforces the 3.3 contract: mTLS source SAN,
strict envelope, `batch_digest` over JCS, canonical `source_event_id` and
`record_digest`, duplicate-vs-conflict and a contiguous per-epoch watermark. The
test fsyncs 120 events while the collector is down, SIGKILLs the process, loses
one ACK after restart and checks that all 245 Q0 events arrive once with original
bytes, two exclusion fixtures get no sequence, and the WAL drains after ACK.

The process test also serves the pinned policy metrics and the committed
policies through the fake API: the lease turns healthy once the backlog is
acknowledged and unhealthy again when the metrics report a disabled policy.

Not covered: the real TASK-07 kernel route (not enabled on main, issue #92), a
real Tetragon process, GKE Pod API latency, and Q0 for unresolved containers.

### Capture verification limits

`bash tests/kernel/run-crd-defaults.sh` downloads the pinned Tetragon 1.7.1
CRDs and verifies their recorded SHA-256 digests and regenerated defaults.
The sensor-capture CI workflow runs this check instead of allowing the CRD
comparison to skip. Both renderer and exporter use `crd_defaults.json`.

This verifies defaulting, not every API-server schema pruning behavior. The
probe compares policy names and metrics rather than cryptographically proving
which policy bytes the running kernel loaded. It reads mounted ConfigMap
settings rather than querying all live Tetragon options, and does not prove the
runtime policy mode. Each node also lists policies every second. These remain
capture-assurance and scaling limits; a healthy result is not proof that those
additional properties were verified.

## Node nonce responder (TASK-09 session worker independent observation, Pod observation readiness verification)

`observe/` polls the node-scope `GET /internal/control-health?scope=node&scope_id=<node_uid>`
once a second over the existing mTLS client and answers only this node/boot's
`pending_worker_observation_challenges` and `pending_work_readiness_challenges`.
It needs config `proc_root`, `cgroup_root` (host procfs and cgroup2, read-only)
and `worker_binaries` (all or none; without them it does not run).

Worker witness, all required or nothing is posted:

- the challenge names this node, boot, `sensor_generation`, and (if set) the
  lease `rule_hash`, and the deadline is at least 0.5 s away; the sensor's own
  health is healthy;
- the container is running in the Pod named by the binding (Pod API), its image
  ID carries a `sha256:` digest, and its cgroup2 directory inode is the binding's;
- each hint resolves to exactly one host PID: innermost `NSpid` = local PID,
  `/proc/<pid>/stat` start ticks equal, cgroup path names the container;
- the worker's `PPid` is the supervisor;
- the worker host PID has exactly one committed `process_exec` in the container
  (from `delivery.Config.Committed`, i.e. after the TASK-07 ACK). It has not
  exited, its binary is a `worker_binaries` entry, and its Tetragon `ns.pid`
  inode equals the hint. Its parent exec is the supervisor's committed exec with
  the supervisor's host PID and namespace;
- both processes still have the same start ticks.

`observed_controls` holds only `/proc/<pid>/status` values (`no_new_privs`,
`seccomp_mode`, `uid`, `cap_eff`); `dumpable` and `seccomp_filter` are
`unknown`. The Pod answer is sent only for a worker this exporter process
witnessed. `worker_alive` is false when that process is gone or its exec exit is
committed, and `filter_included` needs an observed Namespace plus a committed
exec of the container. A 503 is retried with a fresh body inside the nonce. A
lost response is replayed byte-for-byte (control-health returns 200 `existing`).
Any other decision is final.

Not covered: real host `/proc`/cgroup on GKE, Tetragon `ns.pid` in the pinned
export, and the exporter hostPath mounts (TASK-01 3.2.1 allowlist). Exec rows
committed before an exporter restart are not indexed, so workers whose
supervisor started earlier cannot be witnessed until the Pod restarts.

Responder retry history keeps the most recent eight bodies per challenge so a
long sequence of 503s does not discard the body whose commit acknowledgment was
lost. Exporter restarts still lose the in-memory exec/observed index; existing
runtime Pods may need restart before new worker observations are possible.
Deploying the observation responder also requires the merged #231 host-proc
security boundary (recursive read-only mounts, restricted propagation/group,
and non-dumpable raw-socket proxies). The fixture tests here do not establish
those host protections or actual GKE observations.
