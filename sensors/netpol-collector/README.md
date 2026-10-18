# Local network-policy source capture

This is the TASK-09 acquisition part of `netpol-collector`: an executable reads
node JSONL, validates the measured fields and fsyncs an independent local WAL
before advancing its file checkpoint. It reuses `sensors/exporter/wal` and the
inode/device/prefix-checked `tailer.Next` primitive, not Tetragon's rotation-name
inventory or its sensor health/hold reporter.

The committed [Q0 node log](../../evidence/gcp/runs/20261014-task01-q0-min/raw/netpol-policy_action.log)
contains three allow and two deny records. The normalizer preserves their source
timestamp spelling, observed backend IPs, ports, packet counts and supplied
endpoint/policy fields. Missing optional fields stay null and missing count is
one. It does not infer Pod UIDs, sessions, attempts, ClusterIPs or successful
connections. Both allow and deny records are captured regardless of namespace.
Policy vendor labels/revision/kind are not NetworkPolicyRecord fields and are
not copied to the normalized observation.

## Run against a captured source

Build `go build ./sensors/netpol-collector/cmd/capture`, then supply absolute
source paths in a **verified oldest-backup-to-live order**. The UUIDs below are
synthetic and must be replaced with the observed source identifiers for actual
capture. They are operator inputs, not authenticated source registration.

```sh
./capture \
  --file /absolute/path/to/policy_action.log \
  --spool /absolute/path/to/private-netpol-spool \
  --epoch local_boot_instance_1 \
  --cluster-uid 11111111-1111-4111-8111-111111111111 \
  --node-uid 22222222-2222-4222-8222-222222222222 \
  --node-name recorded-node-name \
  --normalization-version local-q0-v1
```

The default mode captures through the last complete live line and exits.
`--follow` polls EOF/partial live lines every 100 ms until interrupted. Repeated
`--file` arguments are supported for a verified rotation inventory (maximum 64).
The library accepts an inventory provider and checks its path/device/inode
snapshot before and after every read. It retries a changing inventory at most
three times per read. With `--follow`, transient ENOENT/changing-inventory races
wait for the next poll without advancing the checkpoint; one-shot capture returns
an error. The CLI's explicit path list is fixed, so a completed rotation outside
that list stops capture if the old checkpoint cannot be found. No new order is
guessed. A missing checkpoint,
truncation, unfinished rotated line, symlink/nonregular input, oversized record,
wrong-node record or full/failed WAL never advances the cursor. Non-ENOENT file-open errors
also stop; no loss recovery is inferred from mtime or inode ordering.

The spool defaults to 256 MiB, uses owner-only files and one process lock, and
retains the shared WAL's bounded 1 MiB records/64 MiB segments. A new local epoch
can reopen it after restart without changing old payloads or sequence values.
Use a dedicated netpol spool, never the kernel/lifecycle spool. This command
never calls `Ack`, deletes unacknowledged segments or emits a final-flush marker.
SIGTERM cancels polling after any in-flight fsynced append; it does not mean a
server received the pending records. At capacity, capture stops and retains its
checkpoint and all pending data.

## Delivery, lease and final flush (`cmd/collector`)

The wire follows TASK-10 3.7 "collector batch wire" (shared-spec PR #170, issue
#103). `Captured` stays the internal spool format (`capture_version=1`);
`WireRecord` derives the NetworkPolicyRecord from it as a pure function, so a
replay sends identical bytes. `record_id` is `canonical.NetworkPolicyRecordID`.

- `Sender` takes the next WAL window (old epochs first), turns missing or
  quarantined sequences into `sequence_range_abandoned` (`stream =
  network_policy`), signs `batch_digest`, and resends the same bytes until a
  validated watermark arrives; only then does it call `wal.Ack`. A record
  rejected as `SCHEMA_INVALID` is quarantined with its original bytes and sent
  as a `record_rejected` range (COMMON batch API); any other rejection, unknown
  IDs or a final-flush acknowledgement beyond the watermark stop delivery with
  the WAL retained and the lease unhealthy. An idle send reports the journal's
  real watermark, and `final_flush.through_sequence` is the last allocated
  sequence (#170).
- `caught_up_at` and `final_flush` are attached only to a batch that carries
  every pending sequence of the current epoch. `final_flush` is complete only
  when the receiver answers `final_flush_recorded = true`.
- A lost checkpoint (rotation while stopped) is sent once as `rotation_loss
  {detected_at, after_sequence}`; capture then stops and the lease turns
  unhealthy. The cursor is never moved to another file silently.
- The 5-second lease (`component = netpol-collector`) carries `details
  {source_epoch, file_offset, acked_through, caught_up_at?,
  schema_rejected_count}` with `source_id = netpol-node/<node_uid>` (#170). It is
  unhealthy after a permanent failure, a rotation loss, a capture stop (for
  example an oversized line, which no longer crash-loops), a live file missing
  for 10 s, or a pending backlog without ACK progress for 30 s. A quiet node
  with nothing pending stays healthy. No hold is requested.
- On SIGTERM the collector reads to the end of the file, sends everything and
  requests the final flush within `final_flush_seconds`; it exits 0 only after
  the flush is recorded.
- Node identity, epoch encoding and the client certificate reuse
  `sensors/exporter/nodeid` and `sensors/exporter/workloadcert` (#160) with SAN
  `spiffe://agentarium.internal/ns/agent-sensors/sa/netpol-collector`; the
  receiver must present `.../agent-observe/sa/correlation`.

The live file is the only inventory entry: anetd rotation naming is still a Q0
gap (#103), so backups are not discovered and a rotation while stopped is
reported as loss rather than guessed.

A complete bounded schema-invalid line is excluded before sequence allocation,
as TASK-10 §3.7 requires. `Journal.RejectSchema` persists its rejection count and
next file checkpoint together in one atomic, fsynced state replacement; only
then does capture continue. `SchemaRejections()` exposes that durable local-spool
lifetime count across process epochs. Retrying a committed checkpoint does not
count it again, and stale checkpoints cannot overwrite current progress.
`AdvanceFiltered` still cannot be used for malformed or lost data. Wrong-node
identity, partial/oversized input, missing rotation history and disk failures
remain fail closed; they are not schema exclusions.

The count is delivered as lease `details.schema_rejected_count`. A legacy spool without a count field starts counting at zero, which
makes no claim about invalid input before this implementation. Nonzero counts
add a local state field; older binaries reject that state rather than discard
it. Do not downgrade a counted spool to an older writer. This compatibility
only allows the new binary to read legacy state. On persistence failure, capture
stops and the journal must be reopened:
recovery reads either the old or new atomic state, so a rename followed by a
failed directory fsync cannot turn an uncertain write into a successful skip.
Automatic rotation discovery, the DaemonSet manifest, runtime drop metrics and
receiver persistence are not implemented here. The `cmd/capture` local tool must
not be installed as the collector; `cmd/collector` is the DaemonSet binary.

The Q0 report explicitly leaves rotation retention/compression/permissions,
delivery delay and dataplane drop counters unmeasured. The generic tailer also
cannot prove detection of adversarial inode reuse with an identical first-line
fingerprint. Source-volume loss remains outside local WAL durability.

## Verification

`go test -race ./sensors/netpol-collector/...` uses the actual five-line Q0 file,
checks exact field preservation and 12 aggregated packets, restart replay,
verified rotation and rotation during a read, missing history, partial lines,
durable schema rejection/restart replay, wrong-node metadata, input bounds, full spool, unsafe paths and canceled
follow loops. WAL tests cover rejection checkpoint CAS, legacy state, count bounds,
and failure before/after state rename without exposing speculative progress. `go vet` and command builds run locally. These are local source
capture tests, not GKE, HTTP, lease, final-flush or M2/M3 completion evidence.

`go test -race ./sensors/netpol-collector/...` also runs `cmd/collector` as a
process against the real Q0 file with mTLS fixtures for identity, TASK-10
(`internal/receivertest`, which enforces the #170 wire: SAN, strict envelope,
`batch_digest`, `record_id`, epoch node binding, cluster UID, range digests,
duplicate-vs-conflict, contiguous watermark, final flush only at the watermark)
and control-health. It covers receiver outage, SIGKILL, a lost ACK with old-epoch
replay, SIGTERM final flush, and rotation loss. No GKE, real receiver or real
anetd rotation was exercised.
