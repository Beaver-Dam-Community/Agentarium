# Runtime lifecycle recorder (TASK-09 3.6)

`recorder` and `cmd/lifecycle-recorder` implement the runtime source of the
mapping_version 1 rules in shared-spec PR #207.

- The recorder subscribes to containerd namespace `k8s.io` with
  `topic~="/tasks/"` before listing containers, so nothing between the list and
  the stream is lost. Every Pod container (identified by CRI labels) present at
  (re)subscription is recorded as `container_present`, without claiming its
  creation or start.
- Task events become `container_created` (with `cgroups_path`, the inode of the
  cgroup v2 directory under the read-only `/sys/fs/cgroup` mount, and the CRI
  `ContainerStatus.image_id`), `container_started`, `container_exited` (init
  process only; exec exits are ignored) and `container_deleted`. `source_time`
  is the event envelope time.
- Records carry the node/boot of the runtime epoch and
  `missing_reason = runtime_metadata_partial`, because the recorder never fills
  `image_manifest_digest`; null fields show what is missing.
- A broken stream or a restart produces a `RUNTIME_RECORD_MISSING` gap from the
  last processed event (fsynced in the spool) to the end of the new reconcile.
  The gap request is fsynced with a stable `gap_id` and resent until
  control-health acknowledges it; a refusal stops the recorder with the request
  kept. A pending gap from a previous boot is not resent (its certificate is
  gone): the new boot's gap replaces it and starts no later than it.
- A create/start/exit whose container record is already gone (NotFound)
  becomes a one-instant gap; other lookup errors resubscribe like a broken
  stream.
- Delivery uses the shared WAL and pump as a runtime lifecycle source.
- The recorder never holds the containerd socket. `ctrdproxy` and
  `cmd/containerd-proxy` serve exactly Events/Subscribe (namespace `k8s.io`, the
  task filter), Containers Get/List (namespace `k8s.io`, no filters) and CRI
  ContainerStatus (non-verbose). They rebuild each upstream request, keep only
  the container ID, the four CRI labels, `linux.cgroupsPath`, the two CRI
  annotations and `image_id`, and answer every other method or service with
  `PermissionDenied` without calling containerd. Subscribe forwards only
  TaskCreate/Start/Exit/Delete reduced to `container_id` and `id`, and sends
  response headers once the upstream subscription is open; the recorder lists
  containers only after those headers. A non-JSON OCI spec is returned
  without the spec. `--prepare-spool` is the
  `spool-owner` init mode that hands the hostPath spool to the non-root user.
- The command adds node identity, the workload certificate (requested from
  the identity service directly), and a 5-second
  `lifecycle-recorder` lease (`source_id = lifecycle-node/<node_uid>`) that is
  healthy only while subscribed and while the backlog makes ACK progress.

`go test -race ./services/lifecycle-recorder/...` uses a real gRPC
containerd/CRI fixture on a unix socket (`internal/ctrdtest`, which requires
the namespace metadata and task filter), real cgroup directories, the on-disk
WAL and mTLS fixtures that check the TASK-07 lifecycle contract and the gap
body. It covers reconcile, the event mapping, an ignored exec exit, a broken
stream with resubscribe, a restart with a new epoch, a permanent gap refusal,
the slice expansion rule, and the command's bootstrap, delivery, gap and lease.
`ctrdproxy` tests run the proxy between a real gRPC client and the fixture on
unix sockets: the four methods pass with reduced records (no env, args, mounts,
image or extensions), and Containers Create/Update/Delete/ListStream, Tasks
Create/Exec/Kill/Delete, Events Publish, Namespaces, CRI ExecSync/Exec/
CreateContainer/RemoveContainer/ListContainers, reflection and health are
`PermissionDenied` with zero upstream calls; other namespaces, list filters, a
different event filter and verbose status are refused too. The command test
runs the recorder through the `containerd-proxy` binary.
GKE socket and cgroup paths, CRI label keys and the systemd conversion are Q0
items and were not run.

## Review regression checks

`bash tests/lifecycle-recorder/run-spool-local.sh` builds the Linux init binary
and checks first start and restart with `--cap-drop ALL --cap-add CHOWN`.
Initialization tightens mode before transferring ownership and leaves an
already prepared 65532:65532, 0700 directory untouched. WAL contents survive
and remain writable by the recorder; symlink targets are not re-owned.

Each subscription has its own context. Lookup failure cancels it before
resubscribing. A transient gap delivery failure also closes the unread stream;
after the pending gap is acknowledged, a fresh subscribe/reconcile covers the
interruption. Permanent refusals still fail closed and keep the pending gap.
New state files bind the last event time to the node. A different node starts
its gap at process start; legacy state without a node retains its conservative
bound unless a pending gap identifies the spool as belonging to another node.
