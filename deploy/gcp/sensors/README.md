# Node sensor installation (TASK-09 3.1-3.3, TASK-16 4a)

`render.py` produces the agent-sensors install for one environment:

```sh
helm pull tetragon --repo https://helm.cilium.io --version 1.7.1   # sha256 pinned in render.py
python3 deploy/gcp/sensors/render.py --values <values.json> --chart tetragon-1.7.1.tgz --out <dir>
kubectl apply -f <dir>/exporter-config.yaml -f <dir>/tetragon.yaml
kubectl apply -f <dir>/policies.yaml        # after the CRDs from tetragon.yaml exist
```

- `tetragon.yaml`: `helm template` of cilium/tetragon 1.7.1 with
  `tetragon-values.yaml`. The chart's export sidecar slot runs our exporter
  image (`sensors/exporter/cmd/exporter`, built with
  `build/docker/go-service.Dockerfile`) instead of hubble-export-stdout.
  Post-rendering renames that container to `exporter` and marks its export
  file mount `readOnly`, which chart values cannot express.
- `policies.yaml`: `network.yaml` and `file-access.yaml` rendered for
  `agent-exec` and `agent-adapters`, plus the cluster-scoped `tcp-state.yaml`.
  `rule_hash` in the exporter config is the TASK-09 4 value (PR #185): JCS
  SHA-256 of `{kind, namespace, name, spec}` sorted by kind/namespace/name.
  Each spec first gets the pinned Tetragon 1.7.1 CRD defaults that the API
  server fills in on store (`sensors/exporter/capture/crd_defaults.json`, the
  file the exporter's verifier embeds), so the value matches the stored
  objects the exporter hashes. The test recomputes it with the exporter's
  `capture.ApplyCRDDefaults` and `capture.RuleHash` and checks that the
  undefaulted hash differs.
- `exporter-config.yaml`: ConfigMap `agentarium-exporter`, including
  `tetragon_settings` (every export/filter key of the rendered
  `tetragon-config`) for the exact-set capture check. The DaemonSet Pod template
  carries `checksum/exporter-config`, so a config change restarts the exporter.
- `sensor-permissions.json`: privileges and hostPath mounts extracted from the
  rendered DaemonSet. The committed copy must equal a fresh render with the
  sample values in `tests/kernel/deploy` (the test fails otherwise).

Values JSON keys (all required, strings): `IMAGE_REPOSITORY`, `EXPORTER_IMAGE`
(digest reference), `IDENTITY_ORIGIN`, `COLLECTOR_ORIGIN`, `HEALTH_ORIGIN`,
`EXPORTER_VERSION`, `SENSOR_GENERATION`, `NORMALIZATION_VERSION`,
`SPOOL_CAPACITY_BYTES`. `metadata_status` and `coverage` are COMMON enums (#185)
and are not install inputs. `IDENTITY_ORIGIN` must be the gateway (`https://policy-gateway.agent-control.svc[:port]`; the renderer rejects other hosts): the hostNetwork
exporter bootstraps its certificate through the gateway relay (TASK-03 3.3) and
pins the gateway SAN (`identity_peer_san`).

Installation inputs for deploy/gcp/base admission:

- `AGENT_SENSORS_IMAGES` must contain the Tetragon and exporter digests.
- `TETRAGON_IMAGE` is the Tetragon digest alone (#183): only the `tetragon`
  container may run it, and every other container in the Pod must be
  unprivileged with `allowPrivilegeEscalation: false`, as the rendered
  exporter is.
- `TETRAGON_HOST_PATHS` must equal `host_paths` in `sensor-permissions.json`:
  the chart mounts `/var/run/cilium` and `/var/run/tetragon` in addition to the
  export directory, `/sys/fs/bpf`, `/proc` and the spool, and the exporter adds
  `/sys/fs/cgroup`. The chart sets no `hostPID` and no BTF mount.

Prerequisites outside this directory: `agentarium-trust` ConfigMap (key
`ca.pem`) in agent-sensors (TASK-06), registration of KSA `tetragon` for
workload certificates (TASK-03) and as the kernel source (TASK-07), and the
"sensor→collector" node-CIDR NetworkPolicy row (TASK-06).

Tetragon metrics are bound to `127.0.0.1:2112` (hostNetwork); only the exporter
reads them. The exporter mounts `tetragon-config` read-only and is not given the
Tetragon gRPC socket, which also serves policy changes (TASK-01 3.2.1).

The exporter runs as UID 0 and GID 0 without capabilities because Tetragon
writes the export file as root with mode 600 and the spool is owner-only. Its
mounts are the export directory (read-only), the spool (read-write) and, for
the TASK-09 node nonce responder, host `/proc` at `/host/proc` and
`/sys/fs/cgroup` at `/host/sys/fs/cgroup`, both with `readOnly: true`,
`recursiveReadOnly: Enabled` and `mountPropagation: None` (TASK-01 3.2.1; the
VAP rejects a missing option, `IfPossible` or `HostToContainer`). Do not
deploy the host `/proc` mount until containerd-proxy is non-dumpable (#264)
and the Pod's `status.containerStatuses[].volumeMounts[].recursiveReadOnly`
reads `Enabled` on the node; the exporter shares UID 0 with the proxy. The DaemonSet
uses `dnsPolicy: ClusterFirstWithHostNet` so the hostNetwork exporter resolves
cluster Services.

`tests/kernel/deploy` renders with sample values (needs `helm`, `python3` with
PyYAML, and the pinned chart via `TETRAGON_CHART` or network) and evaluates the
rendered Pod against the deploy/gcp/base VAPs and PSA. Nothing here was applied
to a cluster.

## Runtime lifecycle recorder (`lifecycle-recorder.yaml`)

`lifecycle-recorder.yaml` installs `services/lifecycle-recorder/cmd/lifecycle-recorder`
as a Pod-network DaemonSet in agent-sensors on exec/control nodes: KSA
`lifecycle-recorder`, a `nodes get` ClusterRole, the config ConfigMap and the
DaemonSet. Following TASK-09 3.6 (containerd access boundary, #207), only the
`containerd-proxy` container (`cmd/containerd-proxy`, root, no capabilities,
no token) mounts the containerd socket. Its image
(`build/docker/containerd-proxy.Dockerfile`) ships the binary execute-only, so
without capabilities UID 0 cannot read it and execve leaves the process
non-dumpable from the start; the first statement of `main` then sets and
confirms `PR_SET_DUMPABLE(0)` and exits if that fails. A same-UID process
(the exporter) therefore cannot reach the socket through `/proc/<pid>/root` or
`/proc/<pid>/fd`. Build the proxy with that Dockerfile, not
`go-service.Dockerfile`. It forwards Events/Subscribe,
Containers Get/List and CRI ContainerStatus with reduced responses on a 0660
socket in a memory emptyDir and denies everything else. The recorder runs as
uid/gid 65532 with read-only `/sys/fs/cgroup` and
`/var/lib/agentarium/lifecycle-spool`; the `spool-owner` init container (CAP_CHOWN
only) hands that spool to it. `automountServiceAccountToken` is false; only the
recorder container mounts the kube-apiserver and identity projected tokens. It
requests its certificate from workload-identity directly under the TASK-06
`lifecycle-recorder-allow` NetworkPolicy. Render inputs:
`LIFECYCLE_RECORDER_IMAGE` and `CONTAINERD_PROXY_IMAGE` (both also in
`AGENT_SENSORS_IMAGES`), `CLUSTER_UID`, `RECORDER_VERSION`. `tests/kernel/deploy`
admits the Pod against the agent-sensors VAP, checks which container holds the
socket, the tokens and each hostPath, and rejects a writable cgroup mount, the
socket in the recorder or init container, and another hostPath in the proxy.

## Network policy collector (`netpol-collector.yaml`, M2-9)

`netpol-collector.yaml` installs `sensors/netpol-collector/cmd/collector` as a
hostNetwork DaemonSet in agent-sensors on exec/control nodes: KSA
`netpol-collector`, a ClusterRole limited to `nodes get` (its own Node for the
node/boot epoch), the config ConfigMap and the DaemonSet. It mounts
`/var/log/network` read-only and `/var/lib/agentarium/netpol-spool` (the TASK-01
3.2.1 hostPath table), bootstraps through the gateway relay, sends to
agent-observe/correlation and has `terminationGracePeriodSeconds: 60` above
`final_flush_seconds: 45`. Render inputs: `NETPOL_COLLECTOR_IMAGE` (also in
`AGENT_SENSORS_IMAGES`), `CLUSTER_UID`, `NETPOL_NORMALIZATION_VERSION`,
`NETPOL_VERSION`. The ClusterRole allows `get` on every Node because RBAC
cannot name each Pod's own Node; the code reads only `NODE_NAME`. anetd
rotation naming and file permissions remain Q0 items (#103), as does the
behaviour on a node without policy logging: `/var/log/network` is
`type: Directory`, so the Pod stays in ContainerCreating there (fail-closed).
`tests/kernel/deploy` admits the Pod against the agent-sensors VAP.

Prerequisites outside this directory (without them the bootstrap or the first
batch is refused and the Pod keeps retrying):

- `agent-sensors/netpol-collector` in `registered_workloads` (TASK-03) and the
  gateway `/internal/workload-certificates` relay (TASK-04).
- the `component_principals` row that lets the collector SAN report the
  `netpol-collector` node lease (TASK-10), with the lease `source_id`
  `netpol-node/<node_uid>` that control-health #209 checks.
- the collector source registration for `POST /internal/network-policy/
  records:batch` on correlation (TASK-10, #170).
- the `agentarium-trust` ConfigMap (key `ca.pem`) in agent-sensors (TASK-06).

## Pod watcher (`pod-watcher.yaml`)

`pod-watcher.yaml` installs the TASK-09 3.6 Pod watcher in agent-observe:
ServiceAccount `pod-watcher`, a Role/RoleBinding for its own coordination Lease
(`create`, and `get`/`update` on `pod-watcher` only), a 1 Gi
PersistentVolumeClaim spool (so unacknowledged records survive a reschedule to
another node), the config ConfigMap and a one-replica `Recreate` Deployment on
control nodes running `services/lifecycle-recorder/cmd/pod-watcher` with leader
election. Pod LIST/WATCH RBAC in agent-exec is TASK-06 (#168). Render inputs:
`POD_WATCHER_IMAGE` (also listed in `AGENT_OBSERVE_IMAGES`) and `CLUSTER_UID`.
`tests/kernel/deploy` admits the Pod against the agent-role-contract VAP and
PSA restricted.

The Pod watcher does not release its Lease early on cancellation. It waits for
an active producer to close its WAL before process exit; a standby SIGTERM exits
normally. A successor can acquire the Lease after its remaining TTL (at most
15 seconds). `Recreate` only governs Deployment rollouts, not eviction or drain.
The single-zone RWO PVC can delay rescheduling until detach and cannot provide
cross-zone recovery during a zone outage; no regional-PD guarantee is implied.

The PVC mount root may be 2775 after fsGroup setup. The producer creates its
owner-only spool at `/var/lib/agentarium/pod-watcher/spool` below that root.
`fsGroupChangePolicy: OnRootMismatch` prevents recursive permission widening
when a correctly configured volume is mounted again. Do not change the root's
ownership/mode or fsGroup between mounts without reviewing existing spool
permissions. Local tests reopen a real epoch/WAL under a 2775 root; actual GCE
PD CSI remount behavior still needs GKE verification.
