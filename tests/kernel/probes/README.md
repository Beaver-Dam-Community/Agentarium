# TASK-09 live ground-truth observation ("ground-truth event observation")

This directory is the independent answer key and checker for part of TASK-09 7
"behavior observation", "connection attempt·establishment" and "denied open". It has not been run against
GKE yet; offline checks only (below). A passing run is evidence for the cases
listed here, not for all of TASK-09 7 (see "Not covered").

| Piece | Role |
| --- | --- |
| `cmd/kernel-stimulus` | Runs in an agent-exec `probe-runner` Pod: N child execs, N TCP connects to an accepting target, N connects to a refused/dropped target (explicit local port, so the attempted tuple is known), N permitted opens and N DAC-denied opens of `/work/protected-fixture`. One JSON line per stimulus (superset of the Q0 `q0-stimulus` format). |
| `cmd/kernel-assert` | Compares the stimulus log with KernelEvents from `exporter inspect-wal` (identity and `record_digest` recomputed) and/or `audit.kernel_events` (read-only). Writes `summary.json` and `observed.jsonl` (COMMON result record). Exit 0 = every expected case passed. |
| `run-live.sh` | The one-command live run. |

## Cases

| case_id | Pass condition |
| --- | --- |
| `process_exec` | `process_exec` events in the stimulus Pod (Pod UID and container ID from the exporter's Pod API resolver) whose `binary` is the stimulus path or its SHA-256, count ≥ children + 1 |
| `process_exit` | `process_exit` in the Pod, count ≥ children |
| `tcp_connect_attempt` | a `tcp_connect` with exactly the stimulus tuple, per accepted connect |
| `tcp_established_linked` / `tcp_close_linked` | `tcp_state` 1 / 7 with the same `sock_ptr` and tuple as that connect |
| `tcp_failed_attempt` / `tcp_failed_not_established` | refused/dropped connect: `tcp_connect` plus `tcp_state` 7 and no `tcp_state` 1 |
| `file_open_allowed` / `openat_allowed` | `security_file_open` with return 0 / `openat` without errno, count ≥ permitted reads |
| `openat_denied_eacces` | `openat` with `return_errno = -13`, per denied open |
| `file_open_not_on_denied` | `security_file_open` count equals permitted reads + the fixture creation (support table: the hook does not see DAC denials) |

A case with no stimulus is `not_run`; a missing observation is `failed`. A TCP
stimulus whose local port was never bound still counts as expected. Every case
in `observed.jsonl` lists the matched `source_event_ids` (`event_ids`).

All TCP stimuli use Go's non-blocking connect (connect returns EINPROGRESS and
the runtime polls), so they also exercise the asynchronous connect path.

## Not covered

- Write attempt on a read-only mount (EROFS, TASK-09 7 "denied open"): the
  policy path filter is `/work/protected-fixture`, which is on the writable
  `work` volume. A read-only fixture mount would need a policy/fixture change.
- `openat2`: the policy hooks `sys_openat2`, but the pinned normalizer accepts
  only `__x64_sys_openat`; an openat2 event on the fixture would stop exporter
  acquisition (fail closed). This is a known TASK-09 gap, so the stimulus does not
  call openat2.
- NetworkPolicy-dropped SYN with a separately verified drop (`tcp_failed` only
  shows the kernel view), softirq attribution, load/loss, rotation, runtime
  boundaries and the other TASK-09 7 rows.

## Live run

Prerequisites (not created by this script):

1. #160 exporter and #165 sensor manifests applied in `agent-sensors`; the
   exporter's workload certificate registration and the `agentarium-trust`
   ConfigMap exist.
2. Build the stimulus image with the shared template and push it by digest:
   `docker build -f build/docker/go-service.Dockerfile --build-arg CMD=./tests/kernel/probes/cmd/kernel-stimulus -t <repo>/kernel-stimulus .`
   Add the digest to `PROBE_IMAGES` and `<digest>=/app` to `PROBE_ENTRYPOINTS`
   (deploy/gcp/base admission inputs), because the template's entrypoint is `/app`.
3. `KUBE_CONTEXT` naming the target cluster (required; every `kubectl` call
   uses `--context`), with rights to create Pods in agent-exec and `exec` into
   agent-sensors Pods.
4. `STIMULUS_TCP_OPEN`: a destination the TASK-06 policy allows for
   `agent-exec/probe-runner` (required; for example the probe-sink Service on
   8443). kube-dns is not allowed for probe-runner, so there is no default.
5. Optional: `KERNEL_PROBES_DSN` for a read-only audit DB session through the
   Cloud SQL Proxy. While TASK-07 kernel ingest is disabled (issue #92) the WAL
   is the only source; once ingest acknowledges events the WAL drains and the
   DSN is required.

```sh
KUBE_CONTEXT=<context> STIMULUS_TCP_OPEN=<probe-sink host>:8443 \
STIMULUS_IMAGE=<region>-docker.pkg.dev/<project>/agentarium/kernel-stimulus@sha256:<digest> \
  tests/kernel/probes/run-live.sh
```

The script picks an exec node (or `NODE`), runs the Pod there, waits for the
`done` record, waits `FLUSH_SECONDS` (15), dumps the exporter WAL, writes
`manifest.json`, `raw/` and the result under `evidence/gcp/runs/<RUN_ID>/`, and
deletes the Pod. `STIMULUS_TCP_FAILED` defaults to `169.254.169.254:80` (denied
for agent-exec by TASK-06; dropped, so the attempt closes on the 3 s connect
timeout). `kernel-assert` is built before it runs, so exit codes 0 (passed), 1
(failed) and 2 (could not evaluate) are preserved.

Expected caveat: until TASK-07 acknowledges kernel batches, the exporter
requests a `sensor_degraded` hold after 30 s without ACK. Neither affects this
check, but both are visible to TASK-10.

## Offline checks

- `go test -race ./tests/kernel/probes/...`: the real Q0 export
  (`20261015-task01-q0-min-2`) normalized by the production normalizer passes
  every case it covers; dropped ESTABLISHED, dropped EACCES, another Pod UID and
  a tampered record fail; the stimulus binary runs locally (refused connect
  keeps its tuple); `kernel-assert` exits 0/1 and writes the result record.
- `tests/kernel/probes/run-local.sh`: the same plus the `audit.kernel_events`
  query against PostgreSQL 16 with every kernel_events migration on main.
