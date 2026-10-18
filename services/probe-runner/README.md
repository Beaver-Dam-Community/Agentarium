# probe-runner (TASK-10 3.2 ground truth probe)

One long-lived Pod per node (DaemonSet) in `agent-exec` and `agent-adapters`.
Every 60 seconds it gives three stimuli in its own container and reports each
one 25 seconds later with `stimulus_at`:

| kind | stimulus | kernel events control-health looks for |
| --- | --- | --- |
| `process` | exec `/probe/bin/marker` (exits 0) | `process_exec`, `process_exit` |
| `tcp` | connect to probe-sink `:8443`, close | `tcp_connect`, `tcp_state` 1 and 7 on that tuple |
| `file` | read `/work/protected-fixture` (mode 0600), `chmod 0`, open again | `file_open` 0, `openat` >= 0, `openat` -13 |

The fixture path is the only path the `agentarium-protected-file`
TracingPolicy watches, and the runner must run as a non-root user without
`CAP_DAC_OVERRIDE` (admission: `runAsUser: 10001`), or the denied open
succeeds and the file stimulus reports fail.

control-health finds the evidence itself (the runner cannot know sensor
event IDs). 409 means it is not there yet: the runner repeats the same
`stimulus_at` every 3 s until the stimulus is 38 s old, then reports `fail`.
A stimulus that did not run as intended is reported as `fail` at once.

Identity: the projected `agentarium-identity` token gives namespace, Pod UID
and node UID (`kubernetes.io` claim, Kubernetes 1.32+); `boot_id` is
`/proc/sys/kernel/random/boot_id`. The Pod-bound clientAuth certificate comes
from the gateway relay (agent-exec) or workload-identity (agent-adapters).
Results go to `POST /v1/runtime/probe-reports` on the gateway (agent-exec) or
`POST /internal/control-health/probe-results` (agent-adapters). Settings are
plain environment values (agent-exec admission allows no args and no
`valueFrom`); see `cmd/probe-runner/main.go`.

Image: `docker build -f services/probe-runner/Dockerfile -t <repo>/probe-runner .`,
entrypoint `/probe/bin/probe-runner` (the `PROBE_ENTRYPOINTS` path).

Not verified here: real Tetragon events for these stimuli on GKE.

