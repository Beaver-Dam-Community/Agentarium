# Risk-event holds (TASK-10 3.2)

`Evaluate` is the deterministic risk-event evaluator. Inputs are stored kernel
events with their historical workload mapping; AI output and NetworkFinding
are never inputs. Only events whose container maps to one historical Pod with
a verified `<namespace>/<ksa>` workload can produce a decision.

| `reason_detail` | Decision | No decision |
| --- | --- | --- |
| `unregistered_connect_established` | `tcp_connect` with a matching ESTABLISHED `tcp_state`, destination outside the workload allow table, latest correlation not `confirmed` | not established, allowed destination, confirmed, no workload |
| `protected_path_write` | `file_open`/`openat` on a protected path with `O_WRONLY`/`O_RDWR` in `flags` | read-only opens, other paths; until TASK-09 Q0 verifies `flags` (`FlagsVerified`), every protected-path open is a marked candidate only |
| `unexpected_child_exec` | `process_exec` whose kernel parent chain leaves the container (parent observed in another container or on the host) before reaching the container start process or a registered worker root | lineage reaches the start process/worker root; a missing parent or unknown start process is a marked candidate only |

`Load` reads the node's candidates and exec history through the TASK-07
`correlation_reader` grant (#171). The container start process is bound to the
lifecycle interval: the container's earliest observed exec counts as the start
process only when it lies in `[started_at - 2s, started_at + 5s]` (start
latency is a Q0 measurement). When the entrypoint exec was missed (sensor
restart, `startup_capture = unsupported`) there is no root and every exec of
that container is a marked candidate, never a normal lineage. A non-numeric
`flags` value reads as unknown instead of failing the node's evaluation, and
exec history starts at the earliest start of a container live in the range. `HoldClient.Request` sends `POST /internal/holds` with
`{scope: workload, scope_id, reason: risk_event, reason_detail,
evidence_refs: ["kernel_event:<id>"]}` (#172); a repeat for the same workload
returns `existing` and control-health records the added evidence while keeping
the first `reason_detail`. control-health accepts `risk_event` only from the
`correlation` principal, only at workload scope and only with a valid detail.

Verification: `bash tests/correlation/run-risk-local.sh` (PostgreSQL 16, all
merged migrations, stand-in for #171's reader grant) and
`testRiskEventHolds` in the control-health PostgreSQL suite.

The service loop is `services/correlation/internal/service` (run by
`cmd/correlation` after the worker for each window). The allow table and
workloads come from `internal/sources`; the protected path is the TASK-10 3.2
fixture `/work/protected-fixture` and `flags` stay unverified.

Not implemented: registered worker roots (no `session_process_bindings` table
yet), operator release of `risk_event` holds (that path is #158) and any GKE
run.
