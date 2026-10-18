# services/runtime — Minimal agent runtime (TASK-15, M3-1 demonstration part)

The demo mode in this document is a Go runtime implementing only the scope required to send 1 M3-1 demonstration action (`receiver.submit` → `receiver-primary`). demo mode does not include ADK, `GatewayLlm`, or tool loops, and does not signify full completion of TASK-15, including multiple sessions and `tools/integration_runner`. There are no model calls in demo mode. See [Python bridge](python/README.md) for the separate ADK image and model/tool loop. Verification of actual Gateway/Gemini/GKE connectivity has not yet been completed.

| Executable | Image path | Role |
| --- | --- | --- |
| `cmd/supervisor` | `/app/bin/agent-runtime` | Container PID 1. Certificate bootstrap (gateway relay), assignments and claim, worker creation, registration, and observation wait, readiness check, `agent_work_*` reporting, action submission, approval wait, and result lookup, binding close |
| `cmd/worker` | `/app/bin/agent-worker` | Supervisor fork+execs once per session. Waits for bootstrap after applying isolation (`process_baseline`), and after go, sends 1 `receiver.submit` request with a fixed payload via IPC (fd 3). No network client. Supervisor does not transfer session tokens or keys via IPC |

## Configuration

Because agent-exec admission blocks container args and env `valueFrom`, all values are plaintext env vars. Flags with the same name (for local execution) also exist.

| env | flag | Default |
| --- | --- | --- |
| `AGENTARIUM_GATEWAY_URL` | `-gateway-url` | Required. E.g.: `https://policy-gateway.agent-control.svc:8443` |
| `AGENTARIUM_GATEWAY_SAN` | `-gateway-san` | `spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway` |
| `AGENTARIUM_TRUST_BUNDLE_PEM` / `_FILE` | `-trust-bundle-pem` / `-trust-bundle-file` | One of the two required |
| `AGENTARIUM_TOKEN_FILE` | `-token-file` | `/run/agentarium/identity/token` |
| `AGENTARIUM_WORKER_PATH` | `-worker-path` | `/app/bin/agent-worker` |
| `AGENTARIUM_SCRATCH_ROOT` | `-scratch-root` | `/work` |
| `AGENTARIUM_MAX_CONCURRENT_WORKERS` | `-max-concurrent-workers` | Required, only `1` allowed |
| `AGENTARIUM_DEMO_TARGET_ID` | `-demo-target-id` | `receiver-primary` |
| `AGENTARIUM_DEMO_SUMMARY` | `-demo-summary` | Required |
| `AGENTARIUM_DEMO_EMAIL` | `-demo-email` | `null` if empty |
| `AGENTARIUM_RUNTIME_VERSION` | `-source-version` | Required. `source_version` (deployment version) of `agent_work_*` audit events |
| `AGENTARIUM_ASSIGNMENT_TIMEOUT` | `-assignment-timeout` | `0` (infinite) |
| `AGENTARIUM_APPROVAL_POLL` / `_TIMEOUT` | `-approval-poll` / `-approval-timeout` | `15s` / `10m` |

The `POST /v1/runtime/work-events` body is `{event_id, event_type, source_version, source_time, safe_payload {work_run_id, check_id, runtime_process_epoch, worker_instance_id, worker_binding_id, outcome?, reason?}}`. session_id, tenant, and source_id are not sent (the gateway determines them from the token and certificate). Only TASK-07 acks that are 201 `created` or 200 `duplicate` and have the same `event_id` and `received_at` are recognized. For any other response, the worker is not released (`WORK_START_NOT_ACKNOWLEDGED`).

claim_code is not an input. It is included in the `GET /v1/runtime/assignments` response (TASK-03 3.3).

## Results

Writes a single line of JSON (`runtime_process_epoch, session_id, worker_instance_id, worker_binding_id, root_exec_id, work_run_id, check_ids, work_started, action_id, decision_id, verdict, execution_state, reason_codes, error`) to stdout and terminates. Success 0, failure 1, configuration error 2.

## Testing

- `go test ./services/runtime/...`: state machine, header propagation, approval wait, fail-closed paths with a fake gateway (mTLS, relay path, #228 body)
- Linux only (`//go:build linux`): actual application of seccomp and prctl, `/proc` hints, actual worker exec (parent PID, comm)

## Security boundary and remaining limitations

The supervisor applies `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` before reading credentials. The worker applies the same settings and seccomp after the final exec. The Linux regression test applies actual `process_baseline` to a worker with the same UID, then verifies that access to the parent's `/proc/<pid>/mem`, `environ`, and `fd` is rejected with `EACCES`. On an unprotected parent, the same test must be able to read the memory marker.

This protection targets the session token and mTLS key in the supervisor's memory. Currently, the projected ServiceAccount token file can also be read by a worker with the same UID. Isolating the workload identity itself is within the scope of subsequent file profiles (Landlock) in TASK-15 and is not claimed as completed in this PR.

Currently, if a refresh response is lost, the previous token is already revoked on the server, so subsequent requests may fail with 401. As the session approaches its maximum lifetime, repeated refreshes occur, and binding close after expiration may fail. Retry rules for lost claim responses must be decided in TASK-03. This minimal runtime does not constitute completion of the full TASK-15.
