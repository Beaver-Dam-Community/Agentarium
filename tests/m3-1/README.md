# M3-1 local end-to-end run

`run-local.sh` runs the M3-1 action path on one macOS or Linux machine with
Docker. It uses the real service binaries, PostgreSQL 16 with the repository
migrations and install SQL, local mTLS issued by the identity service, and the
real runtime supervisor and worker binaries in a container. Only the inputs in
[Simulated locally](#simulated-locally) are replaced.

The run covers these stages:

1. A console OIDC user creates a session (`POST /v1/sessions`).
2. The runtime submits one `receiver.submit` to `receiver-primary`, and the
   gateway decides `approval_required`.
3. The console user renders the approval contract and approves the action.
4. The coordinator dispatches the action, and the `receiver-sender` adapter
   sends it with `X-Agentarium-Receiver-Key`.
5. The receiver accepts the submission, and the evidence collector records the
   receipt.
6. The audit events of the run are queried by its session, its action and its
   `work_run_id`, printed, and checked for every action-path event type. The
   action-path events carry the session and action IDs; only the runtime's
   `agent_work_*` and `work_readiness_*` events carry the `work_run_id`.

It also checks two fail-closed cases:

- (a) With the required adapter lease missing (the adapter has not started),
  the gateway decides `deny` with `CONTROL_HEALTH_UNAVAILABLE`
  (`health.required_leases.v1`), and nothing is dispatched.
- (b) While the action is unapproved, the runtime's `:reevaluate` calls do not
  dispatch it.

## Run

```sh
bash tests/m3-1/run-local.sh
```

Requirements: Docker (amd64 or arm64), Go and `python3`. The script starts its
own `postgres:16-alpine` and `fsouza/fake-gcs-server` containers, labels them
`m31e2e.run=<run tag>`, and removes only containers with that label on exit.
It does not call GCP, `gcloud`, `kubectl` or `terraform`. All keys, tokens and
certificates are generated at run time in a temporary directory, which is
deleted on exit.

Environment:

- `GOCACHE`: default `/tmp/gocache-m31e2e`.
- `M31_E2E_KEEP=1`: keep the work directory (logs and generated keys) and this
  run's containers for debugging.

Exit status:

| Status | Meaning |
|---|---|
| 0 | Every stage and both fail-closed cases passed with the repository install SQL alone. |
| 1 | A stage failed, or every stage passed only with an install gap (see below). |
| 2 | A prerequisite (Docker, Go, `python3`, or the pinned runtime base image) is missing and cannot be pulled. |
| 3 | `BLOCKED at adapter->receiver TLS (TASK-05/TASK-03 conflict)`: every earlier stage and both fail-closed cases passed, and the send failed closed with `TLS_VERIFY_FAILED` with no receiver effect and no receipt. |
| 4 | `BLOCKED at approval contract`: every earlier stage and both fail-closed cases passed, and the approval contract failed closed (503) because the action has no content preview. Nothing was dispatched. |

The receiver, receipt and audit-trail assertions are written in full but run
only after the stage before them succeeds.

A blocked run (status 3 or 4) also fails `TestM31LocalE2E` itself, so running
`go test -tags integration ./tests/m3-1` directly never reports a blocked run
as PASS. The script also maps status 2 for a runtime base image it cannot pull.

## Layout

- `run-local.sh`: containers, builds, and the driver.
- `harness_integration_test.go`: the driver (`TestM31LocalE2E`, build tag
  `integration`).
- `db_integration_test.go`, `local-install.sql`: logins, migrations and
  install SQL.
- `sim_integration_test.go`: the simulated node-side components.
- `runtime_integration_test.go`: the runtime container.
- `console_integration_test.go`: the operator console client.
- Service harnesses: `m31_local_harness_integration_test.go` in
  `services/identity/cmd/identity`, `services/credential-broker/cmd/broker`,
  `services/control-health/cmd/control-health` and `tools/first-bundle`. Each
  one runs the service's real handlers with one dependency replaced. They are
  built as test binaries (`go test -c -tags integration`) and are never part of
  a service build.

## Simulated locally

| Input | Replacement | Where |
|---|---|---|
| Google CAS | A fake CA service signs each CSR with a local CA. It signs exactly the requested URI and DNS SANs. | identity harness |
| Kubernetes TokenReview, Pod and Node | A fixed table of projected tokens, pods (namespace, KSA, pod UID, node) and one node (UID, boot ID). | identity harness, `topology_integration_test.go` |
| Google JWKS | A test RSA key signs the console ID tokens; identity verifies them against that key. | identity harness, `pki_integration_test.go` |
| GCS | `fsouza/fake-gcs-server` for the policy bundle and the audit export buckets. | `run-local.sh` |
| `/proc/self/ns/net` of the adapter | A fixed `netns_inode` (4026531840) for `receiver-sender`; macOS has no `/proc`, and the coordinator refuses a connection key without it. The rest of `run()` is the real binary. | receiver-sender harness (`services/adapters/receiver-sender/m31_local_harness_integration_test.go`) |
| Production policy data (#30) | `policies/gateway/testdata/policy-data.json` plus `adapter_constraints["receiver-sender"]` (route `submissions-v1`, 64 KiB request and response). | `harness_integration_test.go` `publishBundle` |
| Sensor release policies baseline | `active_policy.sensor_release_policies_digest` gets a fixed digest in place of the lock `baseline_digests.sensor_release_policies`; no drift probe runs locally. | `harness_integration_test.go` step 4 |
| Secret Manager | The receiver API key is read from a local file. | credential-broker harness |
| Cloud KMS | The audit exporter signs manifests with a local P-256 key behind a fake KMS endpoint. The policy bundle is signed by a local key (first-bundle supports only KMS signing). | `sim_integration_test.go`, first-bundle harness |
| Kubernetes in-cluster API for control-health | No startup capture (`--startup-capture` needs `InClusterConfig`); the node facts come from the fixed table. | control-health harness |

Node-side inputs. Each simulated component uses its own workload certificate,
issued by identity and registered as the install SQL would register it.

| Input | Simulated component | Path |
|---|---|---|
| node-sensors lease (`tetragon-node/<node_uid>`, rule hash, sensor generation 1) | node-sensors | API: `POST /internal/control-health/leases` |
| lifecycle-recorder lease | lifecycle-recorder | API: `POST /internal/control-health/leases` |
| node-readiness lease (global) | node-readiness | API: `POST /internal/control-health/leases` |
| Kernel `process_exec` events for the worker process (host PID, container ID, parent exec ID) | node-sensors | API: `POST /internal/kernel/events:batch` on the audit writer |
| Worker observation results (image digest from the local Docker image) | node-sensors | API: `POST /internal/control-health/worker-observation-results` |
| Pod observation results for work readiness | node-sensors | API: `POST /internal/control-health/pod-observation-results` |
| Node boot generation `ready` | probe-runner | Direct DB: `UPDATE health.node_boot_generation`. The probe-results API cannot be reached locally: probe-runner certificates carry no pod UID (`services/control-health/internal/health/bootstrap.go`, `recovery.go` `findAnswerEvidence`). |
| Container lifecycle intervals | lifecycle-recorder | Direct DB: `INSERT INTO correlation.lifecycle_intervals`. No service writes this table yet. |

The runtime container runs with the agent-exec settings that Docker can
express: UID 10001, no capabilities, `no-new-privileges`, read-only root and a
tmpfs `/work`. It reaches the gateway on the host through
`host.docker.internal`. NetworkPolicy, admission and GKE Sandbox are not
reproduced.

## Install inputs not in the repository

`local-install.sql` supplies installer inputs that no repository install file
provides yet. Each row follows the service README or its integration tests:

- Login memberships: `broker_reader`, `audit_writer`, `audit_exporter`.
- The audit writer's proxy row in `audit.db_role_sources` and its column read
  on `identity.registered_workloads`.
- Producer grants for kernel ingest (`kernel_event_observed`,
  `sequence_range_abandoned`, `observation_gap_recorded`) and for
  control-health (`execution_held`, `hold_requested`,
  `source_health_changed`).
- `identity.registered_workloads` rows for `workload-identity`,
  `credential-broker`, `control-health`, `audit-writer`, `audit-exporter`,
  `lifecycle-recorder` and `node-readiness`.
- `health.component_principals` rows for `audit-db`, `lifecycle-recorder` and
  `node-readiness`.

An install gap is a repository install file that fails when run as the
installer login. The driver then applies it as the superuser to continue,
prints `INSTALL GAP`, and the script exits non-zero even if every stage
passes. There is no install gap at present: both install files apply as the
installer login (`m3-1-action-path.sql` takes the schema owner roles for its
own transaction, as the migrations do).
