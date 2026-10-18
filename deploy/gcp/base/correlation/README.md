# Correlation service installation (TASK-10)

`correlation.yaml` creates the `agent-observe/correlation` ServiceAccount, a
network values ConfigMap, the audit-epoch PersistentVolumeClaim, a single
replica Deployment and the internal Service. The process serves
`POST /internal/network-policy/records:batch` for the hostNetwork netpol
collectors (`node_cidr` ingress on TCP 8443) and runs the correlation worker,
NetworkFinding and risk-event loops. Risk-event holds go to
`control-health` `POST /internal/holds` with the correlation certificate.

Only the Cloud SQL Auth Proxy native sidecar impersonates the correlation DB
GSA. The KSA has no GSA annotation and the Pod mounts no Secret and no
Kubernetes API token; the projected `agentarium-identity` token is used only
for the in-memory mTLS certificate.

## Inputs

| Mount | Source |
| --- | --- |
| `agentarium-environment-lock` ConfigMap, key `environment.lock.json` | the installed `deploy/gcp/environment.lock.json`, exact bytes (its SHA-256 is the segment `lock_digest`). The kube-dns ClusterIP is the `network.services_range` `.10` (TASK-01 lock rule, Q0 `20261014-task01-q0-min`) |
| `correlation-network-values` ConfigMap (this manifest) | `control_plane_endpoint`, `cloudsql_private_ip`, `node_cidr` render values |
| `agentarium-allow-matrix` ConfigMap, key `allow-matrix.yaml` | `deploy/gcp/base/network/allow-matrix.yaml` from the same render |

## Render values

| Value | Source |
| --- | --- |
| `CORRELATION_IMAGE` | digest of `build/docker/go-service.Dockerfile` built with `CMD=./services/correlation/cmd/correlation`. Add the same digest to `AGENT_OBSERVE_IMAGES` |
| `CORRELATION_DB_GSA`, `CORRELATION_DB_USER` | `services["correlation"]` outputs of `platform/gcp/iam/workload-services` |
| `CORRELATION_AUDIT_SOURCE_ID` | the `audit.db_role_sources` source of the correlation DB login |
| `CLUSTER_UID` | the installation cluster UID (canonical lowercase UUID) |

## Installation order

1. Apply migrations in version order; grant `correlation_writer` and the
   TASK-07 `correlation_reader` to the correlation IAM DB login and register its
   audit source with the event grants it emits (`network_finding_recorded`,
   `observation_gap_recorded`, `sequence_range_abandoned`,
   `evidence_gap_resolved`, `kernel_correlation_checked`).
2. Create the two input ConfigMaps above, then apply this manifest.

Not included: the Node informer for node deletion (TASK-10 3.7, needs a
`nodes` get/list/watch ClusterRole) and the TASK-03 `identity.pod_workloads`
lookup (#206). Until that lookup exists every Pod resolves to an unknown
workload: findings stay unlinked and no risk-event hold is requested.


## Evaluation retries

The service selects unacknowledged kernel/netpol input IDs in `received_at`
order, then evaluates their source-time windows. `correlation.evaluation_receipts`
is internal retry state: an ID is recorded only after worker, netpol and risk
steps all succeed. Restart scans retained inputs regardless of `--lookback`;
transactions that commit late cannot fall behind a timestamp cursor. Receipts
are idempotent and a crash before recording one repeats the evaluation.

Each tick visits at most 64 nodes and 128 pending inputs per node, rotating
through node UUIDs. Source-time minutes form separate evaluation windows with
five minutes of join overlap on either side, capped at `now - MinDelay`.
One failed window remains pending while successful windows advance. The recent
source-time tail is still re-evaluated for late join evidence and is capped at
ten minutes, independently of failures. `--lookback` only controls that tail,
not recovery of pending inputs. This is functional PostgreSQL/unit validation;
production backlog throughput and GCP deployment have not been measured.
