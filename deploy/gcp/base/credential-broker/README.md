# Credential broker installation (TASK-06)

`broker.yaml` creates the `agent-control/credential-broker` ServiceAccount,
Deployment and internal Service. The KSA name equals the Pod label used by the
rendered `credential-broker-allow` NetworkPolicy, whose only ingress is
`agent-adapters/receiver-sender` on TCP 8443. The Pod mounts no Secret and no
Kubernetes API token. It receives only the projected `agentarium-identity`
bootstrap token used by the identity service for its mTLS certificate.

Only the Cloud SQL Auth Proxy native sidecar impersonates the broker DB GSA.
The broker process keeps the direct KSA principal for Application Default
Credentials, so Secret Manager access comes from the per-secret
`roles/secretmanager.secretAccessor` grants in `platform/gcp/iam/workload-services`.
The KSA has no `iam.gke.io/gcp-service-account` annotation. Like every
`agent-control` Pod (bootstrap role Namespace, TASK-01 3 item 3 and 3.5), the
broker tolerates exactly the observation start taint
`agentarium.io/observe-not-ready=true:NoSchedule`, so it can start on control
nodes before node-readiness removes that taint. The protected control
nodeSelector remains required. The broker follows the Namespace rule
rather than a narrower per-service exception because nothing is exposed
early: its only caller, `agent-adapters/receiver-sender`, cannot tolerate the
start taint and is scheduled only after the taint is removed.

## Render values

Render via `deploy/gcp/base/render.py` with these additional values:

| Value | Source |
| --- | --- |
| `BROKER_IMAGE` | digest of `build/docker/go-service.Dockerfile` built with `CMD=./services/credential-broker/cmd/broker`. Add the same digest to `AGENT_CONTROL_IMAGES` |
| `BROKER_DB_GSA` | `services["credential-broker"].gsa` output of `platform/gcp/iam/workload-services` |
| `BROKER_DB_USER` | `services["credential-broker"].db_user` output of the same module |

`SQL_PROXY_IMAGE`, `CLOUDSQL_CONNECTION_NAME` and `DB_NAME` are shared with the
contact services. Real values belong in the ignored environment lock or a
transient values file, never in committed manifests.

## Installation order

1. Apply the workload IAM module with the broker's `credential_secret_resources`.
2. Apply migrations in version order with the migration identity. The broker
   migration creates `broker_reader`; the later TASK-03
   `*_coordinator_credential_scope` migration grants it coordinator USAGE and
   SELECT on `coordinator.attempt_credential_scope` only.
3. Grant `broker_reader` to the broker's IAM DB login. Do not grant it identity
   schema access or any base-table SELECT.
4. Populate `broker.credential_bindings` through the operator with canonical
   secret resource names and fixed numeric versions.
5. Apply the rendered NetworkPolicies, then this manifest. The broker exits at
   startup if its database privileges or view columns are missing.

## Live verification (not yet run)

Run after installation, with the exact kubeconfig and context:

```sh
kubectl --kubeconfig "$KUBECONFIG" --context "$CONTEXT" -n agent-control \
  rollout status deployment/credential-broker --timeout=180s
kubectl --kubeconfig "$KUBECONFIG" --context "$CONTEXT" -n agent-control \
  logs deployment/credential-broker -c credential-broker --tail=50
```

Pass criteria: the rollout completes, the log contains no
`broker database contract or permissions unavailable` or
`certificate bootstrap failed` line, and no secret value appears in the log.
Then run the TASK-06 section 7 `credential contract` cases from
`agent-adapters/receiver-sender`: another adapter's certificate, an attempt that
is not `planned`, and a disabled binding must all return 503
`CREDENTIAL_UNAVAILABLE`. A TCP readiness probe only shows that the listener is
up. It does not prove database access, Secret Manager access or mTLS.
