# Node readiness controller installation (TASK-01 3.5)

`node-readiness.yaml` creates the `agent-control/node-readiness` ServiceAccount
and a single-replica Deployment. The controller watches nodes whose protected
role label is `exec` or `control`, queries
`GET /internal/control-health?scope=node&scope_id=<node_uid>` for each, and
removes the start taint `agentarium.io/observe-not-ready=true:NoSchedule` only
when the TASK-10 conditions hold (it re-adds the taint otherwise). Without this
Deployment the taint is never removed, so `agent-adapters` and `agent-exec`
Pods can never schedule.

- **Placement.** Protected nodeSelector `agentarium-role: control`. As a
  bootstrap role (`agent-control`, TASK-01 3 item 3 and 3.5) the Pod tolerates
  exactly the start taint; it must run before any node is ready.
- **Kubernetes API.** The KSA name matches `rbac/node-readiness.yaml` (nodes
  get/list/watch/patch) and the `node-readiness-scope` admission policy. The
  Pod keeps `automountServiceAccountToken: false` and mounts an explicit
  projected API token, the cluster CA and the namespace at the in-cluster path,
  the same shape as `workload-identity`.
- **mTLS.** The binary bootstraps its client certificate in memory from
  workload-identity with the projected `agentarium-identity` token
  (`--identity-url`, `--bootstrap-token`), like the other control services.
  No certificate file or Secret is mounted. It verifies the control-health
  server SAN `spiffe://agentarium.internal/ns/agent-observe/sa/control-health`.
  SPEC-QUESTION: TASK-01 3.5 does not name the controller's certificate source,
  and the controller code originally read only cert/key files ("issuance is
  out of scope"). This change adds the `--identity-url` mode because the allow
  matrix already grants `node-readiness -> workload-identity` TCP/8443 and no
  file-based issuer exists in GKE. The file mode stays for local tests.
- **Network.** The rendered `node-readiness-allow` NetworkPolicy allows egress
  to `agent-control/workload-identity` and `agent-observe/control-health` on
  TCP 8443, plus kube-dns and the kube-apiserver. There is no listener and no
  Service.
- **No database.** No Cloud SQL Auth Proxy and no Workload Identity, so the Pod
  does not need the GKE metadata-server nodeSelector.
- **One replica.** The controller has no leader election. Do not scale it up.
  The Deployment uses `strategy: Recreate`, so a rollout stops the old Pod
  before it starts the new one and two controllers never run together.

## Render values

| Value | Source |
| --- | --- |
| `NODE_READINESS_IMAGE` | digest of `build/docker/go-service.Dockerfile` built with `CMD=./services/node-readiness`. Add the same digest to `AGENT_CONTROL_IMAGES`; `render.py` rejects it otherwise |

```sh
docker build -f build/docker/go-service.Dockerfile --build-arg CMD=./services/node-readiness \
  -t "$REGION-docker.pkg.dev/$PROJECT/agentarium/node-readiness:$TAG" .
```

The Dockerfile does not set `-ldflags -X main.version`, so the lease
`active_version` is `null`. TASK-10 accepts that (the field is optional).

## Installation data

These rows and profile entries are required before the controller can do
anything useful. Without them it fails closed: control-health answers 403 and
no taint is removed.

1. `identity.registered_workloads`: `('agent-control', 'node-readiness',
   'service', NULL, 'node-readiness', true)`. The seed
   `services/identity/seed/registered_workloads.yaml` lists it, but an
   installer that inserts rows explicitly must include it.
2. `health.component_principals`: SAN
   `spiffe://agentarium.internal/ns/agent-control/sa/node-readiness`,
   component `node-readiness`, allowed scopes `{global}`, no hold reasons. The
   controller reports its own global lease (`scope_id = '*'`).
3. control-health profile `readers` must list the same SAN; the node-scope
   query is a reader call.

Apply after `rbac/`, `network/rendered/policies.yaml` and
`contact-services/contacts.yaml` (identity and control-health must be up):

```sh
kubectl apply -f "$OUT/node-readiness/node-readiness.yaml"
kubectl -n agent-control rollout status deploy/node-readiness --timeout=5m
kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints[*].key
```

A node keeps the taint until its node-sensors, exporter and lifecycle-recorder
leases are valid, the probe passed twice and no node hold is open. That is the
intended fail-closed state, not a controller fault.
