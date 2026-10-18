# Kubernetes reader permission ceiling

`kubernetes-reader.yaml` implements TASK-06 section 3.2. The
`agent-adapters/kubernetes-reader` ServiceAccount can get/list pods and core
events, and get pod logs, only in `agent-targets`. It receives no exec, attach,
port-forward, proxy, Secret, token creation, RBAC mutation or workload write
permissions. Other installed role bindings can add permissions, so the live
check below is required after installation.

The ServiceAccount disables automatic token mounting. The adapter deployment
must explicitly project a short-lived API token and CA for its Kubernetes
client; that deployment belongs to the adapter integration. A role binding
does not replace the adapter's approved namespace, Pod UID and output checks.

Render the base tree, then inspect and apply this manifest as the installer.
The existing identity and drift-probe files remain independent; do not use a
recursive apply of every YAML file as a substitute for the installation order.

```sh
kubectl --kubeconfig "$KUBECONFIG" --context "$CONTEXT" apply --dry-run=server \
  -f "$RENDERED_BASE/rbac/kubernetes-reader.yaml"
kubectl --kubeconfig "$KUBECONFIG" --context "$CONTEXT" apply \
  -f "$RENDERED_BASE/rbac/kubernetes-reader.yaml"
python3 tests/egress/check_reader_rbac.py \
  --kubeconfig "$KUBECONFIG" --context "$CONTEXT" > reader-rbac-report.json
```

The check is read-only and needs an operator authorized to impersonate the
ServiceAccount and its authenticated/service-account groups. Explicit group
impersonation includes grants that would be missed by testing a bare username
([Kubernetes impersonation](https://kubernetes.io/docs/reference/access-authn-authz/user-impersonation/),
[RBAC subjects](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)).
API, credential or impersonation errors are `observed: null`
and fail the report; they never count as an access denial. The local Go check
validates the manifest's exact permission ceiling, identity and namespace. It
does not prove live RBAC enforcement or adapter behavior.

## Execution and release denial check

TASK-06 section 7 requires that execution ServiceAccounts cannot read Secrets,
exec into Pods or change NetworkPolicy. TASK-01 also forbids them Pod,
Deployment, Namespace, admission policy, RBAC binding and node changes.
TASK-06 section 3.4 requires that neither the
execution ServiceAccounts nor the release ServiceAccount hold any verb on the
cluster-scoped `NetworkLogging`. This repository grants these subjects no RBAC,
so the check proves that no other installed binding adds such a permission.
Every one of its 1117 cases expects denial:

```sh
python3 tests/egress/check_denied_rbac.py \
  --kubeconfig "$KUBECONFIG" --context "$CONTEXT" > denied-rbac-report.json
```

The subjects are `agent-exec/{agent-runtime,probe-runner,start-fixture}` and,
for `NetworkLogging` only, `agent-release/{releaser,regression-dispatcher}`.
The releaser's TASK-14 TracingPolicy permissions are not evaluated here. Each
case creates a SelfSubjectAccessReview under impersonation of the
ServiceAccount and its groups. Only `allowed: false` without an
`evaluationError` counts as denial; API, credential, impersonation and
authorizer evaluation errors are `observed: null` and stop the run. `python3 -m unittest discover -s tests/egress
-p 'test_denied*.py'` checks report semantics with fixture decisions only; it is
not live RBAC evidence.

## Workload Roles

These files give each workload that calls the Kubernetes API only the
permissions its owning spec names. They create no ServiceAccounts; the owning
workload manifest does.

| File | Subject | Permissions | Source |
| --- | --- | --- | --- |
| `node-readiness.yaml` | `agent-control/node-readiness` | ClusterRole: nodes get/list/watch/patch; no `nodes/status` | TASK-01 3.2.1 |
| `correlation.yaml` | `agent-observe/correlation` | ClusterRole: nodes get/list/watch | TASK-10 3.7 |
| `control-health.yaml` | `agent-observe/control-health` | Role in `agent-control` and `agent-adapters`: deployments get/list/watch | TASK-10 3.2, 4 |
| `pod-watcher.yaml` | `agent-observe/pod-watcher` | Role in `agent-exec`: pods list/watch | TASK-09 3.6, TASK-07 3.3 |
| `discovery.yaml` | `agent-observe/discovery` | Role in `agent-observe`: jobs create/get, pods list | TASK-02 3.4 |
| `releaser.yaml` | `agent-release/releaser` | Role in `agent-exec`: `tracingpoliciesnamespaced` get/update/patch on `agentarium-tcp-connect` and `agentarium-protected-file` only | TASK-14 3.4, TASK-09 3.2 |

`discovery` is the only subject with a verb that creates a workload. RBAC
cannot restrict what a created Job runs, and `agent-role-contract` only binds
the Pod label to its ServiceAccount and the image to the whole
`agent-observe` list, so a Job could otherwise run as `audit-writer` or any
other `agent-observe` ServiceAccount. `../admission/discovery-snapshot.yaml`
therefore rejects any Job created by `discovery`, and any Job or Pod that runs
as `discovery-snapshot`, unless it uses the `discovery-snapshot` KSA without an
API token, only the pinned `DISCOVERY_SNAPSHOT_IMAGE` with its default
entrypoint, the fixed TASK-02 argument layout for `DISCOVERY_BUCKET`, the single
emptyDir `work` volume, and no host namespaces. Container fields are an
allowlist: lifecycle hooks, all probes, env/envFrom, workingDir, ports,
stdin/tty, resizePolicy, a container restartPolicy and any securityContext
field other than the restricted read-only/no-escalation/drop-ALL profile are
rejected. A test fails if a newer `k8s.io/api` adds an uncovered field. The releaser's TracingPolicy
update and node-readiness's node patch change no workload; the latter stays
limited by `node-readiness-scope`.

Nodes are cluster-scoped and have no fixed names, so the node rules cannot use
`resourceNames`. Informers and per-request Job names prevent `resourceNames`
for the other list/watch/create rules. The node-readiness `patch` remains
limited by the `node-readiness-scope` admission policy, which an access review
does not evaluate. Roles in `agent-exec` become part of the TASK-01 `exec_rbac`
drift baseline when installed.

`go test ./tests/egress` checks each file's exact permission ceiling and that
the live check's allowed cases equal it. After installation, run the read-only
live check (347 cases: every grant allowed, neighbouring permissions denied):

```sh
python3 tests/egress/check_workload_rbac.py \
  --kubeconfig "$KUBECONFIG" --context "$CONTEXT" > workload-rbac-report.json
```

Only `allowed` without an `evaluationError` counts as an observation. API,
credential, impersonation and authorizer errors are `observed: null` and stop
the run.

An access review does not run admission. To check the snapshot policies live
(not yet run), submit server-side dry runs as discovery. A Job built exactly
like `KubernetesJobs.job_manifest` must be accepted, and the same Job with
`serviceAccountName: audit-writer` (and that label), an extra projected token
volume, or another image must be rejected with `SNAPSHOT_IDENTITY_INVALID`,
`SNAPSHOT_VOLUMES_INVALID` or `SNAPSHOT_IMAGE_INVALID`:

```sh
kubectl --kubeconfig "$KUBECONFIG" --context "$CONTEXT" -n agent-observe \
  create --dry-run=server -f job.json \
  --as system:serviceaccount:agent-observe:discovery \
  --as-group system:authenticated --as-group system:serviceaccounts \
  --as-group system:serviceaccounts:agent-observe
```

The offline equivalents are in `tests/platform/admission/discovery_snapshot_test.go`.
