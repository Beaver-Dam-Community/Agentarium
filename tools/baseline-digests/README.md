# baseline-digests

Computes the six `baseline_digests` values of the environment lock
(`admission`, `exec_rbac`, `network_policy`, `node_pool_config`,
`sensor_policy`, `sensor_release_policies`) as defined in
[TASK-01 4](../../docs/tech-specs/TASK-01-gke-platform.md#4-api-data-and-connection-contract-ref) and
[TASK-16 3.1](../../docs/tech-specs/TASK-16-delivery-runbooks.md#31-installation-order-and-the-environment-lock).
Selection, projection, normalization and digests live in
[`packages/baseline/`](../../packages/baseline/), which the TASK-10 drift probe
also uses, so installer and probe cannot diverge.

## When to run

After every install step that creates or changes baseline objects: step 7 in
the production project, step 7r in the regression project. Then render the
lock into ConfigMap `agent-observe/drift-probe-baselines`.

## Usage

```sh
# Production install, after runbook step 7:
go run ./tools/baseline-digests \
  --context <explicit-kube-context> \
  --lock deploy/gcp/environment.lock.json \
  --write-lock deploy/gcp/environment.lock.json

# Print JSON instead of writing the lock:
go run ./tools/baseline-digests --context <ctx> --lock deploy/gcp/environment.lock.json

# Offline / dry run from pre-fetched JSON:
go run ./tools/baseline-digests --from-dir <dir> [--write-lock <lock>]
```

| Flag | Meaning |
| --- | --- |
| `--context` | kubeconfig context to read. Required for cluster reads; the current context is never used. |
| `--kubeconfig` | kubeconfig path (default `$KUBECONFIG` or `~/.kube/config`). |
| `--lock` | environment lock read for `project.id`, `project.location` and `environment`. The GKE cluster is `projects/<id>/locations/<location>/clusters/agentarium-<environment>`, matching `platform/gcp/modules/platform`. |
| `--from-dir` | read `<source-id>.json` files and `cluster.json` instead of the cluster and GKE API. Cannot be combined with `--context`, `--kubeconfig` or `--lock`. |
| `--write-lock` | replace only the top-level `baseline_digests` of this lock (other keys keep their order and values; 2-space indent, trailing newline, atomic rename). Without it the digests are printed to stdout as JSON. |
| `--timeout` | overall read timeout (default 5m). |

The tool is fail-closed: a missing resource type (404), a missing named
object, a missing release TracingPolicyNamespaced, a permission error or any
other read error exits non-zero and leaves the lock unchanged. An empty LIST
is a valid observation.

## What is read

Only `get` and `list` (no watch, no writes). GKE: one `container.clusters.get`.

| Source ID (`--from-dir` file) | Read | Baseline |
| --- | --- | --- |
| `validatingadmissionpolicies` | LIST `admissionregistration.k8s.io/v1` | admission |
| `validatingadmissionpolicybindings` | LIST `admissionregistration.k8s.io/v1` | admission |
| `constraints-configmaps` | GET `agent-control/agent-exec-constraints`, `agent-control/agent-role-constraints` | admission |
| `roles`, `rolebindings` | LIST all Namespaces | exec_rbac |
| `clusterroles`, `clusterrolebindings` | LIST | exec_rbac |
| `networkpolicies` | LIST in the seven role Namespaces | network_policy |
| `networkloggings` | GET `networking.gke.io/v1alpha1` `default` | network_policy |
| `tracingpolicies` | LIST `cilium.io/v1alpha1` | sensor_policy |
| `tracingpoliciesnamespaced` | LIST all Namespaces | sensor_policy / sensor_release_policies |
| `tetragon-config` | GET `agent-sensors/tetragon-config` | sensor_policy |
| `tetragon-daemonset` | GET `agent-sensors/tetragon` (`apps/v1`) | sensor_policy |
| `cluster.json` | GKE clusters.get response (REST JSON) | node_pool_config |

`--from-dir` files are Kubernetes JSON lists (`kubectl get -o json`) or single
objects. Items outside a source's Namespaces or names are ignored, so
`kubectl get <resource> -A -o json` output can be used as is. `cluster.json`
can be `gcloud container clusters describe <name> --location <loc> --project <p> --format=json`.

## Rules (summary)

- Each object loses `metadata.resourceVersion`, `uid`, `creationTimestamp`,
  `managedFields`, `generation`, the annotation
  `kubectl.kubernetes.io/last-applied-configuration` and `status`. Other
  annotations stay. An annotations map left empty by that removal is dropped.
- Objects are sorted by `(apiVersion, kind, metadata.namespace, metadata.name)`;
  the digest is `SHA-256(JCS(array))` via `packages/canonical`.
- The Tetragon DaemonSet is reduced to
  `{apiVersion, kind, metadata.namespace, metadata.name, spec.template}`.
  Only the top-level metadata is normalized; the Pod template is kept as read.
- `sensor_release_policies` is the digest of the TASK-14 release-managed
  `agent-exec` TracingPolicyNamespaced `agentarium-tcp-connect` and
  `agentarium-protected-file`; `sensor_policy` is the digest of everything else
  collected for that kind. The drift comparison value
  `SHA-256(JCS({"install": ..., "release": ...}))` is
  `baseline.SensorDriftDigest` and is not stored in the lock.
- `node_pool_config` is the digest of
  `{"nodePools": [{name, config: {taints, labels, workloadMetadataConfig}, management: {autoUpgrade, autoRepair}, maintenancePolicy}], "maintenanceExclusions": {...}}`
  with pools sorted by name and absent API fields filled with explicit defaults.

## Operator permissions

Kubernetes RBAC: the same read set as the drift probe
(`deploy/gcp/base/rbac/drift-probe.yaml`), that is `get`/`list` on
`validatingadmissionpolicies`, `validatingadmissionpolicybindings`, `roles`,
`rolebindings`, `clusterroles`, `clusterrolebindings`, `networkpolicies` (seven
role Namespaces), `networkloggings`, `tracingpolicies`,
`tracingpoliciesnamespaced`, plus `get` on ConfigMaps
`agent-control/agent-exec-constraints`, `agent-control/agent-role-constraints`,
`agent-sensors/tetragon-config` and DaemonSet `agent-sensors/tetragon`. No
Secret access and no write verbs.

GCP IAM: `container.clusters.get` on the cluster's project (for example
`roles/container.clusterViewer`), with Application Default Credentials.

## Tests

```sh
go test ./packages/baseline/... ./tools/baseline-digests/...
```

`packages/baseline/testdata/golden.json` holds the digests of the fixture in
`packages/baseline/testdata/observation/`. After a reviewed rule change,
regenerate it with `go test ./packages/baseline/ -run TestGoldenDigests -update`.
