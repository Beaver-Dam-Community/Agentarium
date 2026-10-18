# M3-1 GKE Live Measurement Procedure (action path)

This document is the procedure for deploying the M3-1 action path (console session → runtime → gateway evaluation → coordinator → receiver-sender → receiver → evidence-collector receipt → audit query) to production GKE and sending 1 demonstration action. All changes are made exclusively via IaC and repository scripts. Do not create resources manually in the console.

**Status:** This procedure has not yet been executed end-to-end on GKE. The "Expected results" for each step are values derived from the code and offline tests (PR-G render, admission, and Terraform mock tests; PostgreSQL 16 installation SQL tests). Record actual results in `evidence/` and stop if they differ.

## 0. Prerequisites

- Code: Clean checkout of integration branch `rina/m3-1-gke-integration` (PR-A~M + #143, #150, #156, #231, etc., plan step 9). Manifests and SQL in this document are based on the binary flags of that branch.
- Preceding PRs: #222, #223, #230, #237, #240, #252, #264, #267, #273, #275, #278 have been merged into main. With #264, containerd-proxy became non-dumpable starting from execve, but do not deploy exporter's host `/proc` mount before verifying on a GKE node (step 7 sensor verification item, TASK-01 3.2.1 exporter host procfs deployment prerequisite).
  - #225 must be merged before this PR. This is because it creates the `adapter_app` role used by the installation SQL and the receiver-sender flag. Without it, step 6 SQL fails with `role "adapter_app" does not exist`.
  - #156 creates the connection between the step 5 migration Job and step 6 installer. Since it has not been merged yet, steps 5 and 6 cannot be executed as described in this document until it is merged.
- Tools: `gcloud`, `kubectl` (gke-gcloud-auth-plugin), `terraform` 1.9 or higher, `docker buildx`, `crane`, `jq`, `psql` 16, Python 3 (PyYAML).
- lock: `deploy/gcp/environment.lock.json`, which is not committed to the repository. Fill in all `REPLACE_WITH_*` in `environment.lock.example.json`. Newly required keys in M3-1 are as follows (not yet in the TASK-16 schema. SPEC-QUESTION).
  - `identity.oidc_audiences`: List of allowed Google ID token `aud`. If using `gcloud auth print-identity-token`, the gcloud OAuth client ID goes here.
  - `identity.oidc_allowed_hd`: Allowed Workspace domain (`hd` in token). Tokens for gmail accounts have no `hd`, resulting in 401. Verify before live measurement with `gcloud auth print-identity-token | cut -d. -f2 | base64 -d 2>/dev/null | jq .hd`.
  - `receiver.cluster_ip` (within the first 256 of the services range, excluding `.1`, `.10`, and gateway IP), `receiver.probe_cluster_ip` (same range, excluding gateway and receiver IP. TASK-02 `targets.yaml`'s `receiver-probe` Service and `<receiver-probe ClusterIP>/32`), `receiver.receiver_mode` (`idempotent` recommended), `receiver.api_key_secret` (`projects/<number>/secrets/<name>`), `receiver.api_key_versions` (1–2 numeric versions, current version first).
  - Add `receiver.api_key_secret` to `iam.credential_secret_resources`. Broker attaches headers using the same secret, and receiver verifies using the same secret.
- Common variables:

```sh
cd /path/to/Agentarium            # Integration branch
LOCK=deploy/gcp/environment.lock.json
PROJECT=$(jq -r .project.id "$LOCK")
REGION=$(jq -r '.project.location | sub("-[a-z]$"; "")' "$LOCK")
AR="${REGION}-docker.pkg.dev/${PROJECT}/agentarium"
CLUSTER="agentarium-$(jq -r .environment "$LOCK")"
EV=~/scratch/2026-10/goals/m3-1-wiring/evidence     # Live measurement record location (outside repository)
RUN=$(date -u +%Y%m%dT%H%M%SZ)
KCTX="gke_${PROJECT}_$(jq -r .project.location "$LOCK")_${CLUSTER}"   # Context name created by step 4 get-credentials
K() { kubectl --context "$KCTX" "$@"; }   # Define as a function because zsh does not split unquoted variables into words
```

The operator's kubeconfig current-context may be pointing to another cluster. Therefore, all kubectl commands in this document are run with `K` (`kubectl --context <agentarium context>`) without relying on current-context. After step 4, verify that the name matches with `kubectl config get-contexts "$KCTX"`.

## 1. Power On

```sh
platform/gcp/scripts/power.sh on --lock "$LOCK"
platform/gcp/scripts/power.sh status --lock "$LOCK"
```

Expected results: exec, control, and system node pools have lock's `node_count` (2, 3, 1), Cloud SQL `activationPolicy=ALWAYS`, `state=RUNNABLE`. Even if subsequent steps fail, step 10 (Power Off) must be executed at the end.

## 2. Image Build and Push

Build for linux/amd64, push to Artifact Registry `agentarium` repository (immutable tag), and read the digest. Use the integration branch commit for the tag.

```sh
TAG=$(git rev-parse --short=12 HEAD)
build() { # $1 name, $2 CMD path
  docker buildx build --platform linux/amd64 -f build/docker/go-service.Dockerfile \
    --build-arg CMD="$2" -t "$AR/$1:$TAG" --push .
}
build workload-identity  ./services/identity/cmd/identity
build audit-writer       ./services/audit/cmd/writer
build audit-exporter     ./services/audit/cmd/exporter
build control-health     ./services/control-health/cmd/control-health
build credential-broker  ./services/credential-broker/cmd/broker
build policy-gateway     ./services/gateway/cmd/gateway
build coordinator        ./services/coordinator/cmd/coordinator
build receiver-sender    ./services/adapters/receiver-sender
build receiver           ./services/receiver/cmd/receiver
build evidence-collector ./services/evidence-collector/cmd/evidence-collector
build sensor-exporter    ./sensors/exporter/cmd/exporter
build node-readiness     ./services/node-readiness
build lifecycle-recorder ./services/lifecycle-recorder/cmd/lifecycle-recorder
# Only containerd-proxy uses a dedicated Dockerfile. There is no CMD build-arg (Dockerfile hardcodes cmd/containerd-proxy).
docker buildx build --platform linux/amd64 -f build/docker/containerd-proxy.Dockerfile \
  -t "$AR/containerd-proxy:$TAG" --push .
docker buildx build --platform linux/amd64 -f services/runtime/Dockerfile -t "$AR/agent-runtime:$TAG" --push .
for n in workload-identity audit-writer audit-exporter control-health credential-broker policy-gateway coordinator \
         receiver-sender receiver evidence-collector sensor-exporter node-readiness lifecycle-recorder \
         containerd-proxy agent-runtime; do
  echo "$n $AR/$n@$(gcloud artifacts docker images describe "$AR/$n:$TAG" --format='value(image_summary.digest)')"
done | tee "$EV/images-$RUN.txt"
```

Expected results: 15 lines, all `@sha256:<64 hex>`. Cloud SQL Proxy, Tetragon, migrate, and psql images use already mirrored digests (#121, #165, #156 procedures). If `go mod download` fails in local BuildKit (recorded in #234), run the same command on a builder with network access. Do not modify Dockerfiles.

Never build containerd-proxy with `go-service.Dockerfile`. Because `containerd-proxy.Dockerfile` sets `/app` to root-owned `0111` (execute-only), UID 0 processes without capabilities cannot read the binary, and the kernel marks this process as non-dumpable starting from execve. Building with `go-service.Dockerfile` makes `/app` readable, recreating the window between execve and `main`'s first statement `PR_SET_DUMPABLE(0)` where it remains dumpable (#264). During that window, exporter with the same UID 0 can reach the containerd socket via `/proc/<proxy pid>/root`. lifecycle-recorder and node-readiness use `go-service.Dockerfile`.
## 3. Terraform plan/apply

```sh
cd platform/gcp/envs/prod
terraform init -backend-config=backend.hcl
terraform validate
terraform plan -var lock_path="../../../$LOCK" -var gcs_soft_delete_seconds=0 -out=m3-1.tfplan | tee "$EV/tfplan-$RUN.txt"
```

For `karrot-rina`, pass `gcs_soft_delete_seconds=0` because its inherited organization policy `constraints/storage.softDeletePolicySeconds` only permits 0. If omitted, a plan is generated where the `soft_delete_policy` of 4 buckets changes to `604800`, and apply fails with `Error 412 ... violates constraint 'constraints/storage.softDeletePolicySeconds'` (empirically verified on 2026-10-18). In projects without an organization policy, omit this variable to use the default value of 7 days.

Plan review criteria:
- The initial plan involves a large amount of changes. When checked on 2026-10-18, `secretmanager.googleapis.com` and `iam.googleapis.com` were not enabled in `karrot-rina`. This means the `contact-services` module has never been applied. Terraform changes merged into main after 10/15 have also never been applied. Therefore, you should not expect only the single receiver secret accessor added by this PR to be created.
- Check one by one whether the following items appear in the plan:
  - APIs: `module.contact_services.google_project_service.identity_apis` (iam, iamcredentials, secretmanager) and `module.workload_services[0].google_project_service.application_apis` (secretmanager, aiplatform)
  - `contact-services`: DB GSAs, Workload Identity bindings, and IAM DB users for workload-identity, audit-writer, and control-health; CAS pool and template permissions; identity claim key secret and version 1, and its secret accessor
  - `workload-services`: DB GSAs, Workload Identity, IAM DB users, bucket, and KMS permissions for policy-gateway, coordinator, credential-broker, receiver-sender, evidence-collector, etc.; OIDC and broker secret accessors; OIDC client secret resource (no version, `google_secret_manager_secret.identity_oidc`); receiver API key secret and version 1 (`google_secret_manager_secret.receiver_api_key[0]`); receiver KSA accessor (`google_secret_manager_secret_iam_member.receiver_api_key[0]`). Since receiver is also in `database_services`, a DB GSA, Workload Identity binding, and IAM DB user are created. The receiver Pod's cloud-sql-proxy runs as `${RECEIVER_DB_GSA}`, and the installation SQL uses `receiver_login`.
  - `db-installer` (#156): installer GSA, IAM DB user, Workload Identity binding
  - Certificate template (#150) and cluster `secret_manager_config` (Secret Manager CSI add-on)
- The claim key and receiver API key secrets are created by Terraform (#252). The value of the first version (1) is supplied write-only from `ephemeral "random_bytes"` and is not retained in the plan or state. Therefore, write `1` to `identity.claim_key_version` and `receiver.api_key_versions` in the lock. After apply, verify that it matches the version number in `terraform output`. Because these secrets have `deletion_protection` and `prevent_destroy` enabled, stop if any destroy appears in the plan.
- For the OIDC client secret, Terraform only creates the secret resource under the name specified by `iam.oidc_client_secret` in the lock (`google_secret_manager_secret.identity_oidc`, #267), and does not create a version. Because the value is determined by the Google OAuth client, the operator directly adds it as a version after apply. M3-1 logs in using CLI ID tokens and does not read this secret. Do not leave the value in the repository or evidence; record only the resource name and version number.
- In the following cases, stop and report without applying:
  - If there is even a single line with `destroy` or `must be replaced`. Any node_count or activation policy drift resulting from a powered-off state should not exist if step 1 was executed first.
  - If there are resources creating public exposure: external IPs, load balancers or forwarding rules, `0.0.0.0/0` firewall rules, GKE public endpoints, Cloud SQL public IPs, `allUsers` or `allAuthenticatedUsers` bindings, disabling bucket PAP
- Enable APIs exclusively via Terraform. Do not enable APIs or create resources using gcloud.

```sh
terraform apply m3-1.tfplan
terraform output -json workload_services > "$EV/tf-workload-services-$RUN.json"
terraform output -json contact_services  > "$EV/tf-contact-services-$RUN.json"
cd -
```

Expected result: `Apply complete! ... 0 destroyed`. Both outputs contain `gsa` and `db_user` per KSA (inputs for steps 7 and 8).

## 4. kubectl connection

```sh
gcloud container clusters get-credentials "$CLUSTER" --location "$(jq -r .project.location "$LOCK")" \
  --project "$PROJECT" --dns-endpoint
kubectl config get-contexts "$KCTX"
K get nodes -L node-restriction.kubernetes.io/agentarium-role
```

Expected result: exec 2, control 3, and system 1 nodes are `Ready`. The control plane is accessed only via the DNS endpoint (public IP endpoint is disabled).

## 5. migration installation

Execute steps 1 through 9 of the #156 procedure document (`platform/gcp/scripts/db-installer-job.md`) exactly as described. Note that `--migrations-ref` must point to all migrations included in the integration branch (#156 only accepts `origin/main`. To run on an integration branch, supply that commit as the ref). Keep the step 6 binding window open through the step 7 installation SQL.

Expected result: The version in the `verify` log matches the integration branch's latest migration (currently `20261017210001`), `dirty = f`.

## 6. Installation data (role·source·grant·principal)

Open psql using the installer Job Pod or the same db-installer identity (Cloud SQL Proxy + `db-installer@PROJECT.iam`). Example: Spin up a disposable Pod with the same KSA during the window and attach to the Proxy via `kubectl port-forward`.

```sh
DB_USER() { jq -r --arg k "$1" '.[$k].db_user' "$EV/tf-$2-$RUN.json"; }
INSTALLER_DSN="host=127.0.0.1 port=5432 dbname=$DB_NAME user=db-installer@${PROJECT}.iam sslmode=disable"
psql "$INSTALLER_DSN" -v ON_ERROR_STOP=1 -v tenant=hackathon \
  -v identity_login="$(DB_USER workload-identity contact-services)" \
  -v health_login="$(DB_USER control-health contact-services)" \
  -v gateway_login="$(DB_USER policy-gateway workload-services)" \
  -v coordinator_login="$(DB_USER coordinator workload-services)" \
  -v adapter_login="$(DB_USER receiver-sender workload-services)" \
  -v receiver_login="$(DB_USER receiver workload-services)" \
  -v collector_login="$(DB_USER evidence-collector workload-services)" \
  -v health_audit_source_id="$(jq -r .audit_source_id /path/to/control-health-profile.json)" \
  -v receiver_api_key_secret="$(jq -r .receiver.api_key_secret "$LOCK")" \
  -v receiver_api_key_version="$(jq -r '.receiver.api_key_versions[0]' "$LOCK")" \
  -f deploy/gcp/base/installer/m3-1-action-path.sql 2>&1 | tee "$EV/installer-sql-$RUN.txt"
```

Expected result: The last line is `COMMIT`. All 6 `*_ok` checks are `1`. If `ERROR: division by zero` occurs, it means existing rows differ from this file (e.g., control-health login was registered with a different source id in M1). Because the entire transaction was rolled back, inspect which check failed, adjust the values to match, and rerun. Do not overwrite existing rows.

Subsequently, run `m3-1-observe.sql` on the same connection. This file registers the roles and sources for audit-writer, audit exporter, credential-broker, and correlation logins; `*` tenant event grants; and `registered_workloads` and `component_principals` for contact services and node-side workloads (lifecycle-recorder, netpol-collector). All items that local E2E inserts via `tests/m3-1/local-install.sql` are also included in this file. It must not be run before `m3-1-action-path.sql`.

```sh
psql "$INSTALLER_DSN" -v ON_ERROR_STOP=1 \
  -v writer_login="$(DB_USER audit-writer contact-services)" \
  -v exporter_login="$(DB_USER audit-exporter workload-services)" \
  -v correlation_login="$(DB_USER correlation workload-services)" \
  -v broker_login="$(DB_USER credential-broker workload-services)" \
  -v health_audit_source_id="$(jq -r .audit_source_id /path/to/control-health-profile.json)" \
  -v correlation_audit_source_id=correlation \
  -f deploy/gcp/base/installer/m3-1-observe.sql 2>&1 | tee "$EV/installer-observe-sql-$RUN.txt"
```

Expected result: The last line is `COMMIT`. All 5 `*_ok` checks are `1`. For `health_audit_source_id`, use the exact value provided to the action path SQL; for `correlation_audit_source_id`, use the same value as the rendered `CORRELATION_AUDIT_SOURCE_ID`. If `component_principals_ok` yields a division by zero error, it means the audit exporter rows (`audit-export`, `global`·`node`, `export_lag`) inserted by migration `20261017172319` differ or are missing. In this case as well, stop without overwriting existing rows.

Within the same window, complete steps 1 and 2 of the #150 procedure document (certificate template phase transition) within a single maintenance window. Applying step 1 alone blocks all certificate issuances.
## 7. ConfigMap and render

1. Create the public input ConfigMaps (do not commit values to the repository).
   - `agentarium-trust` (key `ca.pem`): All role Namespaces. Output of `gcloud privateca pools get-ca-certs`.
   - `agentarium-bundle-keys` (key `<bundle_key_id>.pem`, public key PEM of KMS bundle key): `agent-control`, `agent-adapters`.
   - `agentarium-identity-role-map` (key `role-map.yaml`, `tenant` and `users[{email, roles}]`): `agent-control`.
   - `agentarium-model-profiles` (key `model-profiles.json`, four profiles: `agent`, `policy_proposal`, `intent_check`, `discovery`): `agent-control`.
   - Put the following in the control-health profile (`agentarium-health-profile`, key `profile.json`). `environment`: `environment` from the lock (if absent, all readiness checks return 503). `readers`: gateway and coordinator SANs and the node-readiness SAN (`spiffe://agentarium.internal/ns/agent-control/sa/node-readiness`). Because node-readiness performs node-scoped queries via reader calls, if this SAN is missing, control-health returns 403 and not a single taint is cleared. `sources`: `{"source_id": "evidence-collector/receiver-primary", "san": "spiffe://agentarium.internal/ns/agent-observe/sa/evidence-collector", "scope_id": "receiver-primary"}` (target lease).
2. Insert the step 2 digests and step 3 outputs into the render values file (`/path/to/values.json`, do not commit). Service images (`GATEWAY_IMAGE`, `COORDINATOR_IMAGE`, `RECEIVER_SENDER_IMAGE`, `RECEIVER_IMAGE`, `EVIDENCE_COLLECTOR_IMAGE`, `IDENTITY_IMAGE`, etc.) must also be in each Namespace list (`AGENT_CONTROL_IMAGES`, etc.), `NODE_READINESS_IMAGE` is the node-readiness digest and the same digest is also placed in `AGENT_CONTROL_IMAGES`. `RUNTIME_IMAGE` is the agent-runtime digest. `AUDIT_EXPORTER_IMAGE` is the audit-exporter digest and is also placed in `AGENT_OBSERVE_IMAGES`. `AUDIT_EXPORTER_DB_GSA` and `AUDIT_EXPORTER_DB_USER` are step 3 `workload_services["audit-exporter"]` outputs. `AUDIT_EXPORTER_KMS_KEY_VERSION` is the full name with `/cryptoKeyVersions/1` appended to the lock's `keys.manifest_signing_key`, and `AUDIT_EXPORTER_PUBLIC_KEY_PEM` is the raw PEM obtained via `gcloud kms keys versions get-public-key 1 --key manifest-signing --keyring <ring> --location <region> --output-file <file>` (if it is not P-256 or is a different key, render rejects it). The two exporter buckets are read only from the lock's `storage`. `*_DB_GSA` and `*_DB_USER` are step 3 outputs, `TRUST_BUNDLE_PEM` is the raw CA PEM, `EVIDENCE_PROBE_ACTION_KEY` is a lowercase UUID chosen once (do not change it), `RELEASE_VERSION` is `$TAG`, and `AGENTARIUM_TENANT` is `hackathon`. The OIDC list, bundle key IDs, gateway and receiver ClusterIPs, receiver mode, and receiver key versions are read only from the lock, so if placed in the values file, render rejects it.

```sh
OUT=/tmp/agentarium-base-$RUN
python3 deploy/gcp/base/render.py --lock "$LOCK" --values /path/to/values.json --out "$OUT"
grep -rn '\${' "$OUT" --include='*.yaml' | grep -v '^\S*:\s*#' ; echo "unrendered=$?"
```

Expected result: render exit code 0, `unrendered=1` (no remaining placeholders). If a Service is not a ClusterIP, or if there is even a single `externalIPs`, `loadBalancer*`, `nodePort`, `hostPort`, Ingress, or Gateway API object, render fails with `public exposure` and deletes the output directory.

3. Application order. Check with `K get pods -A` after each step.

```sh
K apply -k "$OUT/namespaces"
K apply -k "$OUT/admission"
K apply -f "$OUT/rbac/"
K apply -f "$OUT/network/rendered/policies.yaml"
K apply --dry-run=server -f "$OUT/contact-services/contacts.yaml" -f "$OUT/credential-broker/broker.yaml" \
  -f "$OUT/action-path/services.yaml" -f "$OUT/node-readiness/node-readiness.yaml" \
  -f "$OUT/audit-exporter/audit-exporter.yaml"
K apply -f "$OUT/contact-services/contacts.yaml"
K -n agent-control rollout status deploy/workload-identity --timeout=5m
K -n agent-observe rollout status deploy/control-health --timeout=5m
K apply -f "$OUT/audit-exporter/audit-exporter.yaml"   # audit-export lease (control-health RequiredGlobal)
K -n agent-observe rollout status deploy/audit-exporter --timeout=5m
K apply -f "$OUT/node-readiness/node-readiness.yaml"
K -n agent-control rollout status deploy/node-readiness --timeout=5m
K apply -f "$OUT/credential-broker/broker.yaml" -f "$OUT/action-path/services.yaml"
for d in agent-control/policy-gateway agent-control/coordinator agent-adapters/receiver-sender \
         agent-targets/receiver agent-observe/evidence-collector; do
  K -n "${d%/*}" rollout status "deploy/${d#*/}" --timeout=5m
done
K get nodes -o 'custom-columns=NAME:.metadata.name,TAINTS:.spec.taints[*].key'
```

Expected result: 0 admission rejections in server dry-run. The 9 Deployments whose rollout status was checked (including control-health, audit-exporter, and node-readiness) are `successfully rolled out`. Maintain node-readiness at 1 replica and do not increase it. The last command shows the node's readiness taints. Taints are cleared only on nodes where that node's node-sensors and lifecycle-recorder leases are valid, all three answer probes (`process`, `tcp`, `file`) have passed twice consecutively, and there are no open node holds. Before that, taints remaining is the fail-closed state by design, not a controller failure. At this point, sensors and lifecycle-recorder have not yet been applied, so it is normal for taints to remain on all nodes. Re-render and apply Tetragon and exporter (`deploy/gcp/sensors`) with #231 reflected (`proc_root`, `cgroup_root`, and `worker_binaries` must be in the exporter ConfigMap for the node nonce responder to turn on). There is no render tool for lifecycle-recorder (`deploy/gcp/sensors/lifecycle-recorder.yaml`) yet. Substitute `LIFECYCLE_RECORDER_IMAGE`, `CONTAINERD_PROXY_IMAGE` (step 2 digests; both values are also placed in `AGENT_SENSORS_IMAGES`), `CLUSTER_UID`, and `RECORDER_VERSION`, verify that there are no remaining `${`, and then apply. However, apply the exporter's host `/proc` mount only after verifying all of the following. If even one cannot be verified, do not apply Tetragon and exporter, and leave the worker gate as not ready.
- The lifecycle-recorder proxy image was built with `build/docker/containerd-proxy.Dockerfile` (step 2). It is not a digest built with `go-service.Dockerfile`.
- The rendered exporter container's `securityContext.capabilities` has `drop: [ALL]` and no `add`. In particular, `SYS_PTRACE` must not be present. Access to `/proc/<pid>/root` is determined by the kernel's `ptrace_may_access`, and if the caller has `CAP_SYS_PTRACE`, access is allowed even if the proxy is non-dumpable (#264 comment 2). `tests/kernel/deploy` checks this condition.
- The node's `sysctl fs.suid_dumpable` is not 1.
- In the actual Pod, `status.containerStatuses[].volumeMounts[].recursiveReadOnly` is `Enabled` for both `/host/proc` and `/host/sys/fs/cgroup`.
- Reading the proxy's `/proc/<pid>/root` from the exporter returns `Permission denied`.

GID Note (#264 comment 3): proxy runs as UID 0, GID 65532 (image `USER 0:65532`, manifest `runAsGroup: 65532`), and exporter runs as UID 0, GID 0. Since `ptrace_may_access` considers it the same identity only when both UID and GID match, in the current configuration, access is denied based on the GID difference alone, regardless of the dumpable value. This difference is merely dual protection and is not relied upon as the basis of protection. Even if the GIDs of the two containers are aligned later, non-dumpable and the absence of `SYS_PTRACE` must maintain protection, so all of the above verification items must be performed regardless of GID.

Record results in `$EV/`, and write `not_run` if not executed.
4. Generate baseline digests. Execute after applying all manifests above for objects covered by the baseline (admission, exec RBAC, NetworkPolicy, node pool configuration, TracingPolicy and Tetragon configuration). Since the first `active_policy` in step 8 reads `baseline_digests.sensor_release_policies` from the lock, this step must complete before step 8.

```sh
go run ./tools/baseline-digests --context "$KCTX" --lock "$LOCK" --write-lock "$LOCK"
jq .baseline_digests "$LOCK" | tee "$EV/baseline-digests-$RUN.json"
```

   Expected result: Exit code 0; all six keys `admission`, `exec_rbac`, `network_policy`, `node_pool_config`, `sensor_policy`, and `sensor_release_policies` are entered into `baseline_digests` of the lock as 64 lowercase hex characters. The tool operates fail-closed. If an object with a resource kind or name does not exist, release TracingPolicyNamespaced is missing, or a permission error occurs, it exits with a non-zero value and does not modify the lock. In that case, rerun after completing the missing apply, and do not fill in the values manually. `--context` is required, and the tool does not use current-context.

   Operator permissions: In Kubernetes, the same read set as drift probe (`get`/`list` in `deploy/gcp/base/rbac/drift-probe.yaml`, and `get` for ConfigMaps `agent-control/agent-exec-constraints`, `agent-control/agent-role-constraints`, and `agent-sensors/tetragon-config`, and DaemonSet `agent-sensors/tetragon`) is required. Secret access and write permissions are not required. In GCP, `container.clusters.get` (e.g., `roles/container.clusterViewer`) via Application Default Credentials is required.

   There is not yet a manifest or render tool in the repository to create the drift probe's expected value ConfigMap `agent-observe/drift-probe-baselines` (key `baseline_digests.json`, TASK-01 4 · TASK-10). The drift probe Deployment manifest does not exist yet either. Therefore, in this step, only update the lock; when deploying drift probe, render the ConfigMap with this lock value before initiating comparison.
 First bundle and activation

1. Build, sign, and publish the bundle using `tools/first-bundle` following the order of TASK-14 (`-publish -bucket <bundle bucket> -environment <env> -set-by-change-id <UUID>`, `DATABASE_URL` is the installer connection). Save the output JSON (`candidate_digest`, `artifact_digest`, `revision`) to `$EV/first-bundle-$RUN.json`.
2. Wait until `loaded_artifact_digest` of the gateway and receiver-sender leases matches `artifact_digest`.

```sh
psql "$INSTALLER_DSN" -tAc "SELECT component, source_id, loaded_artifact_digest, lease_until > now()
  FROM health.control_health_leases WHERE component IN ('gateway','adapter') ORDER BY 1,2"
```

3. Insert the first epoch (manual because TASK-14 has no procedure. SPEC-QUESTION).

```sh
tar -xzOf bundle.tar.gz data.json | jq -r .catalog.catalog_digest     # catalog_digest
psql "$INSTALLER_DSN" -v ON_ERROR_STOP=1 -v environment=prod -v bundle_id=<id> \
  -v bundle_digest=<candidate_digest> -v artifact_digest=<artifact_digest> \
  -v expected_opa_revision=<revision> -v catalog_digest=<value above> -v change_id=<UUID> \
  -v sensor_release_policies_digest="$(jq -r .baseline_digests.sensor_release_policies deploy/gcp/environment.lock.json)" \
  -f deploy/gcp/base/installer/m3-1-first-active-policy.sql
```

Expected result: `COMMIT`. Afterwards, close the binding window opened in step 6 of #156 according to step 9.

4. Verify that all 7 leases are valid: `gateway`, `coordinator`, `audit-db`, `audit-export`, `adapter`, `destination-evidence`, and `node-sensors` on exec nodes. The coordinator also requires a `node-readiness` lease. If even one is missing, a 503 `CONTROL_HEALTH_UNAVAILABLE` on submit is expected behavior (fail closed).

## 9. Exposure check

Save all results to `$EV/exposure-$RUN.txt`. If anything differs from expectations, immediately delete the relevant manifest (`kubectl delete`) and report.

```sh
{
echo "## external IP address";   gcloud compute addresses list --project "$PROJECT" --filter='addressType=EXTERNAL' --format='value(name,address)'
echo "## VM external IP";     gcloud compute instances list --project "$PROJECT" --format='value(name,networkInterfaces[].accessConfigs[].natIP)' | awk 'NF>1'
echo "## LB/NodePort/externalIPs"; K get svc -A -o json | jq -r '.items[] | select(.spec.type!="ClusterIP" or (.spec.externalIPs|length>0)) | "\(.metadata.namespace)/\(.metadata.name) \(.spec.type)"'
echo "## Ingress";            K get ingress -A --no-headers 2>&1
echo "## Gateway API";        K get gateways.gateway.networking.k8s.io -A --no-headers 2>&1
echo "## hostPort";           K get pods -A -o json | jq -r '.items[] | select([.spec.containers[].ports[]?.hostPort] | any) | "\(.metadata.namespace)/\(.metadata.name)"'
echo "## forwarding rules";   gcloud compute forwarding-rules list --project "$PROJECT" --format='value(name,IPAddress,loadBalancingScheme)'
echo "## 0.0.0.0/0 ingress firewall"; gcloud compute firewall-rules list --project "$PROJECT" --filter='direction=INGRESS AND sourceRanges:0.0.0.0/0 AND disabled=false' --format='value(name)'
echo "## GKE endpoint";       gcloud container clusters describe "$CLUSTER" --location "$(jq -r .project.location "$LOCK")" --project "$PROJECT" \
  --format='value(privateClusterConfig.enablePrivateEndpoint,controlPlaneEndpointsConfig.ipEndpointsConfig.enablePublicEndpoint,privateClusterConfig.enablePrivateNodes)'
echo "## Cloud SQL public IP"; gcloud sql instances describe "$(jq -r '.storage.cloudsql_instance|split(":")[2]' "$LOCK")" --project "$PROJECT" --format='value(settings.ipConfiguration.ipv4Enabled)'
echo "## allUsers/allAuthenticatedUsers (project)"; gcloud projects get-iam-policy "$PROJECT" --format=json | jq -r '.bindings[] | select(.members[] | test("allUsers|allAuthenticatedUsers")) | .role'
echo "## bucket PAP / public members"
for b in $(jq -r '.storage | to_entries[] | select(.key|endswith("_bucket")) | .value' "$LOCK"); do
  echo "$b $(gcloud storage buckets describe "gs://$b" --format='value(public_access_prevention)')"
  gcloud storage buckets get-iam-policy "gs://$b" --format=json | jq -r '.bindings[]? | select(.members[] | test("allUsers|allAuthenticatedUsers")) | "PUBLIC " + .role'
done
} 2>&1 | tee "$EV/exposure-$RUN.txt"
```

Expected result:
- external IP address, VM external IP, LB/NodePort/externalIPs, Ingress/Gateway API (`No resources found` or no CRD), hostPort, `0.0.0.0/0` firewall, project/bucket `allUsers`: all empty output.
- forwarding rules: Empty, or contains only `INTERNAL` entries for the GKE control plane private endpoint. Fails if `EXTERNAL` is present.
- GKE endpoint: `True  False  True` (private endpoint, public endpoint disabled, private nodes).
- Cloud SQL: `False`.
- `enforced` for each bucket.
## 10. Demonstration

All access is performed only via `kubectl port-forward` (via DNS endpoint, local loopback). Do not modify or expose Services.

```sh
K -n agent-control port-forward svc/workload-identity 18443:8443 &
TOKEN=$(gcloud auth print-identity-token)
```

1. Session creation: `POST /v1/sessions` (console user, scope `receiver.submit` / `receiver-primary`). The request body follows the TASK-03 3.1·COMMON `POST /v1/sessions` format. Because identity is a workload mTLS server, the client verifies the server with a trust bundle and sends `Authorization: Bearer $TOKEN`.

```sh
curl -sS --cacert ca.pem --resolve workload-identity.agent-control.svc:18443:127.0.0.1 \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d @session-request.json https://workload-identity.agent-control.svc:18443/v1/sessions | tee "$EV/session-$RUN.json"
```

   Expected result: 201 and `session_id`. If 401, check `aud`·`hd`·role map. If 503 `POLICY_VERSION_MISMATCH`, verify step 8 activation.
2. Launch the runtime Pod. The claim code is retrieved by the runtime from assignments.

```sh
K apply --dry-run=server -f "$OUT/action-path/agent-runtime.yaml"
K apply -f "$OUT/action-path/agent-runtime.yaml"
K -n agent-exec logs -f pod/agent-runtime-demo | tee "$EV/runtime-$RUN.log"
```

   Expected result (log order): certificate bootstrap → assignment claim → worker registration·observed → start check ready → `agent_work_start_requested` ack → `POST /v1/actions` → `approval_required`.
3. Approval: Run the approval console (#268) from the operator's laptop while maintaining the same port-forward. Run the console only in the operator's own terminal. If executed via the agent session's `!` command or the agent harness, the agent will see the output key, allowing the agent to approve via the loopback API.

   ```sh
   go run ./tools/console -ca-file ca.pem
   ```

   The console prints a URL in the format `http://127.0.0.1:PORT/#k=...` once. Open the URL including the `#k=` portion in a browser, enter the `session_id` received in step 1, and click Watch. The console queries `GET /v1/approvals/pending` every 3 seconds, and when an action pending approval occurs, it displays the contract received via `GET /v1/actions/{action_id}/approval-contract` as a card within the timeline. Review the operation, target, exposed fields, content preview, and expiration time displayed on the card, and click Approve to send `POST /v1/approvals`. If the intent check result is `divergent` or `unclear`, all findings must be reviewed before the Approve button is enabled. The console receives the ID token directly via `gcloud auth print-identity-token` and retains it only in memory, without passing it to the browser. Because the runtime performs `:reevaluate` every 15 seconds, it will be allowed in the next cycle.

   Expected result: The card displays `approval_id` and the expiration time, and within about 15 seconds the card is removed from the pending approval list. If the console displays 503 `TOKEN_UNAVAILABLE` or identity returns 401 `AUTH_REQUIRED` prior to approval, too much time has elapsed since the ID token was issued, so log in again with `gcloud auth login` and approve again on the same card. This failure does not consume the nonce. In other failures, the nonce is consumed, so click Reload contract and approve again.
4. Verify results

```sh
K -n agent-exec logs pod/agent-runtime-demo | tail -20     # result succeeded, worker close
psql "$INSTALLER_DSN" -c "SELECT event_type, source_id, received_at FROM audit.audit_events
  WHERE action_id = '<action_id>' OR (event_type LIKE 'agent_work_%' AND received_at > now() - interval '1 hour')
  ORDER BY received_at" \
  | tee "$EV/audit-$RUN.txt"
psql "$INSTALLER_DSN" -c "SELECT count(*) FROM receiver.receiver_effects WHERE action_key = '<action_id>'"
```

   Expected result: Audit events include `request_received`, `policy_decided`, `approval_requested`, `approval_granted`, `action_reevaluated`, `dispatch_enqueued`, `attempt_planned`, `preflight_passed`, `dispatch_started`, `response_received`, `destination_observed`, and `agent_work_*`. 1 receiver effect, evidence-collector receipt matches.
5. If it fails, record the blocked step, HTTP response code, relevant Pod logs (`kubectl logs`), and next actions in `$EV/blockers.md`, fix steps 6–10, and run again. Do not bypass (directly inserting lease rows, disabling admission, exposing Services).

## 11. Cleanup and Power Off

```sh
K -n agent-exec delete pod agent-runtime-demo --ignore-not-found
kill %1 2>/dev/null
platform/gcp/scripts/power.sh off --lock "$LOCK"
platform/gcp/scripts/power.sh status --lock "$LOCK"
```

Expected result: All node pools 0, Cloud SQL `activationPolicy=NEVER`. Do not delete the epoch PVC and DB (if reused with the same source id, the epoch rolls back).
