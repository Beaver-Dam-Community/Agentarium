# M1 contact service installation

The manifests create identity, audit-writer and control-health ServiceAccounts,
Deployments and internal Services. KSA names match NetworkPolicy labels. Only
Cloud SQL Proxy impersonates the DB GSA; application ADC remains the direct KSA.
All three bootstrap Deployments tolerate only the configured observation-readiness
NoSchedule taint, so they can start on control nodes before those services establish
readiness. The protected control node selector remains required. Native sidecar
startup precedes applications. Proxy listens only on loopback.
TCP probes report listener availability; control-health leases, database tests
and mTLS requests are the functional readiness evidence.

Render via `deploy/gcp/base/render.py`. All four image inputs must be digest-pinned
in the installation Artifact Registry, including a mirrored SQL Proxy image.
Add these images to the corresponding namespace admission image lists first.
The identity `--environment` argument comes from `lock.environment` (`prod` or
`regression`) and cannot be overridden by render values. Values additionally
include DB user/GSA per service, database name, connection
name, CA pool, and audit health source/version. These actual values belong in the
ignored environment lock or transient render input, never committed manifests.

## Certificate template rollout (no live apply performed)

The shared spec (#148) and the identity change that reads
`--service-certificate-template` and `--client-certificate-template` (#149)
are merged. Since #149 identity does not start without both flags, and an image
built before #149 rejects them as unknown flags, so deploy these manifests only
with an identity image built from #149 or later.
The renderer derives both full template names from `lock.pki.ca_pool`, project
and location; render values cannot override them. `CA_POOL_ID` must match that
same lock. No new lock fields, CA pool, CA, trust anchor or database roles are
introduced. The templates are `${pool}-service` and `${pool}-client` for pool IDs
up to 55 characters. Longer valid IDs use the first 38 characters plus `-` and
the first 16 lowercase hex characters of SHA-256(pool ID), followed by the profile
suffix. Terraform and renderer tests share exact boundary fixtures.

The explicit Terraform input `certificate_template_issuance_enabled` defaults
to `false`. This is a two-stage rollout, not an automatic dependency guarantee:

1. Keep the input `false` for the first reviewed installation plan. It creates
   the two templates and their exact-resource `templateUser` grants and changes
   identity's pool requester binding to the two-template allowlist. The pool's
   existing non-CA/union-keyUsage baseline stays in place. This stage can deny
   issuance because the templates overlap that baseline; it is deliberately
   fail-closed. Do not claim service readiness or issue production certificates
   before stage two.

   **Stage one is effectively a full issuance outage.** An image without
   template flags is denied by the new IAM condition, and an image with them
   conflicts with the pool baseline that stage one keeps. Identity's own server
   certificate lives 24 hours and starts renewing at half-life, so finish stage
   two and deploy the matching image within about 12 hours of applying stage
   one, and sooner if the current certificate was issued earlier. Schedule both
   stages in one maintenance window. Workloads that cannot renew in that window
   fail closed when their certificates expire.
2. Read back the actual pool/template IAM policies and effective inherited
   permissions for the identity KSA. Confirm only the two exact templates are
   allowed, each template has the strict profile SAN/usage constraints, and no
   unconditional requester/manager/admin grant for that principal at the pool,
   project, folder or organization bypasses the condition. A Terraform mock test
   is not evidence for this check. Do not advance when visibility is incomplete.
3. After that read-back, explicitly set and **persist**
   `certificate_template_issuance_enabled = true` in the installation's Terraform
   inputs. Review the second plan: remove only the pool `baseline_values`, retain
   pool lifetime/key-type/config-only issuance/SAN limits and the same CA/root.
   Both mandatory templates enforce `isCa=false` and exact key usage. The pinned
   google 8.6.0 provider requires keyUsage in every pool baseline block, so non-CA
   cannot remain in a separate pool-only baseline. Deploy the matching identity
   image and rendered arguments only after the second stage is verified.
4. Verify actual signed service and Pod leaves, rejected cross-profile requests,
   missing/foreign templates and unchanged trust-bundle validation. Node-bridge
   leaves cannot be verified yet: identity refuses `node_bridge` issuance
   (`ErrNodeBridgeDisabled`, TASK-03 3.3), so the template's node-bridge SAN rule
   stays unverified until that role is enabled. CAS `validateOnly`, provider
   validation and Terraform mock tests do not replace signed certificate tests.

   The trust bundle is produced by the installation operator, not by identity:
   run `go run ./services/identity/cmd/identity-trust-bundle --ca-pool "$CA_POOL_ID"`
   with the operator's own credentials, which need `privateca.caPools.get` on
   that pool (`FetchCaCerts`), and put the PEM into ConfigMap `agentarium-trust`
   in every role namespace. This change grants `privateca.caPools.get` to no
   workload, and the identity KSA does not need it.

`platform/gcp/envs/regression` does not pass
`certificate_template_issuance_enabled` and has no `contact-services` module, so
the regression pool gets the templates but keeps the overlapping baseline and has
no template IAM; it cannot reach stage two. This is tracked in #198.

Starting with `true` in one apply does **not** establish IAM-before-policy order.
Preserve the completed stage-two input in every later plan: returning to the
false default restores the overlapping pool baseline and breaks template issuance.
This is not a safe rollback. Keep template-restricted IAM while diagnosing errors;
never restore unrestricted issuance to make startup succeed.

Installation prerequisites:

1. The proxy identity contract (#51), audit ack contract (#52), and TASK-03
   bootstrap wire clarification (#53) are merged. Review the M1 audit/health
   implementation PRs (#56/#55) and their images together with these manifests;
   runtime verification follows their merge.
2. Apply the production PGA private DNS/route and IAM modules. Verify allowed
   callers resolve Google API names into `199.36.153.8/30`. Register IAM database
   users. Bootstrap the NOLOGIN control_health_writer role before the older identity migration, which requires
   it. Apply migrations in version order with the migration identity.
3. Grant each IAM login its application role and the specified cross-task SELECT
   columns and audit producer membership. Register sources and event/tenant grants.
4. Install the public CA PEM as ConfigMap `agentarium-trust` key `ca.pem` in both
   namespaces. Install validated `agentarium-audit-sources` (`sources.json`) and
   `agentarium-health-profile` (`profile.json`) ConfigMaps. Runtime creates no roles.
5. Apply identity RBAC, concrete NetworkPolicies and contact manifests. Identity
   uses the namespaced Pod informers merged in #72. Its required
   `--pod-namespaces` argument lists the same seven namespaces as its Pod Roles;
   update both together when adding a namespace that can receive certificates.
   An omitted namespace's existing certificates expire instead of being revoked
   by Pod deletion. All configured informer caches must sync before reconciliation.
   Identity
   requests its own certificate from CAS; audit/health use their projected token
   to bootstrap in-memory certificates from identity and renew at half-life.
6. Keep the control-health epoch PVC across upgrades. A single Recreate replica
   owns its durable counter. Never delete/recreate the PVC with the same source ID.

Do not call M1 complete until actual Pods start and DB, CAS/mTLS, audit storage and
health API requests have been verified. No control-health/export completeness is
implied by a TCP readiness probe. M2 exporter/collector and live egress tests remain.

## Identity claim key (TASK-06 3.3, #101)

The identity entrypoint reads the claim-code HMAC key from
`/var/run/secrets/agentarium/claim-key` before CAS/DB initialization and exits
if it is missing or shorter than 32 bytes. The key is delivered by the GKE
Secret Manager add-on (TASK-01 3 item 10, `secret_manager_config` in
`platform/gcp/modules/platform`):

1. Put `identity.claim_key_secret` (`projects/<project-number>/secrets/<name>`)
   and `identity.claim_key_version` in the ignored environment lock. The
   secret must be separate from the OIDC client secret and the broker
   credential secrets (Terraform rejects a reuse). The version is `1`, the
   first version Terraform creates (a number, never `latest`). `render.py`
   reads both from the lock only.
2. Apply `platform/gcp/envs/prod` (`iam/contact-services`). It creates the
   secret under the lock name (automatic replication, deletion protection,
   `prevent_destroy`) and version 1 from 48 bytes of ephemeral
   `random_bytes`, base64-encoded (64 file bytes, 384 bits of entropy;
   identity uses every byte of the file as the key and checks only the
   32-byte minimum). The value goes only through the write-only
   `secret_data_wo`, so it is in neither the plan nor the state, and nobody
   handles it. Do not create the secret or a version with `gcloud`.
3. The same apply grants `roles/secretmanager.secretAccessor` on that one
   secret to the `agent-control/workload-identity` direct principal, because
   the add-on authenticates as the Pod's KSA. The grant references the created
   secret, so it is applied after it. The DB GSA does not get it.
4. Apply the rendered `contacts.yaml`. Its SecretProviderClass
   `workload-identity-claim-key` mounts the pinned version as `claim-key`; the
   Pod also carries the Standard-cluster nodeSelector
   `iam.gke.io/gke-metadata-server-enabled: "true"`.

**Rotation:** add a new version (through Terraform as well; not implemented
yet), change `identity.claim_key_version`, re-render
and apply the SecretProviderClass, then
`kubectl -n agent-control rollout restart deployment/workload-identity`.
Automatic add-on rotation stays off because the version is pinned. Identity
derives the claim code from the key of the Pod that answers
`/v1/runtime/assignments`. A session created before the rotation and not yet
claimed therefore gets a code from the new key on a new Pod that does not match
its stored digest, and its claim fails with `CLAIM_CODE_INVALID`. This only
affects sessions inside their 60-second claim window; the user starts a new
session. Disable the old version only after the rollout completes and 60 more
seconds pass.

**Live verification (not yet run):**

```sh
kubectl --kubeconfig "$KUBECONFIG" --context "$CONTEXT" -n agent-control \
  rollout status deployment/workload-identity --timeout=180s
kubectl --kubeconfig "$KUBECONFIG" --context "$CONTEXT" -n agent-control \
  logs deployment/workload-identity -c workload-identity --tail=50
gcloud secrets get-iam-policy "$CLAIM_KEY_SECRET" --format=json
```

Pass criteria: the rollout completes; the log has no `claim key` error; the
secret policy has exactly one `secretAccessor` member, the workload-identity
principal. Q0 items: the mounted file's owner/mode with `runAsUser: 65532`,
and whether a failed secret fetch blocks container start (identity fails
closed either way because the file is absent).

## Installation follow-up

- [ ] Execute and verify the install-time PostgreSQL role memberships as part
  of TASK-16 section 3.1 installation step 3. The object-owning Task supplies
  the grants, while the installer grants each IAM login only the roles agreed
  for its service, including
  application roles, cross-task readers and `audit_producer` where specified.
  Examples such as `gateway_app`, `coordinator_app` and `adapter_reader` describe
  different services, not a role set to grant to every login. Check membership
  with the actual login before starting the service. Issues #30/#47 concern
  later bundle/gateway integration and do not by themselves block the three
  M1 services' already specified memberships. This does not imply that the
  actual Cloud SQL login, private route or grants have been verified.
- [ ] TASK-16 must register each adapter login in `decisions.adapter_db_roles`
  after the TASK-04 migration, as required by COMMON. Use the concrete IAM
  `db_user` from the applicable service module's `services` output and map it to
  that adapter's `adapter_id`; never share one login between adapters. The
  current contact-service module exports only identity, audit-writer and
  control-health users, so adapter installation must supply its own login output.
  Verify the adapter views using that login: only its own rows are visible and an
  unmapped login sees no rows. Do not grant the mapping table to `adapter_reader`.

The caller map includes console BFF → control-health for `operator_stop` and
control-health → identity for `POST /internal/sessions:revoke-scope`. Both use
existing TCP/8443 allow-matrix edges. NetworkPolicy permits the connection;
COMMON's BFF/operator/actor checks and revoke-scope authorization remain service
API responsibilities.

## Sensor ingest on audit-writer

The TASK-09 exporter and the lifecycle recorder post to audit-writer
(`--kernel`, `--lifecycle`). The exporter is hostNetwork, so its peer is a node
IP in `${node_cidr}`, except on the node that runs audit-writer: GKE Dataplane V2
delivers host-to-local-Pod traffic from the node-local address `169.254.4.6`
(the source kubelet probes also show). That address only reaches a Pod from its
own host, so `--kernel-node-cidrs` adds `169.254.4.6/32`; the tetragon SAN check
and the certificate-to-node binding still apply. The recorder is not
hostNetwork, so `--lifecycle-node-cidrs` is the Pod range `${pods_range}`. The
receiver epoch directory is the ReadWriteOnce PVC `audit-writer-receiver-epoch`,
exclusive to the single replica (Recreate strategy).

## Identity startup input still requiring installation agreement

[Issue #101](https://github.com/Beaver-Dam-Community/Agentarium/issues/101) tracks
the remaining claim-key installation decision.

The merged identity binary also requires a claim-code HMAC key file (default
`/var/run/secrets/agentarium/claim-key`) containing at least 32 bytes. It reads
this file before contacting CAS or the database. The current manifests do not
mount that file, so the environment fix alone does not make identity start.

The CLI help and merged PR #36 require a Secret Manager claim key mounted as a
file. TASK-03 does not specify its resource/version or delivery mechanism, and
TASK-06 currently grants identity
access only to its OIDC client secret. A separate claim key must not be assumed
to be that OIDC secret or supplied through a ConfigMap/render value. The owner
must define the key reference, authorized delivery/mount and rotation behavior
before installation. This change creates no key, secret, IAM grant or new
shared spec and does not claim live startup verification.
