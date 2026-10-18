# Same-environment workload IAM (TASK-06 section 3.3)

This module adds the 21 Cloud SQL workload identities that are not managed by
`contact-services`. The two modules together cover the 24 DB-using KSAs in
TASK-06, including the `audit-retention` KSA registered by #176. It does not manage the node account, existing contact identities or CAS
binding again. PostgreSQL roles, `db_role_sources`, adapter identity mapping and
cross-task view grants are installed separately after their owning migrations.

Every DB GSA has only instance-conditioned Cloud SQL Client/Instance User and
project Service Usage Consumer. Its exact KSA alone receives Workload Identity
User on that GSA. Applications keep direct KSA identity; only Proxy is configured
to impersonate the DB GSA. This follows the merged Proxy-only DB identity shared spec (#51). A process with the same KSA can use that same GSA;
the sidecar arrangement is not an IAM isolation boundary between containers.

Application grants use exact direct KSA principals, individual bucket/key/secret
resources and additive IAM members. In particular:

- Audit writer and execution workloads receive no GCS/KMS grant.
- Audit exporter gets object create/get on evidence and decision-input exports,
  plus the manifest signing key. Verifier gets object read/list and only public
  key retrieval. Releaser creates bundle objects and signs with the separate
  bundle key.
- The separate `../discovery` module gives discovery snapshot object create/get/list and discovery only read/list.
  Neither gets object delete. Replacing an existing GCS object needs both create
  and delete, per [GCS permissions](https://docs.cloud.google.com/storage/docs/access-control/iam-permissions).
  Object writers must still use generation preconditions for retries.
- Identity can access only the supplied OIDC secret, broker only the explicitly
  supplied credential secrets. Other broker secrets must already exist. The
  module creates the lock-named OIDC client secret (`iam.oidc_client_secret`)
  with deletion protection and `prevent_destroy`, but no version: the value
  is issued by the Google OAuth client, so Terraform cannot generate it, and
  the operator adds it as a version without putting it in the repository, an
  issue or the lock (see [OIDC client secret](#oidc-client-secret)). M3-1
  signs in with CLI ID tokens and does not read it.
  The other exception is `receiver_api_key_secret` (lock
  `receiver.api_key_secret`, also a broker secret): the module creates that
  secret and its version 1, a 43-character unpadded base64url key from 32
  bytes of ephemeral `random_bytes`, written only through the write-only
  `secret_data_wo`, so the value is in neither plan nor state. The secret has
  deletion protection and `prevent_destroy`; the broker grant depends on it.
  The broker's per-operation fixed-version DB allowlist remains a separate check.
- Model adapter gets only `aiplatform.endpoints.predict`; drift-probe gets only
  `container.clusters.get` at project scope. There is no model admin or cluster
  mutation role.
- The same-environment regression-dispatcher keeps request object create and
  report object read. No regression-runner or decision-replay principal from
  another environment is created or granted access by this module.

KMS public-key access uses a one-permission custom role; signing uses the
specified `roles/cloudkms.signerVerifier`
([KMS permission reference](https://docs.cloud.google.com/kms/docs/reference/permissions-and-roles)).

## Installation inputs

The prod root always configures the separate discovery bucket IAM module from
existing platform/storage outputs. Production enables the remaining workload
module only when the owner supplies the TASK-06 `iam`
section in the ignored `deploy/gcp/environment.lock.json`. These are installer
references, not new service API fields. Each task may add its own lock inputs
until TASK-16 finalizes the shared lock schema. Real resource identifiers must
stay in that ignored file. The fixtures below use fictitious resources.

```json
{
  "iam": {
    "oidc_client_secret": "projects/example-prod/secrets/oidc",
    "credential_secret_resources": ["projects/123456789012/secrets/receiver"],
    "regression": {"project_id": "example-regression", "project_number": "222222222222"}
  }
}
```

Use existing, enabled credential binding secrets; this list must match the
broker installation's `credential_bindings` resource allowlist. Secret refs
must belong to the production project, name individual secrets rather than
versions, and be distinct from the OIDC secret even across project ID/number
aliases. No regression project input is required or consumed.
Buckets and keys come directly from `shared-resources` outputs and must be
distinct. The installer must confirm that the project number belongs to the
specified project; input validation cannot establish ownership.

If `iam` is absent, output `full_workload_iam_configured` is false. Only the
separate discovery module and existing contact grants are configured; no secret
references or other full-workload grants are inferred. That is an incomplete installation, not a working
M2 environment. With inputs present, the existing output means this same-environment
module is configured; it does not include the deferred cross-environment grants
and is not runtime proof. Run IAM apply only after dependent contracts and
PRs merge, with the environment powered on as the handoff requires. Do not
apply the full prod stack while intentionally powered off.

## OIDC client secret

The module creates the secret named by `iam.oidc_client_secret` with automatic
replication and no version. Earlier instructions told operators to create that
secret by hand. In such an environment the first apply after this change fails
with `already exists`, so adopt the existing secret before applying. Initialize
the same prod backend, back up its state and confirm with `terraform state list`
that the address is not tracked yet. Then import it once, with the real project
and secret name from the ignored environment lock:

```sh
terraform import 'module.workload_services[0].google_secret_manager_secret.identity_oidc' \
  'projects/<project>/secrets/<name>'
```

Inspect the plan afterward. Label and `deletion_protection` updates are
expected in place. If the existing secret uses user-managed replication, the
plan asks to replace it because replication cannot change in place, and
`prevent_destroy` stops that plan. Do not remove `prevent_destroy` to get past
it; decide separately how to move the value to an automatically replicated
secret.

Add the value as a version from a file or stdin, never as a command argument,
so it does not reach argv, shell history or logs. The value must not end with
a newline, because the Google token exchange uses the bytes as stored:

```sh
tr -d '\n' < client-secret.txt | gcloud secrets versions add <name> \
  --project=<project> --data-file=-
```

Delete the local file afterward and do not paste the value into an issue, a
pull request or the lock.

## Audit export identities (TASK-07 3.2.1)

`audit-verifier` and `audit-retention` each have their own DB GSA and IAM DB
login here. After the `*_audit_export_coverage_lease` migration (#167), the
installer grants exactly one application role to each login and nothing else:

```sql
GRANT audit_verifier TO "audit-verifier-db@<project>.iam";
```

**Do not grant `audit_retention` yet.** The purge deletes records whose
`received_at`/`enqueued_at` is older than 30 days, while the verifier checks
manifests within a 30-day window whose time basis is not yet fixed (#163/#167
review). Purging near the boundary can remove outbox rows of a manifest the
verifier still checks and raise an operator-only global `audit_integrity`
hold. Run the following only after #163 fixes that time basis:

```sql
GRANT audit_retention TO "audit-retention-db@<project>.iam";
```

Use the `services` output for the exact login names. Do not grant
`audit_retention` to any service login, and do not grant `audit_writer` or
`audit_exporter` to either login. `audit-retention` gets no bucket, KMS or
secret grant and no internal API route; it only reaches Cloud SQL. The
verifier keeps its existing evidence/decision-input object read and manifest
public-key grants.

## Verification and remaining runtime gates

`terraform validate` checks the pinned Google 8.6.0 schema. `terraform test`
checks the permission matrix and rejects project, secret, bucket and signing-key
aliasing using a mock provider. Production wiring tests cover absent and present
inputs; the latter is a mock apply to resolve computed outputs. These tests do
not contact GCP or prove cloud IAM enforcement.

After installation, verify direct KSA vs Proxy GSA tokens, instance-scoped IAM
DB logins and owning PostgreSQL role grants, then perform the TASK-06 discovery
bucket create/get/list/overwrite/delete matrix from each actual KSA. Exercise
KMS signing vs public-key-only callers and individual secret isolation. Inherited project/folder/organization grants
can widen effective access; inspect those policies too. No live grants or
credentials were created by the local/mock validation.

## Deferred cross-environment access

[Issue #97](https://github.com/Beaver-Dam-Community/Agentarium/issues/97) tracks
TASK-01's foreign-pool prohibition against TASK-06's four requested resource
grants. This module does not create any of those bindings:

| Foreign KSA | Production resource | Deferred permission |
| --- | --- | --- |
| decision-replay | decision-input-exports bucket | objectViewer |
| decision-replay | manifest signing key | viewPublicKey |
| regression-runner | regression-requests bucket | objectViewer |
| regression-runner | regression-reports bucket | objectCreator |

The #97 owner decision allows exactly these four (TASK-01 4, TASK-06 3.3).
`platform/gcp/iam/checks` exempts a binding only in a Cloud Asset Inventory
IAM-policy export, where the resource name and asset type come from the
export record, and only when resource, asset type, role and the exact
regression KSA principal match one row with no condition. The manifest key and
the `agentariumManifestPublicKey` custom role must belong to the checked
project, and the role definition must contain exactly
`cloudkms.cryptoKeyVersions.viewPublicKey`. A plain `get-iam-policy` file, a
resource appearing twice, or anything else from another pool is still
rejected:

```sh
gcloud asset export --project "$PROD_PROJECT" --content-type=iam-policy \
  --asset-types=storage.googleapis.com/Bucket,cloudkms.googleapis.com/CryptoKey \
  --output-path="gs://$EXPORT_BUCKET/iam.ndjson"
gcloud storage cp "gs://$EXPORT_BUCKET/iam.ndjson" iam.ndjson
gcloud iam roles describe agentariumManifestPublicKey --project "$PROD_PROJECT" \
  --format=json > public-key-role.json
go run ./platform/gcp/iam/checks/cmd/iamcheck -project-id "$PROD_PROJECT" \
  -project-number "$PROD_NUMBER" -cross-env-config cross-env-inputs.json \
  -role-definition public-key-role.json -assets iam.ndjson
```

The module creates the four bindings only when the lock names the
regression project in `lock.iam.regression` (`{"project_id", "project_number"}`,
which must differ from production). They are unconditioned, exact KSA
principals in `agent-release`, and the key grant uses the
`agentariumManifestPublicKey` custom role with only `viewPublicKey`. The
module output `cross_env_grants` lists them in iamcheck form; its tftest
compares that output with `platform/gcp/iam/checks/testdata/cross_env_expected.json`,
which the checker test also uses as `CrossEnvAllowlist`'s expected result.
No other binding references the regression pool. Without
`lock.iam.regression` none of them exists. Local checker
tests cover same-environment acceptance and foreign-pool rejection, including
report creation. That checker validates principal boundaries, not the complete
resource/role permission matrix; Terraform mock tests cover this module's matrix.
The production bucket references for regression requests/reports remain required
because the same-environment dispatcher uses them. No cloud apply has been run.

Discovery role/bucket bindings moved to `../discovery`; the prod root contains
three `moved` blocks for existing state. This module must not recreate those
resources. Its remaining discovery DB identity is unchanged. See the discovery
module runbook before importing manually installed resources.
