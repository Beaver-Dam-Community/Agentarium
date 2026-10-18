# Discovery bucket IAM (TASK-06 section 3.3)

The prod root configures this module from existing project and discovery-bucket
outputs, independently of OIDC and credential-broker secret references. It owns
exactly three resources: the existing `agentariumDiscoverySnapshot` custom role
(object create/get/list) and two additive bucket IAM members. The exact
`agent-observe/discovery-snapshot` KSA receives that role; the exact
`agent-observe/discovery` KSA receives `roles/storage.objectViewer`. No wildcard,
GSA impersonation, delete permission, secret, database or compute resource is
created here. Discovery's DB identity remains in `workload-services`.

`full_workload_iam_configured` remains false when the full module's `lock.iam`
inputs are absent. The discovery principals output describes configuration; it
does not prove a working workload or full M2 completion.

## Existing installations

The role ID and bucket/member/role tuples are unchanged. The prod root includes
three `moved` blocks from their former `module.workload_services[0]` addresses.
Keep those blocks: removing them can make an existing installation destroy and
recreate the resources. Do not import a resource already tracked at its former
address. A previously defaulted role description may receive a descriptive
metadata update; permissions do not change.

For a bounded move rehearsal, Terraform requires both source and destination
addresses in the target set. Include the three exact former addresses from
`envs/prod/discovery.tf` as well as `module.discovery_iam`, then inspect all
dependency changes. Do not interpret a target-exclusion error as a reason to
delete state or skip the moves. Normal deployment still uses a reviewed full
plan.

For resources installed outside Terraform, first initialize the **same** prod
backend and inspect `terraform state list`. Back up its state. If neither old
nor new addresses are tracked, import each exact existing resource once. Use
installation values from the ignored environment lock, never examples or
guessed secret references:

| New resource address (under `module.discovery_iam`) | Import ID |
| --- | --- |
| `google_project_iam_custom_role.snapshot` | `projects/<project>/roles/agentariumDiscoverySnapshot` |
| `google_storage_bucket_iam_member.reader` | `b/<discovery-bucket> roles/storage.objectViewer <exact-discovery-principal>` |
| `google_storage_bucket_iam_member.snapshot` | `b/<discovery-bucket> projects/<project>/roles/agentariumDiscoverySnapshot <exact-snapshot-principal>` |

Pass the bucket-member ID as **one quoted argument**, including its spaces.
See the provider's [bucket IAM import syntax](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_iam)
and Terraform's [module refactoring guidance](https://developer.hashicorp.com/terraform/language/modules/develop/refactoring).
Import updates state, not cloud permissions. Use this version of the prod
configuration afterward: an older checkout without the module would interpret
the new state addresses as removed resources.

After import, inspect a targeted plan for `module.discovery_iam`, passing the
real lock path. Require zero resource create/update/delete actions before
calling adoption complete; record output-only changes separately. Do not apply
the full prod root merely to import these objects, especially while node pools
and SQL are intentionally stopped. Targeted planning is for this bounded
adoption step and is not a substitute for reviewing the next full deployment
plan. Never apply a plan that would delete the role or broaden a principal.
Preserve the environment's existing installer inputs, including any authorized
`gcs_soft_delete_seconds` override required by effective organization policy;
target dependencies can otherwise propose unrelated bucket changes.

## Verification

`terraform validate` and `terraform test` in this directory check the pinned
provider schema, exact KSA principals, exact role permissions and bucket input.
The prod root mock tests cover both absent and present full-IAM inputs; the
remaining workload module tests reject duplicate discovery grants. These are
configuration checks. Use the M2-1 real-KSA discovery probe from PR #124 to
verify cloud enforcement; passing imports or plans do not replace that test.
