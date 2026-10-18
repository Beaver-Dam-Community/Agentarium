# Contact-service IAM

The module creates separate Cloud SQL IAM users and DB GSAs for workload-identity,
audit-writer and control-health. Additive Cloud SQL grants are instance-scoped;
Service Usage Consumer is project-scoped as required by Proxy impersonation.
Only each exact KSA may impersonate its own DB GSA. CAS permission stays with
the direct identity KSA. No service account keys or database passwords are created.
The module creates the identity claim key secret (lock name) and its version 1
from ephemeral `random_bytes` through the write-only `secret_data_wo`, so the
key is in neither plan nor state; see [contact installation](../../../../deploy/gcp/base/contact-services/README.md#identity-claim-key-task-06-33-101).

The owner selected proxy-only impersonation; the contract merged in PR #51. The
prod module is wired locally; review its plan before applying the installation.
The contact manifests deliberately omit GSA annotations and put the impersonation
flag only on the native Cloud SQL sidecar. This is not container-level IAM
isolation: another process with the KSA identity can also use its permitted GSA.

`terraform init -backend=false`, `terraform validate`, and `terraform test`
check provider schemas and a mocked three-service plan. Runtime Cloud SQL/CAS
verification and install-time PostgreSQL grants are separate required steps.

CAS issuance depends on the two exact `certificate_template_ids` outputs from
shared-resources. The identity KSA receives `roles/privateca.templateUser` only
on those template resources. Its pool requester binding requires one of their
IAM template names; an absent or different template is denied. This does not
remove inherited grants outside this module: inspect effective IAM before the
second rollout stage described in [contact installation](../../../../deploy/gcp/base/contact-services/README.md).
No pool read/admin role is added. In particular, `certificateRequester` alone
does not authorize `FetchCaCerts`.
