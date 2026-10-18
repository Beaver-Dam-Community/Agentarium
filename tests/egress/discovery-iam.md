# Discovery bucket IAM verification (TASK-06 / M2-1)

`cmd/discovery-iam-probe` performs real Cloud Storage JSON API operations using
the current Pod's GKE metadata token. It accepts no token, credential file,
impersonation target or alternative endpoint. It does not change IAM or deploy
Pods. Build using the shared `build/docker/go-service.Dockerfile`, with
`CMD=./tests/egress/cmd/discovery-iam-probe`, and deploy the resulting digest.

## Inputs and order

All three runs use the same `IAM_BUCKET` and a fresh `IAM_RUN_ID` (8–64 lowercase
letters, digits and hyphens). Set `IAM_MODE` as follows:

| Mode | Actual Pod KSA | Expected create / get / list / overwrite / delete |
| --- | --- | --- |
| `snapshot` | `agent-observe/discovery-snapshot` | allow / allow / allow / deny / deny |
| `reader` | `agent-observe/discovery` | deny / allow / allow / deny / deny |
| `denied` | Another KSA with the existing network path to metadata and GCS, such as `agent-observe/audit-exporter` | deny / deny / deny / deny / deny |

Run `snapshot` first and require its exit code 0 before running the other modes.
It creates `snapshots/iam-check/<run-id>/fixture.txt` with a generation-zero
precondition. A reused ID fails rather than replacing the fixture. Other modes
attempt creation of their own `reader-new.txt` or `denied-new.txt` in the same
prefix. Every payload is fixed synthetic test text. Overwrite and delete tests
target only the fixture in that fresh prefix, which may be changed or deleted
if the permissions are wrong. Never point the test at a non-test object.

Use actual KSAs without `iam.gke.io/gcp-service-account` annotations. Preserve
their existing NetworkPolicies, placement, taints and admission restrictions;
add only the verified test image digest to the namespace image allowlist.
Record Pod UID, namespace, serviceAccountName, KSA annotations, node and image
digest alongside the logs. A probe cannot independently attest its Pod identity.
Do not substitute an operator token or a DB Proxy GSA. A network timeout is not
evidence that IAM denied access. Do not open a normally blocked network path to
make a forbidden KSA test return 403.

## What counts as a pass

Successful reads must contain the exact synthetic fixture, and successful lists
must include its exact name. After overwrite/delete attempts, the two readers
also check that the original bytes still exist. A denial requires HTTP 403,
Cloud Storage's `forbidden` reason and the relevant `storage.objects.*`
permission in the error message. GCS `alt=media` GET errors instead use a
plain-text, HTML-escaped response; only its specific `storage.objects.get`
permission-denied form is accepted. HTTP 401/404/412, quota errors, retention-policy
errors, redirects and transport failures do not count as permission denials.

The overwrite request deliberately has no generation precondition. This tests
the missing delete permission required to replace an existing object, rather
than accepting a 412 response as proof of IAM enforcement. See Google's
[objects.insert permission requirements](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/insert).
No token or raw API error body is logged; output contains only operation,
HTTP status and pass/fail. Requests have a 15-second timeout and the full run
has a two-minute deadline. HTTP proxies and redirects are disabled.

Before calling a deployment complete, also inspect inherited IAM policies and
the actual bucket/custom-role bindings. A successful test for one forbidden
KSA proves only that KSA's access at that time, not every principal in the
project. This test does not prove the M2 discovery pipeline or all workload IAM.

## Cleanup and validation

Delete the test Pods and restore only the image allowlist entry added for this
run. Remove only test-created KSAs that have no other consumers. An authorized
installer can remove the exact test objects after recording their generations;
the workload identities must not receive delete permission for cleanup. Retain
required application IAM grants. Stop only compute started for the test.

`go test -race ./tests/egress/cmd/discovery-iam-probe` exercises HTTP requests,
authorization headers, the three permission matrices, overprivileged access,
precondition/retention/transport failures, unrelated list results and token
redaction. `go vet ./tests/egress/cmd/discovery-iam-probe` checks the command.
These local HTTP fixtures are not GCP enforcement evidence; report actual Pod
results separately.
