# Audit exporter installation (TASK-07)

`audit-exporter.yaml` creates the `agent-observe/audit-exporter` ServiceAccount,
the trusted manifest key ConfigMap `audit-exporter-keys` and a single replica
Deployment of `services/audit/cmd/exporter`. It follows the audit-writer Pod in
`contact-services/contacts.yaml`: control node, the observation-readiness start
toleration, Cloud SQL Auth Proxy native sidecar on loopback, projected
`agentarium-identity` token for the in-memory mTLS certificate and the
`agentarium-trust` ConfigMap. There is no Service: the exporter has no listener
and `audit-exporter-allow` has no ingress.

Only the proxy impersonates the exporter DB GSA. The application talks to GCS
(create-only uploads to the evidence and decision-input-exports buckets) and
Cloud KMS (`asymmetricSign` on the manifest key) with the KSA's own Workload
Identity principal, which `platform/gcp/iam/workload-services` grants the
`agentariumAuditExport` role on both buckets and `signerVerifier` on the
manifest key. The Pod therefore also selects
`iam.gke.io/gke-metadata-server-enabled: "true"`.

The exporter reports the global `audit-export` lease (control-health
`RequiredGlobal`) with source `audit-exporter`; global leases accept any source
id with scope id `*`, and the caller is authorized by the
`health.component_principals` row of its SAN, which migration
`20261017172319_health_audit_integrity` seeds (`audit-export`, scopes
`global`/`node`, `export_lag` request and release). Without this Pod the
gateway answers every submit with 503 `CONTROL_HEALTH_UNAVAILABLE`.

## Render values

| Value | Source |
| --- | --- |
| `AUDIT_EXPORTER_IMAGE` | digest of `build/docker/go-service.Dockerfile` built with `CMD=./services/audit/cmd/exporter`. Add the same digest to `AGENT_OBSERVE_IMAGES` (render checks it) |
| `AUDIT_EXPORTER_DB_GSA`, `AUDIT_EXPORTER_DB_USER` | `workload_services["audit-exporter"]` `gsa` and `db_user` outputs |
| `AUDIT_EXPORTER_KMS_KEY_VERSION` | `<lock keys.manifest_signing_key>/cryptoKeyVersions/<n>`; render rejects another key or a non-numeric version |
| `AUDIT_EXPORTER_PUBLIC_KEY_PEM` | public key PEM of that version: `gcloud kms keys versions get-public-key <n> --key <key> --keyring <ring> --location <region> --output-file manifest-key.pem`, then the file text (one P-256 `PUBLIC KEY` block, checked by render) |
| `AUDIT_EVIDENCE_BUCKET`, `AUDIT_DECISION_INPUT_EXPORTS_BUCKET` | lock only: `storage.evidence_bucket`, `storage.decision_input_exports_bucket` |
| `SQL_PROXY_IMAGE`, `CLOUDSQL_CONNECTION_NAME`, `DB_NAME`, `AUDIT_VERSION` | the same values as the contact services |

## Installation order

1. Migrations, `installer/m3-1-action-path.sql`, then
   `installer/m3-1-observe.sql` (grants `audit_exporter` to the exporter login,
   registers `agent-observe/audit-exporter` and checks its principal).
2. Contact services (workload-identity, audit-writer, control-health) running.
3. Apply this manifest and wait for the rollout; then check that
   `health.control_health_leases` has a live `audit-export` row.

Not included: key rotation. `keys.json` holds only the signing version; a
rotation must also keep every retired version that signed earlier manifests,
which this single-value render input cannot express yet.
