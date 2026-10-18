# TASK-06 3.3. Contact-service DB identities and CAS remain in contact-services;
# node SA grants remain in modules/platform. Every grant here is additive.
locals {
  database_services = {
    policy-gateway        = "agent-control"
    coordinator           = "agent-control"
    credential-broker     = "agent-control"
    intent-checker        = "agent-control"
    kubernetes-reader     = "agent-adapters"
    receiver-sender       = "agent-adapters"
    model-adapter         = "agent-adapters"
    evidence-reader       = "agent-adapters"
    audit-exporter        = "agent-observe"
    audit-verifier        = "agent-observe"
    audit-retention       = "agent-observe"
    evidence-collector    = "agent-observe"
    timeline              = "agent-observe"
    correlation           = "agent-observe"
    start-coordinator     = "agent-observe"
    policy-proposer       = "agent-observe"
    discovery             = "agent-observe"
    drift-probe           = "agent-observe"
    releaser              = "agent-release"
    regression-dispatcher = "agent-release"
    receiver              = "agent-targets"
  }
  services = merge(local.database_services, {
    workload-identity  = "agent-control"
    discovery-snapshot = "agent-observe"
  })
  principals = {
    for ksa, ns in local.services : ksa => "principal://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${var.project_id}.svc.id.goog/subject/ns/${ns}/sa/${ksa}"
  }
  db_grants = {
    for pair in setproduct(keys(local.database_services), ["roles/cloudsql.client", "roles/cloudsql.instanceUser"]) : "${pair[0]}/${pair[1]}" => { ksa = pair[0], role = pair[1] }
  }
  custom_roles = {
    audit_export = {
      id          = "agentariumAuditExport", title = "Agentarium audit object create and verify"
      permissions = ["storage.objects.create", "storage.objects.get"]
    }
    manifest_public_key = {
      id          = "agentariumManifestPublicKey", title = "Agentarium manifest public key"
      permissions = ["cloudkms.cryptoKeyVersions.viewPublicKey"]
    }
    model_predict = {
      id          = "agentariumModelPredict", title = "Agentarium model prediction"
      permissions = ["aiplatform.endpoints.predict"]
    }
    cluster_get = {
      id          = "agentariumClusterGet", title = "Agentarium cluster baseline read"
      permissions = ["container.clusters.get"]
    }
  }
  role_names = { for name, role in local.custom_roles : name => "projects/${var.project_id}/roles/${role.id}" }
  bucket_grants = merge(
    { for ksa in ["policy-gateway", "workload-identity", "kubernetes-reader", "receiver-sender", "model-adapter", "evidence-reader"] :
      "bundle/${ksa}" => { bucket = "bundle", ksa = ksa, role = "roles/storage.objectViewer" }
    },
    { for bucket in ["evidence", "decision_input_exports"] :
      "${bucket}/audit-exporter" => { bucket = bucket, ksa = "audit-exporter", role = local.role_names.audit_export }
    },
    { for bucket in ["evidence", "decision_input_exports"] :
      "${bucket}/audit-verifier" => { bucket = bucket, ksa = "audit-verifier", role = "roles/storage.objectViewer" }
    },
    {
      "bundle/releaser"                           = { bucket = "bundle", ksa = "releaser", role = "roles/storage.objectCreator" }
      "regression_requests/regression-dispatcher" = { bucket = "regression_requests", ksa = "regression-dispatcher", role = "roles/storage.objectCreator" }
      "regression_reports/regression-dispatcher"  = { bucket = "regression_reports", ksa = "regression-dispatcher", role = "roles/storage.objectViewer" }
    }
  )
}

resource "google_project_service" "application_apis" {
  for_each           = toset(["secretmanager.googleapis.com", "aiplatform.googleapis.com"])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}
resource "google_project_iam_custom_role" "workload" {
  for_each    = local.custom_roles
  project     = var.project_id
  role_id     = each.value.id
  title       = each.value.title
  permissions = each.value.permissions
  stage       = "GA"
  depends_on  = [google_project_service.application_apis]
}

resource "google_service_account" "database" {
  for_each     = local.database_services
  project      = var.project_id
  account_id   = "${each.key}-db"
  display_name = "Agentarium ${each.key} Cloud SQL identity"
}
resource "google_service_account_iam_member" "database_impersonation" {
  for_each           = local.database_services
  service_account_id = google_service_account.database[each.key].name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.principals[each.key]
}
resource "google_project_iam_member" "database" {
  for_each = local.db_grants
  project  = var.project_id
  role     = each.value.role
  member   = "serviceAccount:${google_service_account.database[each.value.ksa].email}"
  condition {
    title       = "agentarium-workload-database"
    description = "Only the installed Agentarium Cloud SQL instance"
    expression  = "resource.name == 'projects/${var.project_id}/instances/${var.cloudsql_instance}'"
  }
}
resource "google_project_iam_member" "database_service_usage" {
  for_each = local.database_services
  project  = var.project_id
  role     = "roles/serviceusage.serviceUsageConsumer"
  member   = "serviceAccount:${google_service_account.database[each.key].email}"
}
resource "google_sql_user" "database" {
  for_each = local.database_services
  project  = var.project_id
  instance = var.cloudsql_instance
  name     = trimsuffix(google_service_account.database[each.key].email, ".gserviceaccount.com")
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

resource "google_storage_bucket_iam_member" "workload" {
  for_each   = local.bucket_grants
  bucket     = var.buckets[each.value.bucket]
  role       = each.value.role
  member     = local.principals[each.value.ksa]
  depends_on = [google_project_iam_custom_role.workload]
}
resource "google_kms_crypto_key_iam_member" "signing" {
  for_each      = { audit-exporter = "manifest", releaser = "bundle" }
  crypto_key_id = var.keys[each.value]
  role          = "roles/cloudkms.signerVerifier"
  member        = local.principals[each.key]
}
resource "google_kms_crypto_key_iam_member" "verification" {
  crypto_key_id = var.keys.manifest
  role          = local.role_names.manifest_public_key
  member        = local.principals["audit-verifier"]
  depends_on    = [google_project_iam_custom_role.workload]
}
# TASK-03 Google OIDC client secret: Terraform creates only the lock-named
# secret, with no version. Google sets the value when the console OAuth client
# is made, and the installer adds it as a version outside Terraform. M3-1 signs
# in with CLI ID tokens and does not read this secret.
resource "google_secret_manager_secret" "identity_oidc" {
  project             = var.project_id
  secret_id           = basename(var.settings.oidc_client_secret)
  deletion_protection = true
  labels              = { managed-by = "terraform", agentarium-secret = "identity-oidc-client" }
  replication {
    auto {}
  }
  depends_on = [google_project_service.application_apis]
  lifecycle {
    prevent_destroy = true
  }
}
resource "google_secret_manager_secret_iam_member" "identity_oidc" {
  project    = var.project_id
  secret_id  = google_secret_manager_secret.identity_oidc.secret_id
  role       = "roles/secretmanager.secretAccessor"
  member     = local.principals["workload-identity"]
  depends_on = [google_project_service.application_apis]
}
# TASK-08 receiver API key (#169, M3-1): Terraform creates the lock-named
# secret and version 1 (the lock's first receiver.api_key_versions entry).
# The key is 32 ephemeral random bytes as 43 characters of unpadded base64url,
# the only form receiver and receiver-sender accept. random_bytes is
# ephemeral and secret_data_wo is write-only, so the value is in neither plan
# nor state. Rotation adds a new version resource; Terraform never destroys
# these. The secret is also a broker credential secret (validated).
resource "google_secret_manager_secret" "receiver_api_key" {
  count               = var.receiver_api_key_secret == null ? 0 : 1
  project             = var.project_id
  secret_id           = basename(var.receiver_api_key_secret)
  deletion_protection = true
  labels              = { managed-by = "terraform", agentarium-secret = "receiver-api-key" }
  replication {
    auto {}
  }
  depends_on = [google_project_service.application_apis]
  lifecycle {
    prevent_destroy = true
  }
}
ephemeral "random_bytes" "receiver_api_key" {
  count  = var.receiver_api_key_secret == null ? 0 : 1
  length = 32
}
resource "google_secret_manager_secret_version" "receiver_api_key" {
  count                  = var.receiver_api_key_secret == null ? 0 : 1
  secret                 = google_secret_manager_secret.receiver_api_key[0].id
  secret_data_wo         = trimsuffix(replace(replace(ephemeral.random_bytes.receiver_api_key[0].base64, "+", "-"), "/", "_"), "=")
  secret_data_wo_version = "1"
  lifecycle {
    prevent_destroy = true
  }
}
resource "google_secret_manager_secret_iam_member" "broker" {
  for_each  = var.settings.credential_secret_resources
  project   = var.project_id
  secret_id = basename(each.value)
  role      = "roles/secretmanager.secretAccessor"
  member    = local.principals["credential-broker"]
  # One of these is the receiver API key secret created above.
  depends_on = [google_project_service.application_apis, google_secret_manager_secret.receiver_api_key]
}
# TASK-08 receiver API key (#169, M3-1): the GKE Secret Manager add-on reads the
# pinned versions as the receiver Pod's own KSA, like the identity claim key.
# The broker reads the same secret to send the header (credential_bindings row
# receiver-api-key), so it must be one of the broker secrets above.
# SPEC-QUESTION: TASK-06 3.3 lists no direct grant for agent-targets/receiver.
resource "google_secret_manager_secret_iam_member" "receiver_api_key" {
  count      = var.receiver_api_key_secret == null ? 0 : 1
  project    = var.project_id
  secret_id  = google_secret_manager_secret.receiver_api_key[0].secret_id
  role       = "roles/secretmanager.secretAccessor"
  member     = local.principals["receiver"]
  depends_on = [google_project_service.application_apis]
}
resource "google_project_iam_member" "application" {
  for_each   = { model-adapter = "model_predict", drift-probe = "cluster_get" }
  project    = var.project_id
  role       = local.role_names[each.value]
  member     = local.principals[each.key]
  depends_on = [google_project_iam_custom_role.workload]
}

# TASK-06 3.3 "cross-environment grant exceptions" (#97): exactly four production-resource
# grants to exact regression KSA principals, no conditions. iamcheck
# (platform/gcp/iam/checks) exempts only these; any other grant to the
# regression pool still fails CROSS_ENV_POOL.
locals {
  regression_principals = var.regression_environment == null ? {} : {
    for ksa in ["decision-replay", "regression-runner"] : ksa => "principal://iam.googleapis.com/projects/${var.regression_environment.project_number}/locations/global/workloadIdentityPools/${var.regression_environment.project_id}.svc.id.goog/subject/ns/agent-release/sa/${ksa}"
  }
  cross_env_bucket_grants = var.regression_environment == null ? {} : {
    "decision_input_exports/decision-replay" = { bucket = "decision_input_exports", ksa = "decision-replay", role = "roles/storage.objectViewer" }
    "regression_requests/regression-runner"  = { bucket = "regression_requests", ksa = "regression-runner", role = "roles/storage.objectViewer" }
    "regression_reports/regression-runner"   = { bucket = "regression_reports", ksa = "regression-runner", role = "roles/storage.objectCreator" }
  }
}
resource "google_storage_bucket_iam_member" "cross_env" {
  for_each = local.cross_env_bucket_grants
  bucket   = var.buckets[each.value.bucket]
  role     = each.value.role
  member   = local.regression_principals[each.value.ksa]
}
resource "google_kms_crypto_key_iam_member" "cross_env_public_key" {
  count         = var.regression_environment == null ? 0 : 1
  crypto_key_id = var.keys.manifest
  role          = local.role_names.manifest_public_key
  member        = local.regression_principals["decision-replay"]
  depends_on    = [google_project_iam_custom_role.workload]
}
output "cross_env_grants" {
  description = "The four cross-environment grants in iamcheck CrossEnvGrant form (full resource name, asset type, role, member)."
  value = concat(
    [for k in ["decision_input_exports/decision-replay"] : {
      resource = "//storage.googleapis.com/${google_storage_bucket_iam_member.cross_env[k].bucket}", asset_type = "storage.googleapis.com/Bucket"
      role     = google_storage_bucket_iam_member.cross_env[k].role, member = google_storage_bucket_iam_member.cross_env[k].member
    } if contains(keys(google_storage_bucket_iam_member.cross_env), k)],
    [for b in google_kms_crypto_key_iam_member.cross_env_public_key : {
      resource = "//cloudkms.googleapis.com/${b.crypto_key_id}", asset_type = "cloudkms.googleapis.com/CryptoKey", role = b.role, member = b.member
    }],
    [for k in ["regression_requests/regression-runner", "regression_reports/regression-runner"] : {
      resource = "//storage.googleapis.com/${google_storage_bucket_iam_member.cross_env[k].bucket}", asset_type = "storage.googleapis.com/Bucket"
      role     = google_storage_bucket_iam_member.cross_env[k].role, member = google_storage_bucket_iam_member.cross_env[k].member
    } if contains(keys(google_storage_bucket_iam_member.cross_env), k)],
  )
}

output "services" {
  description = "Installer mapping only; PostgreSQL role grants are applied after the owning migrations."
  value = { for ksa, ns in local.database_services : ksa => {
    namespace = ns
    gsa       = google_service_account.database[ksa].email
    db_user   = google_sql_user.database[ksa].name
  } }
}
output "principals" {
  value = local.principals
}
output "receiver_api_key_version" {
  description = "Secret Manager version number of the Terraform-created receiver API key (null without lock input); the lock's receiver.api_key_versions must list it."
  value       = one(google_secret_manager_secret_version.receiver_api_key[*].version)
}
