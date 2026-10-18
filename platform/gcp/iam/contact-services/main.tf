# TASK-06 M1-1. Additive grants only: never replaces project/SA IAM policies.
variable "project_id" { type = string }
variable "project_number" { type = string }
variable "cloudsql_instance" { type = string }
variable "ca_pool_id" { type = string }
variable "claim_key_secret" {
  description = "Canonical Secret Manager secret for the identity claim-code HMAC key (TASK-06 3.3, #101). Never a version or value."
  type        = string
  validation {
    condition     = try(can(regex("^projects/[0-9]+/secrets/[A-Za-z0-9_-]{1,255}$", var.claim_key_secret)) && split("/", var.claim_key_secret)[1] == var.project_number, false)
    error_message = "claim_key_secret must be projects/<this project number>/secrets/<name>, not a version, alias or another project."
  }
}
variable "other_secret_resources" {
  description = "Every other Secret Manager secret granted in this environment (OIDC client, broker credentials). The claim key must differ from all of them."
  type        = list(string)
  default     = []
  validation {
    # Compare secret names within this project, treating project ID and number
    # as the same project (Secret Manager accepts both forms).
    condition = try(!contains([
      for s in var.other_secret_resources : split("/", s)[3]
      if contains([var.project_id, var.project_number], split("/", s)[1])
    ], split("/", var.claim_key_secret)[3]), false)
    error_message = "claim_key_secret must be a separate secret from the OIDC client secret and every broker credential secret (#101)."
  }
}
variable "certificate_template_ids" {
  description = "Two installed profile templates in the CA pool's project/location."
  type = object({
    service = string
    client  = string
  })
  validation {
    condition = (
      var.certificate_template_ids.service != var.certificate_template_ids.client &&
      alltrue([for id in values(var.certificate_template_ids) : can(regex("^projects/[a-z][a-z0-9-]+/locations/[a-z][a-z0-9-]+/certificateTemplates/[a-zA-Z0-9_-]{1,63}$", id)) &&
        try(split("/", id)[1] == var.project_id, false) &&
      try(join("/", slice(split("/", id), 0, 4)) == join("/", slice(split("/", var.ca_pool_id), 0, 4)), false)])
    )
    error_message = "Certificate templates must be distinct full resource names in the CA pool's project/location."
  }
}


resource "google_project_service" "identity_apis" {
  for_each           = toset(["iam.googleapis.com", "iamcredentials.googleapis.com", "secretmanager.googleapis.com"])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

locals {
  services = {
    workload-identity = { namespace = "agent-control", db_role = "identity_app" }
    audit-writer      = { namespace = "agent-observe", db_role = "audit_writer" }
    control-health    = { namespace = "agent-observe", db_role = "control_health_writer" }
  }
  principals = {
    for ksa, cfg in local.services : ksa => "principal://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${var.project_id}.svc.id.goog/subject/ns/${cfg.namespace}/sa/${ksa}"
  }
  db_grants = {
    for pair in setproduct(keys(local.services), ["roles/cloudsql.client", "roles/cloudsql.instanceUser"]) : "${pair[0]}/${pair[1]}" => { ksa = pair[0], role = pair[1] }
  }
}
resource "google_service_account" "database" {
  for_each     = local.services
  project      = var.project_id
  account_id   = "${each.key}-db"
  display_name = "Agentarium ${each.key} Cloud SQL identity"
  depends_on   = [google_project_service.identity_apis]
}
resource "google_service_account_iam_member" "database_impersonation" {
  for_each           = local.services
  service_account_id = google_service_account.database[each.key].name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.principals[each.key]
}
resource "google_project_iam_member" "database" {
  for_each = local.db_grants
  project  = var.project_id
  role     = each.value.role
  member   = "serviceAccount:${google_service_account.database[each.value.ksa].email}"
  # Cloud SQL IAM authorization is scoped to this instance, not every DB in
  # the project. Runtime access still requires the instance's IAM DB user.
  condition {
    title       = "agentarium-contact-database"
    description = "Only the installed Agentarium Cloud SQL instance"
    expression  = "resource.name == 'projects/${var.project_id}/instances/${var.cloudsql_instance}'"
  }
}
resource "google_project_iam_member" "database_service_usage" {
  for_each = local.services
  project  = var.project_id
  role     = "roles/serviceusage.serviceUsageConsumer"
  member   = "serviceAccount:${google_service_account.database[each.key].email}"
}
resource "google_sql_user" "database" {
  for_each = local.services
  project  = var.project_id
  instance = var.cloudsql_instance
  name     = trimsuffix(google_service_account.database[each.key].email, ".gserviceaccount.com")
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}
resource "google_privateca_ca_pool_iam_member" "identity_issuer" {
  ca_pool = var.ca_pool_id
  role    = "roles/privateca.certificateRequester"
  member  = local.principals["workload-identity"]
  # Missing template maps to the empty string and is denied. IAM uses
  # project/-/template, not the full resource name carried by CAS requests.
  condition {
    title       = "agentarium-certificate-profiles"
    description = "Only the installed service and client-only certificate templates"
    expression  = "api.getAttribute('privateca.googleapis.com/template', '') in ${jsonencode([for profile in ["service", "client"] : "${var.project_id}/-/${split("/", var.certificate_template_ids[profile])[5]}"])}"
  }
}
resource "google_privateca_certificate_template_iam_member" "identity_template" {
  for_each             = var.certificate_template_ids
  certificate_template = each.value
  role                 = "roles/privateca.templateUser"
  member               = local.principals["workload-identity"]
}
# TASK-06 3.3 (#101): Terraform creates the claim key secret under the lock
# name and its first version (version 1, the lock's claim_key_version). The
# value is 48 ephemeral random bytes, base64 (64 ASCII bytes; identity uses
# the file bytes as the HMAC key and needs >= 32). random_bytes is ephemeral
# and secret_data_wo is write-only, so the value is in neither plan nor state.
# Rotation adds a new version resource; Terraform never destroys these.
resource "google_secret_manager_secret" "identity_claim_key" {
  project             = var.project_id
  secret_id           = basename(var.claim_key_secret)
  deletion_protection = true
  labels              = { managed-by = "terraform", agentarium-secret = "identity-claim-key" }
  replication {
    auto {}
  }
  depends_on = [google_project_service.identity_apis]
  lifecycle {
    prevent_destroy = true
  }
}
ephemeral "random_bytes" "identity_claim_key" {
  length = 48
}
resource "google_secret_manager_secret_version" "identity_claim_key" {
  secret                 = google_secret_manager_secret.identity_claim_key.id
  secret_data_wo         = ephemeral.random_bytes.identity_claim_key.base64
  secret_data_wo_version = "1"
  lifecycle {
    prevent_destroy = true
  }
}
# The GKE Secret Manager add-on reads the claim key as the Pod's KSA
# principal, so only that direct principal gets access, on this one secret.
# The DB GSA stays Proxy-only (#51).
resource "google_secret_manager_secret_iam_member" "identity_claim_key" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.identity_claim_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = local.principals["workload-identity"]
}
output "claim_key_version" {
  description = "Secret Manager version number of the Terraform-created claim key; the lock's identity.claim_key_version must equal it."
  value       = google_secret_manager_secret_version.identity_claim_key.version
}
output "services" {
  value = { for ksa, cfg in local.services : ksa => {
    namespace = cfg.namespace
    gsa       = google_service_account.database[ksa].email
    db_user   = google_sql_user.database[ksa].name
    db_role   = cfg.db_role
  } }
}
