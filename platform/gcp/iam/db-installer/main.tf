# TASK-01 installer DB identity (issue #123, owner decision 2026-10-17).
# A dedicated GSA registered as a Cloud SQL IAM service-account DB user with
# cloudsqlsuperuser runs merged migrations from a one-shot in-cluster Job.
# Runtime contact/workload GSAs gain nothing here. The only principal that can
# use this GSA is KSA agent-control/db-installer, and only while
# enable_workload_binding is true (the installation window).
locals {
  ksa       = "db-installer"
  namespace = "agent-control"
  principal = "principal://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${var.project_id}.svc.id.goog/subject/ns/${local.namespace}/sa/${local.ksa}"
}

resource "google_service_account" "installer" {
  project      = var.project_id
  account_id   = "db-installer"
  display_name = "Agentarium Cloud SQL migration installer"
  description  = "Runs merged migrations from the one-shot installer Job only (issue #123)"
}

resource "google_project_iam_member" "installer" {
  for_each = toset(["roles/cloudsql.client", "roles/cloudsql.instanceUser"])
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.installer.email}"
  condition {
    title       = "agentarium-installer-database"
    description = "Only the installed Agentarium Cloud SQL instance"
    expression  = "resource.name == 'projects/${var.project_id}/instances/${var.cloudsql_instance}'"
  }
}

# Same requirement as the contact-service DB GSAs: the Proxy's
# --impersonate-service-account call is billed to this GSA's project.
resource "google_project_iam_member" "installer_service_usage" {
  project = var.project_id
  role    = "roles/serviceusage.serviceUsageConsumer"
  member  = "serviceAccount:${google_service_account.installer.email}"
}

resource "google_sql_user" "installer" {
  project  = var.project_id
  instance = var.cloudsql_instance
  name     = trimsuffix(google_service_account.installer.email, ".gserviceaccount.com")
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
  # Write-only in provider 8.6.0: sent on create/update, never read back, so
  # Terraform cannot detect drift. The runbook re-asserts it with
  # `gcloud sql users assign-roles` and the Job verifies membership in SQL.
  database_roles = ["cloudsqlsuperuser"]
  # Migrated objects are owned by this login. Cloud SQL cannot delete a
  # PostgreSQL user that owns objects or holds roles; destroy must not try.
  deletion_policy = "ABANDON"
}

resource "google_service_account_iam_member" "installer_workload" {
  count              = var.enable_workload_binding ? 1 : 0
  service_account_id = google_service_account.installer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.principal
}

output "installer" {
  value = {
    namespace                = local.namespace
    ksa                      = local.ksa
    gsa                      = google_service_account.installer.email
    db_user                  = google_sql_user.installer.name
    workload_binding_enabled = var.enable_workload_binding
  }
}
