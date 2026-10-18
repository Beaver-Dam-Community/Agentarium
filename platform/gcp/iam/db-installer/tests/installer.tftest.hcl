mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/example-project/serviceAccounts/db-installer@example-project.iam.gserviceaccount.com"
      email = "db-installer@example-project.iam.gserviceaccount.com"
    }
  }
}
variables {
  project_id        = "example-project"
  project_number    = "123456789012"
  cloudsql_instance = "agentarium-example"
}
run "binding_off_by_default" {
  command = plan
  assert {
    condition     = length(google_service_account_iam_member.installer_workload) == 0 && !output.installer.workload_binding_enabled
    error_message = "No KSA may impersonate the installer GSA outside the install window."
  }
  assert {
    condition     = toset(keys(google_project_iam_member.installer)) == toset(["roles/cloudsql.client", "roles/cloudsql.instanceUser"]) && alltrue([for b in google_project_iam_member.installer : b.condition[0].expression == "resource.name == 'projects/example-project/instances/agentarium-example'"])
    error_message = "Installer project IAM must be instance-scoped Cloud SQL client and instanceUser only."
  }
  assert {
    condition     = google_project_iam_member.installer_service_usage.role == "roles/serviceusage.serviceUsageConsumer"
    error_message = "Proxy impersonation needs service usage on the installer GSA, matching contact GSAs."
  }
  assert {
    condition     = google_sql_user.installer.type == "CLOUD_IAM_SERVICE_ACCOUNT" && google_sql_user.installer.database_roles == tolist(["cloudsqlsuperuser"]) && google_sql_user.installer.deletion_policy == "ABANDON"
    error_message = "Installer DB user must be an IAM service-account user with exactly cloudsqlsuperuser and must not be deleted on destroy."
  }
}
run "install_window_binding" {
  command = apply
  variables { enable_workload_binding = true }
  assert {
    condition     = length(google_service_account_iam_member.installer_workload) == 1 && google_service_account_iam_member.installer_workload[0].role == "roles/iam.workloadIdentityUser"
    error_message = "The install window must add exactly one workload identity binding."
  }
  assert {
    condition     = google_service_account_iam_member.installer_workload[0].member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-project.svc.id.goog/subject/ns/agent-control/sa/db-installer"
    error_message = "Only the exact installer KSA principal may be bound (no principalSet, no runtime KSA)."
  }
  assert {
    condition     = output.installer.db_user == "db-installer@example-project.iam" && output.installer.workload_binding_enabled
    error_message = "Installer DB user must be the GSA email without .gserviceaccount.com."
  }
}
