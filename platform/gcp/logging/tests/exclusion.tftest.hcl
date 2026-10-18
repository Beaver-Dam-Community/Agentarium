mock_provider "google" {}
variables { project_id = "example-project" }
run "only_network_policy_node_records" {
  command = plan
  assert {
    condition     = google_logging_project_exclusion.policy_action.filter == "resource.type=\"k8s_node\" AND logName=\"projects/example-project/logs/policy-action\"" && !google_logging_project_exclusion.policy_action.disabled
    error_message = "Exclude only this project's policy-action node records, without sampling."
  }
  assert {
    condition     = google_logging_project_exclusion.policy_action.project == var.project_id && google_project_service.logging.service == "logging.googleapis.com" && !google_project_service.logging.disable_on_destroy
    error_message = "Configure only the installation project and preserve the shared Logging API."
  }
}
run "reject_filter_injection" {
  command = plan
  variables { project_id = "example-project\" OR logName:*" }
  expect_failures = [var.project_id]
}
