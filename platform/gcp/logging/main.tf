# TASK-06 3.4: the durable network-policy evidence path reads node files.
# This additive resource owns one exclusion, not the _Default sink itself.
resource "google_project_service" "logging" {
  project            = var.project_id
  service            = "logging.googleapis.com"
  disable_on_destroy = false
}

resource "google_logging_project_exclusion" "policy_action" {
  project     = var.project_id
  name        = "agentarium-policy-action-node-evidence"
  description = "TASK-06: collect policy-action evidence from node files instead of duplicate _Default storage."
  disabled    = false
  filter      = "resource.type=\"k8s_node\" AND logName=\"projects/${var.project_id}/logs/policy-action\""
  depends_on  = [google_project_service.logging]
}

output "policy_action_exclusion" {
  value = {
    name   = google_logging_project_exclusion.policy_action.name
    filter = google_logging_project_exclusion.policy_action.filter
  }
}
