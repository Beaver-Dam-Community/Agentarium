# hostNetwork Pods reach the Compute Engine metadata server and get this identity,
# so it holds only the roles TASK-01 section 3 item 2 allows: the GKE minimal node role
# (node logging/monitoring writes) and image pulls. Scopes are narrowed in main.tf.
resource "google_service_account" "nodes" {
  project      = local.project_id
  account_id   = "agentarium-gke-nodes"
  display_name = "Agentarium GKE nodes (${var.env})"
}

resource "google_project_iam_member" "nodes" {
  for_each = toset([
    "roles/container.defaultNodeServiceAccount",
    # SPEC-QUESTION: the spec says "image repository read" without naming the repository;
    # granted on this project. Narrow to the repository once its location/name is in the lock.
    "roles/artifactregistry.reader",
  ])

  project = local.project_id
  role    = each.value
  member  = google_service_account.nodes.member
}
