# TASK-06 3.3: discovery needs no OIDC/broker secret or Cloud SQL installation.
# Keep these resource identities identical to their original workload-services
# definitions; the prod root moves existing state without recreating grants.
locals {
  principals = {
    for ksa in ["discovery", "discovery-snapshot"] : ksa => "principal://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${var.project_id}.svc.id.goog/subject/ns/agent-observe/sa/${ksa}"
  }
}

resource "google_project_iam_custom_role" "snapshot" {
  project     = var.project_id
  role_id     = "agentariumDiscoverySnapshot"
  title       = "Agentarium discovery snapshot objects"
  description = "TASK-06 discovery snapshot create/get/list; no delete or overwrite"
  permissions = ["storage.objects.create", "storage.objects.get", "storage.objects.list"]
  stage       = "GA"
}

resource "google_storage_bucket_iam_member" "reader" {
  bucket = var.bucket
  role   = "roles/storage.objectViewer"
  member = local.principals["discovery"]
}

resource "google_storage_bucket_iam_member" "snapshot" {
  bucket     = var.bucket
  role       = "projects/${var.project_id}/roles/agentariumDiscoverySnapshot"
  member     = local.principals["discovery-snapshot"]
  depends_on = [google_project_iam_custom_role.snapshot]
}

output "principals" {
  value = local.principals
}
