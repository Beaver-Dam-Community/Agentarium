mock_provider "google" {}

variables {
  project_id     = "example-prod"
  project_number = "123456789012"
  bucket         = "example-discovery"
}

run "fixed_discovery_permissions" {
  command = plan
  assert {
    condition = (
      google_project_iam_custom_role.snapshot.role_id == "agentariumDiscoverySnapshot" &&
      toset(google_project_iam_custom_role.snapshot.permissions) == toset(["storage.objects.create", "storage.objects.get", "storage.objects.list"])
    )
    error_message = "Snapshot must have exactly create/get/list, without delete or overwrite permissions."
  }
  assert {
    condition = (
      google_storage_bucket_iam_member.reader.bucket == "example-discovery" &&
      google_storage_bucket_iam_member.reader.role == "roles/storage.objectViewer" &&
      google_storage_bucket_iam_member.reader.member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-prod.svc.id.goog/subject/ns/agent-observe/sa/discovery" &&
      google_storage_bucket_iam_member.snapshot.bucket == "example-discovery" &&
      google_storage_bucket_iam_member.snapshot.role == "projects/example-prod/roles/agentariumDiscoverySnapshot" &&
      google_storage_bucket_iam_member.snapshot.member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-prod.svc.id.goog/subject/ns/agent-observe/sa/discovery-snapshot"
    )
    error_message = "Only the two exact KSAs may receive their distinct roles on the discovery bucket."
  }
}

run "reject_bucket_uri" {
  command = plan
  variables { bucket = "gs://example-discovery" }
  expect_failures = [var.bucket]
}
