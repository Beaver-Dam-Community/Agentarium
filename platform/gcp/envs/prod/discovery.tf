# The discovery permissions are fully determined by existing platform/storage
# outputs. They must not wait for unrelated OIDC or credential-broker secrets.
module "discovery_iam" {
  source         = "../../iam/discovery"
  project_id     = module.platform.project_id
  project_number = module.platform.project_number
  bucket         = module.shared_resources.buckets.discovery
}

# Preserve objects already installed by the former full-workload module.
# Keep these moves for existing state, including installations with lock.iam.
moved {
  from = module.workload_services[0].google_project_iam_custom_role.workload["discovery_snapshot"]
  to   = module.discovery_iam.google_project_iam_custom_role.snapshot
}
moved {
  from = module.workload_services[0].google_storage_bucket_iam_member.workload["discovery/discovery"]
  to   = module.discovery_iam.google_storage_bucket_iam_member.reader
}
moved {
  from = module.workload_services[0].google_storage_bucket_iam_member.workload["discovery/discovery-snapshot"]
  to   = module.discovery_iam.google_storage_bucket_iam_member.snapshot
}
