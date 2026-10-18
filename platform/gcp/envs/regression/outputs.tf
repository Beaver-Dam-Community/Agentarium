output "project_id" {
  value = module.platform.project_id
}

output "project_number" {
  value = module.platform.project_number
}

output "workload_pool" {
  value = module.platform.workload_pool
}

output "location" {
  value = module.platform.location
}

output "cluster_name" {
  value = module.platform.cluster_name
}

output "control_plane_endpoint" {
  value = module.platform.control_plane_endpoint
}

output "gateway_cluster_ip" {
  value = module.platform.gateway_cluster_ip
}

output "network_id" {
  value = module.platform.network_id
}

output "subnetwork_id" {
  value = module.platform.subnetwork_id
}

output "node_service_account" {
  value = module.platform.node_service_account
}

output "platform_manifest" {
  value = module.platform.platform_manifest
}

output "region" {
  value = module.platform.region
}

output "cloudsql_connection_name" {
  value = module.shared_resources.cloudsql_connection_name
}

output "cloudsql_private_ip" {
  value = module.shared_resources.cloudsql_private_ip
}

output "buckets" {
  value = module.shared_resources.buckets
}

output "evidence_bucket" {
  value = module.shared_resources.evidence_bucket
}

output "bundle_bucket" {
  value = module.shared_resources.bundle_bucket
}

output "kms_key_ids" {
  value = module.shared_resources.kms_key_ids
}

output "bundle_key_id" {
  value = module.shared_resources.bundle_key_id
}

output "ca_pool_id" {
  value = module.shared_resources.ca_pool_id
}

output "certificate_authority_id" {
  value = module.shared_resources.certificate_authority_id
}
