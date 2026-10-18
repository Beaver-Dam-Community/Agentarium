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

output "pga_vip_cidr" {
  value = module.private_google_access.pga_vip_cidr
}

output "contact_services" {
  value = module.contact_services.services
}

output "full_workload_iam_configured" {
  description = "False means lock.iam is absent and full same-environment TASK-06 workload bindings are not configured. Discovery bucket IAM is configured independently. Excludes issue #97 cross-environment grants; not runtime verification."
  value       = length(module.workload_services) == 1
}

output "workload_services" {
  value = try(module.workload_services[0].services, {})
}

output "discovery_principals" {
  description = "Exact discovery bucket KSA principals; this is configuration, not runtime verification."
  value       = module.discovery_iam.principals
}

output "db_installer" {
  description = "Migration installer GSA/DB user and whether the install-window KSA binding is currently configured."
  value       = module.db_installer.installer
}

output "certificate_template_ids" {
  value = module.shared_resources.certificate_template_ids
}

output "certificate_template_issuance_enabled" {
  description = "Recorded rollout stage; true is required before issuing with templates."
  value       = var.certificate_template_issuance_enabled
}

output "cross_env_grants" {
  description = "TASK-06 3.3 cross-environment grants (#97); empty without lock.iam.regression."
  value       = try(module.workload_services[0].cross_env_grants, [])
}
