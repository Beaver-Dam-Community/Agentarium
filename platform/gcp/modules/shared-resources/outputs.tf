output "cloudsql_connection_name" {
  value = google_sql_database_instance.this.connection_name
}

output "cloudsql_private_ip" {
  value = google_sql_database_instance.this.private_ip_address
}

output "buckets" {
  description = "Bucket names created in this environment, keyed by role."
  value       = { for k, b in google_storage_bucket.this : k => b.name }
}

output "evidence_bucket" {
  value = google_storage_bucket.this["evidence"].name
}

output "bundle_bucket" {
  value = google_storage_bucket.this["bundle"].name
}

output "kms_key_ids" {
  value = { for k, key in google_kms_crypto_key.signing : k => key.id }
}

output "bundle_key_id" {
  value = var.lock.keys.bundle_key_id
}

output "ca_pool_id" {
  value = google_privateca_ca_pool.this.id
}

output "certificate_authority_id" {
  value = google_privateca_certificate_authority.root.id
}

output "discovery_bucket" {
  value = try(google_storage_bucket.this["discovery"].name, null)
}

output "image_repository" {
  description = "Docker repository prefix for digest-pinned image references."
  value       = "${google_artifact_registry_repository.agentarium.location}-docker.pkg.dev/${local.project_id}/${google_artifact_registry_repository.agentarium.repository_id}"
}

output "certificate_template_ids" {
  description = "Full resource names for identity's service and client-only profiles."
  value       = { for profile, template in google_privateca_certificate_template.workload : profile => template.id }
}

output "certificate_template_issuance_enabled" {
  description = "Recorded rollout stage; true is required before issuing with templates."
  value       = var.certificate_template_issuance_enabled
}
