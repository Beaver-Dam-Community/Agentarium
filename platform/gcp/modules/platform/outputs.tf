# TASK-01 section 4 outputs not produced here: evidence_bucket, bundle_bucket,
# cloudsql_connection_name and kms_key_ids come from modules/shared-resources;
# cluster_uid is not exposed by the provider; pga_vip_cidr is TASK-06; baseline_digests
# are computed at install time.

output "project_id" {
  value = local.project_id
}

output "project_number" {
  value = data.google_project.this.number
}

output "workload_pool" {
  value = local.workload_pool
}

output "location" {
  value = local.location
}

output "region" {
  value = local.region
}

output "cluster_name" {
  value = google_container_cluster.this.name
}

output "control_plane_endpoint" {
  value = google_container_cluster.this.endpoint
}

output "gateway_cluster_ip" {
  value = var.lock.network.gateway_cluster_ip
}

output "network_id" {
  value = google_compute_network.this.id
}

output "subnetwork_id" {
  value = google_compute_subnetwork.nodes.id
}

output "node_service_account" {
  value = google_service_account.nodes.email
}

# Terraform-known subset of the platform manifest keys (TASK-01 section 4).
output "platform_manifest" {
  value = {
    project_id             = local.project_id
    project_number         = data.google_project.this.number
    workload_pool          = local.workload_pool
    location               = local.location
    kubernetes_version     = google_container_cluster.this.master_version
    datapath_provider      = google_container_cluster.this.datapath_provider
    release_channel        = var.lock.gke.release_channel
    workload_metadata_mode = var.lock.node_pools.workload_metadata
    node_service_account   = google_service_account.nodes.email
    node_os                = var.lock.node_pools.image_type
    node_pool = {
      for k, p in google_container_node_pool.this : p.name => {
        machine_type = p.node_config[0].machine_type
        disk_size_gb = p.node_config[0].disk_size_gb
        disk_type    = p.node_config[0].disk_type
        node_count   = p.node_count
        version      = p.version
        labels       = p.node_config[0].labels
        taints       = local.node_pools[k].config.taints
      }
    }
    auto_repair = {
      for p in google_container_node_pool.this : p.name => p.management[0].auto_repair
    }
    maintenance_exclusions = {
      for p in google_container_node_pool.this : p.name => p.maintenance_policy[0].exclusion_until_end_of_support
    }
  }
}
