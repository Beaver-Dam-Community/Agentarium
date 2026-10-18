resource "google_container_node_pool" "this" {
  for_each = local.node_pools

  project  = local.project_id
  location = local.location
  cluster  = google_container_cluster.this.name
  name     = each.value.name

  # SPEC-QUESTION: GKE node_count is per zone. With a regional location the pool has
  # node_count x zones nodes; the lock values (exec 2, control 3) read as totals.
  node_count = each.value.config.node_count

  # Release channel clusters require auto-upgrade; node upgrades are blocked by the
  # node pool maintenance exclusion below instead of --no-enable-autoupgrade (TASK-01 3.5).
  management {
    auto_upgrade = true
    auto_repair  = each.value.auto_repair
  }

  # Node pool exclusion: blocks automatic minor and patch node upgrades until the
  # version's end of support. It cannot block host maintenance, critical security
  # patches, or control plane repair.
  # SPEC-QUESTION: TASK-01 section 9 makes the exclusion period an install input, but a
  # node pool exclusion has no settable end time; it tracks end of support.
  maintenance_policy {
    exclusion_until_end_of_support {
      enabled = true
    }
  }

  node_config {
    machine_type    = each.value.config.machine_type
    disk_size_gb    = each.value.config.disk_size_gb
    disk_type       = each.value.config.disk_type
    image_type      = var.lock.node_pools.image_type
    service_account = google_service_account.nodes.email
    oauth_scopes    = local.node_oauth_scopes
    labels          = each.value.config.labels

    workload_metadata_config {
      mode = var.lock.node_pools.workload_metadata
    }

    dynamic "taint" {
      for_each = each.value.config.taints
      content {
        key    = regex("^([^=]+)=([^:]*):([A-Za-z]+)$", taint.value)[0]
        value  = regex("^([^=]+)=([^:]*):([A-Za-z]+)$", taint.value)[1]
        effect = local.taint_effect[regex("^([^=]+)=([^:]*):([A-Za-z]+)$", taint.value)[2]]
      }
    }
  }
}
