locals {
  project_id    = var.lock.project.id
  location      = var.lock.project.location
  region        = can(regex("-[a-z]$", local.location)) ? regex("^(.*)-[a-z]$", local.location)[0] : local.location
  workload_pool = "${local.project_id}.svc.id.goog"
  name          = "agentarium-${var.env}"

  # hostNetwork Pods (agent-sensors) bypass Workload Identity and get node SA tokens from
  # the Compute Engine metadata server, so the scopes are narrowed to the set GKE assigns
  # nodes by default (Artifact Registry pulls work with devstorage.read_only plus
  # roles/artifactregistry.reader). Effective access is these scopes intersected with the
  # node SA roles in node_service_account.tf.
  node_oauth_scopes = [
    "https://www.googleapis.com/auth/devstorage.read_only",
    "https://www.googleapis.com/auth/logging.write",
    "https://www.googleapis.com/auth/monitoring",
    "https://www.googleapis.com/auth/service.management.readonly",
    "https://www.googleapis.com/auth/servicecontrol",
    "https://www.googleapis.com/auth/trace.append",
  ]

  taint_effect = {
    NoSchedule       = "NO_SCHEDULE"
    PreferNoSchedule = "PREFER_NO_SCHEDULE"
    NoExecute        = "NO_EXECUTE"
  }

  node_pools = {
    exec = {
      name        = "exec-pool"
      config      = var.lock.node_pools.exec
      auto_repair = var.lock.node_pools.auto_repair.exec
    }
    control = {
      name        = "control-pool"
      config      = var.lock.node_pools.control
      auto_repair = var.lock.node_pools.auto_repair.control
    }
    # GKE managed components (kube-dns, metrics-server) have no toleration for the start
    # taint, so they need a pool without it (TASK-01 3.5).
    system = {
      name        = "system-pool"
      config      = var.lock.node_pools.system
      auto_repair = var.lock.node_pools.auto_repair.system
    }
  }
}

data "google_project" "this" {
  project_id = local.project_id
}

resource "google_project_service" "this" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
  ])

  project            = local.project_id
  service            = each.value
  disable_on_destroy = false
}
