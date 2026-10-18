resource "google_container_cluster" "this" {
  project  = local.project_id
  name     = local.name
  location = local.location

  network    = google_compute_network.this.id
  subnetwork = google_compute_subnetwork.nodes.id

  # Dataplane V2 can only be enabled at creation; it enforces NetworkPolicy itself,
  # so no network_policy block is set.
  datapath_provider = var.lock.gke.datapath_provider

  min_master_version = var.lock.gke.kubernetes_minor

  release_channel {
    channel = var.lock.gke.release_channel
  }

  workload_identity_config {
    workload_pool = local.workload_pool
  }

  # SPEC-QUESTION: control plane access is not specified. The example lock uses the most
  # restrictive setting that still allows installation from outside the VPC: no public IP
  # endpoint, authorized networks enforced on the internal endpoint with no extra ranges
  # (cluster node/Pod/Service ranges stay allowed), no global access, and the IAM-gated
  # DNS endpoint for installers. Kubernetes token/cert auth over DNS stays at the disabled default.
  private_cluster_config {
    enable_private_nodes    = var.lock.gke.private_nodes
    enable_private_endpoint = var.lock.gke.control_plane.private_endpoint_only

    master_global_access_config {
      enabled = var.lock.gke.control_plane.master_global_access
    }
  }

  master_authorized_networks_config {
    gcp_public_cidrs_access_enabled      = false
    private_endpoint_enforcement_enabled = true

    dynamic "cidr_blocks" {
      for_each = var.lock.gke.control_plane.authorized_networks
      content {
        cidr_block   = cidr_blocks.value.cidr_block
        display_name = cidr_blocks.value.display_name
      }
    }
  }

  control_plane_endpoints_config {
    dns_endpoint_config {
      allow_external_traffic = var.lock.gke.control_plane.dns_endpoint_allow_external_traffic
    }
  }

  # TASK-06 3: the MVP does not run NodeLocal DNSCache (Google API names resolve through
  # the Cloud DNS private zone). GKE enables it by default on Standard 1.34.1-gke.3720000+,
  # so it is turned off explicitly. Changing it on an existing cluster recreates nodes and
  # follows the node pool maintenance exclusion.
  addons_config {
    dns_cache_config {
      enabled = false
    }
  }

  # TASK-01 3 item 10 (#101): GKE Secret Manager add-on (managed Secrets Store
  # CSI, driver secrets-store-gke.csi.k8s.io) delivers the identity claim key.
  # Versions are pinned in the SecretProviderClass, so auto rotation stays off.
  secret_manager_config {
    enabled = true
  }

  ip_allocation_policy {
    stack_type                    = var.lock.gke.ip_family
    cluster_secondary_range_name  = google_compute_subnetwork.nodes.secondary_ip_range[0].range_name
    services_secondary_range_name = google_compute_subnetwork.nodes.secondary_ip_range[1].range_name
  }

  # Node pools are managed as separate resources. The temporary default pool still
  # gets the dedicated node SA and GKE_METADATA until it is removed.
  # The temporary bootstrap pool retains provider-default disk settings. The
  # per-pool lock inputs apply only to the managed exec/control/system pools;
  # include this temporary pool in initial-creation quota planning.
  remove_default_node_pool = true
  initial_node_count       = 1

  node_config {
    image_type      = var.lock.node_pools.image_type
    service_account = google_service_account.nodes.email
    oauth_scopes    = local.node_oauth_scopes

    workload_metadata_config {
      mode = var.lock.node_pools.workload_metadata
    }
  }

  deletion_protection = true

  lifecycle {
    ignore_changes = [node_config]
  }

  depends_on = [
    google_project_service.this,
    google_project_iam_member.nodes,
  ]
}
