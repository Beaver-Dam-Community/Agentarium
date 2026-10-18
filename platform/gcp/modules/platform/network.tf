# No Cloud Router/NAT: private nodes have no internet egress (TASK-01 section 4, TASK-06 second line of defense).
resource "google_compute_network" "this" {
  project                 = local.project_id
  name                    = local.name
  auto_create_subnetworks = false

  depends_on = [google_project_service.this]
}

resource "google_compute_subnetwork" "nodes" {
  project       = local.project_id
  name          = "${local.name}-nodes"
  region        = local.region
  network       = google_compute_network.this.id
  ip_cidr_range = var.lock.network.node_cidr
  stack_type    = "IPV4_ONLY"

  # Private nodes reach Google APIs only through Private Google Access.
  # SPEC-QUESTION: PGA VIP routing and private DNS zones are owned by TASK-06 (platform/gcp/iam/);
  # only the subnet flag is set here because the subnet is declared in this module.
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.lock.network.pods_range
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.lock.network.services_range
  }
}
