# TASK-06 section 2: IPv4-only Google API names resolve to the private VIP.
locals {
  vip_cidr      = "199.36.153.8/30"
  vip_addresses = ["199.36.153.8", "199.36.153.9", "199.36.153.10", "199.36.153.11"]
}

resource "google_project_service" "dns" {
  project            = var.project_id
  service            = "dns.googleapis.com"
  disable_on_destroy = false
}

resource "google_dns_managed_zone" "googleapis" {
  project     = var.project_id
  name        = "agentarium-private-googleapis"
  dns_name    = "googleapis.com."
  description = "TASK-06 Google APIs via the IPv4 Private Google Access VIP"
  visibility  = "private"
  private_visibility_config {
    networks {
      network_url = var.network_id
    }
  }
  depends_on = [google_project_service.dns]
}

resource "google_dns_record_set" "private" {
  project      = var.project_id
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "private.googleapis.com."
  type         = "A"
  ttl          = 300
  rrdatas      = local.vip_addresses
}

resource "google_dns_record_set" "wildcard" {
  project      = var.project_id
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "*.googleapis.com."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = [google_dns_record_set.private.name]
}

# The existing default route also reaches PGA. This specific route preserves that
# path if a later network change replaces the default route; it adds no NAT.
# Despite its name, this next hop keeps PGA traffic on Google's network.
resource "google_compute_route" "private_googleapis" {
  project          = var.project_id
  name             = "agentarium-private-googleapis"
  network          = var.network_id
  dest_range       = local.vip_cidr
  next_hop_gateway = "default-internet-gateway"
  priority         = 1000
}

output "pga_vip_cidr" {
  value = local.vip_cidr
}
