mock_provider "google" {}
variables {
  project_id = "example-project"
  network_id = "projects/example-project/global/networks/agentarium-prod"
}

run "private_ipv4_google_api_path" {
  command = plan
  assert {
    condition     = google_dns_managed_zone.googleapis.visibility == "private" && google_dns_managed_zone.googleapis.dns_name == "googleapis.com." && one(google_dns_managed_zone.googleapis.private_visibility_config[0].networks).network_url == var.network_id
    error_message = "Google API DNS must be visible only to the selected VPC."
  }
  assert {
    condition     = google_dns_record_set.private.type == "A" && google_dns_record_set.private.name == "private.googleapis.com." && toset(google_dns_record_set.private.rrdatas) == toset(["199.36.153.8", "199.36.153.9", "199.36.153.10", "199.36.153.11"])
    error_message = "Use all four private IPv4 VIP addresses; do not mix restricted or public addresses."
  }
  assert {
    condition     = google_dns_record_set.wildcard.type == "CNAME" && google_dns_record_set.wildcard.name == "*.googleapis.com." && one(google_dns_record_set.wildcard.rrdatas) == "private.googleapis.com."
    error_message = "API names must resolve through the private VIP record."
  }
  assert {
    condition     = google_compute_route.private_googleapis.dest_range == "199.36.153.8/30" && google_compute_route.private_googleapis.next_hop_gateway == "default-internet-gateway" && google_compute_route.private_googleapis.network == var.network_id && output.pga_vip_cidr == google_compute_route.private_googleapis.dest_range
    error_message = "The route and netpol output must target only the private VIP in the selected VPC."
  }
  assert {
    condition     = google_project_service.dns.service == "dns.googleapis.com" && !google_project_service.dns.disable_on_destroy
    error_message = "Enable Cloud DNS without disabling a shared API when this module is removed."
  }
}

run "reject_other_project_network" {
  command = plan
  variables { network_id = "projects/other-project/global/networks/agentarium-prod" }
  expect_failures = [var.network_id]
}

run "accept_provider_self_link" {
  command = plan
  variables { network_id = "https://www.googleapis.com/compute/v1/projects/example-project/global/networks/agentarium-prod" }
}
