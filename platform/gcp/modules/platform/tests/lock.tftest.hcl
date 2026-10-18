# Offline plan tests against a mocked provider; no GCP API is called.
mock_provider "google" {}

variables {
  env = "prod"
  lock = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")), {
    project = { id = "example-prod-123", location = "us-central1-a" }
    gke = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).gke, {
      kubernetes_minor = "1.33"
    })
  })
}

run "example_lock_plans" {
  command = plan

  assert {
    condition     = google_container_cluster.this.datapath_provider == "ADVANCED_DATAPATH"
    error_message = "Dataplane V2 not set."
  }

  assert {
    condition     = google_container_cluster.this.workload_identity_config[0].workload_pool == "example-prod-123.svc.id.goog"
    error_message = "workload pool mismatch."
  }

  assert {
    condition     = google_container_cluster.this.addons_config[0].dns_cache_config[0].enabled == false
    error_message = "NodeLocal DNSCache must be off (TASK-06 3)."
  }

  assert {
    condition = (
      google_container_cluster.this.secret_manager_config[0].enabled == true &&
      length(google_container_cluster.this.secret_manager_config[0].rotation_config) == 0
    )
    error_message = "GKE Secret Manager add-on must be on with auto rotation off (TASK-01 3 item 10, #101)."
  }

  assert {
    condition     = google_container_cluster.this.release_channel[0].channel == "REGULAR"
    error_message = "release channel mismatch."
  }

  assert {
    condition     = google_container_cluster.this.private_cluster_config[0].enable_private_nodes == true
    error_message = "private nodes not enabled."
  }

  assert {
    condition = (
      google_container_cluster.this.private_cluster_config[0].enable_private_endpoint == true &&
      google_container_cluster.this.private_cluster_config[0].master_global_access_config[0].enabled == false &&
      google_container_cluster.this.master_authorized_networks_config[0].gcp_public_cidrs_access_enabled == false &&
      google_container_cluster.this.master_authorized_networks_config[0].private_endpoint_enforcement_enabled == true &&
      length(google_container_cluster.this.master_authorized_networks_config[0].cidr_blocks) == 0 &&
      google_container_cluster.this.control_plane_endpoints_config[0].dns_endpoint_config[0].allow_external_traffic == true
    )
    error_message = "control plane access is not the restrictive default."
  }

  assert {
    condition = alltrue(concat(
      [!contains(google_container_cluster.this.node_config[0].oauth_scopes, "https://www.googleapis.com/auth/cloud-platform")],
      [for p in google_container_node_pool.this : !contains(p.node_config[0].oauth_scopes, "https://www.googleapis.com/auth/cloud-platform")]
    ))
    error_message = "node pools must not use the cloud-platform scope."
  }

  assert {
    condition     = google_container_cluster.this.ip_allocation_policy[0].stack_type == "IPV4"
    error_message = "stack type mismatch."
  }

  assert {
    condition     = google_compute_subnetwork.nodes.region == "us-central1"
    error_message = "region not derived from zone."
  }

  assert {
    condition = alltrue([
      for p in google_container_node_pool.this :
      p.node_config[0].workload_metadata_config[0].mode == "GKE_METADATA" &&
      p.node_config[0].image_type == "COS_CONTAINERD" &&
      p.management[0].auto_upgrade == true &&
      p.maintenance_policy[0].exclusion_until_end_of_support[0].enabled == true
    ])
    error_message = "node pool baseline settings mismatch."
  }

  assert {
    condition = (
      google_container_node_pool.this["exec"].name == "exec-pool" &&
      google_container_node_pool.this["exec"].management[0].auto_repair == false &&
      google_container_node_pool.this["exec"].node_count == 2 &&
      toset([for t in google_container_node_pool.this["exec"].node_config[0].taint : "${t.key}=${t.value}:${t.effect}"]) ==
      toset(["agentarium-role=exec:NO_SCHEDULE", "agentarium.io/observe-not-ready=true:NO_SCHEDULE"])
    )
    error_message = "exec-pool settings mismatch."
  }

  assert {
    condition = (
      google_container_node_pool.this["control"].name == "control-pool" &&
      google_container_node_pool.this["control"].management[0].auto_repair == true &&
      google_container_node_pool.this["control"].node_count == 3 &&
      [for t in google_container_node_pool.this["control"].node_config[0].taint : "${t.key}=${t.value}:${t.effect}"] ==
      ["agentarium.io/observe-not-ready=true:NO_SCHEDULE"] &&
      google_container_node_pool.this["control"].node_config[0].labels["node-restriction.kubernetes.io/agentarium-role"] == "control"
    )
    error_message = "control-pool settings mismatch."
  }

  assert {
    condition = (
      google_container_node_pool.this["system"].name == "system-pool" &&
      google_container_node_pool.this["system"].management[0].auto_repair == true &&
      google_container_node_pool.this["system"].node_count == 1 &&
      [for t in google_container_node_pool.this["system"].node_config[0].taint : "${t.key}=${t.value}:${t.effect}"] ==
      ["components.gke.io/gke-managed-components=true:NO_SCHEDULE"] &&
      google_container_node_pool.this["system"].node_config[0].labels["node-restriction.kubernetes.io/agentarium-role"] == "system"
    )
    error_message = "system-pool settings mismatch."
  }

  assert {
    condition = toset([for m in google_project_iam_member.nodes : m.role]) == toset([
      "roles/container.defaultNodeServiceAccount",
      "roles/artifactregistry.reader",
    ])
    error_message = "node service account roles mismatch."
  }
}

run "placeholder_lock_rejected" {
  command = plan

  variables {
    lock = jsondecode(file("../../../../deploy/gcp/environment.lock.example.json"))
  }

  expect_failures = [var.lock]
}

run "env_mismatch_rejected" {
  command = plan

  variables {
    env = "regression"
  }

  expect_failures = [var.lock]
}

run "legacy_datapath_rejected" {
  command = plan

  variables {
    lock = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")), {
      project = { id = "example-prod-123", location = "us-central1" }
      gke = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).gke, {
        kubernetes_minor  = "1.33"
        datapath_provider = "LEGACY_DATAPATH"
      })
    })
  }

  expect_failures = [var.lock]
}

run "gateway_ip_outside_services_rejected" {
  command = plan

  variables {
    lock = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")), {
      project = { id = "example-prod-123", location = "us-central1" }
      gke = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).gke, {
        kubernetes_minor = "1.33"
      })
      network = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).network, {
        gateway_cluster_ip = "10.31.0.10"
      })
    })
  }

  expect_failures = [var.lock]
}

run "public_endpoint_without_authorized_networks_rejected" {
  command = plan

  variables {
    lock = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")), {
      project = { id = "example-prod-123", location = "us-central1" }
      gke = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).gke, {
        kubernetes_minor = "1.33"
        control_plane = {
          dns_endpoint_allow_external_traffic = true
          private_endpoint_only               = false
          master_global_access                = false
          authorized_networks                 = []
        }
      })
    })
  }

  expect_failures = [var.lock]
}

run "open_authorized_network_rejected" {
  command = plan

  variables {
    lock = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")), {
      project = { id = "example-prod-123", location = "us-central1" }
      gke = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).gke, {
        kubernetes_minor = "1.33"
        control_plane = {
          dns_endpoint_allow_external_traffic = false
          private_endpoint_only               = false
          master_global_access                = false
          authorized_networks                 = [{ cidr_block = "0.0.0.0/0", display_name = "anywhere" }]
        }
      })
    })
  }

  expect_failures = [var.lock]
}

run "system_pool_start_taint_rejected" {
  command = plan

  variables {
    lock = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")), {
      project = { id = "example-prod-123", location = "us-central1" }
      gke = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).gke, {
        kubernetes_minor = "1.33"
      })
      node_pools = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).node_pools, {
        system = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).node_pools.system, {
          taints = ["components.gke.io/gke-managed-components=true:NoSchedule", "agentarium.io/observe-not-ready=true:NoSchedule"]
        })
      })
    })
  }

  expect_failures = [var.lock]
}

run "gateway_ip_on_kube_dns_rejected" {
  command = plan

  variables {
    lock = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")), {
      project = { id = "example-prod-123", location = "us-central1" }
      gke = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).gke, {
        kubernetes_minor = "1.33"
      })
      network = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).network, {
        gateway_cluster_ip = "10.30.0.10"
      })
    })
  }

  expect_failures = [var.lock]
}
