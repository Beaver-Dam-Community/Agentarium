# Mocked plans only. This file never contacts a GCP backend or creates nodes.
mock_provider "google" {}

variables {
  env = "prod"
  lock = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")), {
    project = { id = "example-prod-123", location = "us-central1-a" }
    gke     = merge(jsondecode(file("../../../../deploy/gcp/environment.lock.example.json")).gke, { kubernetes_minor = "1.33" })
  })
}

run "legacy_lock_preserves_disks" {
  command = plan
  variables {
    lock = merge(var.lock, {
      node_pools = merge(var.lock.node_pools, {
        for name in ["exec", "control", "system"] : name => {
          for key, value in var.lock.node_pools[name] : key => value if !contains(["disk_size_gb", "disk_type"], key)
        }
      })
    })
  }
  assert {
    condition     = alltrue([for pool in google_container_node_pool.this : pool.node_config[0].disk_size_gb == 100 && pool.node_config[0].disk_type == "pd-balanced"])
    error_message = "Existing locks must retain the prior 100GB pd-balanced behavior."
  }
  assert {
    condition     = alltrue([for pool in output.platform_manifest.node_pool : pool.disk_size_gb == 100 && pool.disk_type == "pd-balanced"])
    error_message = "The platform manifest must include the legacy disk settings."
  }
}

run "explicit_per_pool_disks" {
  command = plan
  variables {
    lock = merge(var.lock, {
      node_pools = merge(var.lock.node_pools, {
        exec    = merge(var.lock.node_pools.exec, { disk_size_gb = 50, disk_type = "pd-balanced" })
        control = merge(var.lock.node_pools.control, { disk_size_gb = 50, disk_type = "pd-standard" })
        system  = merge(var.lock.node_pools.system, { disk_size_gb = 30, disk_type = "pd-balanced" })
      })
    })
  }
  assert {
    condition = (google_container_node_pool.this["exec"].node_config[0].disk_size_gb == 50 &&
      google_container_node_pool.this["control"].node_config[0].disk_size_gb == 50 &&
      google_container_node_pool.this["system"].node_config[0].disk_size_gb == 30 &&
    google_container_node_pool.this["control"].node_config[0].disk_type == "pd-standard")
    error_message = "Explicit per-pool disk inputs were not passed to the provider."
  }
  assert {
    condition = (output.platform_manifest.node_pool["exec-pool"].disk_size_gb == 50 &&
      output.platform_manifest.node_pool["exec-pool"].disk_type == "pd-balanced" &&
      output.platform_manifest.node_pool["control-pool"].disk_size_gb == 50 &&
      output.platform_manifest.node_pool["control-pool"].disk_type == "pd-standard" &&
      output.platform_manifest.node_pool["system-pool"].disk_size_gb == 30 &&
    output.platform_manifest.node_pool["system-pool"].disk_type == "pd-balanced")
    error_message = "The platform manifest must include each provider-planned disk size and type."
  }
}

run "too_small_rejected" {
  command = plan
  variables {
    lock = merge(var.lock, { node_pools = merge(var.lock.node_pools, {
      exec = merge(var.lock.node_pools.exec, { disk_size_gb = 9 })
    }) })
  }
  expect_failures = [var.lock]
}

run "fractional_rejected" {
  command = plan
  variables {
    lock = merge(var.lock, { node_pools = merge(var.lock.node_pools, {
      control = merge(var.lock.node_pools.control, { disk_size_gb = 50.5 })
    }) })
  }
  expect_failures = [var.lock]
}

run "unknown_type_rejected" {
  command = plan
  variables {
    lock = merge(var.lock, { node_pools = merge(var.lock.node_pools, {
      system = merge(var.lock.node_pools.system, { disk_type = "invented-disk" })
    }) })
  }
  expect_failures = [var.lock]
}
