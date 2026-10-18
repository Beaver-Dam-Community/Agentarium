mock_provider "google" {
  # Valid computed shapes for downstream provider validation, not cloud IDs.
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/example-prod/serviceAccounts/mock-db@example-prod.iam.gserviceaccount.com"
      email = "mock-db@example-prod.iam.gserviceaccount.com"
    }
  }
}
mock_provider "google-beta" {}

# Keep these wiring tests independent of GKE/SQL provisioning. Mock tests in
# modules/platform and modules/shared-resources cover their own configurations.
override_module {
  target = module.platform
  outputs = {
    project_id             = "example-prod"
    project_number         = "123456789012"
    region                 = "us-central1"
    network_id             = "projects/example-prod/global/networks/example"
    workload_pool          = "example-prod.svc.id.goog"
    location               = "us-central1-a"
    cluster_name           = "agentarium-prod"
    control_plane_endpoint = "192.0.2.1"
    gateway_cluster_ip     = "10.30.0.20"
    subnetwork_id          = "projects/example-prod/regions/us-central1/subnetworks/example"
    node_service_account   = "nodes@example-prod.iam.gserviceaccount.com"
    platform_manifest      = {}
  }
}
override_module {
  target = module.shared_resources
  outputs = {
    cloudsql_connection_name = "example-prod:us-central1:agentarium-prod"
    cloudsql_private_ip      = "192.0.2.2"
    ca_pool_id               = "projects/example-prod/locations/us-central1/caPools/example"
    certificate_template_ids = {
      service = "projects/example-prod/locations/us-central1/certificateTemplates/example-service"
      client  = "projects/example-prod/locations/us-central1/certificateTemplates/example-client"
    }
    certificate_authority_id = "example-root"
    evidence_bucket          = "example-evidence"
    bundle_bucket            = "example-bundles"
    bundle_key_id            = "prod-v1"
    buckets = {
      evidence               = "example-evidence"
      bundle                 = "example-bundles"
      summary                = "example-summary"
      decision_input_exports = "example-decision-inputs"
      discovery              = "example-discovery"
      regression_requests    = "example-regression-requests"
      regression_reports     = "example-regression-reports"
    }
    kms_key_ids = {
      manifest = "projects/example-prod/locations/us-central1/keyRings/audit/cryptoKeys/manifest"
      bundle   = "projects/example-prod/locations/us-central1/keyRings/policy/cryptoKeys/bundle"
    }
  }
}

run "no_implicit_full_workload_grants" {
  command = plan
  variables { lock_path = "tests/fixtures/without-iam.json" }
  assert {
    condition     = !output.full_workload_iam_configured && length(module.workload_services) == 0 && length(output.workload_services) == 0
    error_message = "Missing IAM install references must be visible and must not create guessed grants."
  }
  assert {
    condition = (
      output.discovery_principals == {
        discovery          = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-prod.svc.id.goog/subject/ns/agent-observe/sa/discovery"
        discovery-snapshot = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-prod.svc.id.goog/subject/ns/agent-observe/sa/discovery-snapshot"
      }
    )
    error_message = "Discovery IAM must remain configured without unrelated secret references."
  }
  assert {
    condition     = !output.db_installer.workload_binding_enabled && length(module.db_installer.installer) > 0
    error_message = "The installer KSA binding must be off unless the install window explicitly enables it."
  }
}
run "same_environment_inputs_without_regression_connect" {
  # Mock apply resolves computed IAM user outputs; no cloud API is called.
  command = apply
  variables { lock_path = "tests/fixtures/with-iam.json" }
  assert {
    condition     = output.full_workload_iam_configured && length(module.workload_services) == 1 && length(output.workload_services) == 21 && length(output.contact_services) == 3
    error_message = "Configured production IAM must include 21 workloads plus three separate contacts."
  }
  assert {
    condition = (
      module.contact_services.claim_key_version != null &&
      module.workload_services[0].receiver_api_key_version != null
    )
    error_message = "The lock's claim key and receiver.api_key_secret must make Terraform create both secrets and their first version."
  }
  assert {
    condition     = length(output.cross_env_grants) == 0
    error_message = "Without lock.iam.regression no cross-environment grant may exist."
  }
}

run "regression_input_creates_exactly_four_cross_environment_grants" {
  command = apply
  # Own state: this lock has no receiver section, and prevent_destroy must not
  # see that as a destroy of the receiver secret created by the run above.
  state_key = "regression"
  variables { lock_path = "tests/fixtures/with-iam-regression.json" }
  assert {
    condition     = length(output.cross_env_grants) == 4 && alltrue([for g in output.cross_env_grants : strcontains(g.member, "/example-regression.svc.id.goog/subject/ns/agent-release/sa/")])
    error_message = "lock.iam.regression must produce exactly the four TASK-06 3.3 grants."
  }
}

run "installer_window_binding_only_when_enabled" {
  command = plan
  # Own state: without-iam.json has no receiver section, so planning it against
  # the shared state would try to destroy the prevent_destroy receiver secret.
  state_key = "installer_window"
  variables {
    lock_path                     = "tests/fixtures/without-iam.json"
    db_installer_workload_binding = true
  }
  assert {
    condition     = output.db_installer.workload_binding_enabled && output.db_installer.ksa == "db-installer" && output.db_installer.namespace == "agent-control"
    error_message = "Enabling the install window must bind only agent-control/db-installer."
  }
}
