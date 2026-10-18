# Offline plan tests against a mocked provider; no GCP API is called.
mock_provider "google" {}

variables {
  env        = "prod"
  region     = "us-central1"
  network_id = "projects/example-prod-123/global/networks/agentarium-prod"
  lock = {
    project = { id = "example-prod-123" }
    storage = {
      evidence_bucket               = "example-prod-evidence"
      summary_bucket                = "example-prod-summary"
      bundle_bucket                 = "example-prod-bundles"
      decision_input_exports_bucket = "example-prod-decision-input-exports"
      regression_requests_bucket    = "example-prod-regression-requests"
      regression_reports_bucket     = "example-prod-regression-reports"
      discovery_bucket              = "example-prod-discovery"
      cloudsql_instance             = "example-prod-123:us-central1:agentarium-prod"
    }
    keys = {
      bundle_signing_key   = "projects/example-prod-123/locations/us-central1/keyRings/agentarium/cryptoKeys/bundle-signing"
      bundle_key_id        = "prod-v1"
      manifest_signing_key = "projects/example-prod-123/locations/us-central1/keyRings/agentarium/cryptoKeys/manifest-signing"
    }
    cloudsql = {
      database_version             = "POSTGRES_17"
      edition                      = "ENTERPRISE"
      tier                         = "db-custom-2-7680"
      availability_type            = "ZONAL"
      private_service_access_range = "10.40.0.0/20"
    }
    pki = {
      ca_pool                  = "agentarium-prod"
      certificate_authority_id = "agentarium-prod-root"
      ca_common_name           = "Agentarium prod root"
      ca_organization          = "Agentarium"
      ca_lifetime              = "315360000s"
      ca_key_algorithm         = "EC_P256_SHA256"
    }
  }
}

run "prod_plans" {
  command = plan

  assert {
    condition     = length(google_storage_bucket.this) == 7
    error_message = "prod must create all seven buckets."
  }

  assert {
    condition = (
      length(google_storage_bucket.this["discovery"].retention_policy) == 0 &&
      length(google_storage_bucket.this["discovery"].lifecycle_rule) == 0
    )
    error_message = "discovery bucket must have no retention and no lifecycle delete."
  }

  assert {
    condition = (
      google_artifact_registry_repository.agentarium.repository_id == "agentarium" &&
      google_artifact_registry_repository.agentarium.format == "DOCKER" &&
      google_artifact_registry_repository.agentarium.location == "us-central1" &&
      google_artifact_registry_repository.agentarium.docker_config[0].immutable_tags == true
    )
    error_message = "artifact registry repository mismatch."
  }

  assert {
    condition = (
      google_storage_bucket.this["evidence"].retention_policy[0].retention_period == "2592000" &&
      google_storage_bucket.this["evidence"].retention_policy[0].is_locked == false &&
      google_storage_bucket.this["evidence"].soft_delete_policy[0].retention_duration_seconds == 604800 &&
      one(flatten([for r in google_storage_bucket.this["evidence"].lifecycle_rule : [for c in r.condition : c.age]])) == 31
    )
    error_message = "evidence bucket retention/soft delete/lifecycle mismatch."
  }

  assert {
    condition     = google_storage_bucket.this["summary"].retention_policy[0].retention_period == "7776000"
    error_message = "summary bucket must keep 90 days."
  }

  assert {
    condition = alltrue([
      for k in ["decision_input_exports", "regression_requests", "regression_reports"] :
      google_storage_bucket.this[k].retention_policy[0].retention_period == "2592000" &&
      google_storage_bucket.this[k].soft_delete_policy[0].retention_duration_seconds == 604800
    ])
    error_message = "30-day retention and soft delete buckets mismatch."
  }

  assert {
    condition = alltrue([
      for b in google_storage_bucket.this :
      b.uniform_bucket_level_access && b.public_access_prevention == "enforced" && !b.force_destroy
    ])
    error_message = "bucket access settings mismatch."
  }

  assert {
    condition = (
      google_sql_database_instance.this.name == "agentarium-prod" &&
      google_sql_database_instance.this.settings[0].ip_configuration[0].ipv4_enabled == false &&
      google_sql_database_instance.this.settings[0].ip_configuration[0].private_network == var.network_id &&
      google_sql_database_instance.this.settings[0].connector_enforcement == "REQUIRED" &&
      google_sql_database_instance.this.settings[0].backup_configuration[0].enabled &&
      google_sql_database_instance.this.settings[0].backup_configuration[0].point_in_time_recovery_enabled &&
      contains([for f in google_sql_database_instance.this.settings[0].database_flags : "${f.name}=${f.value}"], "cloudsql.iam_authentication=on")
    )
    error_message = "Cloud SQL settings mismatch."
  }

  assert {
    condition = (
      google_privateca_ca_pool.this.tier == "DEVOPS" &&
      google_privateca_ca_pool.this.issuance_policy[0].maximum_lifetime == "86400s" &&
      google_privateca_certificate_authority.root.type == "SELF_SIGNED" &&
      google_privateca_certificate_authority.root.deletion_protection
    )
    error_message = "CA Service settings mismatch."
  }

  assert {
    condition = (
      [for k in google_privateca_ca_pool.this.issuance_policy[0].allowed_key_types : k.elliptic_curve[0].signature_algorithm] == ["ECDSA_P256"] &&
      alltrue([for k in google_privateca_ca_pool.this.issuance_policy[0].allowed_key_types : length(k.rsa) == 0]) &&
      google_privateca_ca_pool.this.issuance_policy[0].allowed_issuance_modes[0].allow_config_based_issuance &&
      !google_privateca_ca_pool.this.issuance_policy[0].allowed_issuance_modes[0].allow_csr_based_issuance &&
      google_privateca_ca_pool.this.issuance_policy[0].identity_constraints[0].allow_subject_alt_names_passthrough &&
      !google_privateca_ca_pool.this.issuance_policy[0].identity_constraints[0].allow_subject_passthrough
    )
    error_message = "CA pool must accept only ECDSA P-256 keys, config-based issuance and no subject passthrough."
  }

  assert {
    condition = (
      google_privateca_ca_pool.this.issuance_policy[0].baseline_values[0].ca_options[0].non_ca == true &&
      google_privateca_ca_pool.this.issuance_policy[0].baseline_values[0].ca_options[0].is_ca != true &&
      google_privateca_ca_pool.this.issuance_policy[0].baseline_values[0].ca_options[0].max_issuer_path_length == null &&
      [for k, v in google_privateca_ca_pool.this.issuance_policy[0].baseline_values[0].key_usage[0].base_key_usage[0] : k if v == true] == ["digital_signature"] &&
      [for k, v in google_privateca_ca_pool.this.issuance_policy[0].baseline_values[0].key_usage[0].extended_key_usage[0] : k if v == true] == ["client_auth", "server_auth"] &&
      length(google_privateca_ca_pool.this.issuance_policy[0].baseline_values[0].key_usage[0].unknown_extended_key_usages) == 0 &&
      length(google_privateca_ca_pool.this.issuance_policy[0].baseline_values[0].additional_extensions) == 0
    )
    error_message = "CA pool baseline must force non-CA leaves with digitalSignature and serverAuth+clientAuth only."
  }

  # The CEL regex is RE2, as is Terraform regex(); evaluate it against the SAN grammar.
  assert {
    condition = alltrue([
      for san in [
        "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway",
        "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer",
        "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/0f8fad5b-d9cb-469f-a165-70867728950e",
        "spiffe://agentarium.internal/node-bridge/7c9e6679-7425-40de-944b-e07fc1f90ae7/b9f4c1a2-3d5e-4f60-8a71-92b3c4d5e6f7",
      ] : can(regex(regex("matches\\('([^']*)'\\)", google_privateca_ca_pool.this.issuance_policy[0].identity_constraints[0].cel_expression[0].expression)[0], san))
    ])
    error_message = "CEL SAN pattern must accept the three TASK-03 SAN forms."
  }

  assert {
    condition = !anytrue([
      for san in [
        "spiffe://agentarium.internal/",
        "spiffe://agentarium.internal/../ns/agent-control/sa/policy-gateway",
        "spiffe://agentarium.internal/ns/agent-control/sa/../../node-bridge/x",
        "spiffe://agentarium.internal//ns/agent-control/sa/policy-gateway",
        "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway/",
        "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway?x=1",
        "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway#x",
        "spiffe://agentarium.internal/ns/agent-control/sa/Policy-Gateway",
        "spiffe://agentarium.internal/ns/agent-control/sa/policy%2dgateway",
        "SPIFFE://agentarium.internal/ns/agent-control/sa/policy-gateway",
        "spiffe://Agentarium.internal/ns/agent-control/sa/policy-gateway",
        "spiffe://agentariumXinternal/ns/agent-control/sa/policy-gateway",
        "spiffe://agentarium.internal.evil/ns/agent-control/sa/policy-gateway",
        "spiffe://user@agentarium.internal/ns/agent-control/sa/policy-gateway",
        "spiffe://agentarium.internal:443/ns/agent-control/sa/policy-gateway",
        "spiffe://agentarium.internal/ns/-bad/sa/policy-gateway",
        "spiffe://agentarium.internal/ns/agent-control/sa/policy.gateway",
        "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway/pod/0f8fad5b-d9cb-469f-a165-70867728950e",
        "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/0F8FAD5B-D9CB-469F-A165-70867728950E",
        "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/not-a-uid",
        "spiffe://agentarium.internal/node-bridge/7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "spiffe://agentarium.internal/node-bridge/7c9e6679-7425-40de-944b-e07fc1f90ae7/b9f4c1a2-3d5e-4f60-8a71-92b3c4d5e6f7/x",
        "spiffe://agentarium.internal/workload/0f8fad5b-d9cb-469f-a165-70867728950e",
        "xspiffe://agentarium.internal/ns/agent-control/sa/policy-gateway",
        "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway\n",
      ] : can(regex(regex("matches\\('([^']*)'\\)", google_privateca_ca_pool.this.issuance_policy[0].identity_constraints[0].cel_expression[0].expression)[0], san))
    ])
    error_message = "CEL SAN pattern must reject path tricks, case changes, other hosts and unknown forms."
  }

  assert {
    condition = (
      startswith(google_privateca_ca_pool.this.issuance_policy[0].identity_constraints[0].cel_expression[0].expression, "subject_alt_names.size() == 1 && subject_alt_names.all(san, san.type == URI && san.value.matches('^") &&
      !strcontains(google_privateca_ca_pool.this.issuance_policy[0].identity_constraints[0].cel_expression[0].expression, "startsWith") &&
      !strcontains(google_privateca_ca_pool.this.issuance_policy[0].identity_constraints[0].cel_expression[0].expression, "\\")
    )
    error_message = "CEL must require exactly one URI SAN matched by an anchored regex, with no backslash escapes."
  }

  assert {
    condition = (
      length(google_kms_key_ring.this) == 1 &&
      toset([for k in google_kms_crypto_key.signing : k.name]) == toset(["bundle-signing", "manifest-signing"]) &&
      alltrue([for k in google_kms_crypto_key.signing : k.purpose == "ASYMMETRIC_SIGN" && k.version_template[0].algorithm == "EC_SIGN_P256_SHA256"])
    )
    error_message = "KMS signing keys mismatch."
  }
}

run "regression_skips_prod_only_buckets" {
  command = plan

  variables {
    env = "regression"
    lock = merge(var.lock, {
      keys = merge(var.lock.keys, { bundle_key_id = "regression-v1" })
    })
  }

  assert {
    condition     = toset(keys(google_storage_bucket.this)) == toset(["evidence", "summary", "bundle"])
    error_message = "regression must create only evidence, summary and bundle buckets."
  }
}

run "regression_with_prod_key_id_rejected" {
  command = plan

  variables {
    env = "regression"
  }

  expect_failures = [var.lock]
}

run "placeholder_lock_rejected" {
  command = plan

  variables {
    lock = jsondecode(file("../../../../deploy/gcp/environment.lock.example.json"))
  }

  expect_failures = [var.lock]
}

run "foreign_project_sql_rejected" {
  command = plan

  variables {
    lock = merge(var.lock, {
      storage = merge(var.lock.storage, { cloudsql_instance = "other-project:us-central1:agentarium-prod" })
    })
  }

  expect_failures = [var.lock]
}

run "org_policy_soft_delete_zero" {
  command = plan

  variables {
    soft_delete_seconds = 0
  }

  assert {
    condition = alltrue([
      for k in ["evidence", "decision_input_exports", "regression_requests", "regression_reports"] :
      google_storage_bucket.this[k].soft_delete_policy[0].retention_duration_seconds == 0 &&
      google_storage_bucket.this[k].retention_policy[0].retention_period == "2592000"
    ])
    error_message = "soft delete 0 must keep the 30-day retention."
  }
}

run "soft_delete_below_minimum_rejected" {
  command = plan

  variables {
    soft_delete_seconds = 86400
  }

  expect_failures = [var.soft_delete_seconds]
}

run "certificate_templates_are_exact_profiles" {
  command = plan
  assert {
    condition = (
      !output.certificate_template_issuance_enabled &&
      toset(keys(google_privateca_certificate_template.workload)) == toset(["service", "client"]) &&
      alltrue([for profile, template in google_privateca_certificate_template.workload :
        template.name == "agentarium-prod-${profile}" && template.location == "us-central1" &&
        [for k, v in template.predefined_values[0].key_usage[0].base_key_usage[0] : k if v == true] == ["digital_signature"] &&
        toset([for k, v in template.predefined_values[0].key_usage[0].extended_key_usage[0] : k if v == true]) == toset(profile == "service" ? ["client_auth", "server_auth"] : ["client_auth"]) &&
        length(template.predefined_values[0].key_usage[0].unknown_extended_key_usages) == 0 &&
        length(template.predefined_values[0].ca_options) == 1 &&
        template.predefined_values[0].ca_options[0].is_ca == false &&
        template.predefined_values[0].ca_options[0].null_ca != true &&
        toset(template.passthrough_extensions[0].known_extensions) == toset(["CA_OPTIONS"]) &&
        length(template.passthrough_extensions[0].additional_extensions) == 0 &&
        template.identity_constraints[0].allow_subject_alt_names_passthrough &&
        !template.identity_constraints[0].allow_subject_passthrough &&
        startswith(template.identity_constraints[0].cel_expression[0].expression, "subject_alt_names.size() == 1 && subject_alt_names.all(san, san.type == URI && san.value.matches('^")
      ])
    )
    error_message = "Templates must enforce exact keyUsage, non-CA, one URI SAN and no extra request extensions."
  }
  assert {
    condition = alltrue([
      for profile, cases in {
        service = [
          { san = "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity", allowed = true },
          { san = "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender", allowed = true },
          { san = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/0f8fad5b-d9cb-469f-a165-70867728950e", allowed = false },
          { san = "spiffe://agentarium.internal/node-bridge/7c9e6679-7425-40de-944b-e07fc1f90ae7/b9f4c1a2-3d5e-4f60-8a71-92b3c4d5e6f7", allowed = false },
          { san = "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity?x=1", allowed = false },
        ],
        client = [
          { san = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/0f8fad5b-d9cb-469f-a165-70867728950e", allowed = true },
          { san = "spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner/pod/0f8fad5b-d9cb-469f-a165-70867728950e", allowed = true },
          { san = "spiffe://agentarium.internal/node-bridge/7c9e6679-7425-40de-944b-e07fc1f90ae7/b9f4c1a2-3d5e-4f60-8a71-92b3c4d5e6f7", allowed = true },
          { san = "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity", allowed = false },
          { san = "spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/0f8fad5b-d9cb-469f-a165-70867728950e", allowed = false },
          { san = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/0F8FAD5B-D9CB-469F-A165-70867728950E", allowed = false },
        ]
      } : alltrue([for c in cases : can(regex(regex("matches\\('([^']*)'\\)", google_privateca_certificate_template.workload[profile].identity_constraints[0].cel_expression[0].expression)[0], c.san)) == c.allowed])
    ])
    error_message = "Template SAN grammars must separate existing profiles without widening namespaces."
  }
}

# Mock apply records stage-one state only; it never contacts GCP.
run "certificate_template_stage_one" {
  command = apply
  assert {
    condition     = !output.certificate_template_issuance_enabled && length(google_privateca_ca_pool.this.issuance_policy[0].baseline_values[0].key_usage) == 1
    error_message = "Default stage must retain the old pool baseline until IAM read-back is verified."
  }
}
run "certificate_template_stage_two" {
  command = plan
  variables { certificate_template_issuance_enabled = true }
  assert {
    condition = (
      output.certificate_template_issuance_enabled &&
      length(google_privateca_ca_pool.this.issuance_policy[0].baseline_values) == 0 &&
      alltrue([for template in google_privateca_certificate_template.workload : template.predefined_values[0].ca_options[0].is_ca == false && template.predefined_values[0].ca_options[0].null_ca != true]) &&
      google_privateca_ca_pool.this.issuance_policy[0].maximum_lifetime == "86400s" &&
      google_privateca_ca_pool.this.tier == "DEVOPS" &&
      output.ca_pool_id == run.certificate_template_stage_one.ca_pool_id &&
      output.certificate_authority_id == run.certificate_template_stage_one.certificate_authority_id &&
      output.certificate_template_ids == run.certificate_template_stage_one.certificate_template_ids
    )
    error_message = "Stage two must only remove pool baseline overlap, preserving the CA/root/templates and strict common limits."
  }
}
run "completed_stage_requires_persisted_input" {
  command = plan
  assert {
    condition     = !output.certificate_template_issuance_enabled && length(google_privateca_ca_pool.this.issuance_policy[0].baseline_values[0].key_usage) == 1
    error_message = "Omitting the persisted stage-two input restores the conflicting baseline: output must expose this rollback."
  }
}

run "maximum_length_pool_keeps_valid_template_names" {
  command = plan
  variables {
    lock = merge(var.lock, { pki = merge(var.lock.pki, { ca_pool = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }) })
  }
  assert {
    condition = (
      google_privateca_ca_pool.this.name == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &&
      alltrue([for profile, template in google_privateca_certificate_template.workload :
      template.name == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-7d3e74a05d7db15b-${profile}" && can(regex("^[a-zA-Z0-9_-]{1,63}$", template.name))])
    )
    error_message = "A valid 63-character pool must retain its identity and derive bounded template IDs."
  }
}
