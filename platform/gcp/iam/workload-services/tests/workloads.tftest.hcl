mock_provider "google" {
  # Valid computed shapes for the mock apply below, not cloud IDs.
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/example-prod/serviceAccounts/mock-db@example-prod.iam.gserviceaccount.com"
      email = "mock-db@example-prod.iam.gserviceaccount.com"
    }
  }
}

variables {
  project_id        = "example-prod"
  project_number    = "123456789012"
  cloudsql_instance = "agentarium-prod"
  buckets = {
    evidence               = "example-evidence"
    bundle                 = "example-bundles"
    decision_input_exports = "example-decision-inputs"
    discovery              = "example-discovery"
    regression_requests    = "example-regression-requests"
    regression_reports     = "example-regression-reports"
  }
  keys = {
    manifest = "projects/example-prod/locations/us-central1/keyRings/audit/cryptoKeys/manifest"
    bundle   = "projects/example-prod/locations/us-central1/keyRings/policy/cryptoKeys/bundle"
  }
  settings = {
    oidc_client_secret          = "projects/example-prod/secrets/oidc"
    credential_secret_resources = ["projects/123456789012/secrets/receiver"]
  }
}

run "same_environment_permission_matrix_without_regression_input" {
  command = plan
  assert {
    condition = (
      google_service_account.database["audit-retention"].account_id == "audit-retention-db" &&
      google_service_account_iam_member.database_impersonation["audit-retention"].member ==
      "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-prod.svc.id.goog/subject/ns/agent-observe/sa/audit-retention" &&
      google_sql_user.database["audit-retention"].type == "CLOUD_IAM_SERVICE_ACCOUNT" &&
      output.services["audit-retention"].namespace == "agent-observe" &&
      !anytrue([for binding in values(google_storage_bucket_iam_member.workload) : binding.member == output.principals["audit-retention"]]) &&
      !anytrue([for binding in values(google_kms_crypto_key_iam_member.signing) : binding.member == output.principals["audit-retention"]]) &&
      google_kms_crypto_key_iam_member.verification.member != output.principals["audit-retention"] &&
      !anytrue([for binding in values(google_project_iam_member.application) : binding.member == output.principals["audit-retention"]]) &&
      !anytrue([for binding in values(google_secret_manager_secret_iam_member.broker) : binding.member == output.principals["audit-retention"]])
    )
    error_message = "The audit-retention KSA gets only its own DB identity: no bucket, KMS, secret or project grant (TASK-06 3.3)."
  }
  assert {
    condition = (
      google_sql_user.database["audit-verifier"].type == "CLOUD_IAM_SERVICE_ACCOUNT" &&
      google_service_account_iam_member.database_impersonation["audit-verifier"].member ==
      "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-prod.svc.id.goog/subject/ns/agent-observe/sa/audit-verifier"
    )
    error_message = "The audit-verifier KSA keeps its DB login for the audit_verifier role."
  }
  assert {
    condition = (
      length(google_service_account.database) == 21 && length(google_sql_user.database) == 21 &&
      length(google_service_account_iam_member.database_impersonation) == 21 &&
      length(google_project_iam_member.database) == 42 && length(google_project_iam_member.database_service_usage) == 21
    )
    error_message = "Exactly 21 remaining KSA DB identities must be added to the existing three contacts."
  }
  assert {
    condition = (
      alltrue([for name, sa in google_service_account.database :
        sa.account_id == "${name}-db" && !contains(["workload-identity", "audit-writer", "control-health", "discovery-snapshot", "node-readiness", "pod-watcher", "regression-runner", "decision-replay"], name)
      ])
    )
    error_message = "Contact identities must not be duplicated and no non-DB/cross-project identity may gain a production DB login."
  }
  assert {
    condition = (
      alltrue([for ksa, binding in google_service_account_iam_member.database_impersonation :
        binding.role == "roles/iam.workloadIdentityUser" && binding.member == output.principals[ksa] &&
        !strcontains(binding.member, "agent-exec") && !strcontains(binding.member, "principalSet")
      ])
    )
    error_message = "Only each exact production KSA may impersonate its own DB GSA."
  }
  assert {
    condition = (
      alltrue([for binding in google_project_iam_member.database :
        contains(["roles/cloudsql.client", "roles/cloudsql.instanceUser"], binding.role) &&
        binding.condition[0].expression == "resource.name == 'projects/example-prod/instances/agentarium-prod'"
      ])
    )
    error_message = "Database IAM must be scoped to the installed instance."
  }
  assert {
    condition = (
      (
        toset(google_project_iam_custom_role.workload["audit_export"].permissions) == toset(["storage.objects.create", "storage.objects.get"]) &&
        toset(google_project_iam_custom_role.workload["manifest_public_key"].permissions) == toset(["cloudkms.cryptoKeyVersions.viewPublicKey"]) &&
        toset(google_project_iam_custom_role.workload["model_predict"].permissions) == toset(["aiplatform.endpoints.predict"]) &&
        toset(google_project_iam_custom_role.workload["cluster_get"].permissions) == toset(["container.clusters.get"])
      )
    )
    error_message = "Custom roles must not broaden into delete, overwrite, key signing, model admin, or cluster mutation."
  }
  assert {
    condition = (
      length(google_storage_bucket_iam_member.workload) == 13 &&
      !contains(keys(google_project_iam_custom_role.workload), "discovery_snapshot") &&
      alltrue([for b in google_storage_bucket_iam_member.workload : b.bucket != var.buckets.discovery]) &&
      alltrue([for b in google_storage_bucket_iam_member.workload :
        startswith(b.member, "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-prod.svc.id.goog/subject/ns/") &&
        !strcontains(b.member, "agent-exec") && !strcontains(b.member, "audit-writer")
      ])
    )
    error_message = "Bucket access must use exact production KSA principals; writer and execution workloads receive none."
  }
  assert {
    condition = (
      length(google_kms_crypto_key_iam_member.signing) == 2 &&
      google_kms_crypto_key_iam_member.signing["audit-exporter"].crypto_key_id == var.keys.manifest &&
      google_kms_crypto_key_iam_member.signing["releaser"].crypto_key_id == var.keys.bundle &&
      google_kms_crypto_key_iam_member.verification.role == "projects/example-prod/roles/agentariumManifestPublicKey" &&
      google_kms_crypto_key_iam_member.verification.member == output.principals["audit-verifier"]
    )
    error_message = "Signing and verification principals/keys must stay separate."
  }
  assert {
    condition = (
      length(google_project_iam_member.application) == 2 &&
      google_project_iam_member.application["model-adapter"].member == output.principals["model-adapter"] &&
      google_project_iam_member.application["model-adapter"].role == "projects/example-prod/roles/agentariumModelPredict" &&
      google_project_iam_member.application["drift-probe"].role == "projects/example-prod/roles/agentariumClusterGet"
    )
    error_message = "Project-level application grants are only model prediction and cluster get."
  }
  assert {
    condition = (
      length(google_secret_manager_secret_iam_member.broker) == 1 &&
      google_secret_manager_secret_iam_member.identity_oidc.member == output.principals["workload-identity"] &&
      google_secret_manager_secret_iam_member.identity_oidc.secret_id == "oidc" &&
      alltrue([for b in google_secret_manager_secret_iam_member.broker : b.project == "example-prod" && b.secret_id == "receiver" && b.member == output.principals["credential-broker"] && b.role == "roles/secretmanager.secretAccessor"])
    )
    error_message = "Secrets must be individual resource bindings for the intended identity/broker only."
  }
  assert {
    condition = alltrue([for member in concat(
      [for b in google_service_account_iam_member.database_impersonation : b.member],
      [for b in google_storage_bucket_iam_member.workload : b.member],
      [for b in google_kms_crypto_key_iam_member.signing : b.member],
      [google_kms_crypto_key_iam_member.verification.member],
      [google_secret_manager_secret_iam_member.identity_oidc.member],
      [for b in google_secret_manager_secret_iam_member.broker : b.member],
      [for b in google_project_iam_member.application : b.member]
    ) : startswith(member, "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-prod.svc.id.goog/subject/ns/")])
    error_message = "Every workload principal must belong to this environment; issue #97 cross-environment grants are excluded."
  }
}

run "oidc_client_secret_created_without_version" {
  command = plan
  assert {
    condition = (
      google_secret_manager_secret.identity_oidc.secret_id == "oidc" &&
      google_secret_manager_secret.identity_oidc.project == "example-prod" &&
      google_secret_manager_secret.identity_oidc.deletion_protection &&
      google_secret_manager_secret.identity_oidc.labels["agentarium-secret"] == "identity-oidc-client" &&
      length(google_secret_manager_secret.identity_oidc.replication[0].auto) == 1 &&
      google_secret_manager_secret_iam_member.identity_oidc.secret_id == "oidc" &&
      google_secret_manager_secret_iam_member.identity_oidc.role == "roles/secretmanager.secretAccessor" &&
      google_secret_manager_secret_iam_member.identity_oidc.member == output.principals["workload-identity"]
    )
    error_message = "Terraform must create the lock-named OIDC client secret, auto-replicated and deletion-protected, and grant only workload-identity accessor on it."
  }
}

run "receiver_api_key_secret_created_with_write_only_first_version" {
  command = plan
  variables { receiver_api_key_secret = "projects/123456789012/secrets/receiver" }
  assert {
    condition = (
      length(google_secret_manager_secret.receiver_api_key) == 1 &&
      google_secret_manager_secret.receiver_api_key[0].secret_id == "receiver" &&
      google_secret_manager_secret.receiver_api_key[0].project == "example-prod" &&
      google_secret_manager_secret.receiver_api_key[0].deletion_protection &&
      length(google_secret_manager_secret.receiver_api_key[0].replication[0].auto) == 1 &&
      google_secret_manager_secret.receiver_api_key[0].labels["agentarium-secret"] == "receiver-api-key"
    )
    error_message = "Terraform must create the lock-named receiver API key secret, auto-replicated and deletion-protected."
  }
  assert {
    condition = (
      length(google_secret_manager_secret_version.receiver_api_key) == 1 &&
      google_secret_manager_secret_version.receiver_api_key[0].secret_data == null &&
      google_secret_manager_secret_version.receiver_api_key[0].secret_data_wo == null &&
      google_secret_manager_secret_version.receiver_api_key[0].secret_data_wo_version == "1"
    )
    error_message = "The receiver API key version must be written only through secret_data_wo (version 1), never secret_data."
  }
}
run "receiver_api_key_grants_follow_created_secret" {
  # Mock apply: the broker grant on the same secret depends on the created
  # secret, so one apply works right after the Secret Manager API is enabled.
  command = apply
  # Own state: later plan-only runs drop the input, and prevent_destroy must
  # not see that as a destroy of the created secret.
  state_key = "receiver_apply"
  variables { receiver_api_key_secret = "projects/123456789012/secrets/receiver" }
  assert {
    condition = (
      google_secret_manager_secret_version.receiver_api_key[0].secret == google_secret_manager_secret.receiver_api_key[0].id &&
      google_secret_manager_secret_iam_member.broker["projects/123456789012/secrets/receiver"].secret_id == google_secret_manager_secret.receiver_api_key[0].secret_id
    )
    error_message = "The receiver key version and broker grant must target the created secret."
  }
  assert {
    condition = (
      length(google_secret_manager_secret_iam_member.receiver_api_key) == 1 &&
      google_secret_manager_secret_iam_member.receiver_api_key[0].secret_id == google_secret_manager_secret.receiver_api_key[0].secret_id &&
      google_secret_manager_secret_iam_member.receiver_api_key[0].role == "roles/secretmanager.secretAccessor" &&
      google_secret_manager_secret_iam_member.receiver_api_key[0].member ==
      "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-prod.svc.id.goog/subject/ns/agent-targets/sa/receiver" &&
      length(google_secret_manager_secret_iam_member.broker) == 1
    )
    error_message = "Only the receiver KSA reads the created receiver API key, and only that one secret (TASK-08 #169)."
  }
}
run "no_receiver_secret_without_lock_input" {
  command = plan
  assert {
    condition = (
      length(google_secret_manager_secret.receiver_api_key) == 0 &&
      length(google_secret_manager_secret_version.receiver_api_key) == 0 &&
      length(google_secret_manager_secret_iam_member.receiver_api_key) == 0
    )
    error_message = "Absent lock receiver.api_key_secret must not create a guessed secret."
  }
}
run "reject_receiver_secret_outside_broker_bindings" {
  command = plan
  variables { receiver_api_key_secret = "projects/123456789012/secrets/other" }
  expect_failures = [var.receiver_api_key_secret]
}
run "reject_receiver_secret_by_project_id" {
  command = plan
  variables { receiver_api_key_secret = "projects/example-prod/secrets/receiver" }
  expect_failures = [var.receiver_api_key_secret]
}

run "reject_foreign_secret" {
  command = plan
  variables {
    settings = {
      oidc_client_secret          = "projects/other-project/secrets/oidc"
      credential_secret_resources = ["projects/example-prod/secrets/receiver"]
    }
  }
  expect_failures = [var.settings]
}
run "reject_oidc_secret_alias_in_broker" {
  command = plan
  variables {
    settings = {
      oidc_client_secret          = "projects/example-prod/secrets/oidc"
      credential_secret_resources = ["projects/123456789012/secrets/oidc"]
    }
  }
  expect_failures = [var.settings]
}
run "reject_duplicate_secret_aliases" {
  command = plan
  variables {
    settings = {
      oidc_client_secret          = "projects/example-prod/secrets/oidc"
      credential_secret_resources = ["projects/example-prod/secrets/receiver", "projects/123456789012/secrets/receiver"]
    }
  }
  expect_failures = [var.settings]
}
run "reject_bucket_aliasing" {
  command = plan
  variables {
    buckets = {
      evidence               = "example-evidence"
      bundle                 = "example-evidence"
      decision_input_exports = "example-decision-inputs"
      discovery              = "example-discovery"
      regression_requests    = "example-regression-requests"
      regression_reports     = "example-regression-reports"
    }
  }
  expect_failures = [var.buckets]
}
run "reject_signing_key_aliasing" {
  command = plan
  variables {
    keys = {
      manifest = "projects/example-prod/locations/us-central1/keyRings/policy/cryptoKeys/shared"
      bundle   = "projects/example-prod/locations/us-central1/keyRings/policy/cryptoKeys/shared"
    }
  }
  expect_failures = [var.keys]
}

run "no_cross_environment_grant_without_regression_input" {
  command = plan
  assert {
    condition     = length(google_storage_bucket_iam_member.cross_env) == 0 && length(google_kms_crypto_key_iam_member.cross_env_public_key) == 0 && length(output.cross_env_grants) == 0
    error_message = "Without a regression environment no cross-environment grant may exist."
  }
}

run "exactly_the_four_cross_environment_grants" {
  command = plan
  variables {
    regression_environment = { project_id = "example-regression", project_number = "222222222222" }
  }
  assert {
    # The same fixture is CrossEnvAllowlist's expected output in
    # platform/gcp/iam/checks, so iamcheck exempts exactly these bindings.
    condition     = output.cross_env_grants == jsondecode(file("../checks/testdata/cross_env_expected.json"))
    error_message = "Cross-environment grants must equal the iamcheck allowlist fixture (TASK-06 3.3, #97)."
  }
  assert {
    condition = (
      length(google_storage_bucket_iam_member.cross_env) == 3 && length(google_kms_crypto_key_iam_member.cross_env_public_key) == 1 &&
      alltrue([for b in google_storage_bucket_iam_member.cross_env : strcontains(b.member, "example-regression.svc.id.goog")]) &&
      !anytrue([for b in google_storage_bucket_iam_member.workload : strcontains(b.member, "example-regression")]) &&
      !anytrue([for b in google_kms_crypto_key_iam_member.signing : strcontains(b.member, "example-regression")]) &&
      !strcontains(google_kms_crypto_key_iam_member.verification.member, "example-regression") &&
      !anytrue([for b in google_project_iam_member.application : strcontains(b.member, "example-regression")]) &&
      !anytrue([for b in google_secret_manager_secret_iam_member.broker : strcontains(b.member, "example-regression")]) &&
      !strcontains(google_secret_manager_secret_iam_member.identity_oidc.member, "example-regression") &&
      !anytrue([for b in google_service_account_iam_member.database_impersonation : strcontains(b.member, "example-regression")])
    )
    # DB GSA members are computed at plan; they are production GSAs by construction.
    error_message = "Only the four cross-environment bindings may reference the regression pool; no DB impersonation, Secret, project or other bucket/key grant."
  }
  assert {
    condition     = google_project_iam_custom_role.workload["manifest_public_key"].permissions == toset(["cloudkms.cryptoKeyVersions.viewPublicKey"])
    error_message = "agentariumManifestPublicKey must contain only viewPublicKey."
  }
}

run "regression_environment_must_differ" {
  command = plan
  variables {
    regression_environment = { project_id = "example-prod", project_number = "222222222222" }
  }
  expect_failures = [var.regression_environment]
}
