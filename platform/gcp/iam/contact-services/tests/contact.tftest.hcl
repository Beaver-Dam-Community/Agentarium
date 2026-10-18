mock_provider "google" {
  # Valid computed shapes for the mock apply below, not cloud IDs.
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/example-project/serviceAccounts/mock-db@example-project.iam.gserviceaccount.com"
      email = "mock-db@example-project.iam.gserviceaccount.com"
    }
  }
}
variables {
  project_id        = "example-project"
  project_number    = "123456789012"
  cloudsql_instance = "agentarium-example"
  ca_pool_id        = "projects/example-project/locations/us-central1/caPools/example"
  claim_key_secret  = "projects/123456789012/secrets/identity-claim-key"
  certificate_template_ids = {
    service = "projects/example-project/locations/us-central1/certificateTemplates/example-service"
    client  = "projects/example-project/locations/us-central1/certificateTemplates/example-client"
  }
}
run "only_contact_identities" {
  command = plan
  assert {
    condition     = toset(keys(google_project_service.identity_apis)) == toset(["iam.googleapis.com", "iamcredentials.googleapis.com", "secretmanager.googleapis.com"]) && alltrue([for api in google_project_service.identity_apis : !api.disable_on_destroy])
    error_message = "GSA creation and Proxy impersonation require IAM and IAM Credentials APIs; the claim key needs Secret Manager."
  }
  assert {
    condition     = length(google_service_account.database) == 3 && length(google_sql_user.database) == 3
    error_message = "M1-1 must create exactly three DB identities."
  }
  assert {
    condition     = length(google_project_iam_member.database) == 6
    error_message = "Only client+instanceUser for each contact GSA are allowed."
  }
  assert {
    condition     = alltrue([for b in google_service_account_iam_member.database_impersonation : !strcontains(b.member, "agent-exec") && !strcontains(b.member, "principalSet") && b.role == "roles/iam.workloadIdentityUser"])
    error_message = "Impersonation must bind exact non-execution principals."
  }
  assert {
    condition     = length(google_project_iam_member.database_service_usage) == 3 && alltrue([for b in google_project_iam_member.database_service_usage : b.role == "roles/serviceusage.serviceUsageConsumer"])
    error_message = "Proxy impersonation requires service usage on only the three DB GSAs."
  }
  assert {
    condition     = google_privateca_ca_pool_iam_member.identity_issuer.member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-project.svc.id.goog/subject/ns/agent-control/sa/workload-identity"
    error_message = "Only the identity KSA may request CAS certificates."
  }
}

run "claim_key_only_identity_principal" {
  command = plan
  assert {
    condition = (
      google_secret_manager_secret_iam_member.identity_claim_key.secret_id == "identity-claim-key" &&
      google_secret_manager_secret_iam_member.identity_claim_key.role == "roles/secretmanager.secretAccessor" &&
      google_secret_manager_secret_iam_member.identity_claim_key.member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-project.svc.id.goog/subject/ns/agent-control/sa/workload-identity"
    )
    error_message = "Only the identity KSA direct principal may read the one claim key secret (#101)."
  }
}

run "claim_key_secret_created_with_write_only_first_version" {
  command = plan
  assert {
    condition = (
      google_secret_manager_secret.identity_claim_key.secret_id == "identity-claim-key" &&
      google_secret_manager_secret.identity_claim_key.project == "example-project" &&
      google_secret_manager_secret.identity_claim_key.deletion_protection &&
      length(google_secret_manager_secret.identity_claim_key.replication[0].auto) == 1 &&
      google_secret_manager_secret.identity_claim_key.labels["agentarium-secret"] == "identity-claim-key"
    )
    error_message = "Terraform must create the lock-named claim key secret, auto-replicated and deletion-protected."
  }
  assert {
    # secret_data stays null: the value goes only through the write-only
    # argument from an ephemeral resource, so neither plan nor state holds it.
    condition = (
      google_secret_manager_secret_version.identity_claim_key.secret_data == null &&
      google_secret_manager_secret_version.identity_claim_key.secret_data_wo == null &&
      google_secret_manager_secret_version.identity_claim_key.secret_data_wo_version == "1"
    )
    error_message = "The claim key version must be written only through secret_data_wo (version 1), never secret_data."
  }
}

run "claim_key_grant_follows_created_secret" {
  # The grant takes secret_id from the created resource (an implicit
  # dependency), so one mock apply orders API -> secret -> grant.
  command = apply
  assert {
    condition = (
      google_secret_manager_secret_iam_member.identity_claim_key.secret_id == google_secret_manager_secret.identity_claim_key.secret_id &&
      google_secret_manager_secret_version.identity_claim_key.secret == google_secret_manager_secret.identity_claim_key.id
    )
    error_message = "The claim key grant and version must reference the created secret."
  }
}

run "claim_key_rejects_versions_aliases_and_other_projects" {
  command = plan
  variables { claim_key_secret = "projects/123456789012/secrets/identity-claim-key/versions/3" }
  expect_failures = [var.claim_key_secret]
}

run "claim_key_rejects_project_id_alias" {
  command = plan
  variables { claim_key_secret = "projects/example-project/secrets/identity-claim-key" }
  expect_failures = [var.claim_key_secret]
}

run "claim_key_rejects_other_project" {
  command = plan
  variables { claim_key_secret = "projects/999999999999/secrets/identity-claim-key" }
  expect_failures = [var.claim_key_secret]
}

run "claim_key_distinct_from_other_secrets" {
  command = plan
  variables {
    other_secret_resources = ["projects/example-project/secrets/oidc", "projects/123456789012/secrets/receiver"]
  }
  assert {
    condition     = google_secret_manager_secret_iam_member.identity_claim_key.secret_id == "identity-claim-key"
    error_message = "Distinct secrets must be accepted."
  }
}

run "claim_key_equal_to_broker_secret_rejected" {
  command = plan
  variables {
    claim_key_secret       = "projects/123456789012/secrets/receiver"
    other_secret_resources = ["projects/example-project/secrets/oidc", "projects/123456789012/secrets/receiver"]
  }
  expect_failures = [var.other_secret_resources]
}

run "claim_key_equal_to_oidc_via_project_id_alias_rejected" {
  command = plan
  variables {
    claim_key_secret       = "projects/123456789012/secrets/oidc"
    other_secret_resources = ["projects/example-project/secrets/oidc"]
  }
  expect_failures = [var.other_secret_resources]
}

run "claim_key_malformed_is_a_validation_failure" {
  command = plan
  variables { claim_key_secret = "foo" }
  expect_failures = [var.claim_key_secret]
}

run "only_exact_templates_and_identity" {
  command = plan
  assert {
    condition = (
      google_privateca_ca_pool_iam_member.identity_issuer.ca_pool == var.ca_pool_id &&
      google_privateca_ca_pool_iam_member.identity_issuer.role == "roles/privateca.certificateRequester" &&
      google_privateca_ca_pool_iam_member.identity_issuer.condition[0].expression == "api.getAttribute('privateca.googleapis.com/template', '') in [\"example-project/-/example-service\",\"example-project/-/example-client\"]" &&
      toset(keys(google_privateca_certificate_template_iam_member.identity_template)) == toset(["service", "client"]) &&
      alltrue([for profile, grant in google_privateca_certificate_template_iam_member.identity_template :
        grant.certificate_template == var.certificate_template_ids[profile] &&
        grant.role == "roles/privateca.templateUser" &&
        grant.member == google_privateca_ca_pool_iam_member.identity_issuer.member
      ])
    )
    error_message = "Only exact identity may use the two exact templates; omitted/other templates must not satisfy requester IAM."
  }
}

run "same_template_rejected" {
  command = plan
  variables {
    certificate_template_ids = {
      service = "projects/example-project/locations/us-central1/certificateTemplates/service"
      client  = "projects/example-project/locations/us-central1/certificateTemplates/service"
    }
  }
  expect_failures = [var.certificate_template_ids]
}

run "other_project_rejected" {
  command = plan
  variables {
    certificate_template_ids = {
      service = "projects/other-project/locations/us-central1/certificateTemplates/service"
      client  = "projects/example-project/locations/us-central1/certificateTemplates/client"
    }
  }
  expect_failures = [var.certificate_template_ids]
}

run "other_location_rejected" {
  command = plan
  variables {
    certificate_template_ids = {
      service = "projects/example-project/locations/us-east1/certificateTemplates/service"
      client  = "projects/example-project/locations/us-central1/certificateTemplates/client"
    }
  }
  expect_failures = [var.certificate_template_ids]
}

run "invalid_id_rejected" {
  command = plan
  variables {
    certificate_template_ids = {
      service = "projects/example-project/locations/us-central1/certificateTemplates/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      client  = "projects/example-project/locations/us-central1/certificateTemplates/client"
    }
  }
  expect_failures = [var.certificate_template_ids]
}
