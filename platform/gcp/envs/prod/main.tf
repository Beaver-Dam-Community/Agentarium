# Every input comes from the environment lock; no value outside the lock is applied.
locals {
  lock = jsondecode(file(var.lock_path))
}

provider "google" {
  project = local.lock.project.id
}

# Pinned for resources that need beta fields; none are used by the platform module yet.
provider "google-beta" {
  project = local.lock.project.id
}

module "platform" {
  source = "../../modules/platform"

  env  = "prod"
  lock = local.lock
}

module "shared_resources" {
  source = "../../modules/shared-resources"

  env        = "prod"
  region     = module.platform.region
  network_id = module.platform.network_id
  lock       = local.lock

  soft_delete_seconds                   = var.gcs_soft_delete_seconds
  certificate_template_issuance_enabled = var.certificate_template_issuance_enabled
}

# TASK-06 Google API DNS must match the VIP allowed by workload NetworkPolicies.
module "private_google_access" {
  source     = "../../iam/private-google-access"
  project_id = module.platform.project_id
  network_id = module.platform.network_id
}

# TASK-06 contact-service identities. Requires the proxy-only impersonation contract.
module "contact_services" {
  source            = "../../iam/contact-services"
  project_id        = module.platform.project_id
  project_number    = module.platform.project_number
  cloudsql_instance = split(":", module.shared_resources.cloudsql_connection_name)[2]
  ca_pool_id        = module.shared_resources.ca_pool_id
  claim_key_secret  = local.lock.identity.claim_key_secret
  # Every other secret this environment grants; the claim key must differ (#101).
  other_secret_resources   = try(concat([local.lock.iam.oidc_client_secret], tolist(local.lock.iam.credential_secret_resources)), [])
  certificate_template_ids = module.shared_resources.certificate_template_ids
}

# TASK-06 optional install input. Absence is visible in outputs and creates no
# inferred secret grants. Same-environment workload IAM supplies lock.iam.
module "workload_services" {
  count             = try(local.lock.iam, null) == null ? 0 : 1
  source            = "../../iam/workload-services"
  project_id        = module.platform.project_id
  project_number    = module.platform.project_number
  cloudsql_instance = split(":", module.shared_resources.cloudsql_connection_name)[2]
  buckets           = module.shared_resources.buckets
  keys              = module.shared_resources.kms_key_ids
  settings          = try(local.lock.iam, null)
  # TASK-06 3.3 (#97): the four cross-environment grants exist only when the
  # lock names the regression project.
  regression_environment = try(local.lock.iam.regression, null)
  # M3-1 receiver API key (TASK-08 #169); absent lock section creates nothing.
  receiver_api_key_secret = try(local.lock.receiver.api_key_secret, null)
  depends_on              = [module.contact_services]
}

# TASK-01 migration installer identity (issue #123). The KSA binding is opt-in
# for the install window only; see platform/gcp/scripts/db-installer-job.md.
module "db_installer" {
  source                  = "../../iam/db-installer"
  project_id              = module.platform.project_id
  project_number          = module.platform.project_number
  cloudsql_instance       = split(":", module.shared_resources.cloudsql_connection_name)[2]
  enable_workload_binding = var.db_installer_workload_binding
  # IAM/IAM Credentials APIs are enabled by the contact-service module.
  depends_on = [module.contact_services]
}
