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

  env  = "regression"
  lock = local.lock
}

module "shared_resources" {
  source = "../../modules/shared-resources"

  env        = "regression"
  region     = module.platform.region
  network_id = module.platform.network_id
  lock       = local.lock

  soft_delete_seconds = var.gcs_soft_delete_seconds
}
