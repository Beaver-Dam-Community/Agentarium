locals {
  project_id = var.lock.project.id
  name       = "agentarium-${var.env}"

  key_pattern = "^projects/[^/]+/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)$"
  signing_keys = {
    bundle   = regex(local.key_pattern, var.lock.keys.bundle_signing_key)
    manifest = regex(local.key_pattern, var.lock.keys.manifest_signing_key)
  }
  key_rings = toset([for k in local.signing_keys : k[1]])
}

resource "google_project_service" "this" {
  for_each = toset([
    "artifactregistry.googleapis.com",
    "cloudkms.googleapis.com",
    "privateca.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
  ])

  project            = local.project_id
  service            = each.value
  disable_on_destroy = false
}
