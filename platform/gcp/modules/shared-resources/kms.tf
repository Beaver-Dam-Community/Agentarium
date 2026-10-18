# Cloud KMS asymmetric signing keys (no IAM here; signer/viewer bindings are TASK-06):
# - manifest: TASK-07 evidence and decision-input manifest chains, EC_SIGN_P256_SHA256
# - bundle: TASK-14 OPA bundle signing, EC_SIGN_P256_SHA256, OPA keyID prod-v1 / regression-v1
# SPEC-QUESTION: protection level is not specified; the provider default (SOFTWARE) is kept.
resource "google_kms_key_ring" "this" {
  for_each = local.key_rings

  project  = local.project_id
  name     = each.value
  location = var.region

  depends_on = [google_project_service.this]
}

resource "google_kms_crypto_key" "signing" {
  for_each = local.signing_keys

  name     = each.value[2]
  key_ring = google_kms_key_ring.this[each.value[1]].id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm = "EC_SIGN_P256_SHA256"
  }
}
