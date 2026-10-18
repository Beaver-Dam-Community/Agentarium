# GCS buckets of the COMMON environment lock "storage" row. IAM bindings are TASK-06.
#
# decision-input-exports, regression-requests and regression-reports exist only in the
# prod project (COMMON policy deployment contract, regression test contract; TASK-06 3.3). The regression lock still
# carries their names because the regression runner and decision-replay read them.
# SPEC-QUESTION: TASK-16 step 7r says the regression project gets "the same buckets"; only
# evidence, summary and bundle are created there.
#
# SPEC-QUESTION (all buckets): location, uniform bucket-level access, public access
# prevention and versioning are not specified. Buckets are regional in the environment
# region with uniform access (TASK-06 grants are bucket-level IAM only) and public access
# prevention enforced; versioning stays off.
locals {
  day = 86400

  buckets = {
    # TASK-07 2/3: unlocked 30-day retention, soft delete; TASK-07 3 / TASK-16 step 3: delete at age >= 31.
    evidence = {
      name             = var.lock.storage.evidence_bucket
      retention_days   = 30
      soft_delete      = true
      lifecycle_delete = 31
      prod_only        = false
    }
    # TASK-07 2/3: 90-day retention. SPEC-QUESTION: soft delete and lifecycle not specified.
    summary = {
      name             = var.lock.storage.summary_bucket
      retention_days   = 90
      soft_delete      = false
      lifecycle_delete = null
      prod_only        = false
    }
    # TASK-14 3 bundle store. SPEC-QUESTION: no retention, soft delete or lifecycle specified.
    bundle = {
      name             = var.lock.storage.bundle_bucket
      retention_days   = null
      soft_delete      = false
      lifecycle_delete = null
      prod_only        = false
    }
    # TASK-07 2 / COMMON policy deployment contract: unlocked 30-day retention, soft delete.
    # SPEC-QUESTION: lifecycle deletion not specified.
    decision_input_exports = {
      name             = var.lock.storage.decision_input_exports_bucket
      retention_days   = 30
      soft_delete      = true
      lifecycle_delete = null
      prod_only        = true
    }
    # COMMON regression test contract: 30-day retention, soft delete. SPEC-QUESTION: lifecycle not specified.
    regression_requests = {
      name             = var.lock.storage.regression_requests_bucket
      retention_days   = 30
      soft_delete      = true
      lifecycle_delete = null
      prod_only        = true
    }
    regression_reports = {
      name             = var.lock.storage.regression_reports_bucket
      retention_days   = 30
      soft_delete      = true
      lifecycle_delete = null
      prod_only        = true
    }
    # TASK-02 3.4: discovery snapshots. No retention and no lifecycle delete because
    # discovery_candidates keep referencing snapshot_id; objects are written once.
    # Discovery runs only in the prod project (static analysis in agent-observe).
    discovery = {
      name             = var.lock.storage.discovery_bucket
      retention_days   = null
      soft_delete      = false
      lifecycle_delete = null
      prod_only        = true
    }
  }

  env_buckets = { for k, b in local.buckets : k => b if var.env == "prod" || !b.prod_only }
}

resource "google_storage_bucket" "this" {
  for_each = local.env_buckets

  project  = local.project_id
  name     = each.value.name
  location = var.region

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  # Unlocked: Bucket Lock is an irreversible operator decision (TASK-07 3, TASK-16).
  dynamic "retention_policy" {
    for_each = each.value.retention_days == null ? [] : [each.value.retention_days]
    content {
      retention_period = tostring(retention_policy.value * local.day)
      is_locked        = false
    }
  }

  # TASK-07 3: soft delete kept on at no less than the 7-day default.
  # SPEC-DELTA: var.soft_delete_seconds = 0 only where an inherited org policy
  # (constraints/storage.softDeletePolicySeconds) allows nothing but 0; see variables.tf.
  dynamic "soft_delete_policy" {
    for_each = each.value.soft_delete ? [1] : []
    content {
      retention_duration_seconds = var.soft_delete_seconds
    }
  }

  dynamic "lifecycle_rule" {
    for_each = each.value.lifecycle_delete == null ? [] : [each.value.lifecycle_delete]
    content {
      action {
        type = "Delete"
      }
      condition {
        age = lifecycle_rule.value
      }
    }
  }

  depends_on = [google_project_service.this]
}
