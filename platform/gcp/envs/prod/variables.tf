variable "lock_path" {
  description = "Path to the prod environment lock JSON (deploy/gcp/environment.lock.json for this environment)."
  type        = string
}

# SPEC-DELTA: see modules/shared-resources/variables.tf soft_delete_seconds. Leave the
# default unless the project's effective storage.softDeletePolicySeconds allows only 0.
variable "gcs_soft_delete_seconds" {
  description = "Soft delete duration for the soft-delete buckets (0 only under an org policy that forbids soft delete)."
  type        = number
  default     = 604800
}

variable "db_installer_workload_binding" {
  description = "Install window only (issue #123): let KSA agent-control/db-installer impersonate the migration installer GSA. Apply with false again after the migration ledger is verified."
  type        = bool
  default     = false
}

# Explicit two-stage rollout: keep false until exact IAM/template read-back.
# After stage 2, persist true in the installation's Terraform inputs.
variable "certificate_template_issuance_enabled" {
  description = "Move the pool non-CA/keyUsage baseline to templates only after template-only issuance IAM is verified (two-stage rollout)."
  type        = bool
  default     = false
  nullable    = false
}
