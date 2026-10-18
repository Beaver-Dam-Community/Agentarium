variable "lock_path" {
  description = "Path to the regression environment lock JSON (deploy/gcp/environment.lock.json for this environment)."
  type        = string
}

# SPEC-DELTA: see modules/shared-resources/variables.tf soft_delete_seconds. Leave the
# default unless the project's effective storage.softDeletePolicySeconds allows only 0.
variable "gcs_soft_delete_seconds" {
  description = "Soft delete duration for the soft-delete buckets (0 only under an org policy that forbids soft delete)."
  type        = number
  default     = 604800
}
