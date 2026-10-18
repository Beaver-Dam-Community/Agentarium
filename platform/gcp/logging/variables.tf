variable "project_id" {
  type        = string
  description = "Installation project from the environment lock."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Use a Google Cloud project ID, not a filter expression or project number."
  }
}
