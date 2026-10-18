variable "project_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be the production project ID."
  }
}
variable "project_number" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{6,20}$", var.project_number))
    error_message = "project_number must be a numeric production project number."
  }
}
variable "cloudsql_instance" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,96}[a-z0-9]$", var.cloudsql_instance))
    error_message = "cloudsql_instance must be an instance name, not a connection string."
  }
}
variable "buckets" {
  type = object({
    evidence               = string
    bundle                 = string
    decision_input_exports = string
    discovery              = string
    regression_requests    = string
    regression_reports     = string
  })
  validation {
    condition     = length(distinct(values(var.buckets))) == 6 && alltrue([for b in values(var.buckets) : can(regex("^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$", b))])
    error_message = "The six resource-scoped buckets must have valid, distinct names."
  }
}
variable "keys" {
  type = object({ manifest = string, bundle = string })
  validation {
    condition = var.keys.manifest != var.keys.bundle && alltrue([
      for key in values(var.keys) : can(regex("^projects/${var.project_id}/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$", key))
    ])
    error_message = "Manifest and bundle keys must be distinct cryptoKeys in the production project."
  }
}
variable "settings" {
  description = "TASK-06 install references from environment.lock.json iam. No secret payloads."
  nullable    = false
  type = object({
    oidc_client_secret          = string
    credential_secret_resources = set(string)
  })
  validation {
    condition = alltrue([
      for secret in concat([var.settings.oidc_client_secret], tolist(var.settings.credential_secret_resources)) :
      can(regex("^projects/(${var.project_id}|${var.project_number})/secrets/[A-Za-z0-9_-]{1,255}$", secret))
    ]) && length(var.settings.credential_secret_resources) > 0
    error_message = "Use individual Secret Manager resource names in this project, with at least one credential binding secret. Broker secrets must already exist; this module creates the OIDC client secret. Never pass versions or secret contents."
  }
  validation {
    condition = try(
      !contains([for s in var.settings.credential_secret_resources : split("/", s)[3]], split("/", var.settings.oidc_client_secret)[3]) &&
      length(distinct([for s in var.settings.credential_secret_resources : split("/", s)[3]])) == length(var.settings.credential_secret_resources),
      false
    )
    error_message = "Broker secrets must be distinct from each other and the OIDC client secret, including project-ID/project-number aliases."
  }
}
variable "regression_environment" {
  description = "Regression project whose decision-replay and regression-runner KSAs receive the four TASK-06 3.3 cross-environment grants (#97). Null creates none."
  type = object({
    project_id     = string
    project_number = string
  })
  default = null
  validation {
    condition = var.regression_environment == null || try(
      can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.regression_environment.project_id)) &&
      can(regex("^[0-9]{6,20}$", var.regression_environment.project_number)) &&
      var.regression_environment.project_id != var.project_id &&
      var.regression_environment.project_number != var.project_number,
      false
    )
    error_message = "regression_environment must name a different project by ID and number."
  }
}
variable "receiver_api_key_secret" {
  description = "Receiver API key secret (lock receiver.api_key_secret), projects/<number>/secrets/<name>. Terraform creates it with version 1 and grants the broker and the receiver KSA access. Null creates nothing."
  type        = string
  default     = null
  validation {
    condition = var.receiver_api_key_secret == null || try(
      can(regex("^projects/${var.project_number}/secrets/[A-Za-z0-9_-]{1,255}$", var.receiver_api_key_secret)) &&
      contains([for s in var.settings.credential_secret_resources : split("/", s)[3]], split("/", var.receiver_api_key_secret)[3]),
      false
    )
    error_message = "The receiver API key must be an individual secret of this project (by number) that is also a broker credential secret."
  }
}
