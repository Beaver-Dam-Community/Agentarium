variable "env" {
  description = "Environment name (prod or regression)."
  type        = string

  validation {
    condition     = contains(["prod", "regression"], var.env)
    error_message = "env must be prod or regression."
  }
}

variable "region" {
  description = "Region of the environment (platform module output)."
  type        = string
}

# SPEC-DELTA: TASK-07 3 requires soft delete of at least 7 days on the evidence,
# decision-input-exports and regression buckets. Some projects inherit the org policy
# constraints/storage.softDeletePolicySeconds with allowedValues ["0"], which rejects any
# other value. Such an environment sets 0 and records the effective policy in its install
# manifest: deleted objects are then not recoverable; the unlocked 30-day retention policy
# still blocks deletes inside the retention window and the manifest chain still detects
# deletions. The spec is unchanged; this is an environment-specific deviation.
variable "soft_delete_seconds" {
  description = "Soft delete duration for buckets that require it. 604800-7776000, or 0 only when the org policy forbids soft delete."
  type        = number
  default     = 604800

  validation {
    condition     = var.soft_delete_seconds == 0 || (var.soft_delete_seconds >= 604800 && var.soft_delete_seconds <= 7776000)
    error_message = "soft_delete_seconds must be 0 (org policy forbids soft delete) or between 604800 and 7776000."
  }
}

variable "network_id" {
  description = "Cluster VPC network ID (platform module output); Cloud SQL gets a private IP on it."
  type        = string
}

# Shared-resource keys of the environment lock. storage.* and keys.* use the
# TASK-16 key names; cloudsql.* and pki.* are added here.
# SPEC-QUESTION: cloudsql.* and pki.* are not in the TASK-16 lock schema.
variable "lock" {
  description = "Decoded environment lock (shared-resource keys)."
  type = object({
    project = object({
      id = string
    })
    storage = object({
      evidence_bucket               = string
      summary_bucket                = string
      bundle_bucket                 = string
      decision_input_exports_bucket = string
      regression_requests_bucket    = string
      regression_reports_bucket     = string
      discovery_bucket              = string
      cloudsql_instance             = string
    })
    keys = object({
      bundle_signing_key   = string
      bundle_key_id        = string
      manifest_signing_key = string
    })
    cloudsql = object({
      database_version             = string
      edition                      = string
      tier                         = string
      availability_type            = string
      private_service_access_range = string
    })
    pki = object({
      ca_pool                  = string
      certificate_authority_id = string
      ca_common_name           = string
      ca_organization          = string
      ca_lifetime              = string
      ca_key_algorithm         = string
    })
  })

  validation {
    condition = alltrue([
      for k, b in var.lock.storage : can(regex("^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$", b)) if k != "cloudsql_instance"
    ])
    error_message = "lock.storage bucket names must be valid bucket names (placeholder not replaced?)."
  }

  validation {
    condition = (
      length(distinct([for k, b in var.lock.storage : b if k != "cloudsql_instance"])) == 7
    )
    error_message = "lock.storage bucket names must be distinct."
  }

  validation {
    condition = try(
      split(":", var.lock.storage.cloudsql_instance)[0] == var.lock.project.id &&
      split(":", var.lock.storage.cloudsql_instance)[1] == var.region &&
      can(regex("^[a-z][a-z0-9-]{0,96}[a-z0-9]$", split(":", var.lock.storage.cloudsql_instance)[2])) &&
      length(split(":", var.lock.storage.cloudsql_instance)) == 3,
      false
    )
    error_message = "lock.storage.cloudsql_instance must be the connection name PROJECT_ID:REGION:INSTANCE of this project and region."
  }

  validation {
    condition = alltrue([
      for key in [var.lock.keys.bundle_signing_key, var.lock.keys.manifest_signing_key] : try(
        regex("^projects/([^/]+)/locations/([^/]+)/keyRings/[a-zA-Z0-9_-]{1,63}/cryptoKeys/[a-zA-Z0-9_-]{1,63}$", key)[0] == var.lock.project.id &&
        regex("^projects/([^/]+)/locations/([^/]+)/keyRings/[a-zA-Z0-9_-]{1,63}/cryptoKeys/[a-zA-Z0-9_-]{1,63}$", key)[1] == var.region,
        false
      )
    ])
    error_message = "lock.keys signing keys must be projects/PROJECT_ID/locations/REGION/keyRings/RING/cryptoKeys/KEY in this project and region."
  }

  validation {
    condition     = var.lock.keys.bundle_signing_key != var.lock.keys.manifest_signing_key
    error_message = "bundle and manifest signing keys must be different keys."
  }

  validation {
    condition     = var.lock.keys.bundle_key_id == (var.env == "prod" ? "prod-v1" : "regression-v1")
    error_message = "lock.keys.bundle_key_id must be prod-v1 for prod and regression-v1 for regression (COMMON policy deployment contract)."
  }

  validation {
    condition = (
      can(regex("^POSTGRES_[0-9]+$", var.lock.cloudsql.database_version)) &&
      contains(["ENTERPRISE", "ENTERPRISE_PLUS"], var.lock.cloudsql.edition) &&
      can(regex("^db-", var.lock.cloudsql.tier)) &&
      contains(["ZONAL", "REGIONAL"], var.lock.cloudsql.availability_type)
    )
    error_message = "lock.cloudsql needs database_version POSTGRES_N, edition ENTERPRISE|ENTERPRISE_PLUS, a db-* tier and availability_type ZONAL|REGIONAL."
  }

  validation {
    condition = try(
      cidrsubnet(var.lock.cloudsql.private_service_access_range, 0, 0) == var.lock.cloudsql.private_service_access_range &&
      tonumber(split("/", var.lock.cloudsql.private_service_access_range)[1]) <= 24,
      false
    )
    error_message = "lock.cloudsql.private_service_access_range must be a canonical IPv4 CIDR of /24 or larger."
  }

  validation {
    condition = (
      can(regex("^[a-z0-9-]{1,63}$", var.lock.pki.ca_pool)) &&
      can(regex("^[a-z0-9-]{1,63}$", var.lock.pki.certificate_authority_id)) &&
      var.lock.pki.ca_common_name != "" &&
      can(regex("^[0-9]+s$", var.lock.pki.ca_lifetime)) &&
      contains(["EC_P256_SHA256", "EC_P384_SHA384", "RSA_PSS_2048_SHA256", "RSA_PSS_3072_SHA256", "RSA_PSS_4096_SHA256", "RSA_PKCS1_2048_SHA256", "RSA_PKCS1_3072_SHA256", "RSA_PKCS1_4096_SHA256"], var.lock.pki.ca_key_algorithm)
    )
    error_message = "lock.pki needs ca_pool and certificate_authority_id IDs, a CA common name, ca_lifetime in seconds (e.g. 315360000s) and a CAS key algorithm."
  }
}

# Explicit two-stage rollout: keep false until exact IAM/template read-back.
# After stage 2, persist true in the installation's Terraform inputs.
variable "certificate_template_issuance_enabled" {
  description = "Move the pool non-CA/keyUsage baseline to templates only after template-only issuance IAM is verified (two-stage rollout)."
  type        = bool
  default     = false
  nullable    = false
}
