# Cloud SQL for PostgreSQL (COMMON "implementation stack and decision status" Atomic state row; TASK-03/07 section 2).
# DB users, roles and grants are created by migrations and TASK-06, not here.

# Private services access range and peering for the private IP.
# SPEC-QUESTION: the spec requires private IP but names no connectivity method or range;
# private services access with the lock range is used.
resource "google_compute_global_address" "cloudsql_psa" {
  project       = local.project_id
  name          = "${local.name}-cloudsql-psa"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  address       = split("/", var.lock.cloudsql.private_service_access_range)[0]
  prefix_length = tonumber(split("/", var.lock.cloudsql.private_service_access_range)[1])
  network       = var.network_id

  depends_on = [google_project_service.this]
}

resource "google_service_networking_connection" "cloudsql" {
  network                 = var.network_id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.cloudsql_psa.name]
}

resource "google_sql_database_instance" "this" {
  project          = local.project_id
  name             = split(":", var.lock.storage.cloudsql_instance)[2]
  region           = var.region
  database_version = var.lock.cloudsql.database_version

  deletion_protection = true

  settings {
    # SPEC-QUESTION: tier, edition and availability are install inputs ("DB instance size",
    # TASK-07 section 9) without spec values; they come from the lock.
    tier              = var.lock.cloudsql.tier
    edition           = var.lock.cloudsql.edition
    availability_type = var.lock.cloudsql.availability_type

    # Every client connects through the Cloud SQL Auth Proxy sidecar; direct connections are
    # rejected (TASK-07 section 7 "Cloud SQL IAM connection": connecting without the proxy is denied).
    connector_enforcement = "REQUIRED"

    ip_configuration {
      ipv4_enabled       = false
      private_network    = var.network_id
      allocated_ip_range = google_compute_global_address.cloudsql_psa.name
    }

    # Daily backups and point-in-time recovery (TASK-07 section 9).
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    # IAM database authentication for the per-KSA GSAs (TASK-06 3.3).
    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
  }

  depends_on = [google_service_networking_connection.cloudsql]
}
