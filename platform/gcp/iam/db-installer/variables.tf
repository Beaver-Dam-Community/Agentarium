variable "project_id" { type = string }
variable "project_number" { type = string }
variable "cloudsql_instance" { type = string }

variable "enable_workload_binding" {
  description = "Install window only. True lets KSA agent-control/db-installer impersonate the installer GSA; set false again after migrations are verified."
  type        = bool
  default     = false
}
