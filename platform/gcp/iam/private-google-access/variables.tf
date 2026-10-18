variable "project_id" {
  type        = string
  description = "Installation project from the environment lock."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Use a Google Cloud project ID."
  }
}

variable "network_id" {
  type        = string
  description = "Platform VPC ID or self link in the installation project."
  validation {
    condition     = can(regex("^(https://www[.]googleapis[.]com/compute/v1/)?projects/${var.project_id}/global/networks/[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.network_id))
    error_message = "The private zone and VIP route must use a VPC in the installation project."
  }
}
