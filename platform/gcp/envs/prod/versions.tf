terraform {
  required_version = "~> 1.15"

  # State lives in each environment's own GCS bucket (partial configuration).
  # Each person applies to their own project, so the bucket is not fixed here:
  #   terraform init -backend-config=backend.hcl   (copy backend.hcl.example; not committed)
  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "8.6.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "8.6.0"
    }
    # Ephemeral random_bytes for the Terraform-created secret versions (TASK-06 3.3).
    random = {
      source  = "hashicorp/random"
      version = "3.9.1"
    }
  }
}
