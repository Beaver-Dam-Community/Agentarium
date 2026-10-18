terraform {
  required_version = "~> 1.15"
  required_providers {
    google = { source = "hashicorp/google", version = "8.6.0" }
    # 3.9.0+ for ephemeral random_bytes (secret values never enter plan/state).
    random = { source = "hashicorp/random", version = "3.9.1" }
  }
}
