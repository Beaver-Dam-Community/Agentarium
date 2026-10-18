# Image repository referenced by the admission image allowlists
# (LOCATION-docker.pkg.dev/PROJECT/agentarium/<name>@sha256:DIGEST, TASK-01 3.2).
# Node pulls use the node SA roles/artifactregistry.reader (platform module).
# SPEC-QUESTION: the spec fixes only the reference format. Tags are immutable here because
# every deploy input pins a digest; cleanup policies and vulnerability scanning are not set.
resource "google_artifact_registry_repository" "agentarium" {
  project       = local.project_id
  location      = var.region
  repository_id = "agentarium"
  format        = "DOCKER"
  description   = "Agentarium ${var.env} images (digest-pinned)."

  docker_config {
    immutable_tags = true
  }

  depends_on = [google_project_service.this]
}
