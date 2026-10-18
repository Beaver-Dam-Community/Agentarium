#!/usr/bin/env bash
# Isolated PostgreSQL integration runner. Never points at Cloud SQL.
set -euo pipefail
cd "$(dirname "$0")/../.."
name="agentarium-audit-test-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
# Override only for an explicitly selected PostgreSQL image/version.
image="${AUDIT_POSTGRES_IMAGE:-postgres:16-alpine}"
docker run --rm -d --name "$name" -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1::5432 "$image" >/dev/null
for i in {1..30}; do
  if docker exec "$name" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
port="$(docker port "$name" 5432/tcp | sed 's/.*://')"
export AUDIT_TEST_ADMIN_DSN="postgres://postgres@127.0.0.1:${port}/postgres?sslmode=disable"
# Both source-helper migrations are merged. Always run real lifecycle SQL in
# this disposable DB; overrides are useful when validating a future helper PR.
export AUDIT_LIFECYCLE_TEST_DSN="$AUDIT_TEST_ADMIN_DSN"
export LIFECYCLE_IDENTITY_MIGRATION="${LIFECYCLE_IDENTITY_MIGRATION:-$PWD/migrations/20261017074056_identity_audit_source_certificate.up.sql}"
export LIFECYCLE_HEALTH_MIGRATION="${LIFECYCLE_HEALTH_MIGRATION:-$PWD/migrations/20261017002500_health_audit_source_current_boot.up.sql}"
test -r "$LIFECYCLE_IDENTITY_MIGRATION"
test -r "$LIFECYCLE_HEALTH_MIGRATION"
go test -race -p 1 -tags integration ./services/audit/... -count=1 "$@"
