#!/usr/bin/env bash
# Isolated PostgreSQL 16 runner for the TASK-08 receiver and evidence-collector
# integration tests. Never points at Cloud SQL. Roles are cluster-wide and the
# tests install migrations that create them, so each test group gets its own
# disposable cluster:
#   collector  TestCollectorPostgres: all migrations by a non-superuser
#              installer (with up/down/up of the collector migrations), cursor,
#              R1-R6, destination_observed audit, rollback, retry idempotency
#   mtls       TestCollectorReceiverMTLS: the actual receiver binary with
#              --api-key-dir and the collector over mTLS
#   views      internal/feed and internal/receipt (receiver binary, key 401s)
#   receiver   services/receiver store and HTTP tests (receiver key rotation)
set -euo pipefail
cd "$(dirname "$0")/../.."
image="${EVIDENCE_POSTGRES_IMAGE:-postgres:16-alpine}"
groups=(collector mtls views receiver)
trap 'for g in "${groups[@]}"; do docker rm -f "agentarium-evidence-$g-$$" >/dev/null 2>&1 || true; done' EXIT
start() {
  local name="agentarium-evidence-$1-$$"
  docker run --rm -d --name "$name" -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1::5432 "$image" >/dev/null
  for _ in {1..30}; do
    if docker exec "$name" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
    sleep 1
  done
  sleep 1
  echo "postgres://postgres@127.0.0.1:$(docker port "$name" 5432/tcp | sed 's/.*://')/postgres?sslmode=disable"
}
collector="$(start collector)"
mtls="$(start mtls)"
views="$(start views)"
receiver="$(start receiver)"
EVIDENCE_COLLECTOR_TEST_ADMIN_DSN="$collector" \
  go test -race -count=1 -tags integration -run '^TestCollectorPostgres$' ./services/evidence-collector/internal/collector/ "$@"
EVIDENCE_COLLECTOR_TEST_ADMIN_DSN="$mtls" \
  go test -race -count=1 -tags integration -run '^TestCollectorReceiverMTLS$' ./services/evidence-collector/internal/collector/ "$@"
EVIDENCE_FEED_TEST_ADMIN_DSN="$views" EVIDENCE_TEST_ADMIN_DSN="$views" \
  go test -race -p 1 -count=1 -tags integration ./services/evidence-collector/internal/feed/... ./services/evidence-collector/internal/receipt/... "$@"
DATABASE_URL="$receiver" \
  go test -race -count=1 -tags integration ./services/receiver/... "$@"
