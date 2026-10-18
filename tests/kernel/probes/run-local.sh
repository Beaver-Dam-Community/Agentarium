#!/usr/bin/env bash
# Offline checks for the TASK-09 live verification harness, including the
# audit.kernel_events query against a disposable PostgreSQL 16. Never points
# at Cloud SQL.
set -euo pipefail
cd "$(dirname "$0")/../../.."
name="agentarium-kernel-probes-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
image="${KERNEL_PROBES_POSTGRES_IMAGE:-postgres:16-alpine}"
docker run --rm -d --name "$name" -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1::5432 "$image" >/dev/null
for i in {1..30}; do
  if docker exec "$name" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
port="$(docker port "$name" 5432/tcp | sed 's/.*://')"
export KERNEL_PROBES_TEST_ADMIN_DSN="postgres://postgres@127.0.0.1:${port}/postgres?sslmode=disable"
go test -race -count=1 -tags integration ./tests/kernel/probes/... "$@"
