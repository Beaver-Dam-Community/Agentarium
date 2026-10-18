#!/usr/bin/env bash
# Isolated PostgreSQL 16 runner for the receiver-sender adapter integration
# tests. Never points at Cloud SQL. Two disposable clusters, because roles are
# cluster-wide: the package tests (store, inputs, flow) install migrations as
# the superuser into DATABASE_URL, while TestWiredEnginePostgres installs them
# as a non-superuser that must create the group roles itself.
set -euo pipefail
cd "$(dirname "$0")/../.."
image="${ADAPTER_POSTGRES_IMAGE:-postgres:16-alpine}"
shared="agentarium-adapter-test-$$"
wiring="agentarium-adapter-wiring-test-$$"
trap 'docker rm -f "$shared" "$wiring" >/dev/null 2>&1 || true' EXIT
start() {
  docker run --rm -d --name "$1" -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1::5432 "$image" >/dev/null
  for _ in {1..30}; do
    if docker exec "$1" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
    sleep 1
  done
  docker port "$1" 5432/tcp | sed 's/.*://'
}
shared_port="$(start "$shared")"
wiring_port="$(start "$wiring")"
base="postgres://postgres@127.0.0.1"
export ADAPTER_WIRING_TEST_ADMIN_DSN="${base}:${wiring_port}/postgres?sslmode=disable"
# The package tests each install the migrations into an empty DATABASE_URL
# when their schema is missing, so every package gets its own database.
# inputs applies AGENTARIUM_GATEWAY_MIGRATION (every migration, in order).
# Roles of other Tasks that migrations grant to before their own migration
# exists are created first (TASK-16 step 2), as in tests/coordinator.
AGENTARIUM_GATEWAY_MIGRATION="$(ls "$PWD"/migrations/*.up.sql | sort | paste -sd: -)"
export AGENTARIUM_GATEWAY_MIGRATION
for r in control_health_writer gateway_app timeline_app broker_reader; do
  docker exec "$shared" psql -q -U postgres -c "CREATE ROLE $r NOLOGIN" >/dev/null
done
n=0
for pkg in $(go list ./packages/adapters/... ./services/adapters/...); do
  n=$((n + 1))
  docker exec "$shared" psql -q -U postgres -c "CREATE DATABASE adapter_$n" >/dev/null
  DATABASE_URL="${base}:${shared_port}/adapter_$n?sslmode=disable" \
    go test -race -tags integration -count=1 "$pkg" "$@"
done
