#!/usr/bin/env bash
# Isolated PostgreSQL 16 runner for the gateway integration tests. Never
# points at Cloud SQL. Two disposable clusters, because roles are
# cluster-wide: the gateway package and tests/gateway install migrations as
# the superuser into DATABASE_URL, while TestWiredGatewayPostgres installs
# them as a non-superuser that must create the group roles itself.
set -euo pipefail
cd "$(dirname "$0")/../.."
image="${GATEWAY_POSTGRES_IMAGE:-postgres:16-alpine}"
shared="agentarium-gateway-test-$$"
wiring="agentarium-gateway-wiring-test-$$"
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
docker exec "$shared" psql -q -U postgres -c 'CREATE DATABASE gateway_shared' >/dev/null
docker exec "$shared" psql -q -U postgres -c 'CREATE DATABASE gateway_schema' >/dev/null
base="postgres://postgres@127.0.0.1"
export GATEWAY_WIRING_TEST_ADMIN_DSN="${base}:${wiring_port}/postgres?sslmode=disable"
# Each package installs the migrations into its own empty database.
DATABASE_URL="${base}:${shared_port}/gateway_shared?sslmode=disable" \
  go test -race -p 1 -tags integration ./services/gateway/... -count=1 "$@"
DATABASE_URL="${base}:${shared_port}/gateway_schema?sslmode=disable" \
  go test -race -p 1 -tags integration ./tests/gateway/... -count=1 "$@"
