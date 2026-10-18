#!/usr/bin/env bash
# Isolated PostgreSQL 16 runner for the coordinator integration tests. Never
# points at Cloud SQL. Two disposable clusters, because roles are
# cluster-wide: the dispatch package tests install migrations as the
# superuser into DATABASE_URL, while TestWiredServicePostgres installs them as
# a non-superuser that must create the group roles itself.
set -euo pipefail
cd "$(dirname "$0")/../.."
image="${COORDINATOR_POSTGRES_IMAGE:-postgres:16-alpine}"
shared="agentarium-coordinator-test-$$"
wiring="agentarium-coordinator-wiring-test-$$"
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
docker exec "$shared" psql -q -U postgres -c 'CREATE DATABASE coordinator_shared' >/dev/null
base="postgres://postgres@127.0.0.1"
export DATABASE_URL="${base}:${shared_port}/coordinator_shared?sslmode=disable"
export COORDINATOR_WIRING_TEST_ADMIN_DSN="${base}:${wiring_port}/postgres?sslmode=disable"
# Tests in the dispatch package share DATABASE_URL, so packages run one at a time.
go test -race -p 1 -tags integration ./services/coordinator/... -count=1 "$@"
