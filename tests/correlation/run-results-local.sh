#!/usr/bin/env bash
# Disposable PostgreSQL only. No Cloud SQL, shared database or remote state.
set -euo pipefail
cd "$(dirname "$0")/../.."
name="agentarium-correlation-results-test-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run --rm -d --name "$name" -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1::5432 "${CORRELATION_POSTGRES_IMAGE:-postgres:16-alpine}" >/dev/null
for i in {1..30}; do
  if docker exec "$name" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
port="$(docker port "$name" 5432/tcp | sed 's/.*://')"
CORRELATION_RESULTS_TEST_DSN="postgres://postgres@127.0.0.1:${port}/postgres?sslmode=disable" go test -race -tags integration ./services/correlation/internal/results -count=1 "$@"
