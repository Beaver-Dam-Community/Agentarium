#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
name="agentarium-broker-test-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run --rm -d --name "$name" -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1::5432 postgres:17-alpine >/dev/null
for i in {1..30}; do
 if docker exec "$name" pg_isready -U postgres >/dev/null 2>&1; then break; fi
 sleep 1
done
port="$(docker port "$name" 5432/tcp | sed 's/.*://')"
BROKER_TEST_ADMIN_DSN="postgres://postgres@127.0.0.1:${port}/postgres?sslmode=disable" go test -race ./services/credential-broker/... -count=1 "$@"
