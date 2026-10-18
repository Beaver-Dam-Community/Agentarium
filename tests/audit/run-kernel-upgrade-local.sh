#!/usr/bin/env bash
# Prove a DB already migrated through main receives the pending kernel function.
set -euo pipefail
cd "$(dirname "$0")/../.."
baseline="${AUDIT_UPGRADE_BASE:-origin/main}"
tmp="$(mktemp -d)"
name="agentarium-kernel-upgrade-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
git archive "$baseline" migrations | tar -x -C "$tmp"
docker run --rm -d --name "$name" -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16-alpine >/dev/null
for i in {1..30}; do
  if docker exec "$name" pg_isready -U postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$name" psql -U postgres -v ON_ERROR_STOP=1 -c 'CREATE ROLE control_health_writer NOLOGIN' >/dev/null
migrate() {
 docker run --rm --network "container:$name" -v "$1:/migrations:ro" migrate/migrate:v4.18.3 \
   -path /migrations -database 'postgres://postgres@127.0.0.1/postgres?sslmode=disable' up
}
migrate "$tmp/migrations"
before="$(docker exec "$name" psql -U postgres -Atc 'SELECT version FROM schema_migrations')"
migrate "$PWD/migrations"
after="$(docker exec "$name" psql -U postgres -Atc 'SELECT version FROM schema_migrations WHERE NOT dirty')"
test "$after" -gt "$before"
test "$(docker exec "$name" psql -U postgres -Atc "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='audit' AND p.proname IN ('ingest_kernel_batch','_kernel_record')")" = 2
echo "PASS: main $before -> $after; kernel ingest functions installed, migration clean"
