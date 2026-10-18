#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
# Before M1-3 merges, supply its actual migration from its isolated worktree.
if [ -z "${HEALTH_TEST_AUDIT_MIGRATION:-}" ]; then
  HEALTH_TEST_AUDIT_MIGRATION="$(find "$PWD/migrations" -name '*_audit_store.up.sql' -print -quit)"
fi
: "${HEALTH_TEST_AUDIT_MIGRATION:?Set the TASK-07 audit migration path}"
export HEALTH_TEST_AUDIT_MIGRATION
# Two disposable clusters, because roles are cluster-wide: the existing
# suites share one, and TestWorkReadinessPostgres installs every migration as
# a non-superuser installer that must create the group roles itself.
# TestSensorObservationPostgres (the TASK-09 exporter responder against this
# store) installs the same way and gets a third cluster.
name="agentarium-health-test-$$"
readiness="agentarium-health-readiness-test-$$"
sensor="agentarium-health-sensor-test-$$"
trap 'docker rm -fv "$name" "$readiness" "$sensor" >/dev/null 2>&1 || true' EXIT
start() {
  docker run --rm -d --tmpfs /var/lib/postgresql/data:rw,size=512m --name "$1" -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1::5432 "${HEALTH_POSTGRES_IMAGE:-postgres:16-alpine}" >/dev/null
  for i in {1..30}; do
    if docker exec "$1" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
    sleep 1
  done
  docker port "$1" 5432/tcp | sed 's/.*://'
}
port="$(start "$name")"
readiness_port="$(start "$readiness")"
sensor_port="$(start "$sensor")"
HEALTH_TEST_ADMIN_DSN="postgres://postgres@127.0.0.1:${port}/postgres?sslmode=disable" \
HEALTH_READINESS_TEST_ADMIN_DSN="postgres://postgres@127.0.0.1:${readiness_port}/postgres?sslmode=disable" \
HEALTH_SENSOR_TEST_ADMIN_DSN="postgres://postgres@127.0.0.1:${sensor_port}/postgres?sslmode=disable" \
  go test -race ./services/control-health/... -count=1 "$@"
