#!/usr/bin/env bash
# M3-1 local end-to-end run (see tests/m3-1/README.md).
#
# Runs the real M3-1 action path on one machine with Docker: the real service
# binaries on PostgreSQL 16 with the repository migrations and local mTLS,
# the real runtime binaries in a container, and only the simulations listed
# in the README under "Simulated locally".
#
#   bash tests/m3-1/run-local.sh
#
# Exit status: 0 only when every stage passes. A run whose only failure is
# the adapter -> receiver TLS handshake exits 3 with
# "BLOCKED at adapter->receiver TLS (TASK-05/TASK-03 conflict)"; a run that
# stops at the approval contract for lack of a content preview exits 4.
#
# Environment: GOCACHE (default /tmp/gocache-m31e2e), M31_E2E_KEEP=1 keeps the
# work directory (logs and generated keys) and this run's containers.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export GOCACHE="${GOCACHE:-/tmp/gocache-m31e2e}"
PG_IMAGE="postgres:16-alpine"
GCS_IMAGE="fsouza/fake-gcs-server:1.52.2"
RUNTIME_IMAGE="gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"
TAG="$(date +%H%M%S)-$$"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/m31e2e.XXXXXX")"
PG="m31e2e-pg-$TAG"
GCS="m31e2e-gcs-$TAG"

log() { printf '\n== %s\n' "$*"; }

cleanup() {
  status=$?
  # Only containers this run created (label m31e2e.run=$TAG).
  ids="$(docker ps -aq --filter "label=m31e2e.run=$TAG" 2>/dev/null || true)"
  if [ -n "$ids" ] && [ "${M31_E2E_KEEP:-}" = "1" ]; then
    echo "containers kept: docker rm -f \$(docker ps -aq --filter label=m31e2e.run=$TAG)"
  elif [ -n "$ids" ]; then
    # shellcheck disable=SC2086
    docker rm -f $ids >/dev/null 2>&1 || true
  fi
  # Generated keys and tokens never outlive the run unless asked.
  if [ "${M31_E2E_KEEP:-}" = "1" ]; then
    echo "work directory kept: $WORK"
  else
    rm -rf "$WORK"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

for tool in docker go python3; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
docker info >/dev/null 2>&1 || { echo "docker daemon not reachable" >&2; exit 2; }
ARCH="$(docker version -f '{{.Server.Arch}}')"
case "$ARCH" in amd64|arm64) ;; *) echo "unsupported docker arch $ARCH" >&2; exit 2 ;; esac
# The runtime container base image (services/runtime/Dockerfile), pinned by
# digest; the driver only inspects it, so pull it when it is missing.
docker image inspect "$RUNTIME_IMAGE" >/dev/null 2>&1 ||
  docker pull -q --platform "linux/$ARCH" "$RUNTIME_IMAGE" >/dev/null ||
  { echo "cannot pull $RUNTIME_IMAGE" >&2; exit 2; }

log "PostgreSQL 16 and GCS emulator containers ($TAG)"
PG_PORT="$(free_port)"
docker run -d --name "$PG" --label "m31e2e.run=$TAG" -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" -c fsync=off >/dev/null
GCS_PORT="$(free_port)"
docker run -d --name "$GCS" --label "m31e2e.run=$TAG" -p "127.0.0.1:$GCS_PORT:$GCS_PORT" "$GCS_IMAGE" \
  -scheme http -port "$GCS_PORT" -external-url "http://127.0.0.1:$GCS_PORT" -public-host "127.0.0.1:$GCS_PORT" -backend memory >/dev/null
for _ in $(seq 1 60); do
  docker exec "$PG" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$PG" pg_isready -U postgres -h 127.0.0.1 >/dev/null
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$GCS_PORT/storage/v1/b?project=m31-local" >/dev/null 2>&1 && break
  sleep 1
done
echo "   postgres $PG_IMAGE on 127.0.0.1:$PG_PORT, $GCS_IMAGE on 127.0.0.1:$GCS_PORT"

log "Build (GOCACHE=$GOCACHE)"
BIN="$WORK/bin"
RTBIN="$WORK/runtime-bin"
mkdir -p "$BIN" "$RTBIN"
cd "$REPO"
go build -o "$BIN/gateway" ./services/gateway/cmd/gateway
go build -o "$BIN/coordinator" ./services/coordinator/cmd/coordinator
go build -o "$BIN/receiver-sender" ./services/adapters/receiver-sender
go build -o "$BIN/receiver" ./services/receiver/cmd/receiver
go build -o "$BIN/evidence-collector" ./services/evidence-collector/cmd/evidence-collector
go build -o "$BIN/audit-writer" ./services/audit/cmd/writer
go build -o "$BIN/audit-exporter" ./services/audit/cmd/exporter
# Harness tests for the services whose main needs GCP or the Kubernetes API
# (README "Simulated locally"); each is a test binary, never a service build.
go test -c -tags integration -o "$BIN/identity.test" ./services/identity/cmd/identity
go test -c -tags integration -o "$BIN/broker.test" ./services/credential-broker/cmd/broker
go test -c -tags integration -o "$BIN/control-health.test" ./services/control-health/cmd/control-health
go test -c -tags integration -o "$BIN/first-bundle.test" ./tools/first-bundle
go test -c -tags integration -o "$BIN/receiver-sender.test" ./services/adapters/receiver-sender
# The runtime image contents (services/runtime/Dockerfile): CGO off, trimpath.
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags="-s -w" -o "$RTBIN/agent-runtime" ./services/runtime/cmd/supervisor
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags="-s -w" -o "$RTBIN/agent-worker" ./services/runtime/cmd/worker
chmod 0755 "$RTBIN" "$RTBIN"/*
echo "   built into $BIN and $RTBIN (linux/$ARCH)"

log "Driver: go test -tags integration ./tests/m3-1 -run TestM31LocalE2E"
set +e
M31_E2E_REPO="$REPO" M31_E2E_WORK="$WORK" M31_E2E_BIN="$BIN" M31_E2E_RUNTIME_BIN="$RTBIN" \
M31_E2E_PG_CONTAINER="$PG" M31_E2E_PG_PORT="$PG_PORT" M31_E2E_GCS_HOST="127.0.0.1:$GCS_PORT" \
M31_E2E_RUNTIME_IMAGE="$RUNTIME_IMAGE" M31_E2E_RUNTIME_PLATFORM="linux/$ARCH" M31_E2E_RUN_TAG="$TAG" \
STORAGE_EMULATOR_HOST="127.0.0.1:$GCS_PORT" GOOGLE_CLOUD_PROJECT=m31-local \
  go test -tags integration -count=1 -run '^TestM31LocalE2E$' -v -timeout 30m ./tests/m3-1
driver=$?
set -e
result="$(cat "$WORK/result" 2>/dev/null || echo fail)"

if [ "$result" != "pass" ] && [ -d "$WORK/logs" ]; then
  log "Service log tails"
  for f in "$WORK"/logs/*.log; do
    echo "--- $(basename "$f")"
    tail -n 15 "$f"
  done
fi

gaps=""
if [ -s "$WORK/gaps" ]; then
  gaps="$(cat "$WORK/gaps")"
  log "Install gaps (the repository install SQL failed as the installer login; applied as superuser to continue)"
  sed 's/^/   /' "$WORK/gaps"
fi

case "$result" in
  pass)
    [ "$driver" -eq 0 ] || { echo "FAIL: driver exited $driver" >&2; exit 1; }
    [ -z "$gaps" ] || { log "FAIL: every stage passed, but only with the install gaps above"; exit 1; }
    log "PASS: M3-1 local end-to-end"
    exit 0 ;;
  blocked_tls)
    log "BLOCKED at adapter->receiver TLS (TASK-05/TASK-03 conflict)"
    echo "   Every stage up to the send and both fail-closed cases passed; the send failed closed with TLS_VERIFY_FAILED."
    exit 3 ;;
  blocked_preview)
    log "BLOCKED at approval contract: no content preview for a data_class none action (migration 20261016181826 SPEC-QUESTION)"
    echo "   Every stage up to the approval contract and both fail-closed cases passed; the contract failed closed (503), nothing was dispatched."
    exit 4 ;;
  *)
    log "FAIL (driver exit $driver)"
    exit 1 ;;
esac
