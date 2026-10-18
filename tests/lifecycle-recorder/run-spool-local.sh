#!/usr/bin/env bash
# Exercise the actual init binary with exactly the DaemonSet capabilities.
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp="$(mktemp -d)"
name="agentarium-spool-test-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
arch="$(docker info --format '{{.Architecture}}')"
case "$arch" in aarch64|arm64) arch=arm64;; x86_64|amd64) arch=amd64;; *) exit 1;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$tmp/recorder" ./services/lifecycle-recorder/cmd/lifecycle-recorder
docker run -d --name "$name" --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges:true alpine:3.21 sleep 300 >/dev/null
docker cp "$tmp/recorder" "$name:/recorder"
docker exec "$name" sh -ec '
  mkdir -p /spool/wal/private
  chmod 755 /spool
  chmod 700 /spool/wal/private
  echo retained > /spool/wal/private/segment
  echo outside > /outside
  ln -s /outside /spool/link
  /recorder --prepare-spool /spool --spool-owner 65532 --spool-group 65532
  test "$(stat -c "%u:%g:%a" /spool)" = 65532:65532:700
  test "$(stat -c %u /outside)" = 0
  # Restart cannot traverse the directory with CHOWN alone, and must not try.
  /recorder --prepare-spool /spool --spool-owner 65532 --spool-group 65532
'
docker exec --user 65532:65532 "$name" sh -ec '
  test "$(cat /spool/wal/private/segment)" = retained
  test "$(stat -c "%u:%g" /spool/wal/private/segment)" = 65532:65532
  echo append >> /spool/wal/private/segment
'
# Crash fixture: a child subtree has been transferred, its parent has not.
docker exec "$name" sh -ec '
  mkdir -p /partial/wal
  chmod 700 /partial /partial/wal
  echo retained-after-crash > /partial/wal/segment
  chown -R 65532:65532 /partial/wal
  /recorder --prepare-spool /partial --spool-owner 65532 --spool-group 65532
  /recorder --prepare-spool /partial --spool-owner 65532 --spool-group 65532
'
docker exec --user 65532:65532 "$name" sh -ec '
  test "$(cat /partial/wal/segment)" = retained-after-crash
  echo append >> /partial/wal/segment
'
echo 'PASS: first start, restart and partial-chown crash recovery with CAP_CHOWN only; WAL retained and writable'
