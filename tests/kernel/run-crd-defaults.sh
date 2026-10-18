#!/usr/bin/env bash
# Compare committed defaults with the exact upstream 1.7.1 schemas.
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for file in cilium.io_tracingpolicies.yaml cilium.io_tracingpoliciesnamespaced.yaml; do
 curl --fail --silent --show-error --location --retry 2 \
  "https://raw.githubusercontent.com/cilium/tetragon/v1.7.1/install/kubernetes/tetragon/crds-yaml/$file" -o "$tmp/$file"
done
# The test compares both SHA-256 source digests and regenerated defaults.
TETRAGON_CRD_DIR="$tmp" go test ./sensors/exporter/capture -run '^TestCRDDefaultsMatchPinnedCRD$' -count=1 -v
