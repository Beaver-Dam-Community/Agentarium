#!/usr/bin/env bash
# TASK-10 M2-4 live drill: sensor lease loss -> node hold -> readers see the
# hold -> probe-runner passes -> automatic release, with audit rows.
#
# Not run by any automation. Prints the plan unless --execute is given. It
# changes no manifests, RBAC, policies or node pools: the fault is the
# operator-supplied FAULT_CMD (suspend one node's sensor exporter lease
# reporting) and RESTORE_CMD undoes it. Reads use an installed health reader
# certificate and a read-only DB login; nothing is written to the database.
#
# Required environment:
#   NODE_UID            target node UID (kubectl get node <n> -o jsonpath='{.metadata.uid}')
#   HEALTH_URL          https://<control-health service>:<port>
#   READER_CERT/READER_KEY/HEALTH_CA  certificate of a SAN listed in profile "readers"
#   READ_DATABASE_URL   health_reader + audit read login through the Cloud SQL Auth Proxy
#   FAULT_CMD           e.g. kubectl -n agent-sensors exec <exporter-pod-on-node> -c exporter -- kill -STOP 1
#   RESTORE_CMD         e.g. kubectl -n agent-sensors exec <exporter-pod-on-node> -c exporter -- kill -CONT 1
# Optional: LEASE_WAIT_SECONDS (default 30), RECOVERY_TIMEOUT_SECONDS (default 420)
set -euo pipefail

execute=false
[ "${1:-}" = "--execute" ] && execute=true
for v in NODE_UID HEALTH_URL READER_CERT READER_KEY HEALTH_CA READ_DATABASE_URL FAULT_CMD RESTORE_CMD; do
  : "${!v:?set $v}"
done
lease_wait="${LEASE_WAIT_SECONDS:-30}"
recovery_timeout="${RECOVERY_TIMEOUT_SECONDS:-420}"
out="${EVIDENCE_DIR:-./health-recovery-$(date -u +%Y%m%dT%H%M%SZ)}"

snapshot() {
  curl --silent --show-error --fail --cert "$READER_CERT" --key "$READER_KEY" --cacert "$HEALTH_CA" \
    "$HEALTH_URL/internal/control-health?scope=node&scope_id=$NODE_UID"
}
db() { psql "$READ_DATABASE_URL" -v ON_ERROR_STOP=1 -At -c "$1"; }
open_reasons() { snapshot | jq -r '[.open_holds[].reason] | sort | join(",")'; }

cat <<PLAN
plan (node $NODE_UID):
 1. baseline GET /internal/control-health; require state=healthy and no open holds
 2. FAULT_CMD; wait ${lease_wait}s (> lease_ttl 15s + expiry tick 5s)
 3. require open hold lease_expired (owner control-health), node state held,
    execution_held + source_health_changed audit rows for the hold
 4. RESTORE_CMD; heartbeat alone must not release the hold
 5. wait up to ${recovery_timeout}s for probe-runner to report two consecutive
    passes of process/tcp/file (60s interval); require the hold released with
    release_ref auto:control-health:<probe_result_id> of a stored pass, a
    hold_released audit row, node state ready and state=healthy
evidence directory: $out
PLAN
$execute || { echo "dry run: pass --execute to run against the cluster"; exit 0; }

mkdir -p "$out"
snapshot >"$out/01-baseline.json"
jq -e '.state == "healthy" and (.open_holds | length) == 0' "$out/01-baseline.json" >/dev/null ||
  { echo "baseline not healthy; refusing to inject a fault"; exit 1; }
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
restored=false
trap '$restored || { echo "restoring after failure"; eval "$RESTORE_CMD"; }' EXIT
eval "$FAULT_CMD"
sleep "$lease_wait"
snapshot >"$out/02-held.json"
jq -e '[.open_holds[] | select(.reason == "lease_expired" and .owner_component == "control-health")] | length == 1' "$out/02-held.json" >/dev/null ||
  { echo "no lease_expired node hold after the fault"; exit 1; }
hold="$(jq -r '.open_holds[] | select(.reason == "lease_expired") | .hold_id' "$out/02-held.json")"
db "SELECT state FROM health.node_boot_generation WHERE node_uid='$NODE_UID' AND state<>'retired'" | tee "$out/02-node-state.txt" | grep -qx held
db "SELECT count(*) FROM audit.audit_events WHERE event_type='execution_held' AND safe_payload->>'hold_id'='$hold'" | grep -qx 1
eval "$RESTORE_CMD"
restored=true
sleep 10
[ "$(open_reasons)" != "" ] || { echo "heartbeat alone released the hold"; exit 1; }
deadline=$(( $(date +%s) + recovery_timeout ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  ref="$(db "SELECT coalesce(release_ref,'') FROM health.holds WHERE hold_id='$hold'")"
  [ -n "$ref" ] && break
  sleep 15
done
[ -n "${ref:-}" ] || { echo "hold not released within ${recovery_timeout}s"; exit 1; }
echo "$ref" >"$out/03-release-ref.txt"
probe="${ref#auto:control-health:}"
db "SELECT result FROM health.probe_results WHERE probe_result_id='$probe'" | grep -qx pass
db "SELECT count(*) FROM audit.audit_events WHERE event_type='hold_released' AND safe_payload->>'hold_id'='$hold' AND safe_payload->>'release_ref'='$ref'" | grep -qx 1
db "SELECT probe_kind,result,judged_at FROM health.probe_results WHERE node_uid='$NODE_UID' AND judged_at>='$started' ORDER BY judged_at" >"$out/04-probes.txt"
snapshot >"$out/05-recovered.json"
jq -e '.state == "healthy" and (.open_holds | length) == 0' "$out/05-recovered.json" >/dev/null
db "SELECT state FROM health.node_boot_generation WHERE node_uid='$NODE_UID' AND state<>'retired'" | grep -qx ready
echo "recovered: hold $hold released by $ref; evidence in $out"
