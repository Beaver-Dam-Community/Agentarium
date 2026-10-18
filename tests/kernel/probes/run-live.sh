#!/usr/bin/env bash
# One-command live check of TASK-09 "answer event observation" (TASK-09 7 behaviour
# observation, connection attempt and establishment, denied open). Runs the kernel-stimulus answer key as a
# probe-runner Pod in agent-exec on one exec node, collects the exporter's
# fsynced KernelEvents (and, with KERNEL_PROBES_DSN, the stored
# audit.kernel_events rows), and writes a COMMON result record under
# evidence/gcp/runs/<RUN_ID>/. See README.md for prerequisites.
#
#   KUBE_CONTEXT=<context> STIMULUS_TCP_OPEN=<host:port allowed for probe-runner> \
#   STIMULUS_IMAGE=<region>-docker.pkg.dev/<project>/agentarium/kernel-stimulus@sha256:<d> \
#     tests/kernel/probes/run-live.sh
#
# KUBE_CONTEXT is required and passed to every kubectl call. STIMULUS_TCP_OPEN
# is required: it must be a destination the TASK-06 policy allows for
# agent-exec/probe-runner (for example the probe-sink Service on 8443).
# Optional: KERNEL_PROBES_DSN (read-only audit DB via Cloud SQL Proxy),
# STIMULUS_TCP_FAILED (default 169.254.169.254:80, denied for agent-exec),
# STIMULUS_COUNT (10), RUN_ID, NODE (exec node name), FLUSH_SECONDS (15).
set -euo pipefail
cd "$(dirname "$0")/../../.."
: "${KUBE_CONTEXT:?KUBE_CONTEXT is required; every kubectl call uses --context}"
: "${STIMULUS_TCP_OPEN:?STIMULUS_TCP_OPEN (allowed destination for probe-runner) is required}"
: "${STIMULUS_IMAGE:?STIMULUS_IMAGE digest reference is required}"
kubectl() { command kubectl --context "$KUBE_CONTEXT" "$@"; }
kubectl get namespace agent-exec >/dev/null || { echo "context $KUBE_CONTEXT has no agent-exec" >&2; exit 2; }
[[ "$STIMULUS_IMAGE" == *@sha256:* ]] || { echo "STIMULUS_IMAGE must be a digest reference" >&2; exit 2; }
count="${STIMULUS_COUNT:-10}"
run_id="${RUN_ID:-$(date -u +%Y%m%d-%H%M%S)-task09-kernel-ground-truth}"
out="evidence/gcp/runs/$run_id"
raw="$out/raw"
mkdir -p "$raw"
pod="kernel-stimulus-$(date -u +%H%M%S)"
cleanup() { kubectl -n agent-exec delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== preflight"
kubectl -n agent-sensors rollout status daemonset/tetragon --timeout=120s
kubectl -n agent-sensors get daemonset tetragon -o jsonpath='{.spec.template.spec.containers[*].name}' | tr ' ' '\n' | grep -qx exporter \
  || { echo "tetragon DaemonSet has no exporter sidecar (deploy/gcp/sensors)" >&2; exit 2; }
node="${NODE:-}"
if [[ -z "$node" ]]; then
  node="$(kubectl get nodes -l node-restriction.kubernetes.io/agentarium-role=exec -o jsonpath='{.items[0].metadata.name}')"
fi
[[ -n "$node" ]] || { echo "no exec node" >&2; exit 2; }
tpod="$(kubectl -n agent-sensors get pods -l app.kubernetes.io/name=tetragon --field-selector spec.nodeName="$node" -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$tpod" ]] || { echo "no tetragon Pod on $node" >&2; exit 2; }
node_uid="$(kubectl get node "$node" -o jsonpath='{.metadata.uid}')"
open="$STIMULUS_TCP_OPEN"
failed="${STIMULUS_TCP_FAILED:-169.254.169.254:80}"

echo "== stimulus on $node"
kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata: {name: $pod, namespace: agent-exec, labels: {app.kubernetes.io/name: probe-runner}}
spec:
  serviceAccountName: probe-runner
  automountServiceAccountToken: false
  restartPolicy: Never
  nodeSelector: {node-restriction.kubernetes.io/agentarium-role: exec}
  affinity: {nodeAffinity: {requiredDuringSchedulingIgnoredDuringExecution: {nodeSelectorTerms: [{matchFields: [{key: metadata.name, operator: In, values: [$node]}]}]}}}
  tolerations:
    - {key: agentarium-role, operator: Equal, value: exec, effect: NoSchedule}
    - {key: agentarium.io/observe-not-ready, operator: Equal, value: "true", effect: NoSchedule}
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: probe-runner
      image: $STIMULUS_IMAGE
      command: [/app]
      env:
        - {name: STIMULUS_COUNT, value: "$count"}
        - {name: STIMULUS_TCP_OPEN, value: "$open"}
        - {name: STIMULUS_TCP_FAILED, value: "$failed"}
      securityContext: {runAsUser: 10001, runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      resources: {requests: {cpu: 50m, memory: 32Mi, ephemeral-storage: 32Mi}, limits: {cpu: 200m, memory: 64Mi, ephemeral-storage: 64Mi}}
      volumeMounts: [{name: work, mountPath: /work}]
  volumes: [{name: work, emptyDir: {sizeLimit: 16Mi}}]
YAML
kubectl -n agent-exec wait --for=condition=Ready "pod/$pod" --timeout=180s
for i in $(seq 1 120); do
  kubectl -n agent-exec logs "$pod" > "$raw/stimulus.jsonl"
  grep -q '"kind":"done"' "$raw/stimulus.jsonl" && break
  sleep 2
done
grep -q '"kind":"done"' "$raw/stimulus.jsonl" || { echo "stimulus did not finish" >&2; exit 2; }
pod_uid="$(kubectl -n agent-exec get pod "$pod" -o jsonpath='{.metadata.uid}')"
kubectl -n agent-exec get pod "$pod" -o json > "$raw/stimulus-pod.json"

echo "== collect"
sleep "${FLUSH_SECONDS:-15}"
kubectl -n agent-sensors exec "$tpod" -c exporter -- /app inspect-wal /var/lib/agentarium/sensor-spool/journal > "$raw/wal.ndjson"
cat > "$out/manifest.json" <<JSON
{"run_id": "$run_id", "implementation_commit": "$(git rev-parse HEAD)", "kube_context": "$KUBE_CONTEXT",
 "node": "$node", "node_uid": "$node_uid", "tetragon_pod": "$tpod", "stimulus_pod_uid": "$pod_uid",
 "stimulus_image": "$STIMULUS_IMAGE", "exporter_image": "$(kubectl -n agent-sensors get pod "$tpod" -o jsonpath='{.spec.containers[?(@.name=="exporter")].image}')",
 "tcp_open": "$open", "tcp_failed": "$failed", "count": $count, "db_source": $([[ -n "${KERNEL_PROBES_DSN:-}" ]] && echo true || echo false)}
JSON

echo "== assert"
args=(--stimulus "$raw/stimulus.jsonl" --wal "$raw/wal.ndjson" --pod-uid "$pod_uid" --node-uid "$node_uid" --run-id "$run_id" --out "$out")
# Build first: `go run` maps every non-zero exit to 1, which would hide the
# "could not evaluate" (2) result.
bin="$(mktemp -d)/kernel-assert"
go build -o "$bin" ./tests/kernel/probes/cmd/kernel-assert
set +e
"$bin" "${args[@]}"
code=$?
set -e
echo "result: $out/summary.json (exit $code)"
exit $code
