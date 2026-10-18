#!/usr/bin/env bash
# Pause or resume the billable compute of one environment without deleting
# anything (TASK-01 platform). Reads the environment lock for the project,
# location, node counts and Cloud SQL instance.
#
#   platform/gcp/scripts/power.sh status [--lock PATH] [--env prod|regression]
#   platform/gcp/scripts/power.sh off    [--lock PATH] [--env prod|regression] [--dry-run]
#   platform/gcp/scripts/power.sh on     [--lock PATH] [--env prod|regression] [--dry-run]
#
# off: every node pool of agentarium-<env> is resized to 0 nodes and the Cloud
#      SQL instance is stopped (activation policy NEVER).
# on:  node pools go back to the lock's node_count and Cloud SQL to ALWAYS.
#
# What keeps costing while off (small): the GKE cluster management fee (unless
# covered by the free tier for one zonal cluster), Cloud SQL storage, the CAS
# DevOps CA, KMS key versions, GCS and Artifact Registry storage. Nothing is
# deleted, so KMS keys, the CA, buckets and the cluster stay as they are.
#
# While off, `terraform plan` shows node_count and Cloud SQL activation policy
# drift. Run `on` before any terraform apply; applying while off would turn the
# resources back on anyway.
#
# Nodes created by `on` register with the start taint again (pool setting), so
# node-readiness must clear them as on any new node (TASK-01 3.5).
set -euo pipefail

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

mode="${1:-}"; shift || true
[[ "$mode" =~ ^(status|off|on)$ ]] || usage
lock="deploy/gcp/environment.lock.json"
env="prod"
dry=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lock) lock="$2"; shift 2 ;;
    --env) env="$2"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    *) usage ;;
  esac
done
[[ -f "$lock" ]] || { echo "lock not found: $lock" >&2; exit 1; }

read_lock() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); exec(sys.argv[2])' "$lock" "$1"; }
project=$(read_lock 'print(d["project"]["id"])')
location=$(read_lock 'print(d["project"]["location"])')
lock_env=$(read_lock 'print(d["environment"])')
sql_instance=$(read_lock 'print(d["storage"]["cloudsql_instance"].split(":")[2])')
[[ "$lock_env" == "$env" ]] || { echo "lock environment is $lock_env, not $env" >&2; exit 1; }
cluster="agentarium-${env}"
# pool name -> node_count from the lock (pool names follow modules/platform/main.tf)
pools=$(read_lock 'print(" ".join(k + "-pool=" + str(v["node_count"]) for k, v in d["node_pools"].items() if isinstance(v, dict) and "node_count" in v))')

if [[ "$location" =~ -[a-z]$ ]]; then loc_flag=(--zone "$location"); else loc_flag=(--region "$location"); fi
gc=(gcloud --project "$project")

run() {
  echo "+ $*"
  if [[ $dry -eq 0 ]]; then "$@"; fi
}

status() {
  echo "project=$project cluster=$cluster location=$location"
  "${gc[@]}" container node-pools list --cluster "$cluster" "${loc_flag[@]}" \
    --format="table(name,config.machineType,initialNodeCount,status)"
  echo "running nodes per pool:"
  "${gc[@]}" compute instances list --filter="name~^gke-${cluster}-" \
    --format="value(name,status)" | awk '{split($1,a,"-"); p=a[4]"-"a[5]; c[p" "$2]++} END{for (k in c) print "  " k ": " c[k]}'
  echo "cloud sql:"
  "${gc[@]}" sql instances describe "$sql_instance" \
    --format="value(name,state,settings.activationPolicy,settings.tier)" | sed 's/^/  /'
}

case "$mode" in
  status) status ;;
  off)
    for p in $pools; do
      run "${gc[@]}" container clusters resize "$cluster" "${loc_flag[@]}" --node-pool "${p%%=*}" --num-nodes 0 --quiet
    done
    run "${gc[@]}" sql instances patch "$sql_instance" --activation-policy=NEVER --quiet
    [[ $dry -eq 1 ]] || status
    ;;
  on)
    run "${gc[@]}" sql instances patch "$sql_instance" --activation-policy=ALWAYS --quiet
    for p in $pools; do
      run "${gc[@]}" container clusters resize "$cluster" "${loc_flag[@]}" --node-pool "${p%%=*}" --num-nodes "${p##*=}" --quiet
    done
    [[ $dry -eq 1 ]] || status
    ;;
esac
