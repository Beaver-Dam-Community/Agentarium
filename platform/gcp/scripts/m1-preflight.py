#!/usr/bin/env python3
"""Read-only M1 deployment inventory. Does not start, deploy or grant anything.

The report is a prerequisite inventory, not functional proof of CAS issuance,
DB privileges, mTLS requests or event storage. Keep actual reports outside git.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlparse

CONTACTS = {
    "workload-identity": "agent-control",
    "audit-writer": "agent-observe",
    "control-health": "agent-observe",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--kubeconfig", required=True, type=Path)
    parser.add_argument("--account", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    lock = json.loads(args.lock.read_text())
    project = lock["project"]["id"]
    location = lock["project"]["location"]
    environment = lock["environment"]
    cluster = "agentarium-" + environment
    sql_instance = lock["storage"]["cloudsql_instance"].split(":")[-1]
    env = os.environ.copy()
    env.update(CLOUDSDK_CORE_PROJECT=project, CLOUDSDK_CORE_ACCOUNT=args.account,
               KUBECONFIG=str(args.kubeconfig))
    commands = {
        "cluster": ["gcloud", "container", "clusters", "describe", cluster,
                    "--location=" + location,
                    "--format=json(name,status,endpoint,privateClusterConfig.privateEndpoint,controlPlaneEndpointsConfig.dnsEndpointConfig.endpoint)"],
        "kube_server": ["kubectl", "config", "view", "--minify",
                        "-o", "jsonpath={.clusters[0].cluster.server}"],
        "sql": ["gcloud", "sql", "instances", "describe", sql_instance,
                "--format=json(state,settings.activationPolicy,databaseVersion)"],
        "service_accounts": ["gcloud", "iam", "service-accounts", "list",
                             "--format=json(email,disabled)"],
        "nodes": ["kubectl", "--request-timeout=30s", "get", "nodes", "-o", "json"],
        "deployments": ["kubectl", "--request-timeout=30s", "get", "deployments", "-A", "-o", "json"],
        "configmaps": ["kubectl", "--request-timeout=30s", "get", "configmaps", "-A", "-o", "json"],
    }

    def read(item):
        name, command = item
        try:
            result = subprocess.run(command, env=env, capture_output=True, text=True,
                                    timeout=45, check=False)
            if result.returncode:
                # Do not copy arbitrary CLI diagnostic output into evidence.
                return name, None, f"command failed (exit {result.returncode})"
            value = result.stdout.strip() if name == "kube_server" else json.loads(result.stdout)
            return name, value, None
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
            return name, None, type(exc).__name__

    with ThreadPoolExecutor(max_workers=6) as executor:
        fetched = list(executor.map(read, commands.items()))
    data = {name: value for name, value, error in fetched if error is None}
    errors = {name: error for name, value, error in fetched if error is not None}
    checks = []

    def check(name, ok, detail):
        checks.append({"check": name, "pass": bool(ok), "detail": detail})

    check("inventory_complete", not errors, errors)
    cluster_info = data.get("cluster", {})
    endpoints = {cluster_info.get("endpoint"),
                 cluster_info.get("privateClusterConfig", {}).get("privateEndpoint"),
                 cluster_info.get("controlPlaneEndpointsConfig", {}).get("dnsEndpointConfig", {}).get("endpoint")}
    server = urlparse(data.get("kube_server", ""))
    same_cluster = (server.scheme == "https" and server.hostname is not None and
                    server.hostname in endpoints and server.path in ("", "/") and
                    not server.username and not server.query and not server.fragment)
    check("kubeconfig_matches_cluster", same_cluster,
          "kubeconfig server matches an endpoint returned for the selected GKE cluster")
    cluster_state = data.get("cluster", {}).get("status")
    check("cluster_running", cluster_state == "RUNNING", cluster_state)
    sql = data.get("sql", {})
    check("sql_running", sql.get("state") == "RUNNABLE" and
          sql.get("settings", {}).get("activationPolicy") == "ALWAYS", sql)
    nodes = data.get("nodes", {}).get("items", [])
    ready_by_role = {}
    for node in nodes:
        ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in node.get("status", {}).get("conditions", []))
        role = node["metadata"].get("labels", {}).get("node-restriction.kubernetes.io/agentarium-role")
        if ready and role:
            ready_by_role[role] = ready_by_role.get(role, 0) + 1
    # Contact services require control and DNS/system nodes; exec is not M1.
    check("contact_nodes_ready", all(ready_by_role.get(r, 0) > 0 for r in ("control", "system")), ready_by_role)
    accounts = {a.get("email") for a in data.get("service_accounts", []) if not a.get("disabled")}
    deployments = {(d["metadata"]["namespace"], d["metadata"]["name"]): d
                   for d in data.get("deployments", {}).get("items", [])}
    for service, namespace in CONTACTS.items():
        check(service + "_db_identity", f"{service}-db@{project}.iam.gserviceaccount.com" in accounts,
              "enabled DB service account exists")
        deployment = deployments.get((namespace, service), {})
        desired = deployment.get("spec", {}).get("replicas", 1)
        status = deployment.get("status", {})
        observed = status.get("observedGeneration", 0) >= deployment.get("metadata", {}).get("generation", 1)
        check(service + "_deployment", desired > 0 and observed and
              status.get("availableReplicas", 0) >= desired and status.get("updatedReplicas", 0) == desired,
              {"present": bool(deployment), "desired": desired,
               "available": status.get("availableReplicas", 0), "observed_generation_current": observed})
    maps = {(c["metadata"]["namespace"], c["metadata"]["name"]): c
            for c in data.get("configmaps", {}).get("items", [])}
    required_maps = [("agent-control", "agentarium-trust", "ca.pem"),
                     ("agent-observe", "agentarium-trust", "ca.pem"),
                     ("agent-observe", "agentarium-audit-sources", "sources.json"),
                     ("agent-observe", "agentarium-health-profile", "profile.json")]
    for namespace, name, key in required_maps:
        check(f"configmap:{namespace}/{name}", bool(maps.get((namespace, name), {}).get("data", {}).get(key)),
              f"nonempty {key} exists; content validity requires service verification")
    report = {"captured_at": datetime.now(timezone.utc).isoformat(),
              "project": project, "cluster": cluster,
              "prerequisites_present": all(c["pass"] for c in checks),
              "functional_verification": "not performed by this inventory",
              "checks": checks}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    for c in checks:
        print(("PASS" if c["pass"] else "MISSING") + " " + c["check"])
    print("Report:", args.report)
    return 0 if report["prerequisites_present"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
