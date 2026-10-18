#!/usr/bin/env python3
"""Live admission checks for the policies added after run 20261014-task01-admission.

Covers what that run did not: VAP typeChecking on the API server,
agent-role-status-metadata (pods/status relabel/annotate), the
agent-exec-profile pods/resize rule, node-readiness-scope (target-node limit
and taint-only scope) and agent-sensors-contract. Results are written as JSON
lines (one per case) for evidence/gcp/runs/<run_id>/observed.jsonl.

Preconditions: KUBECONFIG points at the cluster; deploy/gcp/base is applied
and rendered with values that allow the given images (AGENT_TARGETS_IMAGES has
--target-image, PROBE_IMAGES/PROBE_ENTRYPOINTS have --probe-image at
/app/bin/probe-runner). Mutating cases use dryRun=All except the two Pods
created for status/resize, which are deleted afterwards. A temporary
ClusterRole/Binding grants the node-readiness KSA its spec permissions on
nodes (get/list/watch/patch) for the duration of the node checks and is
deleted afterwards.

  python3 tests/platform/admission/live_delta_check.py \
      --target-image <digest ref> --probe-image <digest ref> --out observed.jsonl
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

AGENT_VAPS = [
    "agent-exec-contract", "agent-exec-probe-contract", "agent-exec-profile",
    "agent-role-contract", "agent-role-status-metadata", "agent-sensors-contract",
    "node-readiness-scope",
]
NR_USER = "system:serviceaccount:agent-control:node-readiness"
ROLE = "node-restriction.kubernetes.io/agentarium-role"
START = "agentarium.io/observe-not-ready"


def kubectl(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["kubectl", *args], input=stdin, capture_output=True, text=True)


def full(res: subprocess.CompletedProcess) -> str:
    # PodSecurity "would violate" warnings (agent-sensors warns at restricted) are
    # not admission results; drop them so the policy message is what remains.
    lines = (res.stdout + res.stderr).splitlines()
    return " ".join(l for l in lines if not l.startswith("Warning:")).strip()


def out(res: subprocess.CompletedProcess) -> str:
    return full(res)[:400]


class Recorder:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, case: str, expected: str, observed: str, ok: bool) -> None:
        self.rows.append({"case": case, "expected": expected, "observed": observed,
                          "outcome": "pass" if ok else "fail"})
        print(("PASS " if ok else "FAIL ") + case + ": " + observed[:160], file=sys.stderr)

    def expect_denied(self, case: str, marker: str, res: subprocess.CompletedProcess) -> None:
        # marker may list alternatives separated by "|": a VAP reports its first
        # failing validation, so a request that breaks two rules shows either.
        f = full(res)
        self.add(case, f"denied ({marker})", out(res),
                 res.returncode != 0 and any(m in f for m in marker.split("|")))

    def expect_admitted(self, case: str, res: subprocess.CompletedProcess) -> None:
        o = out(res)
        self.add(case, "admitted", o, res.returncode == 0)


def pod_yaml(name: str, ns: str, sa: str, image: str, node_role: str, extra_tol: bool,
             command: str | None = None, uid: int = 65532) -> str:
    tol = [{"key": START, "operator": "Equal", "value": "true", "effect": "NoSchedule"}] if extra_tol else []
    if node_role == "exec":
        tol.append({"key": "agentarium-role", "operator": "Equal", "value": "exec", "effect": "NoSchedule"})
    c = {"name": "main", "image": image,
         "securityContext": {"runAsUser": uid, "runAsNonRoot": True, "readOnlyRootFilesystem": True,
                             "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
         "resources": {"requests": {"cpu": "50m", "memory": "32Mi", "ephemeral-storage": "32Mi"},
                       "limits": {"cpu": "200m", "memory": "64Mi", "ephemeral-storage": "64Mi"}}}
    spec = {"serviceAccountName": sa, "automountServiceAccountToken": False, "restartPolicy": "Never",
            "schedulerName": "default-scheduler", "nodeSelector": {ROLE: node_role}, "tolerations": tol,
            "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [c]}
    if command:
        c["command"] = [command]
        c["env"] = [{"name": "Q0_TCP_TARGET", "value": ""}, {"name": "Q0_COUNT", "value": "1"}]
        c["volumeMounts"] = [{"name": "work", "mountPath": "/work"}]
        spec["volumes"] = [{"name": "work", "emptyDir": {"sizeLimit": "16Mi"}}]
    return json.dumps({"apiVersion": "v1", "kind": "Pod",
                       "metadata": {"name": name, "namespace": ns, "labels": {"app.kubernetes.io/name": sa}},
                       "spec": spec})


def wait_ready(ns: str, name: str) -> bool:
    return kubectl("-n", ns, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=120s").returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-image", required=True)
    ap.add_argument("--probe-image", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    r = Recorder()

    # 1. typeChecking on the API server
    vaps = json.loads(kubectl("get", "validatingadmissionpolicies", "-o", "json").stdout)["items"]
    by = {v["metadata"]["name"]: v for v in vaps}
    for n in AGENT_VAPS:
        v = by.get(n)
        st = (v or {}).get("status", {})
        warns = (st.get("typeChecking") or {}).get("expressionWarnings") or []
        ok = v is not None and st.get("observedGeneration") == v["metadata"]["generation"] and not warns
        r.add(f"typecheck.{n}", "present, observedGeneration == generation, 0 expressionWarnings",
              "missing" if v is None else f"gen={v['metadata']['generation']} observed={st.get('observedGeneration')} warnings={len(warns)}", ok)

    # 2. agent-role-status-metadata on a real agent-targets Pod
    kubectl("-n", "agent-targets", "create", "sa", "admission-probe")
    kubectl("apply", "-f", "-", stdin=pod_yaml("delta-status", "agent-targets", "admission-probe", a.target_image, "control", True))
    if wait_ready("agent-targets", "delta-status"):
        base = ["-n", "agent-targets", "patch", "pod", "delta-status", "--subresource=status", "--type=merge", "--dry-run=server", "-p"]
        r.expect_denied("role_status.relabel", "ROLE_STATUS_METADATA_IMMUTABLE",
                        kubectl(*base, json.dumps({"metadata": {"labels": {"app.kubernetes.io/name": "policy-gateway"}}})))
        r.expect_denied("role_status.annotate", "ROLE_STATUS_METADATA_IMMUTABLE",
                        kubectl(*base, json.dumps({"metadata": {"annotations": {"example.com/x": "y"}}})))
        r.expect_admitted("role_status.status_only",
                          kubectl(*base, json.dumps({"status": {"conditions": [{"type": "ZZDeltaProbe", "status": "True"}]}})))
    else:
        r.add("role_status.pod_ready", "Running", "pod did not become Ready", False)
    kubectl("-n", "agent-targets", "delete", "pod", "delta-status", "--wait=false")
    kubectl("-n", "agent-targets", "delete", "sa", "admission-probe")

    # 3. agent-exec-profile pods/resize on a real probe Pod
    kubectl("-n", "agent-exec", "create", "sa", "probe-runner")
    kubectl("apply", "-f", "-", stdin=pod_yaml("delta-resize", "agent-exec", "probe-runner", a.probe_image, "exec", True,
                                                command="/app/bin/probe-runner", uid=10001))
    if wait_ready("agent-exec", "delta-resize"):
        r.expect_denied("exec_profile.resize_cpu_limit", "EXEC_RESIZE_FORBIDDEN",
                        kubectl("-n", "agent-exec", "patch", "pod", "delta-resize", "--subresource=resize", "--type=strategic",
                                "--dry-run=server", "-p", json.dumps({"spec": {"containers": [{"name": "main", "resources": {"limits": {"cpu": "300m"}}}]}})))
        r.expect_denied("exec_profile.status_relabel", "EXEC_STATUS_METADATA_IMMUTABLE|EXEC_ROLE_LABEL_INVALID",
                        kubectl("-n", "agent-exec", "patch", "pod", "delta-resize", "--subresource=status", "--type=merge",
                                "--dry-run=server", "-p", json.dumps({"metadata": {"labels": {"app.kubernetes.io/name": "agent-runtime"}}})))
    else:
        r.add("exec_profile.pod_ready", "Running", "pod did not become Ready", False)
    kubectl("-n", "agent-exec", "delete", "pod", "delta-resize", "--wait=false")
    kubectl("-n", "agent-exec", "delete", "sa", "probe-runner")

    # 4. node-readiness-scope with the node-readiness KSA (temporary RBAC)
    kubectl("create", "clusterrole", "zz-delta-nr", "--verb=get,list,watch,patch", "--resource=nodes")
    kubectl("create", "clusterrolebinding", "zz-delta-nr", "--clusterrole=zz-delta-nr", "--serviceaccount=agent-control:node-readiness")
    time.sleep(3)
    nodes = json.loads(kubectl("get", "nodes", "-o", "json").stdout)["items"]
    def node(role: str) -> dict:
        return next(n for n in nodes if n["metadata"]["labels"].get(ROLE) == role)
    def taint_patch(n: dict, add: dict | None, drop_start: bool) -> str:
        t = [x for x in n["spec"].get("taints", []) if not (drop_start and x["key"] == START)]
        if add:
            t.append(add)
        return json.dumps({"spec": {"taints": t}})
    as_nr = ["--as", NR_USER]
    sysn, exe = node("system"), node("exec")
    r.expect_denied("node_readiness.system_add_start_taint", "NODE_READINESS_SCOPE_INVALID",
                    kubectl(*as_nr, "patch", "node", sysn["metadata"]["name"], "--type=merge", "--dry-run=server",
                            "-p", taint_patch(sysn, {"key": START, "value": "true", "effect": "NoSchedule"}, False)))
    r.expect_admitted("node_readiness.exec_remove_start_taint",
                      kubectl(*as_nr, "patch", "node", exe["metadata"]["name"], "--type=merge", "--dry-run=server",
                              "-p", taint_patch(exe, None, True)))
    r.expect_denied("node_readiness.exec_add_other_taint", "NODE_READINESS_SCOPE_INVALID",
                    kubectl(*as_nr, "patch", "node", exe["metadata"]["name"], "--type=merge", "--dry-run=server",
                            "-p", taint_patch(exe, {"key": "other", "value": "x", "effect": "NoSchedule"}, False)))
    r.expect_denied("node_readiness.exec_change_role_label", "NODE_READINESS_SCOPE_INVALID",
                    kubectl(*as_nr, "patch", "node", exe["metadata"]["name"], "--type=merge", "--dry-run=server",
                            "-p", json.dumps({"metadata": {"labels": {ROLE: "control"}}})))
    kubectl("delete", "clusterrolebinding", "zz-delta-nr")
    kubectl("delete", "clusterrole", "zz-delta-nr")

    # 5. agent-sensors-contract (dryRun=All). The running Tetragon DaemonSet is the admitted case.
    ds = json.loads(kubectl("-n", "agent-sensors", "get", "ds", "tetragon", "-o", "json").stdout)
    ready = ds.get("status", {}).get("numberReady", 0)
    r.add("sensors.tetragon_admitted", "Tetragon DaemonSet Pods admitted and Ready", f"numberReady={ready}", ready > 0)
    tpl = ds["spec"]["template"]
    def sensor_pod(mut) -> str:
        p = {"apiVersion": "v1", "kind": "Pod",
             "metadata": {"name": "delta-sensor", "namespace": "agent-sensors", "labels": dict(tpl["metadata"]["labels"])},
             "spec": json.loads(json.dumps(tpl["spec"]))}
        mut(p)
        return json.dumps(p)
    def dry(case: str, marker: str, mut) -> None:
        r.expect_denied(case, marker, kubectl("apply", "--dry-run=server", "-f", "-", stdin=sensor_pod(mut)))
    def bad_image(p): p["spec"]["containers"][0]["image"] = a.target_image
    def bad_hostpath(p): p["spec"]["volumes"].append({"name": "etc", "hostPath": {"path": "/etc"}})
    def host_ipc(p): p["spec"]["hostIPC"] = True
    def bad_label(p): p["metadata"]["labels"]["app.kubernetes.io/name"] = "lifecycle-recorder"
    dry("sensors.image_not_allowed", "SENSORS_IMAGE_NOT_ALLOWED", bad_image)
    dry("sensors.hostpath_not_allowed", "SENSORS_HOSTPATH_NOT_ALLOWED", bad_hostpath)
    dry("sensors.host_ipc", "SENSORS_HOST_NAMESPACE_FORBIDDEN", host_ipc)
    dry("sensors.label_sa_mismatch", "SENSORS_IDENTITY_INVALID", bad_label)

    with open(a.out, "w") as f:
        for row in r.rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    failed = sum(row["outcome"] == "fail" for row in r.rows)
    print(f"{len(r.rows) - failed}/{len(r.rows)} passed", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
