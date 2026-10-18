#!/usr/bin/env python3
"""Render the TASK-09 node sensor installation (TASK-09 3.1-3.3, TASK-16 4a).

  python3 deploy/gcp/sensors/render.py --values <values.json> \
      --chart <tetragon-1.7.1.tgz> --out <dir> [--permissions <file>]

Outputs in <dir>:
  tetragon.yaml          helm template of cilium/tetragon 1.7.1 with
                         tetragon-values.yaml, post-rendered for the exporter
  policies.yaml          TracingPolicyNamespaced for each observed Namespace and
                         the cluster-scoped tcp-state TracingPolicy
  exporter-config.yaml   ConfigMap agentarium-exporter (config.json)
  sensor-permissions.json  privileges, host namespaces and hostPath mounts
                         extracted from the rendered DaemonSet (TASK-09 3.1)

The chart archive must match CHART_SHA256. Every value is required; a missing
or malformed value fails rendering, and no default image or tag is used.
rule_hash follows TASK-09 4 (PR #185): the JCS SHA-256 of the policies reduced
to {kind, namespace, name, spec} and sorted by (kind, namespace, name); the
exporter recomputes it from the TracingPolicy objects Tetragon loads. Each spec
first gets the pinned 1.7.1 CRD defaults, which the API server fills in when it
stores the policy, from sensors/exporter/capture/crd_defaults.json (the file
the exporter's capture.ApplyCRDDefaults embeds).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
POLICIES = REPO / "sensors" / "tetragon" / "policies"
CRD_DEFAULTS = REPO / "sensors" / "exporter" / "capture" / "crd_defaults.json"
CHART_VERSION = "1.7.1"
CHART_SHA256 = "79ec0f7d35b6fcad99ca317348deac136c00b674430c28be17aa818d2015c632"
NAMESPACE = "agent-sensors"
OBSERVED = ["agent-exec", "agent-adapters"]
EXPORTER = "exporter"
DIGEST = re.compile(r"^[a-z0-9.-]+-docker\.pkg\.dev/[a-z0-9-]+/agentarium/[a-z0-9-]+@sha256:[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[a-z0-9.-]+-docker\.pkg\.dev/[a-z0-9-]+/agentarium$")
ORIGIN = re.compile(r"^https://[a-z0-9.-]+(:[0-9]+)?$")

REQUIRED = {
    "IMAGE_REPOSITORY": REPOSITORY,
    "EXPORTER_IMAGE": DIGEST,
    # The hostNetwork exporter bootstraps through the gateway relay and pins
    # the gateway SAN (TASK-03 3.3), so the origin must be the gateway.
    "IDENTITY_ORIGIN": re.compile(r"^https://policy-gateway\.agent-control\.svc(\.cluster\.local)?(:[0-9]+)?$"),
    "COLLECTOR_ORIGIN": ORIGIN,
    "HEALTH_ORIGIN": ORIGIN,
    "EXPORTER_VERSION": re.compile(r"^[A-Za-z0-9._-]{1,64}$"),
    "SENSOR_GENERATION": re.compile(r"^[1-9][0-9]{0,15}$"),
    "NORMALIZATION_VERSION": re.compile(r"^\S.{0,127}$"),
    "SPOOL_CAPACITY_BYTES": re.compile(r"^[1-9][0-9]{0,11}$"),
}


class RenderError(Exception):
    pass


def load_values(path: Path) -> dict[str, str]:
    values = json.loads(path.read_text())
    if not isinstance(values, dict) or set(values) != set(REQUIRED):
        raise RenderError(f"values must have exactly {sorted(REQUIRED)}")
    for key, pattern in REQUIRED.items():
        if not isinstance(values[key], str) or not pattern.match(values[key]):
            raise RenderError(f"invalid value for {key}")
    return values


def substitute(text: str, values: dict[str, str]) -> str:
    def repl(m: re.Match[str]) -> str:
        if m.group(1) not in values:
            raise RenderError(f"unknown placeholder {m.group(1)}")
        return values[m.group(1)]

    out = re.sub(r"\$\{([A-Z_]+)\}", repl, text)
    if "${" in out:
        raise RenderError("unrendered placeholder")
    return out


def helm(chart: Path, values_file: Path) -> list[dict]:
    digest = hashlib.sha256(chart.read_bytes()).hexdigest()
    if digest != CHART_SHA256:
        raise RenderError(f"chart digest {digest} != pinned {CHART_SHA256}")
    out = subprocess.run(
        ["helm", "template", "tetragon", str(chart), "--namespace", NAMESPACE, "-f", str(values_file)],
        check=True, capture_output=True, text=True,
    ).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def post_render(docs: list[dict]) -> dict:
    daemonsets = [d for d in docs if d.get("kind") == "DaemonSet"]
    if len(daemonsets) != 1:
        raise RenderError("expected exactly one DaemonSet")
    ds = daemonsets[0]
    spec = ds["spec"]["template"]["spec"]
    sidecars = [c for c in spec["containers"] if c["name"] == "export-stdout"]
    if len(sidecars) != 1:
        raise RenderError("chart export sidecar slot not found")
    sidecar = sidecars[0]
    sidecar["name"] = EXPORTER
    mounts = [m for m in sidecar["volumeMounts"] if m["name"] == "export-logs"]
    if len(mounts) != 1:
        raise RenderError("export-logs mount not found")
    # TASK-09 3.1: the export file hostPath is read-only for the exporter.
    mounts[0]["readOnly"] = True
    for d in docs:
        if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "tetragon-config":
            if d["data"].get("enable-process-ns") != "true" or d["data"].get("export-rate-limit") != "-1":
                raise RenderError("pinned Tetragon export settings missing")
    return ds


def policies() -> tuple[str, list[dict]]:
    docs: list[dict] = []
    for name in ("network.yaml", "file-access.yaml"):
        src = yaml.safe_load((POLICIES / name).read_text())
        if src["kind"] != "TracingPolicyNamespaced":
            raise RenderError(f"{name} must be namespaced")
        for ns in OBSERVED:
            doc = json.loads(json.dumps(src))
            doc["metadata"]["namespace"] = ns
            docs.append(doc)
    state = yaml.safe_load((POLICIES / "tcp-state.yaml").read_text())
    if state["kind"] != "TracingPolicy" or "namespace" in state["metadata"]:
        raise RenderError("tcp-state.yaml must be cluster scoped")
    docs.append(state)
    text = "".join("---\n" + yaml.safe_dump(d, sort_keys=True) for d in docs)
    return text, docs


def jcs(value) -> str:
    """RFC 8785 for the value types policy specs use (str, int, bool, None,
    list, dict); floats are rejected because their JCS form needs ES6 rules."""
    def check(v):
        if isinstance(v, float):
            raise RenderError("float in policy spec; JCS number form not implemented")
        if isinstance(v, dict):
            for k, x in v.items():
                if not isinstance(k, str):
                    raise RenderError("non-string key")
                check(x)
        elif isinstance(v, list):
            for x in v:
                check(x)
    check(value)

    def utf16_key(s: str) -> list[int]:
        return list(s.encode("utf-16-be"))

    def enc(v) -> str:
        if isinstance(v, dict):
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(v[k]) for k in sorted(v, key=utf16_key)) + "}"
        if isinstance(v, list):
            return "[" + ",".join(enc(x) for x in v) + "]"
        return json.dumps(v, ensure_ascii=False)
    return enc(value)


def apply_defaults(value, node: dict | None):
    """Structural CRD defaulting, the same walk as capture.ApplyCRDDefaults: a
    missing property with a default gets a copy of it, then defaulting
    continues inside every present value."""
    if not node:
        return
    if isinstance(value, dict):
        props = node.get("properties", {})
        for key, child in props.items():
            if key not in value and "default" in child:
                value[key] = copy.deepcopy(child["default"])
            if key in value:
                apply_defaults(value[key], child)
        extra = node.get("additionalProperties")
        if extra:
            for key, v in value.items():
                if key not in props:
                    apply_defaults(v, extra)
    elif isinstance(value, list):
        for v in value:
            apply_defaults(v, node.get("items"))
    elif value is not None and ("properties" in node or "items" in node):
        raise RenderError("policy spec value does not match the CRD schema shape")


def defaulted_spec(kind: str, spec: dict) -> dict:
    specs = json.loads(CRD_DEFAULTS.read_text())["specs"]
    if kind not in specs:
        raise RenderError(f"no CRD defaults for kind {kind}")
    out = copy.deepcopy(spec)
    apply_defaults(out, specs[kind])
    return out


def compute_rule_hash(docs: list[dict]) -> str:
    elems = [{"kind": d["kind"], "namespace": d["metadata"].get("namespace", ""), "name": d["metadata"]["name"], "spec": defaulted_spec(d["kind"], d["spec"])} for d in docs]
    elems.sort(key=lambda e: (e["kind"], e["namespace"], e["name"]))
    return hashlib.sha256(jcs(elems).encode("utf-8")).hexdigest()


# TASK-09 3.5 capture check 3: keys the exporter compares as an exact set.
INVARIANTS = {
    "enable-process-ns": "true", "export-rate-limit": "-1", "export-denylist": '{"health_check":true}',
    "export-file-compress": "false", "export-file-perm": "600", "field-filters": "", "redaction-filters": "",
    "metrics-server": "127.0.0.1:2112",
}


def export_key(k: str) -> bool:
    return k.startswith("export-") or "filter" in k


def tetragon_settings(docs: list[dict]) -> dict[str, str]:
    cms = [d for d in docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "tetragon-config"]
    if len(cms) != 1:
        raise RenderError("tetragon-config ConfigMap not found")
    data = cms[0]["data"]
    settings = {k: str(v).strip() for k, v in data.items() if export_key(k) or k in INVARIANTS}
    for k, v in INVARIANTS.items():
        if settings.get(k) != v:
            raise RenderError(f"tetragon-config {k} must be {v!r}, got {settings.get(k)!r}")
    if settings.get("export-filename") != "/var/run/cilium/tetragon/tetragon.log":
        raise RenderError("unexpected export-filename")
    return settings


def exporter_config(values: dict[str, str], rule_hash: str, settings: dict[str, str]) -> dict:
    config = {
        "version": values["EXPORTER_VERSION"],
        "export_file": "/var/run/cilium/tetragon/tetragon.log",
        # live file + exportFileMaxBackups (5)
        "export_max_files": 6,
        "max_line_bytes": 1048576,
        # A subdirectory the exporter creates 0700: kubelet creates the
        # DirectoryOrCreate hostPath itself as 0755, which the journal's
        # owner-only check rejects.
        "spool_dir": "/var/lib/agentarium/sensor-spool/journal",
        "spool_capacity_bytes": int(values["SPOOL_CAPACITY_BYTES"]),
        "boot_id_path": "/proc/sys/kernel/random/boot_id",
        "collector_origin": values["COLLECTOR_ORIGIN"],
        "health_origin": values["HEALTH_ORIGIN"],
        "identity_origin": values["IDENTITY_ORIGIN"],
        # hostNetwork node components bootstrap through the gateway relay
        # (TASK-03 3.3); IDENTITY_ORIGIN is the gateway.
        "identity_peer_san": "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway",
        "token_file": "/var/run/secrets/agentarium-identity/token",
        "ca_file": "/etc/agentarium-trust/ca.pem",
        # Tetragon's chart default metrics listener on the shared host network.
        "metrics_endpoint": "http://127.0.0.1:2112/metrics",
        # tetragon-config mounted read-only for the TASK-09 3.5 capture check.
        "tetragon_config_dir": "/etc/tetragon-config",
        "tetragon_settings": settings,
        "tetragon_version": CHART_VERSION,
        "sensor_generation": int(values["SENSOR_GENERATION"]),
        "rule_hash": rule_hash,
        "normalization_version": values["NORMALIZATION_VERSION"],
        "recovery_reason": "wal_segment_corrupt",
        "allowed_binaries": [],
        "protected_paths": ["/work/protected-fixture"],
        "observed_namespaces": OBSERVED,
        "metadata_grace_seconds": 30,
        "pod_retention_seconds": 900,
        # Node nonce responder (#232): read-only host mounts from
        # tetragon-values.yaml and the one approved runtime worker executable
        # (services/runtime image, /app/bin/agent-worker, #234).
        "proc_root": "/host/proc",
        "cgroup_root": "/host/sys/fs/cgroup",
        "worker_binaries": ["/app/bin/agent-worker"],
    }
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "agentarium-exporter", "namespace": NAMESPACE, "labels": {"app.kubernetes.io/name": "tetragon"}},
        "data": {"config.json": json.dumps(config, indent=2, sort_keys=True) + "\n"},
    }


def permissions(ds: dict) -> dict:
    spec = ds["spec"]["template"]["spec"]
    volumes = {v["name"]: v for v in spec.get("volumes", [])}
    containers = []
    for c in (spec.get("initContainers") or []) + spec["containers"]:
        sc = c.get("securityContext", {})
        mounts = []
        for m in c.get("volumeMounts", []):
            v = volumes[m["name"]]
            if "hostPath" in v:
                mounts.append({"host_path": v["hostPath"]["path"], "mount_path": m["mountPath"], "read_only": bool(m.get("readOnly", False)),
                               "recursive_read_only": m.get("recursiveReadOnly"), "mount_propagation": m.get("mountPropagation")})
        containers.append({
            "name": c["name"],
            "privileged": bool(sc.get("privileged", False)),
            "run_as_user": sc.get("runAsUser"),
            "run_as_group": sc.get("runAsGroup"),
            "capabilities_add": sorted(sc.get("capabilities", {}).get("add", [])),
            "capabilities_drop": sorted(sc.get("capabilities", {}).get("drop", [])),
            "host_path_mounts": sorted(mounts, key=lambda x: (x["host_path"], x["mount_path"])),
        })
    host_paths = sorted({v["hostPath"]["path"] for v in volumes.values() if "hostPath" in v})
    return {
        "source": "deploy/gcp/sensors/render.py (helm template cilium/tetragon " + CHART_VERSION + ")",
        "service_account": spec["serviceAccountName"],
        "host_network": bool(spec.get("hostNetwork", False)),
        "host_pid": bool(spec.get("hostPID", False)),
        "host_ipc": bool(spec.get("hostIPC", False)),
        "dns_policy": spec.get("dnsPolicy"),
        "host_paths": host_paths,
        "containers": containers,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--values", type=Path, required=True)
    ap.add_argument("--chart", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    try:
        values = load_values(args.values)
        args.out.mkdir(parents=True, exist_ok=True)
        rendered_values = args.out / "values.rendered.yaml"
        rendered_values.write_text(substitute((HERE / "tetragon-values.yaml").read_text(), values))
        docs = helm(args.chart, rendered_values)
        ds = post_render(docs)
        policy_text, policy_docs = policies()
        (args.out / "policies.yaml").write_text(policy_text)
        rule_hash = compute_rule_hash(policy_docs)
        config_doc = exporter_config(values, rule_hash, tetragon_settings(docs))
        config_text = yaml.safe_dump(config_doc, sort_keys=False)
        (args.out / "exporter-config.yaml").write_text(config_text)
        # Restart the DaemonSet when the exporter config changes; the exporter
        # reads it once at start (and the sensor_policy baseline sees it).
        ds["spec"]["template"]["metadata"].setdefault("annotations", {})["checksum/exporter-config"] = hashlib.sha256(config_doc["data"]["config.json"].encode()).hexdigest()
        (args.out / "tetragon.yaml").write_text("".join("---\n" + yaml.safe_dump(d, sort_keys=False) for d in docs))
        (args.out / "sensor-permissions.json").write_text(json.dumps(permissions(ds), indent=2) + "\n")
    except (RenderError, subprocess.CalledProcessError, KeyError, ValueError) as e:
        print(f"render failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
