#!/usr/bin/env python3
"""Render deploy/gcp/base for one environment (TASK-01 3.2, TASK-16 step 2).

Fills every ${NAME} placeholder from the environment lock and a values file,
then writes the rendered tree to --out. Rendering fails when a placeholder has
no value, a value is malformed, or a ${...} token is left over; it never falls
back to `latest` or an arbitrary image (TASK-01 3.2).

  python3 deploy/gcp/base/render.py \
      --lock deploy/gcp/environment.lock.json \
      --values <values.json> --out <dir>
  kubectl apply -k <dir>/namespaces   # then admission, rbac

The values file is a JSON object with every placeholder name except the
LOCK_DERIVED names below (PSS_VERSION, AGENTARIUM_ENVIRONMENT, the
CLAIM_KEY_SECRET* pair, the certificate template names, the identity OIDC
lists, BUNDLE_KEY_ID, the gateway and receiver ClusterIPs, RECEIVER_MODE,
the receiver API key SecretProviderClass objects and the audit exporter's two
export buckets). Image lists are comma-separated digest
references in this project's Artifact Registry `agentarium` repository. An
empty string is allowed and is fail-closed: no image matches, so the
admission policies reject every Pod that needs that list.

After rendering, every written manifest is checked for public exposure: a
Service must be ClusterIP (no LoadBalancer, NodePort, ExternalName,
externalIPs or load balancer fields), and no Ingress/Gateway API object or
hostPort may appear (TASK-01 4: private endpoints only).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import re
import shutil
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
PLACEHOLDER = re.compile(r"\$\{([A-Za-z0-9_]+)\}")
# Only the YAML manifests carry placeholders; comments in kustomization files
# mention ${NAME} literally and are copied unchanged.
RENDERED_SUFFIXES = {".yaml"}
SKIPPED_FILES = {"kustomization.yaml"}
# Generators and renderers are source, not install output.
NOT_COPIED_SUFFIXES = {".py", ".pyc"}

IMAGE_LISTS = {
    "IDENTITY_IMAGE", "AUDIT_IMAGE", "HEALTH_IMAGE", "BROKER_IMAGE", "SQL_PROXY_IMAGE",
    "GATEWAY_IMAGE", "COORDINATOR_IMAGE", "RECEIVER_SENDER_IMAGE", "RECEIVER_IMAGE", "EVIDENCE_COLLECTOR_IMAGE",
    "CORRELATION_IMAGE", "NODE_READINESS_IMAGE", "RUNTIME_IMAGE", "PROBE_RUNNER_IMAGE", "PROBE_SINK_IMAGE",
    "PROBE_IMAGES", "AUDIT_EXPORTER_IMAGE",
    "FIXTURE_IMAGES",
    "AGENT_CONTROL_IMAGES",
    "AGENT_ADAPTERS_IMAGES",
    "AGENT_OBSERVE_IMAGES",
    "AGENT_RELEASE_IMAGES",
    "AGENT_TARGETS_IMAGES",
    "AGENT_SENSORS_IMAGES",
    "TETRAGON_IMAGE",
}
# Deployed service images: exactly one digest reference, never empty.
SERVICE_IMAGES = {"IDENTITY_IMAGE", "AUDIT_IMAGE", "HEALTH_IMAGE", "BROKER_IMAGE", "SQL_PROXY_IMAGE",
                  "CORRELATION_IMAGE", "GATEWAY_IMAGE", "COORDINATOR_IMAGE", "RECEIVER_SENDER_IMAGE",
                  "RECEIVER_IMAGE", "EVIDENCE_COLLECTOR_IMAGE", "NODE_READINESS_IMAGE", "PROBE_RUNNER_IMAGE",
                  "PROBE_SINK_IMAGE", "AUDIT_EXPORTER_IMAGE"}
SINGLE_IMAGE = SERVICE_IMAGES | {"RUNTIME_IMAGE", "TETRAGON_IMAGE"}
# TASK-01 3.2 agent-role-contract: a service image must also be on its
# Namespace image list, or admission rejects the Pod after apply.
SERVICE_IMAGE_NAMESPACES = {
    "GATEWAY_IMAGE": "AGENT_CONTROL_IMAGES",
    "COORDINATOR_IMAGE": "AGENT_CONTROL_IMAGES",
    "RECEIVER_SENDER_IMAGE": "AGENT_ADAPTERS_IMAGES",
    "RECEIVER_IMAGE": "AGENT_TARGETS_IMAGES",
    "EVIDENCE_COLLECTOR_IMAGE": "AGENT_OBSERVE_IMAGES",
    "NODE_READINESS_IMAGE": "AGENT_CONTROL_IMAGES",
    # TASK-10 3.2: the agent-adapters probe runner (agent-role-contract) and
    # the agent-targets probe sink.
    "PROBE_RUNNER_IMAGE": "AGENT_ADAPTERS_IMAGES",
    "PROBE_SINK_IMAGE": "AGENT_TARGETS_IMAGES",
    "AUDIT_EXPORTER_IMAGE": "AGENT_OBSERVE_IMAGES",
}
# The probe runner image's command (services/probe-runner/Dockerfile). The
# agent-exec probe contract admits it only as a PROBE_ENTRYPOINTS pair.
PROBE_RUNNER_ENTRYPOINT = "/probe/bin/probe-runner"


# /sys/fs/cgroup: exporter node nonce responder, read-only (#231, #232).
TETRAGON_HOST_PATHS = [
    "/proc", "/sys/fs/bpf", "/var/lib/agentarium/sensor-spool",
    "/var/run/cilium", "/var/run/cilium/tetragon", "/var/run/tetragon", "/sys/fs/cgroup",
]


LOCK_DERIVED = ("SERVICE_CERTIFICATE_TEMPLATE", "CLIENT_CERTIFICATE_TEMPLATE", "PSS_VERSION", "AGENTARIUM_ENVIRONMENT", "CLAIM_KEY_SECRET", "CLAIM_KEY_SECRET_VERSION",
                "OIDC_AUDIENCES", "OIDC_ALLOWED_HD", "BUNDLE_KEY_ID", "GATEWAY_CLUSTER_IP",
                "RECEIVER_CLUSTER_IP", "RECEIVER_PROBE_CLUSTER_IP", "RECEIVER_MODE", "RECEIVER_API_KEY_SECRET_OBJECTS",
                "AUDIT_EVIDENCE_BUCKET", "AUDIT_DECISION_INPUT_EXPORTS_BUCKET")
SECRET_RESOURCE = re.compile(r"projects/[0-9]+/secrets/[A-Za-z0-9_-]{1,255}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?")
PEM_PUBLIC_KEY = re.compile(r"-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n?")
# DER SubjectPublicKeyInfo prefix of an uncompressed P-256 key (id-ecPublicKey,
# prime256v1): the only key type the audit exporter's --keys file accepts.
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
BUCKET = re.compile(r"[a-z0-9][a-z0-9_.-]{1,220}[a-z0-9]")
# TASK-01 4: nothing in the rendered base may publish a workload outside the
# VPC. Gateway API kinds are listed too although no manifest uses them.
EXPOSING_KINDS = {"Ingress", "Gateway", "HTTPRoute", "GRPCRoute", "TLSRoute", "TCPRoute", "UDPRoute"}
SERVICE_EXPOSURE_FIELDS = ("externalIPs", "loadBalancerIP", "loadBalancerSourceRanges", "loadBalancerClass",
                           "externalName", "externalTrafficPolicy", "healthCheckNodePort")
YAML_EXPOSURE = re.compile(
    r"^\s*(type:\s*[\"']?(LoadBalancer|NodePort|ExternalName)\b|externalIPs:|loadBalancer(IP|SourceRanges|Class):|"
    r"hostPort:|kind:\s*[\"']?(" + "|".join(sorted(EXPOSING_KINDS)) + r")[\"']?\s*$)", re.M)


class RenderError(Exception):
    pass


def image_pattern(lock: dict) -> re.Pattern[str]:
    location = lock["project"]["location"]
    region = re.sub(r"-[a-z]$", "", location)
    project = lock["project"]["id"]
    return re.compile(
        rf"^{re.escape(region)}-docker\.pkg\.dev/{re.escape(project)}/agentarium/"
        r"[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$"
    )


def check_value(name: str, value: object, images: re.Pattern[str]) -> str:
    if not isinstance(value, str):
        raise RenderError(f"{name}: value must be a string")
    if name == "TRUST_BUNDLE_PEM":
        # The agent-exec runtime gets the CA bundle as a plain env value
        # (admission forbids volumes and valueFrom). The manifest is JSON, so
        # the PEM text is inserted JSON-escaped.
        if not value or PEM_CERT.sub("", value).strip() or "${" in value:
            raise RenderError(f"{name}: must be one or more PEM CERTIFICATE blocks")
        return json.dumps(value)[1:-1]
    if name == "AUDIT_EXPORTER_PUBLIC_KEY_PEM":
        # The manifest key public key (`gcloud kms keys versions
        # get-public-key`). It is a JSON string inside keys.json, which is
        # itself a JSON string of the ConfigMap, so it is escaped twice.
        m = PEM_PUBLIC_KEY.fullmatch(value)
        try:
            der = base64.b64decode(m.group(1).replace("\n", ""), validate=True) if m else b""
        except ValueError:
            der = b""
        if len(der) != 91 or not der.startswith(P256_SPKI_PREFIX):
            raise RenderError(f"{name}: must be one PEM PUBLIC KEY block of a P-256 key")
        return json.dumps(json.dumps(value)[1:-1])[1:-1]
    if "${" in value or "\n" in value or '"' in value:
        raise RenderError(f"{name}: value contains a placeholder, newline or quote")
    items = [v for v in value.split(",")] if value else []
    if name in SERVICE_IMAGES and not value:
        raise RenderError(f"{name}: deployed service image cannot be empty")
    if name in IMAGE_LISTS:
        if name in SINGLE_IMAGE and len(items) > 1:
            raise RenderError(f"{name}: exactly one image reference expected")
        for item in items:
            if not images.match(item):
                raise RenderError(f"{name}: {item!r} is not a digest reference in {images.pattern}")
    elif name in {"control_plane_endpoint", "cloudsql_private_ip", "node_cidr", "pods_range"}:
        try:
            if name in ("node_cidr", "pods_range"):
                network = ipaddress.ip_network(value, strict=True)
                if network.version != 4 or network.prefixlen == 0:
                    raise ValueError("expected a bounded IPv4 network")
            elif ipaddress.ip_address(value).version != 4:
                raise ValueError("expected IPv4")
        except ValueError as exc:
            raise RenderError(f"{name}: invalid network value") from exc
    elif name == "DISCOVERY_SNAPSHOT_IMAGE":
        # Empty is fail-closed: the discovery-snapshot policies reject every Job.
        if value and not images.match(value):
            raise RenderError(f"{name}: {value!r} is not a digest reference in {images.pattern}")
    elif name == "DISCOVERY_BUCKET":
        if value and not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]", value):
            raise RenderError(f"{name}: {value!r} is not a bucket name")
    elif name == "CLUSTER_UID":
        # Installation cluster UID: canonical lowercase UUID, never empty.
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value) or value == "00000000-0000-0000-0000-000000000000":
            raise RenderError(f"{name}: must be the canonical lowercase cluster UID")
    elif name == "PROBE_ENTRYPOINTS":
        for item in items:
            image, sep, path = item.partition("=")
            if not sep or not images.match(image) or not path.startswith("/"):
                raise RenderError(f"{name}: {item!r} must be <image digest ref>=<absolute path>")
    elif name == "EVIDENCE_PROBE_ACTION_KEY":
        if not UUID.fullmatch(value):
            raise RenderError(f"{name}: must be a lower-case UUID")
    elif name in ("AGENTARIUM_TENANT", "RELEASE_VERSION"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value):
            raise RenderError(f"{name}: must be a short token")
    elif name == "GUARDED_RUNTIME_ENABLED":
        if value not in ("true", "false"):
            raise RenderError(f"{name}: must be \"true\" or \"false\"")
    elif name == "FORBIDDEN_ANNOTATION_KEYS":
        for item in items:
            if not re.fullmatch(r"([a-z0-9.-]+/)?[A-Za-z0-9._-]+", item):
                raise RenderError(f"{name}: {item!r} is not an annotation key")
    elif name == "TETRAGON_HOST_PATHS":
        # TASK-01 3.2.1: exactly the hostPaths the pinned chart and TASK-09
        # values mount (deploy/gcp/sensors/sensor-permissions.json). Empty is
        # fail-closed like the image lists: no Tetragon Pod is admitted.
        if value != "" and (sorted(items) != sorted(TETRAGON_HOST_PATHS) or len(set(items)) != len(items)):
            raise RenderError(f"{name}: must be exactly {','.join(TETRAGON_HOST_PATHS)}")
    return value


def certificate_templates(lock: dict) -> dict[str, str]:
    """Same stable name derivation as shared-resources/pki.tf; no new lock fields."""
    pool = lock.get("pki", {}).get("ca_pool")
    if not isinstance(pool, str) or not re.fullmatch(r"[a-z0-9-]{1,63}", pool):
        raise RenderError("lock pki.ca_pool must be a valid CA pool ID")
    project = lock["project"]["id"]
    region = re.sub(r"-[a-z]$", "", lock["project"]["location"])
    if not re.fullmatch(r"[a-z][a-z0-9-]+", project) or not re.fullmatch(r"[a-z][a-z0-9-]+", region):
        raise RenderError("lock project/location cannot form a CAS resource name")
    prefix = pool if len(pool) <= 55 else pool[:38] + "-" + hashlib.sha256(pool.encode()).hexdigest()[:16]
    return {name: f"projects/{project}/locations/{region}/certificateTemplates/{prefix}-{profile}"
            for name, profile in (("SERVICE_CERTIFICATE_TEMPLATE", "service"),
                                  ("CLIENT_CERTIFICATE_TEMPLATE", "client"))}


def cluster_ip(lock: dict, value: object, name: str) -> str:
    services = ipaddress.ip_network(lock["network"]["services_range"], strict=True)
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise RenderError(f"lock {name} must be an IPv4 address") from exc
    offset = int(ip) - int(services.network_address)
    # GKE gives .1 to kubernetes and .10 to kube-dns (TASK-01 network.gateway_cluster_ip).
    if ip.version != 4 or ip not in services or offset in (0, 1, 10) or offset >= 256:
        raise RenderError(f"lock {name} must be in the first 256 addresses of services_range, not .0/.1/.10")
    return str(ip)


def token_list(lock_value: object, name: str, pattern: str) -> str:
    if not isinstance(lock_value, list) or not lock_value or len(set(lock_value)) != len(lock_value) or \
            not all(isinstance(v, str) and re.fullmatch(pattern, v) for v in lock_value):
        raise RenderError(f"lock {name} must be a non-empty list of distinct values")
    return ",".join(lock_value)


def action_path_lock_values(lock: dict) -> dict:
    """Lock values of the M3-1 action path (identity console, gateway, receiver).

    SPEC-QUESTION (TASK-16 3.1 lock schema): `identity.oidc_audiences`,
    `identity.oidc_allowed_hd` and the whole `receiver` section are not yet
    lock keys. TASK-08 fixes receiver_mode in the lock and TASK-02 takes the
    receiver ClusterIP from it; the receiver API key (TASK-05 credential_binding
    receiver-api-key) is a Secret Manager secret pinned to numeric versions
    like the claim key.
    """
    identity = lock.get("identity") or {}
    audiences = token_list(identity.get("oidc_audiences"), "identity.oidc_audiences", r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}")
    domains = token_list(identity.get("oidc_allowed_hd"), "identity.oidc_allowed_hd",
                         r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
    keys = lock.get("keys") or {}
    key_id = keys.get("bundle_key_id", "")
    if key_id != f"{lock['environment']}-v1":
        raise RenderError("lock keys.bundle_key_id must be prod-v1 for prod and regression-v1 for regression")
    network = lock.get("network") or {}
    gateway_ip = cluster_ip(lock, network.get("gateway_cluster_ip"), "network.gateway_cluster_ip")
    receiver = lock.get("receiver") or {}
    receiver_ip = cluster_ip(lock, receiver.get("cluster_ip"), "receiver.cluster_ip")
    if receiver_ip == gateway_ip:
        raise RenderError("lock receiver.cluster_ip must differ from network.gateway_cluster_ip")
    # TASK-02 targets.yaml receiver-probe: allowed_cidrs is this address /32.
    probe_ip = cluster_ip(lock, receiver.get("probe_cluster_ip"), "receiver.probe_cluster_ip")
    if probe_ip in (gateway_ip, receiver_ip):
        raise RenderError("lock receiver.probe_cluster_ip must differ from the gateway and receiver ClusterIPs")
    mode = receiver.get("receiver_mode")
    if mode not in ("idempotent", "non_idempotent"):
        raise RenderError("lock receiver.receiver_mode must be idempotent or non_idempotent")
    secret = receiver.get("api_key_secret", "")
    versions = receiver.get("api_key_versions")
    if not isinstance(secret, str) or not SECRET_RESOURCE.fullmatch(secret):
        raise RenderError("lock receiver.api_key_secret must be projects/<number>/secrets/<name>")
    if secret == identity.get("claim_key_secret"):
        raise RenderError("lock receiver.api_key_secret must not be the identity claim key")
    # The current version first, then the previous one only while rotating
    # (receiver --api-key-dir accepts one or two version files).
    if not isinstance(versions, list) or not 1 <= len(versions) <= 2 or len(set(versions)) != len(versions) or \
            not all(isinstance(v, str) and re.fullmatch(r"[1-9][0-9]{0,9}", v) for v in versions):
        raise RenderError("lock receiver.api_key_versions must be one or two pinned numeric versions, never latest")
    objects = "".join(f'- resourceName: "{secret}/versions/{v}"\n  path: "{v}"\n' for v in versions)
    # The value lands inside a JSON string of the manifest, so it is escaped.
    return {"OIDC_AUDIENCES": audiences, "OIDC_ALLOWED_HD": domains, "BUNDLE_KEY_ID": key_id,
            "GATEWAY_CLUSTER_IP": gateway_ip, "RECEIVER_CLUSTER_IP": receiver_ip,
            "RECEIVER_PROBE_CLUSTER_IP": probe_ip, "RECEIVER_MODE": mode,
            "RECEIVER_API_KEY_SECRET_OBJECTS": json.dumps(objects)[1:-1]}


def audit_export_lock_values(lock: dict) -> dict:
    """Export buckets of the TASK-07 audit exporter (lock storage section)."""
    storage = lock.get("storage") or {}
    result = {}
    for name, key in (("AUDIT_EVIDENCE_BUCKET", "evidence_bucket"),
                      ("AUDIT_DECISION_INPUT_EXPORTS_BUCKET", "decision_input_exports_bucket")):
        bucket = storage.get(key)
        if not isinstance(bucket, str) or not BUCKET.fullmatch(bucket) or ".." in bucket:
            raise RenderError(f"lock storage.{key} must be a bucket name")
        result[name] = bucket
    if result["AUDIT_EVIDENCE_BUCKET"] == result["AUDIT_DECISION_INPUT_EXPORTS_BUCKET"]:
        raise RenderError("lock storage.evidence_bucket and decision_input_exports_bucket must differ")
    return result


def exposure_errors(rel: Path, text: str) -> list[str]:
    """Public exposure in one rendered manifest (TASK-01 4)."""
    errors = []
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if doc is None:
        for m in YAML_EXPOSURE.finditer(text):
            if not text[:m.start()].rsplit("\n", 1)[-1].lstrip().startswith("#"):
                errors.append(f"{rel}: forbidden exposure {m.group(0).strip()!r}")
        return errors
    objects = doc.get("items", []) if isinstance(doc, dict) and doc.get("kind") == "List" else [doc]

    def walk(node):
        if isinstance(node, dict):
            if "hostPort" in node:
                errors.append(f"{rel}: hostPort is forbidden")
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        kind, name = obj.get("kind"), (obj.get("metadata") or {}).get("name")
        if kind in EXPOSING_KINDS:
            errors.append(f"{rel}: {kind} {name} is forbidden")
        if kind == "Service":
            spec = obj.get("spec") or {}
            if spec.get("type", "ClusterIP") != "ClusterIP":
                errors.append(f"{rel}: Service {name} type {spec.get('type')} is forbidden; use ClusterIP")
            errors += [f"{rel}: Service {name} field {f} is forbidden" for f in SERVICE_EXPOSURE_FIELDS if f in spec]
            if any("nodePort" in p for p in spec.get("ports", [])):
                errors.append(f"{rel}: Service {name} nodePort is forbidden")
        walk(obj)
    return errors


def render(lock: dict, values: dict, out: Path) -> list[Path]:
    minor = lock["gke"]["kubernetes_minor"]
    if not re.fullmatch(r"1\.[0-9]+", minor):
        raise RenderError(f"lock gke.kubernetes_minor {minor!r} is not a minor version")
    for name in LOCK_DERIVED:
        if name in values:
            raise RenderError(f"{name} comes from the lock; remove it from the values file")
    environment = lock["environment"]
    if environment not in ("prod", "regression"):
        raise RenderError("lock environment must be prod or regression")
    # TASK-06 3.3 (#101): the claim key secret and its pinned numeric version.
    identity = lock.get("identity") or {}
    claim_secret = identity.get("claim_key_secret", "")
    claim_version = identity.get("claim_key_version", "")
    if not isinstance(claim_secret, str) or not re.fullmatch(r"projects/[0-9]+/secrets/[A-Za-z0-9_-]{1,255}", claim_secret):
        raise RenderError("lock identity.claim_key_secret must be projects/<number>/secrets/<name>")
    if not isinstance(claim_version, str) or not re.fullmatch(r"[1-9][0-9]*", claim_version):
        raise RenderError("lock identity.claim_key_version must be a pinned numeric version, never latest")
    images = image_pattern(lock)
    resolved = {"PSS_VERSION": f"v{minor}", "AGENTARIUM_ENVIRONMENT": environment,
                "CLAIM_KEY_SECRET": claim_secret, "CLAIM_KEY_SECRET_VERSION": claim_version}
    resolved.update(certificate_templates(lock))
    expected_pool = f"projects/{lock['project']['id']}/locations/{re.sub(r'-[a-z]$', '', lock['project']['location'])}/caPools/{lock['pki']['ca_pool']}"
    if values.get("CA_POOL_ID") != expected_pool:
        raise RenderError("CA_POOL_ID must match the pool in the environment lock")
    resolved.update(action_path_lock_values(lock))
    resolved.update(audit_export_lock_values(lock))
    for name, value in values.items():
        resolved[name] = check_value(name, value, images)
    # The exporter signs manifests with one exact version of the lock's
    # manifest key (TASK-07; IAM grants signerVerifier on that key only).
    if "AUDIT_EXPORTER_KMS_KEY_VERSION" in values:
        key = (lock.get("keys") or {}).get("manifest_signing_key", "")
        if not isinstance(key, str) or not re.fullmatch(r"projects/[a-z][a-z0-9-]+/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+", key):
            raise RenderError("lock keys.manifest_signing_key must be a Cloud KMS cryptoKey name")
        if not re.fullmatch(re.escape(key) + r"/cryptoKeyVersions/[1-9][0-9]{0,9}", values["AUDIT_EXPORTER_KMS_KEY_VERSION"]):
            raise RenderError("AUDIT_EXPORTER_KMS_KEY_VERSION: must be <lock keys.manifest_signing_key>/cryptoKeyVersions/<number>")
    # TASK-01 3.2.1: the privileged Tetragon container is pinned to one digest
    # that is also on the agent-sensors image list.
    tetragon = resolved.get("TETRAGON_IMAGE", "")
    if tetragon and tetragon not in resolved.get("AGENT_SENSORS_IMAGES", "").split(","):
        raise RenderError("TETRAGON_IMAGE: must also be listed in AGENT_SENSORS_IMAGES")
    for name, listed in SERVICE_IMAGE_NAMESPACES.items():
        image = resolved.get(name, "")
        if image and image not in resolved.get(listed, "").split(","):
            raise RenderError(f"{name}: must also be listed in {listed}")
    # The runtime image is admitted by agent-exec-constraints runtimeImage only.
    # TASK-01 3.2 agent-exec-probe-contract: the agent-exec probe runner needs
    # its digest on probeImages and the exact image=entrypoint pair.
    runner = resolved.get("PROBE_RUNNER_IMAGE", "")
    if runner:
        if runner not in resolved.get("PROBE_IMAGES", "").split(","):
            raise RenderError("PROBE_RUNNER_IMAGE: must also be listed in PROBE_IMAGES")
        if f"{runner}={PROBE_RUNNER_ENTRYPOINT}" not in resolved.get("PROBE_ENTRYPOINTS", "").split(","):
            raise RenderError(f"PROBE_ENTRYPOINTS: must pair PROBE_RUNNER_IMAGE with {PROBE_RUNNER_ENTRYPOINT}")
    # The agent-exec runner has no DNS egress (TASK-06), so the sink Service
    # has a fixed ClusterIP like the gateway and receiver.
    # SPEC-QUESTION: TASK-01/16 name no lock key for it; it is a value here.
    if "PROBE_SINK_CLUSTER_IP" in values:
        sink_ip = cluster_ip(lock, values["PROBE_SINK_CLUSTER_IP"], "PROBE_SINK_CLUSTER_IP")
        taken = {resolved[k] for k in ("GATEWAY_CLUSTER_IP", "RECEIVER_CLUSTER_IP", "RECEIVER_PROBE_CLUSTER_IP")}
        if sink_ip in taken:
            raise RenderError("PROBE_SINK_CLUSTER_IP must differ from the gateway and receiver ClusterIPs")

    if out.exists():
        raise RenderError(f"{out} already exists; pass a new directory")
    used: set[str] = set()
    written: list[Path] = []
    for src in sorted(BASE.rglob("*")):
        if src.is_dir() or src.suffix in NOT_COPIED_SUFFIXES or "__pycache__" in src.parts:
            continue
        rel = src.relative_to(BASE)
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.suffix not in RENDERED_SUFFIXES or src.name in SKIPPED_FILES:
            shutil.copyfile(src, dst)
            continue
        text = src.read_text()
        # Only replace placeholders outside comment lines.
        lines = []
        for line in text.splitlines(keepends=True):
            if line.lstrip().startswith("#"):
                lines.append(line)
                continue
            def sub(m: re.Match[str]) -> str:
                name = m.group(1)
                if name not in resolved:
                    raise RenderError(f"{rel}: no value for ${{{name}}}")
                used.add(name)
                return resolved[name]
            lines.append(PLACEHOLDER.sub(sub, line))
        rendered = "".join(lines)
        for line in rendered.splitlines():
            if not line.lstrip().startswith("#") and "${" in line:
                raise RenderError(f"{rel}: unrendered token left: {line.strip()}")
        dst.write_text(rendered)
        written.append(dst)
    unused = set(values) - used
    if unused:
        raise RenderError(f"values not used by any manifest: {sorted(unused)}")
    exposed = [e for path in written for e in exposure_errors(path.relative_to(out), path.read_text())]
    if exposed:
        shutil.rmtree(out)
        raise RenderError("public exposure: " + "; ".join(exposed))
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lock", required=True, type=Path)
    ap.add_argument("--values", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)
    try:
        lock = json.loads(args.lock.read_text())
        values = json.loads(args.values.read_text())
        if not isinstance(values, dict):
            raise RenderError("values file must be a JSON object")
        written = render(lock, values, args.out)
    except (RenderError, KeyError, json.JSONDecodeError) as e:
        print(f"render: {e}", file=sys.stderr)
        return 1
    for p in written:
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
