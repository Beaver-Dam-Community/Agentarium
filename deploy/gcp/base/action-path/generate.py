#!/usr/bin/env python3
"""Generate the M3-1 action path manifests (TASK-01 3.2, TASK-06 3.1/3.3).

  python3 deploy/gcp/base/action-path/generate.py           # rewrite the files
  python3 deploy/gcp/base/action-path/generate.py --check   # fail on drift

Writes two JSON Kubernetes Lists next to this file, both rendered later by
deploy/gcp/base/render.py like contact-services/contacts.yaml:

  services.yaml       gateway, coordinator, receiver-sender, receiver and
                      evidence-collector: KSA, epoch PVC, Deployment, ClusterIP
                      Service (the collector has no Service; the receiver also
                      has the receiver-probe Service)
  agent-runtime.yaml  one agent-exec runtime Pod for the M3-1 demo, applied
                      only after the console session exists (runbook step 9)

Flags follow the merged-together binaries of the M3-1 code PRs (#218 cert
bootstrap, #220/#222/#223/#225/#227/#230/#234/#236/#237). Each workload
bootstraps its certificate in memory from workload-identity with a projected
`agentarium-identity` token; there are no certificate files in GKE.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPIFFE = "spiffe://agentarium.internal/ns/{}/sa/{}"
IDENTITY = "--identity-url=https://workload-identity.agent-control.svc:8443"
TOKEN = "--bootstrap-token=/var/run/agentarium-bootstrap/token"
HEALTH = "--health-url=https://control-health.agent-observe.svc:8443"
TRUST = "/etc/agentarium-trust/ca.pem"
EPOCH = "/var/lib/agentarium/epoch"
VERSION = "${RELEASE_VERSION}"
BUNDLE_ARGS = ["--bundle-key-id=${BUNDLE_KEY_ID}", "--bundle-key-file=/etc/agentarium-bundle-keys/${BUNDLE_KEY_ID}.pem"]
# Bootstrap role Namespaces tolerate the observation start taint (TASK-01 3
# item 3, 3.5); agent-adapters must not (ROLE_ADAPTER_BOOTSTRAP_TOLERATION_FORBIDDEN).
START_TAINT = [{"key": "agentarium.io/observe-not-ready", "operator": "Equal", "value": "true", "effect": "NoSchedule"}]
HARDENED = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
POD_SECURITY = {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
                "seccompProfile": {"type": "RuntimeDefault"}}


def proxy(prefix: str) -> dict:
    """Cloud SQL Auth Proxy native sidecar, the contact-services shape."""
    return {
        "name": "cloud-sql-proxy", "image": "${SQL_PROXY_IMAGE}", "restartPolicy": "Always",
        "args": ["--auto-iam-authn", "--private-ip", "--address=127.0.0.1", "--port=5432", "--health-check",
                 "--http-address=0.0.0.0", "--http-port=9801",
                 "--impersonate-service-account=${%s_DB_GSA}" % prefix, "${CLOUDSQL_CONNECTION_NAME}"],
        "securityContext": copy.deepcopy(HARDENED),
        "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}},
        "startupProbe": {"httpGet": {"path": "/startup", "port": 9801}, "periodSeconds": 2, "failureThreshold": 60},
        "readinessProbe": {"httpGet": {"path": "/readiness", "port": 9801}, "periodSeconds": 5},
        "livenessProbe": {"httpGet": {"path": "/liveness", "port": 9801}, "periodSeconds": 10},
    }


def env(prefix: str, extra: list[dict]) -> list[dict]:
    return extra + [
        {"name": "DB_USER", "value": "${%s_DB_USER}" % prefix},
        {"name": "DB_NAME", "value": "${DB_NAME}"},
        {"name": "DATABASE_URL", "value": "host=127.0.0.1 port=5432 user=$(DB_USER) dbname=$(DB_NAME) sslmode=disable"},
    ]


POD_NAME = {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}
POD_UID = {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}


def mount(name: str, path: str, read_only: bool = True) -> dict:
    m = {"name": name, "mountPath": path}
    if read_only:
        m["readOnly"] = True
    return m


def config_map(name: str, cm: str) -> dict:
    return {"name": name, "configMap": {"name": cm}}


BOOTSTRAP = {"name": "bootstrap", "projected": {"sources": [{"serviceAccountToken": {
    "path": "token", "expirationSeconds": 600, "audience": "agentarium-identity"}}]}}


def tcp_probes() -> dict:
    return {"startupProbe": {"tcpSocket": {"port": "https"}, "periodSeconds": 2, "failureThreshold": 60},
            "readinessProbe": {"tcpSocket": {"port": "https"}, "periodSeconds": 5},
            "livenessProbe": {"tcpSocket": {"port": "https"}, "periodSeconds": 10}}


def service_account(ns: str, ksa: str) -> dict:
    return {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ksa, "namespace": ns},
            "automountServiceAccountToken": False}


def epoch_claim(ns: str, ksa: str) -> dict:
    # The audit producer epoch counter must survive restarts and upgrades
    # (TASK-07 3.2 durable epoch); never delete/recreate it for the same source.
    return {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": f"{ksa}-epoch", "namespace": ns},
            "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}}


def service(ns: str, ksa: str, cluster_ip: str | None = None, name: str | None = None) -> dict:
    # ClusterIP only (TASK-01 4: no public endpoint); render.py rejects others.
    spec: dict = {"type": "ClusterIP", "selector": {"app.kubernetes.io/name": ksa},
                  "ports": [{"name": "https", "port": 8443, "targetPort": "https"}]}
    if cluster_ip:
        spec = {"type": "ClusterIP", "clusterIP": cluster_ip, **{k: v for k, v in spec.items() if k != "type"}}
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name or ksa, "namespace": ns}, "spec": spec}


def deployment(ns: str, ksa: str, prefix: str, args: list[str], *, env_extra: list[dict] = (),
               mounts: list[dict] = (), volumes: list[dict] = (), listen: bool = True, tolerate: bool = True,
               epoch: bool = True) -> dict:
    container: dict = {"name": ksa, "image": "${%s_IMAGE}" % prefix, "args": args, "env": env(prefix, list(env_extra))}
    if listen:
        container["ports"] = [{"name": "https", "containerPort": 8443}]
    container["volumeMounts"] = [mount("trust", "/etc/agentarium-trust"), mount("bootstrap", "/var/run/agentarium-bootstrap")]
    container["volumeMounts"] += list(mounts)
    pod_volumes = [config_map("trust", "agentarium-trust"), copy.deepcopy(BOOTSTRAP)] + list(volumes)
    if epoch:
        container["volumeMounts"].append(mount("epoch", EPOCH, read_only=False))
        pod_volumes.append({"name": "epoch", "persistentVolumeClaim": {"claimName": f"{ksa}-epoch"}})
    container["securityContext"] = copy.deepcopy(HARDENED)
    container["resources"] = {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "1", "memory": "512Mi"}}
    if listen:
        container.update(tcp_probes())
    # Every Pod here runs cloud-sql-proxy with --impersonate-service-account,
    # so it needs the GKE metadata server (Workload Identity), like contacts.yaml.
    selector = {"node-restriction.kubernetes.io/agentarium-role": "control",
                "iam.gke.io/gke-metadata-server-enabled": "true"}
    spec: dict = {"serviceAccountName": ksa, "automountServiceAccountToken": False, "nodeSelector": selector,
                  "schedulerName": "default-scheduler", "securityContext": copy.deepcopy(POD_SECURITY),
                  "terminationGracePeriodSeconds": 30, "initContainers": [proxy(prefix)], "containers": [container],
                  "volumes": pod_volumes}
    if tolerate:
        spec["tolerations"] = copy.deepcopy(START_TAINT)
    out: dict = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": ksa, "namespace": ns},
                 "spec": {"replicas": 1, "selector": {"matchLabels": {"app.kubernetes.io/name": ksa}},
                          "template": {"metadata": {"labels": {"app.kubernetes.io/name": ksa}}, "spec": spec}}}
    if epoch:
        # One process per epoch directory (internal/epoch exclusive lock): a
        # rolling update would start the new Pod against the same RWO volume.
        out["spec"]["strategy"] = {"type": "Recreate"}
    return out


def services() -> list[dict]:
    items: list[dict] = []
    # TASK-04 policy gateway: fixed ClusterIP (TASK-06 3.1 gateway bootstrap address).
    items += [
        service_account("agent-control", "policy-gateway"), epoch_claim("agent-control", "policy-gateway"),
        deployment("agent-control", "policy-gateway", "GATEWAY", [
            "--listen=:8443", "--database-url=$(DATABASE_URL)", "--environment=${AGENTARIUM_ENVIRONMENT}",
            "--gateway-san=" + SPIFFE.format("agent-control", "policy-gateway"),
            "--trust-bundle=" + TRUST, IDENTITY, TOKEN, *BUNDLE_ARGS,
            "--adapter-urls=receiver-sender=https://receiver-sender.agent-adapters.svc:8443",
            "--model-profiles=/etc/agentarium-model-profiles/model-profiles.json",
            "--audit-source-id=policy-gateway", "--audit-source-version=" + VERSION, "--epoch-dir=" + EPOCH,
            HEALTH, "--health-source-id=gateway/$(POD_NAME)",
            "--audit-url=https://audit-writer.agent-observe.svc:8443"],
            env_extra=[POD_NAME],
            mounts=[mount("bundle-keys", "/etc/agentarium-bundle-keys"), mount("model-profiles", "/etc/agentarium-model-profiles")],
            volumes=[config_map("bundle-keys", "agentarium-bundle-keys"), config_map("model-profiles", "agentarium-model-profiles")]),
        service("agent-control", "policy-gateway", "${GATEWAY_CLUSTER_IP}"),
    ]
    # TASK-03 dispatch coordinator.
    items += [
        service_account("agent-control", "coordinator"), epoch_claim("agent-control", "coordinator"),
        deployment("agent-control", "coordinator", "COORDINATOR", [
            "--listen=:8443", "--database-url=$(DATABASE_URL)", "--environment=${AGENTARIUM_ENVIRONMENT}",
            "--trust-bundle=" + TRUST, IDENTITY, TOKEN,
            "--audit-source-id=coordinator", "--audit-source-version=" + VERSION, "--epoch-dir=" + EPOCH,
            HEALTH, "--health-source-id=coordinator/$(POD_NAME)"],
            env_extra=[POD_NAME]),
        service("agent-control", "coordinator"),
    ]
    # TASK-05 receiver-sender adapter: observed workload, no start-taint
    # toleration (TASK-01 3.2). DATABASE_URL and POD_UID come from env.
    items += [
        service_account("agent-adapters", "receiver-sender"), epoch_claim("agent-adapters", "receiver-sender"),
        deployment("agent-adapters", "receiver-sender", "RECEIVER_SENDER", [
            "--listen=:8443", IDENTITY, TOKEN, "--tls-ca-file=" + TRUST,
            "--coordinator-url=https://coordinator.agent-control.svc:8443",
            "--broker-url=https://credential-broker.agent-control.svc:8443",
            "--stored-inputs=postgres", "--environment=${AGENTARIUM_ENVIRONMENT}", *BUNDLE_ARGS,
            "--audit-source-id=receiver-sender", "--audit-source-version=" + VERSION, "--epoch-dir=" + EPOCH,
            HEALTH, "--health-source-id=receiver-sender/$(POD_NAME)"],
            env_extra=[POD_NAME, POD_UID],
            mounts=[mount("bundle-keys", "/etc/agentarium-bundle-keys")],
            volumes=[config_map("bundle-keys", "agentarium-bundle-keys")], tolerate=False),
        service("agent-adapters", "receiver-sender"),
    ]
    # TASK-08 receiver: fixed ClusterIP (TASK-02 targets.yaml), receiver mode
    # from the lock, API key versions from Secret Manager via the GKE add-on.
    items += [
        service_account("agent-targets", "receiver"),
        {"apiVersion": "secrets-store.csi.x-k8s.io/v1", "kind": "SecretProviderClass",
         "metadata": {"name": "receiver-api-key", "namespace": "agent-targets"},
         "spec": {"provider": "gke", "parameters": {"secrets": "${RECEIVER_API_KEY_SECRET_OBJECTS}"}}},
        deployment("agent-targets", "receiver", "RECEIVER", [
            "--listen=:8443", "--database-url=$(DATABASE_URL)", "--receiver-mode=${RECEIVER_MODE}",
            "--target-id=receiver-primary", "--route-id=submissions-v1",
            "--trust-bundle=" + TRUST, IDENTITY, TOKEN,
            "--api-key-dir=/var/run/secrets/agentarium/receiver-api-key"],
            mounts=[mount("api-key", "/var/run/secrets/agentarium/receiver-api-key")],
            volumes=[{"name": "api-key", "csi": {"driver": "secrets-store-gke.csi.k8s.io", "readOnly": True,
                                                 "volumeAttributes": {"secretProviderClass": "receiver-api-key"}}}],
            epoch=False),
        service("agent-targets", "receiver", "${RECEIVER_CLUSTER_IP}"),
        # TASK-02 targets.yaml receiver-probe: the activation probe target is a
        # second Service over the same receiver Pods (receiver KSA, so the URI
        # SAN is the receiver's), with its own fixed ClusterIP from the lock.
        service("agent-targets", "receiver", "${RECEIVER_PROBE_CLUSTER_IP}", name="receiver-probe"),
    ]
    # TASK-08 evidence collector: outbound only, no listener and no Service.
    items += [
        service_account("agent-observe", "evidence-collector"), epoch_claim("agent-observe", "evidence-collector"),
        deployment("agent-observe", "evidence-collector", "EVIDENCE_COLLECTOR", [
            "--database-url=$(DATABASE_URL)", "--tenant=${AGENTARIUM_TENANT}",
            "--receiver-url=https://receiver.agent-targets.svc:8443", "--target-id=receiver-primary",
            "--tls-ca=" + TRUST, IDENTITY, TOKEN,
            # A target lease source is matched against the control-health
            # profile `sources` binding (source_id, SAN, scope_id), so it must
            # be stable across Pod names: one Recreate replica per target.
            HEALTH, "--health-source-id=evidence-collector/receiver-primary", "--version=" + VERSION,
            "--audit-source-id=evidence-collector", "--audit-source-version=" + VERSION, "--epoch-dir=" + EPOCH,
            "--probe-action-key=${EVIDENCE_PROBE_ACTION_KEY}"],
            listen=False),
    ]
    return items


def runtime_pod() -> dict:
    """agent-exec runtime Pod (TASK-01 3.2 agent-exec-contract, TASK-15 #234).

    Admission forbids args, env valueFrom and any volume except `work` and
    `identity`, so every setting is a plain env value and the trust bundle is
    the PEM text itself. The Pod reaches only the gateway, by its fixed
    ClusterIP (no DNS egress from agent-exec, TASK-06 3.1).
    """
    plain = [("AGENTARIUM_GATEWAY_URL", "https://${GATEWAY_CLUSTER_IP}:8443"),
             ("AGENTARIUM_GATEWAY_SAN", SPIFFE.format("agent-control", "policy-gateway")),
             ("AGENTARIUM_TRUST_BUNDLE_PEM", "${TRUST_BUNDLE_PEM}"),
             ("AGENTARIUM_TOKEN_FILE", "/run/agentarium/identity/token"),
             ("AGENTARIUM_WORKER_PATH", "/app/bin/agent-worker"),
             ("AGENTARIUM_SCRATCH_ROOT", "/work"),
             ("AGENTARIUM_MAX_CONCURRENT_WORKERS", "1"),
             ("AGENTARIUM_RUNTIME_VERSION", VERSION),
             ("AGENTARIUM_DEMO_TARGET_ID", "receiver-primary"),
             ("AGENTARIUM_DEMO_SUMMARY", "M3-1 GKE demo submission")]
    limits = {"cpu": "1", "memory": "512Mi", "ephemeral-storage": "1Gi"}
    container = {
        "name": "agent-runtime", "image": "${RUNTIME_IMAGE}", "command": ["/app/bin/agent-runtime"],
        "env": [{"name": k, "value": v} for k, v in plain],
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                            **copy.deepcopy(HARDENED)},
        "resources": {"requests": {"cpu": "500m", "memory": "512Mi", "ephemeral-storage": "256Mi"}, "limits": limits},
        "volumeMounts": [mount("work", "/work", read_only=False), mount("identity", "/run/agentarium/identity")],
    }
    spec = {
        "serviceAccountName": "agent-runtime", "automountServiceAccountToken": False,
        "priorityClassName": "agentarium-runtime",
        "nodeSelector": {"node-restriction.kubernetes.io/agentarium-role": "exec"},
        "schedulerName": "default-scheduler", "restartPolicy": "Never",
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "tolerations": [{"key": "agentarium-role", "operator": "Equal", "value": "exec", "effect": "NoSchedule"}],
        "containers": [container],
        "volumes": [{"name": "work", "emptyDir": {"sizeLimit": "512Mi"}},
                    {"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
                        "path": "token", "expirationSeconds": 600, "audience": "agentarium-identity"}}]}}],
    }
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "agent-runtime-demo", "namespace": "agent-exec",
                         "labels": {"app.kubernetes.io/name": "agent-runtime"}},
            "spec": spec}


def check(items: list[dict]) -> None:
    """Invariants the manifests rely on; generation fails if one breaks."""
    for o in items:
        if o["kind"] != "Deployment":
            continue
        name, spec = o["metadata"]["name"], o["spec"]
        # One process per epoch directory and per fixed health source id
        # (evidence-collector/receiver-primary); a second replica would share both.
        if spec.get("replicas") != 1:
            raise SystemExit(f"generate: Deployment {name} must have replicas 1")
        pod = spec["template"]["spec"]
        if any(v.get("persistentVolumeClaim") for v in pod["volumes"]) and spec.get("strategy") != {"type": "Recreate"}:
            raise SystemExit(f"generate: Deployment {name} with an epoch volume must use Recreate")
        if pod["nodeSelector"].get("iam.gke.io/gke-metadata-server-enabled") != "true":
            raise SystemExit(f"generate: Deployment {name} uses Workload Identity and needs the metadata-server nodeSelector")


def documents() -> dict[str, str]:
    def dump(items: list[dict]) -> str:
        check(items)
        return json.dumps({"apiVersion": "v1", "kind": "List", "items": items}, indent=2, ensure_ascii=False) + "\n"
    return {"services.yaml": dump(services()),
            "agent-runtime.yaml": dump([service_account("agent-exec", "agent-runtime"), runtime_pod()])}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail when a committed file differs")
    args = ap.parse_args(argv)
    stale = []
    for name, text in documents().items():
        path = HERE / name
        if args.check:
            if not path.exists() or path.read_text() != text:
                stale.append(name)
        else:
            path.write_text(text)
    if stale:
        print(f"generate: stale {stale}; run deploy/gcp/base/action-path/generate.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
