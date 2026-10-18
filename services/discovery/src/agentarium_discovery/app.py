"""Process wiring: configuration from the environment and the background worker.

All values are installation inputs (deploy/gcp/environment.lock.json); none
has a production default.
"""

from __future__ import annotations

import logging
import os
import threading

import httpx

from .analyzer import Analyzer
from .api import create_app
from .audit import publish_pending
from .auth import AsgiTlsPeerIdentity
from .clients import HttpAudit, HttpGateway, HttpRegression, KubernetesJobs
from .digest import CanonicalDigestCLI
from .matcher import InfraDestinations
from .postgres import PostgresStore
from .service import Config, DiscoveryService
from .snapshots import SnapshotStore

log = logging.getLogger("agentarium_discovery")


def env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"missing required setting {name}")
    return v


def mtls_client() -> httpx.Client:
    # Service certificate issued by TASK-03; redirects are never followed.
    return httpx.Client(
        cert=(env("DISCOVERY_TLS_CERT"), env("DISCOVERY_TLS_KEY")),
        verify=env("DISCOVERY_TLS_CA"),
        timeout=10.0,
        follow_redirects=False,
    )


def job_service_account() -> str:
    """The snapshot Job KSA is fixed to `discovery-snapshot` (TASK-02 3.4, PR #8):
    it is the only KSA with bucket write access and no DB access. Another value
    fails at startup instead of silently running the Job under a different
    identity."""
    sa = os.environ.get("DISCOVERY_JOB_SERVICE_ACCOUNT") or KubernetesJobs.DEFAULT_SERVICE_ACCOUNT
    if sa != KubernetesJobs.DEFAULT_SERVICE_ACCOUNT:
        raise RuntimeError(f"DISCOVERY_JOB_SERVICE_ACCOUNT must be {KubernetesJobs.DEFAULT_SERVICE_ACCOUNT!r}, got {sa!r}")
    return sa


def infra_destinations() -> InfraDestinations:
    """Agentarium infrastructure of the environment the discovery scenarios
    run in (TASK-02 3.4, PR #19), from two lock values:
    DISCOVERY_INFRA_GATEWAY_IP = network.gateway_cluster_ip and
    DISCOVERY_SERVICES_RANGE = network.services_range. Cluster DNS and the
    `kubernetes` Service are derived from the range (.10 and .1). Both are
    required; an invalid value fails at startup. The metadata server address
    is fixed in the matcher; the Private Google Access VIP is never excluded."""
    gateway, services = env("DISCOVERY_INFRA_GATEWAY_IP"), env("DISCOVERY_SERVICES_RANGE")
    try:
        return InfraDestinations.from_lock(gateway, services)
    except ValueError as e:
        raise RuntimeError(f"DISCOVERY_INFRA_GATEWAY_IP / DISCOVERY_SERVICES_RANGE invalid: {e}") from e


def build_service() -> DiscoveryService:
    client = mtls_client()
    gateway = HttpGateway(client, env("DISCOVERY_IDENTITY_URL"), env("DISCOVERY_GATEWAY_URL"),
                          env("DISCOVERY_TENANT"), env("DISCOVERY_MODEL_TARGET_ID"),
                          env("DISCOVERY_SNAPSHOTS_TARGET_ID"))
    regression = HttpRegression(client, env("DISCOVERY_REGRESSION_URL"), env("DISCOVERY_ENVIRONMENT_ID"),
                                env("DISCOVERY_CANDIDATE_DIGEST"), env("DISCOVERY_BASELINE_BUNDLE_DIGEST"))
    jobs = KubernetesJobs(env("DISCOVERY_JOB_NAMESPACE"), env("DISCOVERY_JOB_IMAGE"), env("DISCOVERY_BUCKET"),
                          service_account=job_service_account())
    return DiscoveryService(
        store=PostgresStore(env("DISCOVERY_DATABASE_URL")),
        # gs://<DISCOVERY_BUCKET> in GKE; DISCOVERY_SNAPSHOT_ROOT overrides it with a
        # local directory for development.
        snapshots=SnapshotStore(os.environ.get("DISCOVERY_SNAPSHOT_ROOT") or f"gs://{env('DISCOVERY_BUCKET')}"),
        jobs=jobs,
        analyzer=Analyzer(gateway),
        regression=regression,
        config=Config(tenant=env("DISCOVERY_TENANT"), discovery_bucket=env("DISCOVERY_BUCKET"),
                      infra=infra_destinations()),
        digester=CanonicalDigestCLI(os.environ.get("CANONICAL_DIGEST_BIN", "canonical-digest")),
    )


def worker(service: DiscoveryService, stop: threading.Event, interval: float = 5.0) -> None:
    client = mtls_client()
    audit = HttpAudit(client, env("DISCOVERY_AUDIT_URL"))
    digester = CanonicalDigestCLI(os.environ.get("CANONICAL_DIGEST_BIN", "canonical-digest"))
    while not stop.is_set():
        try:
            while service.process_next_run():
                pass
            service.poll_reproductions()
            publish_pending(service.store, audit, digester, service.config.source_id, service.config.source_version)
        except Exception:
            log.exception("discovery worker iteration failed")
        stop.wait(interval)


def main() -> None:
    from . import server

    service = build_service()
    stop = threading.Event()
    t = threading.Thread(target=worker, args=(service, stop), daemon=True)
    t.start()
    app = create_app(service, AsgiTlsPeerIdentity())
    try:
        server.run(app, "0.0.0.0", int(os.environ.get("PORT", "8443")),
                   env("DISCOVERY_TLS_CERT"), env("DISCOVERY_TLS_KEY"), env("DISCOVERY_TLS_CA"))
    finally:
        stop.set()


if __name__ == "__main__":
    main()
