"""TASK-02 3.4 (PR #19/#20): both control arms are matched and recorded as
matched_arms; Agentarium infrastructure observations are only counted.

Values follow the prod lock: gateway_cluster_ip 10.30.0.20, services_range
10.30.0.0/20, so cluster DNS is 10.30.0.10 and `kubernetes` is 10.30.0.1.
"""

import ipaddress
import json

import pytest
from conftest import SNAPSHOT_ID, candidate_json

from agentarium_discovery import app as app_module
from agentarium_discovery import matcher
from agentarium_discovery.models import DynamicMatch, Observation, RunState

H = {"X-Agentarium-Console-Actor": "google:op", "X-Agentarium-Console-Roles": "operator"}
INFRA = matcher.InfraDestinations.from_lock("10.30.0.20", "10.30.0.0/20")
GATEWAY, DNS, KUBERNETES, METADATA = "10.30.0.20", "10.30.0.10", "10.30.0.1", "169.254.169.254"


def obs(arm, ip="203.0.113.5", port=443, sni="api.example.com", source="kernel", **kw):
    return Observation(arm=arm, process_exec_id=kw.pop("proc", "p"), dst_ip=ip, dst_port=port, tls_sni=sni,
                       source=source, **kw)


def test_derived_addresses():
    assert INFRA.gateway_ip == ipaddress.IPv4Address(GATEWAY)
    assert INFRA.cluster_dns_ip == ipaddress.IPv4Address(DNS)
    assert INFRA.kubernetes_ip == ipaddress.IPv4Address(KUBERNETES)


# --- arms ---------------------------------------------------------------------

@pytest.mark.parametrize("arms,expected", [
    (["off"], ("off",)),
    (["on"], ("on",)),
    (["on", "off"], ("off", "on")),
    (["off", "off", "on"], ("off", "on")),
])
def test_matched_arms_for_static_candidates(arms, expected):
    r = matcher.match([("c1", "https://api.example.com/")], [obs(a) for a in arms], infra=INFRA)
    m = r.candidates["c1"]
    assert m.dynamic_match == DynamicMatch.matched and m.matched_arms == expected


@pytest.mark.parametrize("arms,expected", [(["off"], ("off",)), (["on"], ("on",)), (["off", "on"], ("off", "on"))])
def test_matched_arms_for_observed_candidates(arms, expected):
    r = matcher.match([], [obs(a, sni="other.example.com") for a in arms], infra=INFRA)
    [o] = r.observed
    assert o.destination_template == "https://other.example.com/" and o.matched_arms == expected


def test_static_not_observed_has_no_arms():
    r = matcher.match([("c1", "https://api.example.com/")], [obs("off", sni="else.example.com")], infra=INFRA)
    assert r.candidates["c1"].matched_arms is None


def test_infra_is_a_required_keyword_argument():
    with pytest.raises(TypeError):
        matcher.match([], [obs("off")])  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        matcher.match([], [obs("off")], INFRA)  # type: ignore[misc]


# --- infrastructure -----------------------------------------------------------

INFRA_OBS = [
    obs("off", ip=GATEWAY, port=8443, sni=None),  # gateway
    obs("on", ip=DNS, port=53, sni=None),  # cluster DNS
    obs("off", ip=KUBERNETES, port=443, sni="kubernetes.default.svc"),  # kubernetes Service
    obs("on", ip=METADATA, port=80, sni=None, source="adapter"),  # adapter WIF token, on arm
]


def test_infra_observations_are_counted_not_matched():
    r = matcher.match([("k8s", "https://kubernetes.default.svc/")], INFRA_OBS, infra=INFRA)
    assert r.infra_filtered == 4 and r.observed == []
    # Excluded before matching: an infra observation does not reproduce a static candidate either.
    assert r.candidates["k8s"].dynamic_match == DynamicMatch.static_not_observed


@pytest.mark.parametrize("o", [
    obs("off", ip=GATEWAY, port=443, sni=None),  # gateway address, other port
    obs("off", ip=DNS, port=8443, sni=None),  # DNS address on the gateway port: address and port both matter
    obs("off", ip=DNS, port=853, sni=None),  # DNS address, other port
    obs("off", ip=KUBERNETES, port=6443, sni=None),  # kubernetes address, other port
    obs("off", ip=GATEWAY, port=53, sni=None),  # gateway address on the DNS port
])
def test_address_and_port_must_both_match(o):
    r = matcher.match([], [o], infra=INFRA)
    assert r.infra_filtered == 0 and len(r.observed) == 1


@pytest.mark.parametrize("o,filtered", [
    (obs("on", ip=METADATA, port=80, sni=None, source="adapter"), True),  # adapter fetching its WIF token
    (obs("off", ip=METADATA, port=80, sni=None, source="kernel"), False),  # SDK credential behaviour
    (obs("off", ip=METADATA, port=80, sni=None, source="adapter"), False),
    (obs("on", ip=METADATA, port=80, sni=None, source="kernel"), False),  # on arm, not the adapter
    (obs("on", ip=METADATA, port=80, sni=None, source="egress_log"), False),
])
def test_metadata_server_is_infra_only_for_the_on_arm_adapter(o, filtered):
    r = matcher.match([], [o], infra=INFRA)
    assert r.infra_filtered == (1 if filtered else 0)
    assert [x.destination_template for x in r.observed] == ([] if filtered else ["https://169.254.169.254:80/"])


def test_private_google_access_vip_is_not_infra():
    vip = [obs("on", ip="199.36.153.8", sni="storage.googleapis.com", http_path="/v1/b/o"),
           obs("off", ip="199.36.153.9", sni="oauth2.googleapis.com")]
    r = matcher.match([("gcs", "https://storage.googleapis.com/v1/")], vip, infra=INFRA)
    assert r.infra_filtered == 0
    assert r.candidates["gcs"].matched_arms == ("on",)
    assert [o.destination_template for o in r.observed] == ["https://oauth2.googleapis.com/"]


def test_run_reports_infra_filtered_and_creates_no_infra_candidates(env):
    env.svc.config.infra = INFRA
    env.gw.turns = [(json.dumps({"candidates": [candidate_json(destination_template="https://api.example.com/")]}), [])]
    run_id = env.client.post("/internal/discovery/runs", json={"snapshot_id": SNAPSHOT_ID, "scenario_set_id": "s"},
                             headers=H).json()["run_id"]
    env.svc.process_next_run()
    off_metadata = obs("off", ip=METADATA, port=80, sni=None)  # stays a candidate
    env.reg.observations = INFRA_OBS + [obs("on"), obs("off", sni="new.example.com"), off_metadata]
    env.svc.poll_reproductions()
    run = env.store.get_run("hackathon", run_id)
    assert run.state == RunState.completed and run.infra_filtered == 4
    assert env.svc.metrics(run_id)["infra_filtered"] == 4
    items = env.client.get("/internal/discovery/candidates", params={"run_id": run_id}, headers=H).json()["items"]
    got = {c["destination_template"]: (c["state"], c["dynamic_match"], c["matched_arms"]) for c in items}
    assert got == {
        "https://api.example.com/": ("reproduced", "matched", ["on"]),
        "https://new.example.com/": ("reproduced", "observed_not_static", ["off"]),
        "https://169.254.169.254:80/": ("reproduced", "observed_not_static", ["off"]),
    }
    # Evidence refs still point at report indexes after the infra entries.
    new = next(c for c in items if c["destination_template"] == "https://new.example.com/")
    assert new["evidence_ref"].endswith("#observations/5")


def test_service_requires_infra(env):
    from agentarium_discovery.service import Config, DiscoveryService
    with pytest.raises(ValueError):
        DiscoveryService(env.store, env.svc.snapshots, env.jobs, env.svc.analyzer, env.reg, Config(tenant="hackathon"))


# --- startup config -----------------------------------------------------------

def _set_infra_env(monkeypatch, **override):
    vals = {"DISCOVERY_INFRA_GATEWAY_IP": GATEWAY, "DISCOVERY_SERVICES_RANGE": "10.30.0.0/20", **override}
    for k, v in vals.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)


def test_infra_config_from_env(monkeypatch):
    _set_infra_env(monkeypatch)
    assert app_module.infra_destinations() == INFRA


@pytest.mark.parametrize("override", [
    {"DISCOVERY_INFRA_GATEWAY_IP": None},
    {"DISCOVERY_SERVICES_RANGE": None},
    {"DISCOVERY_SERVICES_RANGE": ""},
    {"DISCOVERY_SERVICES_RANGE": "10.30.0.5/20"},  # host bits set
    {"DISCOVERY_SERVICES_RANGE": "10.30.0.0/020"},  # not canonical
    {"DISCOVERY_SERVICES_RANGE": "10.30.0.0"},  # no prefix length given: /32
    {"DISCOVERY_SERVICES_RANGE": "fd00::/108"},  # IPv4 only
    {"DISCOVERY_SERVICES_RANGE": "10.30.0.0/29"},  # too small for .10
    {"DISCOVERY_INFRA_GATEWAY_IP": "10.31.0.20"},  # outside the range
    {"DISCOVERY_INFRA_GATEWAY_IP": KUBERNETES},  # the kubernetes Service address
    {"DISCOVERY_INFRA_GATEWAY_IP": DNS},  # the cluster DNS address
    {"DISCOVERY_INFRA_GATEWAY_IP": "10.30.0.0"},  # network address
    {"DISCOVERY_INFRA_GATEWAY_IP": "10.30.15.255"},  # broadcast address
    {"DISCOVERY_INFRA_GATEWAY_IP": "fd00::20"},
    {"DISCOVERY_INFRA_GATEWAY_IP": "10.30.0.20\n"},
    {"DISCOVERY_INFRA_GATEWAY_IP": "010.30.0.20"},
])
def test_infra_config_is_validated(monkeypatch, override):
    _set_infra_env(monkeypatch, **override)
    with pytest.raises(RuntimeError):
        app_module.infra_destinations()
