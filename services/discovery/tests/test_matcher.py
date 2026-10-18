"""TASK-02 section 7 "discovery matcher": fixed observations and templates
covering host glob, port and path-boundary cases."""

from conftest import TEST_INFRA

from agentarium_discovery.matcher import match, observation_hosts, observation_scheme
from agentarium_discovery.models import DynamicMatch, Observation, parse_observation


def obs(**kw):
    base = {"arm": "on", "process_exec_id": "p1", "dst_ip": "203.0.113.10", "dst_port": 443, "source": "kernel"}
    base.update(kw)
    return Observation.model_validate_json(__import__("json").dumps(base))


OBSERVATIONS = [
    # 0: TLS to storage.googleapis.com with a path
    obs(tls_sni="storage.googleapis.com", http_method="GET", http_path="/v1/b/x", source="adapter"),
    # 1: token endpoint, path known
    obs(tls_sni="oauth2.googleapis.com", http_path="/token", process_exec_id="p2", dst_ip="203.0.113.11"),
    # 2: kernel-only record, host from same-process DNS observation (3)
    obs(process_exec_id="p3", dst_ip="198.51.100.7"),
    # 3: DNS lookup by p3 to the resolver
    obs(process_exec_id="p3", dst_ip="10.0.0.10", dns_name="metadata.example.internal", dst_port=53, source="egress_log"),
    # 4: path /v10 must not match prefix /v1
    obs(tls_sni="api.example.com", http_path="/v10/items", process_exec_id="p4", dst_ip="203.0.113.20"),
    # 5: unknown host, odd port
    obs(process_exec_id="p5", dst_ip="192.0.2.99", dst_port=8443),
    # 6: plaintext http on 8080
    obs(http_method="POST", http_path="/hook", dns_name="hooks.example.com", process_exec_id="p6", dst_ip="192.0.2.50", dst_port=8080, arm="off"),
]

TEMPLATES = [
    ("glob", "https://*.googleapis.com/v1/"),  # matches 0 by glob+path
    ("token", "https://oauth2.googleapis.com/token"),  # exact path
    ("tokens", "https://oauth2.googleapis.com/tokens"),  # boundary: /token is not /tokens
    ("meta", "https://metadata.example.internal/"),  # host via same-process DNS, no path
    ("v1", "https://api.example.com/v1"),  # /v10 must not match
    ("deep", "https://*.example.com/v10"),  # glob one label, /v10/items matches
    ("twolabel", "https://*.googleapis.com.evil.net/"),  # never matches
    ("port", "https://storage.googleapis.com:8443/"),  # port mismatch with 0
    ("hook", "http://hooks.example.com:8080/hook"),  # plaintext http, explicit port
    ("hook443", "http://hooks.example.com/hook"),  # default port 80 != 8080
]


def test_matcher_fixed_fixture():
    r = match(TEMPLATES, OBSERVATIONS, infra=TEST_INFRA)
    expect = {
        "glob": (DynamicMatch.matched, False),
        "token": (DynamicMatch.matched, False),
        "tokens": (DynamicMatch.static_not_observed, None),
        "meta": (DynamicMatch.matched, True),
        "v1": (DynamicMatch.static_not_observed, None),
        "deep": (DynamicMatch.matched, False),
        "twolabel": (DynamicMatch.static_not_observed, None),
        "port": (DynamicMatch.static_not_observed, None),
        "hook": (DynamicMatch.matched, False),
        "hook443": (DynamicMatch.static_not_observed, None),
    }
    got = {cid: (m.dynamic_match, m.path_unverified) for cid, m in r.candidates.items()}
    assert got == expect
    assert r.candidates["glob"].observation_indexes == (0,)
    assert r.candidates["meta"].observation_indexes == (2,)

    observed = {o.destination_template: o.observation_indexes for o in r.observed}
    # 3: the resolver record itself matches nothing; host known, scheme unknown -> explicit port.
    # 5: unknown host -> https://<dst_ip>:<dst_port>/
    assert observed == {
        "https://metadata.example.internal:53/": (3,),
        "https://192.0.2.99:8443/": (5,),
    }


def test_path_unverified_only_when_no_matching_observation_had_a_path():
    r = match([("c", "https://api.example.com/v1")], [obs(tls_sni="api.example.com"), obs(tls_sni="api.example.com", http_path="/v1/x")], infra=TEST_INFRA)
    assert r.candidates["c"].path_unverified is False
    r = match([("c", "https://api.example.com/v1")], [obs(tls_sni="api.example.com")], infra=TEST_INFRA)
    assert r.candidates["c"].path_unverified is True


def test_observation_with_path_outside_prefix_does_not_match_even_if_host_port_do():
    r = match([("c", "https://api.example.com/v1")], [obs(tls_sni="api.example.com", http_path="/v2")], infra=TEST_INFRA)
    assert r.candidates["c"].dynamic_match is DynamicMatch.static_not_observed
    assert [o.destination_template for o in r.observed] == ["https://api.example.com/"]


def test_scheme_rules():
    assert observation_scheme(obs(tls_sni="a.example", dst_port=8443)) == "https"
    assert observation_scheme(obs(http_method="GET", dst_port=443)) == "http"
    assert observation_scheme(obs(dst_port=443)) == "https"
    assert observation_scheme(obs(dst_port=80)) == "http"
    assert observation_scheme(obs(dst_port=8443)) is None
    # Unknown scheme never matches a template.
    r = match([("c", "https://192.0.2.99:8443/")], [obs(dst_ip="192.0.2.99", dst_port=8443)], infra=TEST_INFRA)
    assert r.candidates["c"].dynamic_match is DynamicMatch.static_not_observed


def test_ip_literal_template_matches_destination_address():
    r = match([("c", "https://192.0.2.99:443/")], [obs(dst_ip="192.0.2.99")], infra=TEST_INFRA)
    assert r.candidates["c"].dynamic_match is DynamicMatch.matched


def test_ambiguous_same_process_dns_gives_unknown_host():
    o = [
        obs(process_exec_id="p", dst_ip="192.0.2.1"),
        obs(process_exec_id="p", dst_ip="10.0.0.10", dns_name="a.example.com", dst_port=53),
        obs(process_exec_id="p", dst_ip="10.0.0.10", dns_name="b.example.com", dst_port=53),
    ]
    assert observation_hosts(o)[0] is None


def test_task13_observation_shape_is_accepted():
    o = parse_observation({
        "scenario_id": "s1", "control": "off", "process_exec_id": "p", "dest_addr": "192.0.2.1",
        "dest_port": 443, "sni": "x.example.com", "dns_name": None, "source": "adapter_observation",
        "source_time": "2026-10-14T00:00:00Z",
    })
    assert (o.arm, o.dst_ip, o.tls_sni, o.source) == ("off", "192.0.2.1", "x.example.com", "adapter")


def test_matcher_is_deterministic():
    a = match(TEMPLATES, OBSERVATIONS, infra=TEST_INFRA)
    b = match(list(reversed(TEMPLATES)), OBSERVATIONS, infra=TEST_INFRA)
    assert a.candidates == b.candidates
    assert a.observed == b.observed
