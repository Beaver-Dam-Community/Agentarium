"""Deterministic discovery matcher (TASK-02 3.4 "matching").

Input is the static candidates' destination_template list and the dynamic
observation list of one reproduction run. The model is never consulted here.

- host: tls_sni; otherwise the process's dns_name (the observation's own value,
  else the single dns_name seen for the same process_exec_id).
- scheme: https when TLS was seen (tls_sni), http when plaintext HTTP was seen
  (http_method without TLS); otherwise 443 -> https and 80 -> http.
- A candidate is `matched` when some observation agrees on scheme, host-glob
  and port, and, if the observation has a path, on the path-prefix. If no
  matching observation carried a path, `path_unverified = True`.
- Candidates no observation matches are `static_not_observed`.
- Observations no candidate matches become `observed_not_static` candidates,
  one per derived template.
- Both control arms (off and on) are matched; each result records the arms
  that reproduced it as `matched_arms`, a sorted subset of ("off", "on").
- Observations to Agentarium infrastructure (gateway 8443, cluster DNS 53,
  `kubernetes` Service 443, and the metadata server only for the on-arm
  adapter) are not library behaviour: they are counted as `infra_filtered` and
  take no part in matching. The Private Google Access VIP is not
  infrastructure here (TASK-02 3.4, PR #19).
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field

from . import template as tpl
from .models import DynamicMatch, Observation


METADATA_IP = ipaddress.IPv4Address("169.254.169.254")


# GKE assigns these Service ClusterIPs inside network.services_range
# (confirmed in TASK-01 Q0 20261014-task01-q0-min).
KUBERNETES_HOST_INDEX = 1  # `kubernetes` Service
CLUSTER_DNS_HOST_INDEX = 10  # kube-dns Service


@dataclass(frozen=True)
class InfraDestinations:
    """Agentarium infrastructure of the environment the scenarios ran in.

    Matching is by destination address and port. Kernel observations carry
    the Service ClusterIP, not a backend Pod: in TASK-01 Q0 the tcp_connect
    daddr for DNS was the kube-dns ClusterIP 10.30.0.10 (Dataplane V2
    socket-level load balancing), so no destination-Pod fields are needed in
    the TASK-13 observation schema.
    """

    gateway_ip: ipaddress.IPv4Address  # lock network.gateway_cluster_ip, port 8443
    cluster_dns_ip: ipaddress.IPv4Address  # cidrhost(services_range, 10), port 53
    kubernetes_ip: ipaddress.IPv4Address  # cidrhost(services_range, 1), port 443

    @classmethod
    def from_lock(cls, gateway_cluster_ip: str, services_range: str) -> InfraDestinations:
        """From lock network.gateway_cluster_ip and network.services_range.
        Raises ValueError unless the range is a canonical IPv4 CIDR and the
        gateway is a host address inside it other than the kubernetes (.1) and
        cluster DNS (.10) addresses."""
        net = ipaddress.IPv4Network(services_range, strict=True)  # ValueError if host bits set
        if str(net) != services_range:
            raise ValueError(f"services range {services_range!r} is not canonical (want {net})")
        if net.num_addresses <= CLUSTER_DNS_HOST_INDEX + 1:
            raise ValueError(f"services range {net} is too small")
        gw = ipaddress.IPv4Address(gateway_cluster_ip)
        if str(gw) != gateway_cluster_ip:
            raise ValueError(f"gateway address {gateway_cluster_ip!r} is not canonical")
        k8s, dns = net[KUBERNETES_HOST_INDEX], net[CLUSTER_DNS_HOST_INDEX]
        if gw not in net or gw in (net.network_address, net.broadcast_address, k8s, dns):
            raise ValueError(f"gateway {gw} must be a host address in {net} other than {k8s} and {dns}")
        return cls(gateway_ip=gw, cluster_dns_ip=dns, kubernetes_ip=k8s)

    def contains(self, o: Observation) -> bool:
        try:
            ip = ipaddress.ip_address(o.dst_ip)
        except ValueError:
            return False
        if ip == METADATA_IP:
            # Only the adapter fetching its WIF token in the on arm is infrastructure;
            # an off-arm metadata request is SDK credential behaviour (PR #19 review).
            return o.arm == "on" and o.source == "adapter"
        return (ip, o.dst_port) in {(self.gateway_ip, 8443), (self.cluster_dns_ip, 53), (self.kubernetes_ip, 443)}


@dataclass(frozen=True)
class CandidateMatch:
    dynamic_match: DynamicMatch
    path_unverified: bool | None
    observation_indexes: tuple[int, ...]
    matched_arms: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ObservedCandidate:
    destination_template: str
    observation_indexes: tuple[int, ...]
    matched_arms: tuple[str, ...] = ()


@dataclass
class MatchResult:
    candidates: dict[str, CandidateMatch] = field(default_factory=dict)
    observed: list[ObservedCandidate] = field(default_factory=list)
    infra_filtered: int = 0


def _arms(observations: list[Observation], indexes) -> tuple[str, ...]:
    return tuple(sorted({observations[i].arm for i in indexes}))


def observation_scheme(o: Observation) -> str | None:
    if o.tls_sni is not None:
        return "https"
    if o.http_method is not None:
        return "http"
    # SPEC-QUESTION: TASK-02 states only "443+TLS -> https". Kernel records
    # without TLS/HTTP detail fall back to the well-known ports.
    return {443: "https", 80: "http"}.get(o.dst_port)


def observation_hosts(observations: list[Observation]) -> list[str | None]:
    names_by_proc: dict[str, set[str]] = defaultdict(set)
    for o in observations:
        if o.dns_name:
            names_by_proc[o.process_exec_id].add(o.dns_name)
    hosts: list[str | None] = []
    for o in observations:
        if o.tls_sni:
            hosts.append(o.tls_sni)
        elif o.dns_name:
            hosts.append(o.dns_name)
        else:
            # SPEC-QUESTION: "the same process's dns_name" is used only when the
            # process resolved exactly one name; several names leave it unknown.
            names = names_by_proc.get(o.process_exec_id, set())
            hosts.append(next(iter(names)) if len(names) == 1 else None)
    return hosts


def _matches(t: tpl.Template, o: Observation, host: str | None, scheme: str | None) -> bool:
    if scheme != t.scheme or o.dst_port != t.port:
        return False
    # IP-literal templates compare the destination address, others the host.
    target = o.dst_ip if t.is_ip_literal else host
    if target is None or not t.host_matches(target):
        return False
    if o.http_path is not None and not t.path_matches(o.http_path):
        return False
    return True


def match(candidates: list[tuple[str, str]], observations: list[Observation],
          *, infra: InfraDestinations) -> MatchResult:
    """candidates: (candidate_id, destination_template) of static candidates.

    Observation indexes in the result are positions in `observations`.
    Observations of both arms are matched and the reproducing arms recorded
    (TASK-02 3.4, PR #19); infrastructure observations are only counted."""
    hosts = observation_hosts(observations)
    schemes = [observation_scheme(o) for o in observations]
    result = MatchResult()
    # Infrastructure observations are excluded before matching: they are not
    # library behaviour and must neither reproduce nor create candidates.
    used: set[int] = {i for i, o in enumerate(observations) if infra.contains(o)}
    result.infra_filtered = len(used)
    infra_ix = set(used)
    for cid, text in candidates:
        try:
            t = tpl.parse(text)
        except tpl.TemplateError:
            result.candidates[cid] = CandidateMatch(DynamicMatch.static_not_observed, None, ())
            continue
        hits = [i for i, o in enumerate(observations)
                if i not in infra_ix and _matches(t, o, hosts[i], schemes[i])]
        if hits:
            used.update(hits)
            with_path = any(observations[i].http_path is not None for i in hits)
            result.candidates[cid] = CandidateMatch(DynamicMatch.matched, not with_path, tuple(hits),
                                                    _arms(observations, hits))
        else:
            result.candidates[cid] = CandidateMatch(DynamicMatch.static_not_observed, None, ())

    grouped: dict[str, list[int]] = {}
    for i, o in enumerate(observations):
        if i in used:
            continue
        text = tpl.for_observation(schemes[i], hosts[i], o.dst_ip, o.dst_port)
        if not tpl.is_valid(text):
            text = tpl.for_observation(None, None, o.dst_ip, o.dst_port)
        grouped.setdefault(text, []).append(i)
    result.observed = [ObservedCandidate(t, tuple(ix), _arms(observations, ix)) for t, ix in sorted(grouped.items())]
    return result
