"""Caller identity (COMMON "service PKI and identifiers", "console path and IdP").

- The peer SAN comes from the mTLS connection.
- Console calls arrive from the identity service BFF; only on that connection
  are X-Agentarium-Console-Actor / -Roles trusted.
- Snapshot read routes accept only the evidence-reader adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from starlette.requests import Request

SAN_PREFIX = "spiffe://agentarium.internal/ns/"
IDENTITY_BFF_SAN = SAN_PREFIX + "agent-control/sa/workload-identity"
EVIDENCE_READER_SAN = SAN_PREFIX + "agent-adapters/sa/evidence-reader"

ACTOR_HEADER = "x-agentarium-console-actor"
ROLES_HEADER = "x-agentarium-console-roles"
OPERATOR = "operator"


@dataclass(frozen=True)
class Caller:
    san: str | None
    actor: str | None = None
    roles: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_operator(self) -> bool:
        return self.san == IDENTITY_BFF_SAN and self.actor is not None and OPERATOR in self.roles

    @property
    def is_evidence_reader(self) -> bool:
        return self.san == EVIDENCE_READER_SAN


class PeerIdentity(Protocol):
    def peer_san(self, request: Request) -> str | None: ...


class AsgiTlsPeerIdentity:
    """Reads the client certificate from the ASGI TLS extension
    (scope["extensions"]["tls"]["client_cert_chain"], PEM strings).

    Neither uvicorn (0.54) nor hypercorn (0.18) fills this extension, so the
    service runs uvicorn with TlsExtensionH11Protocol (server.py), which copies
    the handshake-verified peer certificate into it.
    SPEC-QUESTION: the spec does not say how the Python service terminates mTLS.
    """

    def peer_san(self, request: Request) -> str | None:
        tls = request.scope.get("extensions", {}).get("tls") or {}
        chain = tls.get("client_cert_chain") or []
        if not chain:
            return None
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(chain[0].encode())
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return None
        uris = [u for u in ext.value.get_values_for_type(x509.UniformResourceIdentifier) if u.startswith(SAN_PREFIX)]
        # A service certificate carries exactly one service SAN.
        return uris[0] if len(uris) == 1 else None


def resolve(request: Request, peer: PeerIdentity) -> Caller:
    san = peer.peer_san(request)
    if san != IDENTITY_BFF_SAN:
        return Caller(san=san)
    actors = request.headers.getlist(ACTOR_HEADER)
    roles_raw = request.headers.getlist(ROLES_HEADER)
    # The BFF sets each header once. A repeated header means a client value got
    # through next to the BFF's; trust neither.
    if len(actors) > 1 or len(roles_raw) > 1:
        return Caller(san=san)
    actor = (actors[0] if actors else "") or None
    # SPEC-QUESTION: the roles header format is not fixed; comma-separated here.
    raw = roles_raw[0] if roles_raw else ""
    roles = frozenset(r.strip() for r in raw.split(",") if r.strip())
    return Caller(san=san, actor=actor, roles=roles)
