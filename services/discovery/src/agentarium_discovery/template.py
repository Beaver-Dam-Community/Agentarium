"""destination_template grammar (TASK-02 3.4).

    <scheme>://<host-glob>[:<port>]<path-prefix>

scheme is https or http. host-glob is dot-separated labels where `*` stands
for exactly one label (`**` and partial wildcards are invalid). Scheme and host
compare ASCII case-insensitively. A missing port is the scheme default (443,
80). path-prefix is a literal starting with `/` that matches only on a segment
boundary: `/v1` matches `/v1` and `/v1/x`, not `/v10`.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

MAX_TEMPLATE_BYTES = 512
DEFAULT_PORTS = {"https": 443, "http": 80}

_TEMPLATE_RE = re.compile(
    r"^(?P<scheme>[A-Za-z]+)://"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[^/:\[\]]+)"
    r"(?::(?P<port>[0-9]{1,5}))?"
    r"(?P<path>/.*)$",
    re.DOTALL,
)
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PATH_RE = re.compile(r"^/[\x21-\x7e]*$")


class TemplateError(ValueError):
    pass


@dataclass(frozen=True)
class Template:
    scheme: str
    # Lowercase labels, or None when the host is an IPv6 literal.
    labels: tuple[str, ...] | None
    ip: str | None
    port: int
    path_prefix: str

    @property
    def is_ip_literal(self) -> bool:
        if self.ip is not None:
            return True
        assert self.labels is not None
        try:
            ipaddress.IPv4Address(".".join(self.labels))
        except ValueError:
            return False
        return True

    def host_matches(self, host: str) -> bool:
        host = host.rstrip(".").lower()
        if self.ip is not None:
            try:
                return str(ipaddress.ip_address(host.strip("[]"))) == self.ip
            except ValueError:
                return False
        assert self.labels is not None
        parts = host.split(".")
        if len(parts) != len(self.labels):
            return False
        return all(t == "*" or t == p for t, p in zip(self.labels, parts, strict=True))

    def path_matches(self, path: str) -> bool:
        path = path.split("?", 1)[0].split("#", 1)[0]
        prefix = self.path_prefix
        if path == prefix:
            return True
        if not path.startswith(prefix):
            return False
        return prefix.endswith("/") or path[len(prefix)] == "/"


def parse(text: str) -> Template:
    if len(text.encode()) > MAX_TEMPLATE_BYTES:
        raise TemplateError("template too long")
    m = _TEMPLATE_RE.fullmatch(text)
    if not m:
        raise TemplateError("template must be <scheme>://<host-glob>[:<port>]<path-prefix>")
    scheme = m["scheme"].lower()
    if scheme not in DEFAULT_PORTS:
        raise TemplateError("scheme must be https or http")
    port = DEFAULT_PORTS[scheme]
    if m["port"] is not None:
        port = int(m["port"])
        if not 1 <= port <= 65535:
            raise TemplateError("port out of range")
    path = m["path"]
    if not _PATH_RE.fullmatch(path) or "*" in path or "?" in path or "#" in path:
        raise TemplateError("path-prefix must be a literal path")
    host = m["host"]
    if host.startswith("["):
        # IPv6 literal, only produced for observed_not_static templates.
        try:
            ip = ipaddress.IPv6Address(host[1:-1])
        except ValueError as e:
            raise TemplateError("invalid IPv6 literal") from e
        return Template(scheme, None, str(ip), port, path)
    host = host.lower()
    if len(host) > 253:
        raise TemplateError("host too long")
    labels = tuple(host.split("."))
    for label in labels:
        if label != "*" and not _LABEL_RE.fullmatch(label):
            raise TemplateError(f"invalid host label {label!r}")
    return Template(scheme, labels, None, port, path)


def is_valid(text: str) -> bool:
    try:
        parse(text)
    except TemplateError:
        return False
    return True


def for_observation(scheme: str | None, host: str | None, ip: str, port: int) -> str:
    """Template for an observed_not_static candidate.

    Unknown host: `https://<dst_ip>:<dst_port>/` (TASK-02 3.4). Known host:
    `<scheme>://<host>[:<port>]/`; an unknown scheme falls back to https with an
    explicit port.
    """
    if host is None:
        addr = ipaddress.ip_address(ip)
        h = f"[{addr}]" if addr.version == 6 else str(addr)
        return f"https://{h}:{port}/"
    s = scheme or "https"
    if scheme is not None and DEFAULT_PORTS[s] == port:
        return f"{s}://{host}/"
    return f"{s}://{host}:{port}/"
