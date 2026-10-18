"""mTLS HTTP server: uvicorn's h11 protocol plus the ASGI TLS extension.

uvicorn does not populate scope["extensions"]["tls"], so AsgiTlsPeerIdentity
would see no client certificate and every route would answer 401. This
protocol reads the peer certificate from the SSL transport once per
connection and adds the extension to every HTTP scope on that connection.
The certificate is only present after the handshake verified it against
ssl_ca_certs with CERT_REQUIRED, so a missing or untrusted client certificate
never reaches the application.
"""

from __future__ import annotations

import ssl
from typing import Any

from uvicorn.protocols.http.h11_impl import H11Protocol


def tls_extension(transport: Any) -> dict:
    ssl_object = transport.get_extra_info("ssl_object")
    der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
    return {
        "server_cert": None,
        # Leaf only: the handshake already validated the chain to the trust bundle.
        "client_cert_chain": [ssl.DER_cert_to_PEM_cert(der)] if der else [],
        "client_cert_name": None,
        "client_cert_error": None,
        "tls_version": None,
        "cipher_suite": None,
    }


class TlsExtensionH11Protocol(H11Protocol):
    def connection_made(self, transport):  # type: ignore[override]
        super().connection_made(transport)
        tls = tls_extension(transport)
        app = self.app

        async def with_tls(scope, receive, send):
            if scope["type"] == "http":
                scope = {**scope, "extensions": {**(scope.get("extensions") or {}), "tls": tls}}
            await app(scope, receive, send)

        self.app = with_tls


def run(app: Any, host: str, port: int, certfile: str, keyfile: str, ca_certs: str) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port, http=TlsExtensionH11Protocol,
                ssl_certfile=certfile, ssl_keyfile=keyfile, ssl_ca_certs=ca_certs,
                ssl_cert_reqs=ssl.CERT_REQUIRED)
