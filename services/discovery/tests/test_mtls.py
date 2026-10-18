"""Real mTLS on localhost: uvicorn + TlsExtensionH11Protocol + AsgiTlsPeerIdentity.

No fake PeerIdentity: the SAN must come from the verified client certificate
of an actual TLS connection.
"""

import datetime
import ipaddress
import socket
import ssl
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agentarium_discovery import auth
from agentarium_discovery.api import create_app
from agentarium_discovery.server import TlsExtensionH11Protocol
from conftest import SNAPSHOT_ID


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def _leaf(ca_key, ca_cert, sans, client):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    eku = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH if client else x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
    cert = (x509.CertificateBuilder().subject_name(_name("leaf")).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def _write(path, key, cert):
    path.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        path.with_suffix(".key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(path.with_suffix(".crt")), str(path.with_suffix(".key"))


@pytest.fixture
def pki(tmp_path):
    ca_key, ca_cert = _ca("agentarium test CA")
    ca_file, _ = _write(tmp_path / "ca", None, ca_cert)
    skey, scert = _leaf(ca_key, ca_cert, [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], client=False)
    server = _write(tmp_path / "server", skey, scert)
    ckey, ccert = _leaf(ca_key, ca_cert, [x509.UniformResourceIdentifier(auth.EVIDENCE_READER_SAN)], client=True)
    reader = _write(tmp_path / "reader", ckey, ccert)
    okey, ocert = _leaf(ca_key, ca_cert, [x509.UniformResourceIdentifier(auth.SAN_PREFIX + "agent-exec/sa/agent-runtime")], client=True)
    other = _write(tmp_path / "other", okey, ocert)
    rogue_key, rogue_ca = _ca("rogue CA")
    rkey, rcert = _leaf(rogue_key, rogue_ca, [x509.UniformResourceIdentifier(auth.EVIDENCE_READER_SAN)], client=True)
    rogue = _write(tmp_path / "rogue", rkey, rcert)
    return {"ca": ca_file, "server": server, "reader": reader, "other": other, "rogue": rogue}


def _serve(env, pki, http):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    app = create_app(env.svc, auth.AsgiTlsPeerIdentity())
    config = uvicorn.Config(app, host="127.0.0.1", port=port, http=http, log_level="warning",
                            ssl_certfile=pki["server"][0], ssl_keyfile=pki["server"][1],
                            ssl_ca_certs=pki["ca"], ssl_cert_reqs=ssl.CERT_REQUIRED)
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline or not t.is_alive():
            pytest.fail("uvicorn did not start")
        time.sleep(0.05)
    return f"https://127.0.0.1:{port}", server, t


@pytest.fixture
def live(env, pki):
    url, server, t = _serve(env, pki, TlsExtensionH11Protocol)
    yield url
    server.should_exit = True
    t.join(10)


@pytest.fixture
def stock_uvicorn(env, pki):
    url, server, t = _serve(env, pki, "h11")
    yield url
    server.should_exit = True
    t.join(10)


def client(pki, cert):
    ctx = ssl.create_default_context(cafile=pki["ca"])
    if cert:
        ctx.load_cert_chain(*pki[cert])
    return httpx.Client(verify=ctx)


FILES = f"/internal/discovery/snapshots/{SNAPSHOT_ID}/files"
PARAMS = {"path": "httpx/_client.py", "start_line": "1", "end_line": "2"}


def test_client_san_reaches_the_handler(live, pki):
    with client(pki, "reader") as c:
        r = c.get(live + FILES, params=PARAMS)
    assert r.status_code == 200, r.text
    assert r.json()["lines"] == ["line 1", "line 2"]


def test_other_service_san_is_forbidden(live, pki):
    with client(pki, "other") as c:
        r = c.get(live + FILES, params=PARAMS)
    assert r.status_code == 403


@pytest.mark.parametrize("cert", [None, "rogue"])
def test_missing_or_untrusted_client_cert_is_rejected_in_the_handshake(live, pki, cert):
    with client(pki, cert) as c:
        with pytest.raises(httpx.TransportError):
            c.get(live + FILES, params=PARAMS)


def test_stock_uvicorn_does_not_expose_the_client_cert(stock_uvicorn, pki):
    # The PR #12 review finding: plain uvicorn leaves extensions.tls empty, so a
    # valid client certificate still ends in 401.
    with client(pki, "reader") as c:
        r = c.get(stock_uvicorn + FILES, params=PARAMS)
    assert r.status_code == 401
