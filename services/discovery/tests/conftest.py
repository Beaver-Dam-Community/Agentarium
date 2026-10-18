import hashlib
import itertools
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentarium_discovery import auth
from agentarium_discovery.analyzer import Analyzer
from agentarium_discovery.api import create_app
from agentarium_discovery.clients import (
    FunctionCall,
    GatewayError,
    JobStatus,
    ModelTurn,
    RegressionStatus,
    ServiceSession,
)
from agentarium_discovery.matcher import InfraDestinations
from agentarium_discovery.service import Config, DiscoveryService
from agentarium_discovery.snapshots import SnapshotStore
from agentarium_discovery.store import InMemoryStore, SnapshotRecord

SNAPSHOT_ID = "a" * 64
BUCKET = "disc-bucket"
# Lock network.gateway_cluster_ip and network.services_range of the test environment.
TEST_INFRA = InfraDestinations.from_lock("10.30.0.20", "10.30.0.0/20")
OPERATOR = {"actor": "google:operator-1", "roles": "operator"}


def write_snapshot(root: Path, snapshot_id: str = SNAPSHOT_ID, call_sites: list | None = None,
                   language: str = "python", source_digest: str = "b" * 64) -> bytes:
    """Writes a snapshot in the tools/discovery-snapshot layout; returns the
    manifest.json bytes."""
    d = root / "snapshots" / snapshot_id
    (d / "src" / "httpx").mkdir(parents=True)
    files = {
        "httpx/_client.py": "".join(f"line {i}\n" for i in range(1, 1001)).encode(),
        "httpx/big.py": (("x" * 1000 + "\n") * 300).encode(),
    }
    for path, data in files.items():
        (d / "src" / path).write_bytes(data)
    manifest = json.dumps({"language": language, "scanner_version": "discovery-snapshot/1", "source_digest": source_digest,
                           "files": [{"path": p, "sha256": hashlib.sha256(b).hexdigest()} for p, b in sorted(files.items())]}).encode()
    (d / "manifest.json").write_bytes(manifest)
    graph = {"httpx.Client.send": ["httpx.Client._send_single", "httpx.Client.build"],
             "httpx.Client._send_single": ["httpx.HTTPTransport.handle_request"],
             "httpx.HTTPTransport.handle_request": ["httpcore.ConnectionPool.handle_request"],
             "httpx.Client.build": []}
    (d / "callgraph.json").write_text(json.dumps(graph))
    sites = call_sites if call_sites is not None else [
        {"caller": "httpx.Client.send", "callee": "socket.create_connection", "category": "socket",
         "path": "httpx/_client.py", "line": 10, "column": 5, "import_alias": None},
    ]
    (d / "call_sites.json").write_text(json.dumps({"language": "python", "tool": "python-ast", "call_sites": sites,
                                                    "imports": [], "limitations": ["dynamic dispatch is not followed"]}))
    return manifest


class ShaDigester:
    """Stands in for canonical-digest in tests: sha256 of the document bytes."""

    def digest_bytes(self, doc: bytes) -> str:
        return hashlib.sha256(doc).hexdigest()


def write_verified_snapshot(root: Path, **kw) -> str:
    """A snapshot whose snapshot_id is the (test) digest of its manifest."""
    tmp = root / "_staging"
    manifest = write_snapshot(tmp, "0" * 64, **kw)
    sid = ShaDigester().digest_bytes(manifest)
    (root / "snapshots").mkdir(exist_ok=True)
    (tmp / "snapshots" / ("0" * 64)).rename(root / "snapshots" / sid)
    return sid


class FakePeer:
    def __init__(self) -> None:
        self.san: str | None = auth.IDENTITY_BFF_SAN

    def peer_san(self, request):
        return self.san


@dataclass
class FakeGateway:
    """Scripted model turns; records every call."""

    turns: list = field(default_factory=list)
    calls: list = field(default_factory=list)
    fail_open: bool = False
    ids: itertools.count = field(default_factory=lambda: itertools.count(1))

    def _id(self) -> str:
        return f"00000000-0000-4000-8000-{next(self.ids):012d}"

    def open_session(self, snapshot_id):
        self.calls.append(("open_session", snapshot_id))
        if self.fail_open:
            raise GatewayError("identity unavailable")
        return ServiceSession("11111111-1111-4111-8111-111111111111", "tok", "2026-10-14T01:00:00Z")

    def generate(self, session, conversation_id, messages):
        self.calls.append(("generate", conversation_id, json.loads(json.dumps(messages))))
        if not self.turns:
            raise GatewayError("no scripted turn")
        t = self.turns.pop(0)
        if isinstance(t, Exception):
            raise t
        text, fcs = t
        return ModelTurn(self._id(), len([c for c in self.calls if c[0] == "generate"]) - 1, text,
                         [FunctionCall(n, a) for n, a in fcs])

    def source_read(self, session, snapshot_id, path, start_line, end_line):
        self.calls.append(("source_read", snapshot_id, path, start_line, end_line))
        return self._id()

    def callgraph_read(self, session, snapshot_id, symbol, depth):
        self.calls.append(("callgraph_read", snapshot_id, symbol, depth))
        return self._id()


@dataclass
class FakeRegression:
    run_id: str = "22222222-2222-4222-8222-222222222222"
    observations: list | None = None
    finished: bool = True
    requested: list = field(default_factory=list)

    def request(self, scenario_set_id):
        self.requested.append(scenario_set_id)
        return self.run_id

    def status(self, run_id):
        return RegressionStatus(run_id, self.finished, "pass" if self.finished else "not_run",
                                self.observations if self.finished else None)


@dataclass
class FakeJobs:
    launched: list = field(default_factory=list)
    result: JobStatus = field(default_factory=lambda: JobStatus("running"))

    def launch(self, request_id, language, source_uri, source_digest, library, library_version):
        self.launched.append((request_id, language, source_uri, source_digest))
        return f"job-{len(self.launched)}"

    def status(self, job_name):
        return self.result


def candidate_json(**over):
    c = {"call_site": "httpx/_client.py:10 httpx.Client.send -> socket.create_connection",
         "library_version": "0.27.0",
         "trigger_condition": "Client.send on a new connection",
         "destination_template": "https://*.googleapis.com/v1/",
         "retry_redirect_behavior": "no retry; redirects disabled by default",
         "evidence_ref": "httpx/_client.py#L5-L20"}
    c.update(over)
    return c


@pytest.fixture
def env(tmp_path):
    write_snapshot(tmp_path)
    store = InMemoryStore()
    store.put_snapshot(SnapshotRecord(SNAPSHOT_ID, "hackathon", "httpx", "0.27.0", "python",
                                      "https://files.example/httpx-0.27.0.tar.gz", "b" * 64, 2))
    gw = FakeGateway()
    reg = FakeRegression()
    jobs = FakeJobs()
    svc = DiscoveryService(store, SnapshotStore(tmp_path), jobs, Analyzer(gw), reg, Config(tenant="hackathon", discovery_bucket=BUCKET, infra=TEST_INFRA),
                           digester=ShaDigester())
    peer = FakePeer()
    client = TestClient(create_app(svc, peer))

    @dataclass
    class Env:
        pass

    e = Env()
    e.store, e.gw, e.reg, e.jobs, e.svc, e.peer, e.client, e.root = store, gw, reg, jobs, svc, peer, client, tmp_path
    return e
