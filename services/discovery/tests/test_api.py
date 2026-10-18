import json

import pytest
from conftest import OPERATOR, SNAPSHOT_ID

from agentarium_discovery import auth
from agentarium_discovery.clients import JobStatus
from agentarium_discovery.service import PAGE_SIZE
from agentarium_discovery.store import CandidateRecord, Origin, OutboxEvent, now

H = {"X-Agentarium-Console-Actor": OPERATOR["actor"], "X-Agentarium-Console-Roles": "viewer, operator"}
JSON = {**H, "Content-Type": "application/json"}


def post_raw(env, path, raw: bytes):
    return env.client.post(path, content=raw, headers=JSON)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"snapshot_id":"' + b"a" * 64 + b'","scenario_set_id":"s","scenario_set_id":"t"}',  # duplicate
        b'{"snapshot_id":"' + b"a" * 64 + b'","scenario_set_id":"s","Scenario_set_id":"t"}',  # case-only
        b'{"snapshot_id":"' + b"a" * 64 + b'","Scenario_Set_Id":"s"}',  # tag case mismatch
        b'{"snapshot_id":"' + b"a" * 64 + b'","scenario_set_id":"s","extra":1}',  # unknown field
        b'{"snapshot_id":"' + b"A" * 64 + b'","scenario_set_id":"s"}',  # uppercase digest
        b'{"snapshot_id":"' + b"a" * 64 + b'","scenario_set_id":"\\ud800"}',  # lone surrogate
        b'{"snapshot_id":"' + b"a" * 64 + b'","scenario_set_id":"\xff"}',  # invalid UTF-8
        b'{"snapshot_id":NaN,"scenario_set_id":"s"}',
        b'{"snapshot_id":"' + b"a" * 64 + b'","scenario_set_id":"s"} {}',  # trailing token
        b'{"snapshot_id":"' + b"a" * 64 + b'","scenario_set_id":5}',  # strict type
        b"[]",
    ],
)
def test_strict_body_rejected(env, raw):
    r = post_raw(env, "/internal/discovery/runs", raw)
    assert r.status_code == 422
    body = r.json()
    assert body["reason_codes"] == ["SCHEMA_INVALID"] and set(body) == {"request_id", "reason_codes"}
    assert env.store.runs == {}


def test_body_too_large(env):
    r = post_raw(env, "/internal/discovery/runs", b'{"x":"' + b"a" * (1 << 20) + b'"}')
    assert r.status_code == 413 and r.json()["reason_codes"] == ["BODY_TOO_LARGE"]


def _request(headers: list[tuple[bytes, bytes]], chunks):
    """A Starlette request whose body comes from `chunks`; counts bytes pulled."""
    from starlette.requests import Request

    pulled = {"bytes": 0, "calls": 0}
    it = iter(chunks)

    async def receive():
        pulled["calls"] += 1
        chunk = next(it, None)
        if chunk is None:
            return {"type": "http.request", "body": b"", "more_body": False}
        pulled["bytes"] += len(chunk)
        return {"type": "http.request", "body": chunk, "more_body": True}

    scope = {"type": "http", "method": "POST", "path": "/", "headers": headers, "query_string": b""}
    return Request(scope, receive), pulled


def _endless(chunk_size=64 * 1024, total=16 << 20):
    for _ in range(total // chunk_size):
        yield b"a" * chunk_size


def test_body_cap_rejects_on_content_length_without_reading():
    import asyncio

    from agentarium_discovery.api import MAX_BODY, parse_body
    from agentarium_discovery.models import RunCreate
    from agentarium_discovery.service import ApiError

    req, pulled = _request([(b"content-length", str(MAX_BODY + 1).encode())], _endless())
    with pytest.raises(ApiError) as e:
        asyncio.run(parse_body(req, RunCreate))
    assert e.value.status == 413 and e.value.reason_codes == ["BODY_TOO_LARGE"]
    assert pulled["calls"] == 0


def test_body_cap_stops_reading_a_body_without_content_length():
    import asyncio

    from agentarium_discovery.api import MAX_BODY, parse_body
    from agentarium_discovery.models import RunCreate
    from agentarium_discovery.service import ApiError

    req, pulled = _request([], _endless())
    with pytest.raises(ApiError) as e:
        asyncio.run(parse_body(req, RunCreate))
    assert e.value.status == 413 and e.value.reason_codes == ["BODY_TOO_LARGE"]
    assert MAX_BODY < pulled["bytes"] <= MAX_BODY + 64 * 1024


def test_body_cap_rejects_bad_content_length():
    import asyncio

    from agentarium_discovery.api import parse_body
    from agentarium_discovery.models import RunCreate
    from agentarium_discovery.service import ApiError

    req, pulled = _request([(b"content-length", b"-1")], [b"{}"])
    with pytest.raises(ApiError) as e:
        asyncio.run(parse_body(req, RunCreate))
    assert e.value.status == 422 and pulled["calls"] == 0


def test_chunked_body_too_large_over_http(env):
    r = env.client.post("/internal/discovery/runs", content=_endless(total=2 << 20),
                        headers={**H, "content-type": "application/json"})
    assert r.status_code == 413 and r.json()["reason_codes"] == ["BODY_TOO_LARGE"]


def test_run_for_unknown_snapshot_is_404(env):
    r = env.client.post("/internal/discovery/runs", json={"snapshot_id": "c" * 64, "scenario_set_id": "s"}, headers=H)
    assert r.status_code == 404 and r.json()["reason_codes"] == ["RESOURCE_NOT_FOUND"]


def test_operator_role_required_for_console_routes(env):
    for hdr in [{}, {"X-Agentarium-Console-Actor": "google:x", "X-Agentarium-Console-Roles": "viewer"},
                {"X-Agentarium-Console-Roles": "operator"}]:
        r = env.client.get("/internal/discovery/candidates", headers=hdr)
        assert r.status_code == 403
    env.peer.san = None
    assert env.client.get("/internal/discovery/candidates", headers=H).status_code == 401
    env.peer.san = auth.EVIDENCE_READER_SAN
    assert env.client.get("/internal/discovery/candidates", headers=H).status_code == 403


def seed(env, n):
    for i in range(n):
        rec = CandidateRecord(
            candidate_id=f"00000000-0000-4000-8000-{i:012d}", tenant="hackathon",
            run_id="55555555-5555-4555-8555-555555555555", snapshot_id=SNAPSHOT_ID, origin=Origin.static,
            library="httpx", library_version="0.27.0", call_site="c", trigger_condition="t",
            destination_template="https://x.example.com/", retry_redirect_behavior="r", evidence_ref="e",
            model_run_ref="m")
        env.store.record_candidate(rec, OutboxEvent(f"e{i}", "discovery_candidate_recorded", "hackathon", 1, now(), None, {}))


def test_candidate_pagination(env):
    seed(env, PAGE_SIZE + 5)
    r = env.client.get("/internal/discovery/candidates", headers=H)
    page = r.json()
    assert len(page["items"]) == PAGE_SIZE and page["next_cursor"]
    r2 = env.client.get("/internal/discovery/candidates", params={"cursor": page["next_cursor"]}, headers=H).json()
    assert len(r2["items"]) == 5 and r2["next_cursor"] is None
    ids = [c["candidate_id"] for c in page["items"] + r2["items"]]
    assert len(set(ids)) == PAGE_SIZE + 5
    assert set(page["items"][0]) == {
        "candidate_id", "library", "library_version", "call_site", "trigger_condition", "destination_template",
        "retry_redirect_behavior", "evidence_ref", "model_run_ref", "dynamic_match", "path_unverified",
        "matched_arms", "reproduction_run_id", "state", "promotion_kind", "reviewed_by_actor", "catalog_change_ref"}
    filt = env.client.get("/internal/discovery/candidates", params={"state": "reproduced"}, headers=H).json()
    assert filt["items"] == []
    other = env.client.get("/internal/discovery/candidates",
                           params={"run_id": "66666666-6666-4666-8666-666666666666"}, headers=H).json()
    assert other["items"] == []


@pytest.mark.parametrize("params", [{"cursor": "!!"}, {"cursor": "c2VxOng"}, {"state": "allowed"},
                                    {"run_id": "not-a-uuid"}, {"limit": "5"}])
def test_candidate_query_rejected(env, params):
    r = env.client.get("/internal/discovery/candidates", params=params, headers=H)
    assert r.status_code == 422


# --- snapshot read tools ------------------------------------------------------

FILES = f"/internal/discovery/snapshots/{SNAPSHOT_ID}/files"
GRAPH = f"/internal/discovery/snapshots/{SNAPSHOT_ID}/callgraph"


def test_source_read(env):
    env.peer.san = auth.EVIDENCE_READER_SAN
    r = env.client.get(FILES, params={"path": "httpx/_client.py", "start_line": 10, "end_line": 12})
    assert r.status_code == 200
    assert r.json()["lines"] == ["line 10", "line 11", "line 12"] and r.json()["truncated"] is False
    # At most 400 lines (TASK-02 table: more than 400 lines -> 422).
    r = env.client.get(FILES, params={"path": "httpx/_client.py", "start_line": 1, "end_line": 400})
    assert r.status_code == 200 and len(r.json()["lines"]) == 400
    r = env.client.get(FILES, params={"path": "httpx/_client.py", "start_line": 1, "end_line": 401})
    assert r.status_code == 422
    r = env.client.get(FILES, params={"path": "httpx/big.py", "start_line": 1, "end_line": 300})
    assert r.status_code == 200 and r.json()["truncated"] is True
    assert len(r.content) <= 64 * 1024
    assert r.json()["end_line"] == len(r.json()["lines"])


@pytest.mark.parametrize("params", [
    {"path": "httpx/_client.py", "start_line": 1, "end_line": 401},  # > 400 lines
    {"path": "httpx/_client.py", "start_line": 600, "end_line": 1000},  # 401 lines
    {"path": "httpx/_client.py", "start_line": 0, "end_line": 2},
    {"path": "httpx/_client.py", "start_line": 5, "end_line": 4},
    {"path": "httpx/_client.py", "start_line": "1.5", "end_line": 4},
    {"path": "../manifest.json", "start_line": 1, "end_line": 2},
    {"path": "manifest.json", "start_line": 1, "end_line": 2},  # not in manifest
    {"path": "httpx/missing.py", "start_line": 1, "end_line": 2},
    {"path": "x" * 513, "start_line": 1, "end_line": 2},
    {"path": "httpx/_client.py", "start_line": 1},
    {"path": "httpx/_client.py", "start_line": 1, "end_line": 2, "url": "https://evil"},
])
def test_source_read_rejected(env, params):
    env.peer.san = auth.EVIDENCE_READER_SAN
    assert env.client.get(FILES, params=params).status_code == 422


def test_read_tools_only_for_evidence_reader(env):
    params = {"path": "httpx/_client.py", "start_line": 1, "end_line": 2}
    assert env.client.get(FILES, params=params, headers=H).status_code == 403  # console BFF
    env.peer.san = None
    assert env.client.get(FILES, params=params).status_code == 401
    env.peer.san = auth.EVIDENCE_READER_SAN
    r = env.client.get(f"/internal/discovery/snapshots/{'d' * 64}/files", params=params)
    assert r.status_code == 404


def test_callgraph_read(env):
    env.peer.san = auth.EVIDENCE_READER_SAN
    r = env.client.get(GRAPH, params={"symbol": "httpx.Client.send", "depth": 1}).json()
    assert r["edges"] == [{"symbol": "httpx.Client.send", "callees": ["httpx.Client._send_single", "httpx.Client.build"]}]
    r = env.client.get(GRAPH, params={"symbol": "httpx.Client.send", "depth": 3}).json()
    assert [e["symbol"] for e in r["edges"]] == [
        "httpx.Client.send", "httpx.Client._send_single", "httpx.Client.build", "httpx.HTTPTransport.handle_request"]
    for params in [{"symbol": "httpx.Client.send", "depth": 4}, {"symbol": "nope", "depth": 1},
                   {"symbol": "httpx.Client.send", "depth": "1.5"}, {"symbol": "s" * 257, "depth": 1}]:
        assert env.client.get(GRAPH, params=params).status_code == 422


# --- snapshot creation ------------------------------------------------------

SNAP = {"library": "httpx", "library_version": "0.28.1", "language": "python",
        "source_uri": "gs://disc-bucket/sources/" + "e" * 64 + ".tar.gz", "source_digest": "e" * 64}


def test_snapshot_creation_flow(env):
    r = env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H)
    assert r.status_code == 202 and r.json()["state"] == "running" and r.json()["snapshot_id"] is None
    assert len(env.jobs.launched) == 1
    # Same request while running: no second Job.
    assert env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H).status_code == 202
    assert len(env.jobs.launched) == 1
    # Job finished but the snapshot is not in the bucket: failed, never registered.
    env.jobs.result = JobStatus("succeeded", {"snapshot_id": "f" * 64})
    r = env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H)
    assert r.status_code == 200 and r.json()["state"] == "failed"
    assert env.store.get_snapshot("hackathon", "f" * 64) is None
    # Retry launches a new Job; this time the snapshot exists and verifies.
    env.jobs.result = JobStatus("running")
    assert env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H).status_code == 202
    assert len(env.jobs.launched) == 2
    from conftest import write_verified_snapshot
    sid = write_verified_snapshot(env.root, source_digest=SNAP["source_digest"])
    env.jobs.result = JobStatus("succeeded", {"snapshot_id": sid})
    r = env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H)
    assert r.status_code == 200 and r.json() == {**{k: SNAP[k] for k in ("library", "library_version", "language", "source_digest")},
                                                  "state": "succeeded", "snapshot_id": sid}
    assert env.store.get_snapshot("hackathon", sid).file_count == 2


def _job_returns(env, sid):
    assert env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H).status_code == 202
    env.jobs.result = JobStatus("succeeded", {"snapshot_id": sid})
    return env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H)


@pytest.mark.parametrize("case", ["digest", "source_digest", "language", "malformed_id", "no_digester"])
def test_job_result_is_verified_before_use(env, case):
    """The Job ran untrusted source with bucket write access: its returned
    snapshot_id is checked against the stored manifest (PR #12 review)."""
    from conftest import write_snapshot, write_verified_snapshot
    if case == "digest":
        # A snapshot planted under an id that is not its manifest digest.
        write_snapshot(env.root, "f" * 64, source_digest=SNAP["source_digest"])
        sid = "f" * 64
    elif case == "source_digest":
        sid = write_verified_snapshot(env.root, source_digest="c" * 64)
    elif case == "language":
        sid = write_verified_snapshot(env.root, source_digest=SNAP["source_digest"], language="go")
    elif case == "malformed_id":
        sid = "../" + "a" * 61
    else:
        sid = write_verified_snapshot(env.root, source_digest=SNAP["source_digest"])
        env.svc.digester = None
    r = _job_returns(env, sid)
    assert r.status_code == 200 and r.json()["state"] == "failed" and r.json()["snapshot_id"] is None
    assert env.store.get_snapshot("hackathon", sid) is None


def test_deleted_job_fails_the_request(env):
    assert env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H).status_code == 202
    env.jobs.result = JobStatus("failed", None, "job_gone")
    r = env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H)
    assert r.status_code == 200 and r.json()["state"] == "failed"
    # A failed request can be retried with a new Job.
    env.jobs.result = JobStatus("running")
    assert env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H).status_code == 202
    assert len(env.jobs.launched) == 2


def test_snapshot_creation_validation(env):
    for bad in [{**SNAP, "language": "rust"}, {**SNAP, "source_digest": "x"}, {k: v for k, v in SNAP.items() if k != "library"}]:
        assert env.client.post("/internal/discovery/snapshots", json=bad, headers=H).status_code == 422
    assert env.jobs.launched == []


@pytest.mark.parametrize("source_uri", [
    # Outbound fetches are not accepted (SSRF; no Cloud NAT): stage the archive in the bucket.
    "https://files.example/httpx-0.28.1.tar.gz",
    "http://10.0.0.1/" + "e" * 64 + ".tar.gz",
    "git+https://github.com/encode/httpx#" + "a" * 40,
    "file:///tmp/" + "e" * 64 + ".tar.gz",
    # Wrong bucket, wrong digest in the name, wrong prefix/extension/shape.
    "gs://other-bucket/sources/" + "e" * 64 + ".tar.gz",
    "gs://disc-bucket/sources/" + "f" * 64 + ".tar.gz",
    "gs://disc-bucket/snapshots/" + "e" * 64 + ".tar.gz",
    "gs://disc-bucket/sources/x/" + "e" * 64 + ".tar.gz",
    "gs://disc-bucket/sources/" + "e" * 64 + ".rar",
    "gs://disc-bucket/sources/" + "E" * 64 + ".tar.gz",
    "gs://disc-bucket/sources/" + "e" * 64 + ".tar.gz?x=1",
])
def test_snapshot_source_uri_must_be_staged_in_the_bucket(env, source_uri):
    r = env.client.post("/internal/discovery/snapshots", json={**SNAP, "source_uri": source_uri}, headers=H)
    assert r.status_code == 422 and r.json()["reason_codes"] == ["SCHEMA_INVALID"]
    assert env.jobs.launched == []


@pytest.mark.parametrize("ext", ["tar.gz", "tgz", "tar", "zip", "whl"])
def test_snapshot_source_uri_extensions(env, ext):
    uri = "gs://disc-bucket/sources/" + "e" * 64 + "." + ext
    assert env.client.post("/internal/discovery/snapshots", json={**SNAP, "source_uri": uri}, headers=H).status_code == 202


def test_snapshot_source_uri_rejected_without_configured_bucket(env):
    env.svc.config.discovery_bucket = None
    assert env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H).status_code == 422
    assert env.jobs.launched == []


def test_job_launch_failure_is_503(env):
    def boom(*a):
        raise RuntimeError("k8s down")

    env.jobs.launch = boom
    r = env.client.post("/internal/discovery/snapshots", json=SNAP, headers=H)
    assert r.status_code == 503 and r.headers["Retry-After"] == "2"


def test_unknown_route_is_404(env):
    r = env.client.get("/internal/discovery/nothing", headers=H)
    assert r.status_code == 404 and r.json()["reason_codes"] == ["RESOURCE_NOT_FOUND"]
    assert json.loads(r.content)["request_id"]


@pytest.mark.parametrize("raw,status", [
    (b'{"reason":"ok"}', 404),  # parses; candidate does not exist
    (b'{"reason":"\\ud800"}', 422),  # lone surrogate in free text
    (b'{"reason":"a","reason":"b"}', 422),
    (b'{"reason":"a","REASON":"b"}', 422),
    (b'{"reason":"a\xc3"}', 422),
])
def test_strict_parsing_on_free_text_field(env, raw, status):
    r = post_raw(env, "/internal/discovery/candidates/44444444-4444-4444-8444-444444444444/reject", raw)
    assert r.status_code == status


def test_repeated_console_identity_headers_are_not_trusted(env):
    # A proxy that appends instead of replacing would leave the client's value
    # first; an ambiguous identity is no identity.
    for hdrs in [
        [("X-Agentarium-Console-Actor", "google:viewer"), ("X-Agentarium-Console-Roles", "operator"),
         ("X-Agentarium-Console-Roles", "viewer")],
        [("X-Agentarium-Console-Actor", "google:operator-1"), ("X-Agentarium-Console-Actor", "google:viewer"),
         ("X-Agentarium-Console-Roles", "operator")],
    ]:
        assert env.client.get("/internal/discovery/candidates", headers=hdrs).status_code == 403
