"""PR #12 review fixes: stuck states, integrity checks, auth order, config."""

import json
from dataclasses import replace

import httpx
import pytest
from conftest import SNAPSHOT_ID, candidate_json

from agentarium_discovery import app as app_module
from agentarium_discovery import template
from agentarium_discovery.clients import HttpRegression, KubernetesJobs
from agentarium_discovery.models import Observation, RunState
from agentarium_discovery.service import valid_source_uri

H = {"X-Agentarium-Console-Actor": "google:op", "X-Agentarium-Console-Roles": "operator"}
IMAGE = "r.example/agentarium/discovery-snapshot@sha256:" + "0" * 64


def _start_run(env):
    r = env.client.post("/internal/discovery/runs", json={"snapshot_id": SNAPSHOT_ID, "scenario_set_id": "s"}, headers=H)
    assert r.status_code == 202
    return r.json()["run_id"]


# --- 4(a) Job deleted after ttlSecondsAfterFinished ---------------------------

def test_job_status_404_is_job_gone(tmp_path, monkeypatch):
    def handler(request):
        return httpx.Response(404, json={"kind": "Status", "code": 404})

    jobs = KubernetesJobs("agent-observe", IMAGE, "bucket-1", client=httpx.Client(transport=httpx.MockTransport(handler)))
    token = tmp_path / "token"
    token.write_text("t")
    monkeypatch.setattr(KubernetesJobs, "TOKEN", str(token))
    st = jobs.status("discovery-snapshot-x")
    assert (st.state, st.error) == ("failed", "job_gone")


# --- 4(b) claimed run with a non-gateway failure ------------------------------

@pytest.mark.parametrize("exc", [KeyError("candidates"), httpx.ConnectError("down"), OSError("gcs read")])
def test_claimed_run_fails_on_any_exception(env, exc):
    run_id = _start_run(env)

    def boom(*a, **k):
        raise exc

    env.svc.analyzer.analyze = boom
    assert env.svc.process_next_run() is True
    run = env.store.get_run("hackathon", run_id)
    assert run.state == RunState.failed and run.error == f"static analysis failed: {type(exc).__name__}"
    assert env.store.runs_in_state(RunState.analyzing) == []


def test_reproduction_request_failure_after_analysis_is_terminal(env):
    env.gw.turns = [(json.dumps({"candidates": [candidate_json()]}), [])]
    run_id = _start_run(env)

    def boom(_):
        raise RuntimeError("unexpected")

    env.reg.request = boom
    env.svc.process_next_run()
    assert env.store.get_run("hackathon", run_id).state == RunState.failed


# --- 4(c) invalid observation in the reproduction report ----------------------

def test_http_regression_skips_invalid_observations():
    good = {"arm": "off", "process_exec_id": "p", "dst_ip": "203.0.113.9", "dst_port": 443,
            "tls_sni": "api.example.com", "source": "kernel"}
    report = {"state": "pass", "observations": [{"arm": "off", "dst_port": "not-a-port"}, good, {"nonsense": 1}]}

    def handler(request):
        return httpx.Response(200, json={"state": "finished", "report": report})

    reg = HttpRegression(httpx.Client(transport=httpx.MockTransport(handler)), "https://reg.example", "env", "c" * 64, "d" * 64)
    st = reg.status("r1")
    assert st.finished and len(st.observations) == 1 and st.observation_indexes == [1]
    assert [r.split(":")[0] for r in st.rejected_observations] == ["0", "2"]


def test_poll_records_skipped_observations_and_keeps_report_indexes(env):
    env.gw.turns = [(json.dumps({"candidates": []}), [])]
    run_id = _start_run(env)
    env.svc.process_next_run()
    obs = Observation(arm="off", process_exec_id="p", dst_ip="203.0.113.9", dst_port=443, tls_sni="api.example.com",
                      source="kernel")
    env.reg.observations = [obs]
    orig = env.reg.status

    def status(run_id_):
        return replace(orig(run_id_), observation_indexes=[3],
                       rejected_observations=["0: ValidationError", "1: ValidationError", "2: ValidationError"])

    env.reg.status = status
    assert env.svc.poll_reproductions() == 1
    run = env.store.get_run("hackathon", run_id)
    assert run.state == RunState.completed and run.error.startswith("skipped 3 invalid observation(s)")
    observed = [c for c in env.store.run_candidates("hackathon", run_id) if c.reproduction_run_id]
    assert [c.evidence_ref.rsplit("/", 1)[1] for c in observed] == ["3"]


def test_one_failing_reconcile_does_not_stop_polling(env):
    env.gw.turns = [(json.dumps({"candidates": []}), []), (json.dumps({"candidates": []}), [])]
    first, second = _start_run(env), _start_run(env)
    env.svc.process_next_run()
    env.svc.process_next_run()
    env.reg.observations = []
    real = env.svc.reconcile
    calls = []

    def flaky(run, *a, **k):
        calls.append(run.run_id)
        if run.run_id == first:
            raise ValueError("bad report")
        return real(run, *a, **k)

    env.svc.reconcile = flaky
    env.svc.poll_reproductions()
    assert set(calls) == {first, second}
    assert env.store.get_run("hackathon", second).state == RunState.completed


# --- 3 file integrity against the manifest ------------------------------------

def test_source_file_must_match_manifest_sha256(env):
    from agentarium_discovery import auth
    env.peer.san = auth.EVIDENCE_READER_SAN
    (env.root / "snapshots" / SNAPSHOT_ID / "src" / "httpx" / "_client.py").write_text("tampered\n")
    r = env.client.get(f"/internal/discovery/snapshots/{SNAPSHOT_ID}/files",
                       params={"path": "httpx/_client.py", "start_line": 1, "end_line": 1})
    assert r.status_code == 404


# --- 6 auth before parsing, KSA pin, regex anchors ----------------------------

@pytest.mark.parametrize("path,body", [
    ("/internal/discovery/runs", b"not json"),
    ("/internal/discovery/snapshots", b'{"x":1}'),
    ("/internal/discovery/candidates/" + "0" * 8 + "-0000-4000-8000-" + "0" * 12 + "/promote", b"[]"),
])
def test_unauthenticated_gets_401_before_body_parsing(env, path, body):
    env.peer.san = None
    r = env.client.post(path, content=body, headers={"content-type": "application/json"})
    assert r.status_code == 401 and r.json()["reason_codes"] == ["AUTH_REQUIRED"]


def test_unauthenticated_get_gets_401_before_query_validation(env):
    env.peer.san = None
    r = env.client.get(f"/internal/discovery/snapshots/{SNAPSHOT_ID}/files", params={"bogus": "1"})
    assert r.status_code == 401


def test_job_service_account_is_pinned(monkeypatch):
    monkeypatch.delenv("DISCOVERY_JOB_SERVICE_ACCOUNT", raising=False)
    assert app_module.job_service_account() == "discovery-snapshot"
    monkeypatch.setenv("DISCOVERY_JOB_SERVICE_ACCOUNT", "discovery-snapshot")
    assert app_module.job_service_account() == "discovery-snapshot"
    monkeypatch.setenv("DISCOVERY_JOB_SERVICE_ACCOUNT", "discovery")
    with pytest.raises(RuntimeError):
        app_module.job_service_account()


def test_trailing_newline_is_not_accepted():
    uri = "gs://disc-bucket/sources/" + "e" * 64 + ".tar.gz"
    assert valid_source_uri(uri, "e" * 64, "disc-bucket")
    assert not valid_source_uri(uri + "\n", "e" * 64, "disc-bucket")
    assert template.is_valid("https://api.example.com/v1")
    assert not template.is_valid("https://api.example.com/v1\n")
    with pytest.raises(ValueError):
        KubernetesJobs("agent-observe", IMAGE + "\n", "bucket-1", client=httpx.Client())
