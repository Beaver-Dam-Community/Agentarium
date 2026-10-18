"""PostgresStore and migration constraints against a real PostgreSQL.

Run with: DISCOVERY_TEST_DATABASE_URL=postgresql://... pytest -m integration
The test drops and recreates the `discovery` schema in that database.
"""

import os
import pathlib
import uuid

import pytest

pytestmark = pytest.mark.integration

psycopg = pytest.importorskip("psycopg")

from agentarium_discovery.models import CandidateState, DynamicMatch, PromotionKind, RunState  # noqa: E402
from agentarium_discovery.postgres import PostgresStore  # noqa: E402
from agentarium_discovery.store import (  # noqa: E402
    CandidateRecord,
    Origin,
    Outcome,
    OutboxEvent,
    RunRecord,
    SnapshotRecord,
    now,
)

MIGRATIONS = pathlib.Path(__file__).resolve().parents[3] / "migrations"
DSN = os.environ.get("DISCOVERY_TEST_DATABASE_URL")
SNAP = "a" * 64


@pytest.fixture
def store():
    if not DSN:
        pytest.skip("DISCOVERY_TEST_DATABASE_URL not set")
    # Every discovery migration in version order, as golang-migrate applies them.
    ups = sorted(MIGRATIONS.glob("*_discovery_*.up.sql"))
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS discovery CASCADE")
        for f in ups:
            conn.execute(f.read_text())
    s = PostgresStore(DSN)
    s.put_snapshot(SnapshotRecord(SNAP, "hackathon", "httpx", "0.27.0", "python", "https://x/y.tar.gz", "b" * 64, 2))
    yield s
    # Rows left by the test may block the down migrations (see the newest
    # .down.sql); they are exercised on an empty schema in
    # test_migrations_roll_back_cleanly instead.
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS discovery CASCADE")


def ev(kind="discovery_candidate_recorded"):
    return OutboxEvent(str(uuid.uuid4()), kind, "hackathon", 1, now(), None, {"k": "v"})


def make(store, origin=Origin.static, **over):
    run_id = str(uuid.uuid4())
    store.create_run(RunRecord(run_id, "hackathon", SNAP, "s", RunState.queued, "google:op"))
    fields = dict(candidate_id=str(uuid.uuid4()), tenant="hackathon", run_id=run_id, snapshot_id=SNAP, origin=origin,
                  library="httpx", library_version="0.27.0", call_site="c", trigger_condition="t",
                  destination_template="https://x.example.com/", retry_redirect_behavior="r", evidence_ref="e",
                  model_run_ref="m")
    fields.update(over)
    return store.record_candidate(CandidateRecord(**fields), ev())


def test_model_only_candidate_promote_conflicts_without_change(store):
    c = make(store)
    before = store.get_candidate("hackathon", c.candidate_id)
    outcome, _ = store.promote("hackathon", c.candidate_id, str(uuid.uuid4()), PromotionKind.allow_operation,
                               "google:op", "n", ev("discovery_candidate_promoted"))
    assert outcome == Outcome.conflict
    assert store.get_candidate("hackathon", c.candidate_id) == before
    assert [e.event_type for e in store.pending_events(10)] == ["discovery_candidate_recorded"]
    assert [(t.from_state, t.to_state) for t in store.transitions(c.candidate_id)] == [(None, CandidateState.candidate)]


def test_full_transition_path_is_logged(store):
    c = make(store)
    repro = str(uuid.uuid4())
    assert store.apply_match(c.candidate_id, DynamicMatch.matched, True, repro, ("off", "on")) == Outcome.ok
    assert store.get_candidate("hackathon", c.candidate_id).matched_arms == ("off", "on")
    assert store.apply_match(c.candidate_id, DynamicMatch.matched, True, repro, ("off",)) == Outcome.conflict
    outcome, rec = store.promote("hackathon", c.candidate_id, repro, PromotionKind.deny_fixture, "google:op",
                                 "reviewed", ev("discovery_candidate_promoted"))
    assert outcome == Outcome.ok and rec.state == CandidateState.promoted and rec.reviewed_by_actor == "google:op"
    ts = store.transitions(c.candidate_id)
    assert [(t.from_state, t.to_state, t.actor) for t in ts] == [
        (None, CandidateState.candidate, "service:discovery"),
        (CandidateState.candidate, CandidateState.reproduced, "service:discovery:matcher"),
        (CandidateState.reproduced, CandidateState.promoted, "google:op"),
    ]
    assert ts[-1].note == "reviewed"
    assert store.reject("hackathon", c.candidate_id, "late", "google:op")[0] == Outcome.conflict


def test_database_rejects_shortcuts(store):
    c = make(store)
    with psycopg.connect(DSN) as conn:
        for sql in [
            # candidate -> promoted without reproduction
            "UPDATE discovery.discovery_candidates SET state='promoted', promotion_kind='allow_operation', reviewed_by_actor='x' WHERE candidate_id=%s",
            # reproduced without a matcher result
            "UPDATE discovery.discovery_candidates SET state='reproduced' WHERE candidate_id=%s",
            # path flag without a match result
            "UPDATE discovery.discovery_candidates SET path_unverified=true WHERE candidate_id=%s",
            # model output rewritten
            "UPDATE discovery.discovery_candidates SET destination_template='https://*.evil.com/' WHERE candidate_id=%s",
            "DELETE FROM discovery.discovery_candidates WHERE candidate_id=%s",
            "UPDATE discovery.discovery_candidate_transitions SET actor='x' WHERE candidate_id=%s",
        ]:
            with pytest.raises(psycopg.Error), conn.transaction():
                cur = conn.execute(sql, (c.candidate_id,))
                pytest.fail(f"accepted ({cur.rowcount} rows): {sql}")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("INSERT INTO discovery.discovery_candidates (candidate_id, tenant, run_id, snapshot_id, origin,"
                             " library, library_version, destination_template, evidence_ref, state, dynamic_match,"
                             " path_unverified, reproduction_run_id) VALUES (%s,'hackathon',%s,%s,'static','l','v','https://x/',"
                             "'e','reproduced','matched',false,%s)",
                             (str(uuid.uuid4()), c.run_id, SNAP, str(uuid.uuid4())))
        with pytest.raises(psycopg.Error), conn.transaction():
            conn.execute("INSERT INTO discovery.discovery_candidates (candidate_id, tenant, run_id, snapshot_id, origin,"
                         " library, library_version, destination_template, evidence_ref) VALUES"
                         " (%s,'hackathon',%s,%s,'observed','l','v','https://x/','e')",
                         (str(uuid.uuid4()), c.run_id, SNAP))


def test_observed_candidate_and_pagination(store):
    repro = str(uuid.uuid4())
    o = make(store, origin=Origin.observed, call_site=None, trigger_condition=None, retry_redirect_behavior=None,
             model_run_ref=None, dynamic_match=DynamicMatch.observed_not_static, matched_arms=("on",),
             reproduction_run_id=repro, state=CandidateState.reproduced)
    assert (o.dynamic_match, o.state, o.matched_arms) == (DynamicMatch.observed_not_static, CandidateState.reproduced, ("on",))
    assert store.apply_match(o.candidate_id, DynamicMatch.matched, False, repro, ("on",)) == Outcome.conflict
    for _ in range(3):
        make(store)
    page = store.list_candidates("hackathon", None, None, 0, 2)
    rest = store.list_candidates("hackathon", None, None, page[-1].seq, 10)
    assert len(page) == 2 and len(rest) == 2
    assert store.list_candidates("other", None, None, 0, 10) == []


def _observed(store, arms=("off",)):
    repro = str(uuid.uuid4())
    o = make(store, origin=Origin.observed, call_site=None, trigger_condition=None, retry_redirect_behavior=None,
             model_run_ref=None, dynamic_match=DynamicMatch.observed_not_static, matched_arms=arms,
             reproduction_run_id=repro, state=CandidateState.reproduced)
    return o, repro


def test_observed_not_static_promotion_kinds(store):
    """TASK-02 3.4 (PR #19): allow_operation is a 409 with no change;
    deny_fixture and sdk_setting_check promote."""
    o, repro = _observed(store)
    before = store.get_candidate("hackathon", o.candidate_id)
    outcome, _ = store.promote("hackathon", o.candidate_id, repro, PromotionKind.allow_operation, "google:op", "n",
                               ev("discovery_candidate_promoted"))
    assert outcome == Outcome.conflict and store.get_candidate("hackathon", o.candidate_id) == before
    for kind in (PromotionKind.deny_fixture, PromotionKind.sdk_setting_check):
        o, repro = _observed(store)
        outcome, rec = store.promote("hackathon", o.candidate_id, repro, kind, "google:op", "n",
                                     ev("discovery_candidate_promoted"))
        assert outcome == Outcome.ok and (rec.state, rec.promotion_kind) == (CandidateState.promoted, kind)
    # The database also refuses an allow for an observed candidate written directly.
    o, _ = _observed(store)
    with psycopg.connect(DSN) as conn, pytest.raises(psycopg.Error), conn.transaction():
        conn.execute("UPDATE discovery.discovery_candidates SET state='promoted', promotion_kind='allow_operation',"
                     " reviewed_by_actor='x' WHERE candidate_id=%s", (o.candidate_id,))


@pytest.mark.parametrize("arms", ["{}", "{on,off}", "{off,off}", "{x}"])
def test_database_rejects_invalid_matched_arms(store, arms):
    o, _ = _observed(store)
    with psycopg.connect(DSN) as conn, pytest.raises(psycopg.Error), conn.transaction():
        conn.execute("UPDATE discovery.discovery_candidates SET matched_arms=%s::text[] WHERE candidate_id=%s",
                     (arms, o.candidate_id))


def test_database_requires_arms_with_a_match(store):
    c = make(store)
    with psycopg.connect(DSN) as conn:
        with pytest.raises(psycopg.Error), conn.transaction():
            # matched without arms
            conn.execute("UPDATE discovery.discovery_candidates SET dynamic_match='matched', path_unverified=false,"
                         " reproduction_run_id=%s WHERE candidate_id=%s", (str(uuid.uuid4()), c.candidate_id))
        with pytest.raises(psycopg.Error), conn.transaction():
            # arms without a match
            conn.execute("UPDATE discovery.discovery_candidates SET matched_arms='{off}' WHERE candidate_id=%s",
                         (c.candidate_id,))
        with pytest.raises(psycopg.Error), conn.transaction():
            # a static candidate cannot be inserted already reproduced
            conn.execute("INSERT INTO discovery.discovery_candidates (candidate_id, tenant, run_id, snapshot_id, origin,"
                         " library, library_version, call_site, trigger_condition, destination_template,"
                         " retry_redirect_behavior, evidence_ref, model_run_ref, state, dynamic_match, path_unverified,"
                         " matched_arms, reproduction_run_id) VALUES (%s,'hackathon',%s,%s,'static','l','v','c','t',"
                         "'https://x/','r','e','m','reproduced','matched',false,'{off}',%s)",
                         (str(uuid.uuid4()), c.run_id, SNAP, str(uuid.uuid4())))


def test_run_infra_filtered_is_stored(store):
    from dataclasses import replace
    r = RunRecord(str(uuid.uuid4()), "hackathon", SNAP, "s", RunState.queued, "google:op")
    store.create_run(r)
    store.update_run(replace(r, state=RunState.completed, infra_filtered=7))
    assert store.get_run("hackathon", r.run_id).infra_filtered == 7
    with psycopg.connect(DSN) as conn, pytest.raises(psycopg.Error), conn.transaction():
        conn.execute("UPDATE discovery.discovery_runs SET infra_filtered=-1 WHERE run_id=%s", (r.run_id,))


def test_migrations_roll_back_cleanly():
    if not DSN:
        pytest.skip("DISCOVERY_TEST_DATABASE_URL not set")
    ups = sorted(MIGRATIONS.glob("*_discovery_*.up.sql"))
    downs = sorted(MIGRATIONS.glob("*_discovery_*.down.sql"), reverse=True)
    assert [f.name.split("_")[0] for f in ups] == [f.name.split("_")[0] for f in reversed(downs)]
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS discovery CASCADE")
        for f in ups:
            conn.execute(f.read_text())
        for f in downs:
            conn.execute(f.read_text())
        assert conn.execute("SELECT count(*) FROM pg_namespace WHERE nspname = 'discovery'").fetchone()[0] == 0


def test_runs_and_epochs(store):
    r = RunRecord(str(uuid.uuid4()), "hackathon", SNAP, "s", RunState.queued, "google:op")
    store.create_run(r)
    claimed = store.claim_queued_run()
    assert claimed.run_id == r.run_id and claimed.state == RunState.analyzing
    assert store.claim_queued_run() is None
    assert store.next_producer_epoch("discovery") == 1
    assert store.next_producer_epoch("discovery") == 2


def test_promotion_invariant_over_http_with_postgres(store, tmp_path):
    """TASK-02 section 7 "discovery promotion invariant" against the real schema."""
    import json

    from conftest import (
        TEST_INFRA,
        FakeGateway,
        FakeJobs,
        FakePeer,
        FakeRegression,
        ShaDigester,
        candidate_json,
        write_snapshot,
    )
    from fastapi.testclient import TestClient

    from agentarium_discovery.analyzer import Analyzer
    from agentarium_discovery.api import create_app
    from agentarium_discovery.models import Observation
    from agentarium_discovery.service import Config, DiscoveryService
    from agentarium_discovery.snapshots import SnapshotStore

    write_snapshot(tmp_path, SNAP)
    gw, reg = FakeGateway(), FakeRegression()
    svc = DiscoveryService(store, SnapshotStore(tmp_path), FakeJobs(), Analyzer(gw), reg, Config(tenant="hackathon", discovery_bucket="disc-bucket", infra=TEST_INFRA),
                           digester=ShaDigester())
    client = TestClient(create_app(svc, FakePeer()))
    h = {"X-Agentarium-Console-Actor": "google:op", "X-Agentarium-Console-Roles": "operator"}
    gw.turns = [(json.dumps({"candidates": [candidate_json()]}), [])]
    run_id = client.post("/internal/discovery/runs", json={"snapshot_id": SNAP, "scenario_set_id": "s"}, headers=h).json()["run_id"]
    assert svc.process_next_run()
    [c] = client.get("/internal/discovery/candidates", params={"run_id": run_id}, headers=h).json()["items"]
    body = {"promotion_kind": "allow_operation", "reproduction_run_id": reg.run_id, "review_note": "ok"}
    before = store.get_candidate("hackathon", c["candidate_id"])
    r = client.post(f"/internal/discovery/candidates/{c['candidate_id']}/promote", json=body, headers=h)
    assert r.status_code == 409
    assert store.get_candidate("hackathon", c["candidate_id"]) == before
    assert svc.ai_created_allow_count() == 0

    reg.observations = [Observation(arm="on", process_exec_id="p", dst_ip="203.0.113.1", dst_port=443,
                                    tls_sni="storage.googleapis.com", source="kernel")]
    assert svc.poll_reproductions() == 1
    r = client.post(f"/internal/discovery/candidates/{c['candidate_id']}/promote", json=body, headers=h)
    assert r.status_code == 200 and r.json()["state"] == "promoted" and r.json()["path_unverified"] is True
    assert store.get_run("hackathon", run_id).state == RunState.completed
    assert svc.ai_created_allow_count() == 0
    kinds = sorted(e.event_type for e in store.pending_events(10))
    assert kinds == ["discovery_candidate_promoted", "discovery_candidate_recorded"]
