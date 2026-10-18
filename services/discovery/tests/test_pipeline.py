"""End-to-end run with fakes: static candidates -> TASK-13 reproduction ->
deterministic matcher -> states, events and metrics."""

import json

from conftest import SNAPSHOT_ID, candidate_json

from agentarium_discovery.models import Observation, RunState

H = {"X-Agentarium-Console-Actor": "google:op", "X-Agentarium-Console-Roles": "operator"}


def test_run_classifies_candidates_and_observations(env):
    env.gw.turns = [(json.dumps({"candidates": [
        candidate_json(destination_template="https://*.googleapis.com/v1/"),
        candidate_json(call_site="b", destination_template="https://oauth2.googleapis.com/token"),
        candidate_json(call_site="c", destination_template="https://api.example.com/v1"),
    ]}), [])]
    run_id = env.client.post("/internal/discovery/runs", json={"snapshot_id": SNAPSHOT_ID, "scenario_set_id": "httpx-basic"},
                             headers=H).json()["run_id"]
    env.svc.process_next_run()
    run = env.store.get_run("hackathon", run_id)
    assert run.state == RunState.reproducing and run.reproduction_run_id == env.reg.run_id
    assert env.reg.requested == ["httpx-basic"]

    env.reg.finished = False
    assert env.svc.poll_reproductions() == 0
    env.reg.finished = True
    env.reg.observations = [
        Observation(arm="on", process_exec_id="p1", dst_ip="203.0.113.1", dst_port=443, tls_sni="storage.googleapis.com",
                    http_path="/v1/b/o", source="adapter"),
        Observation(arm="off", process_exec_id="p2", dst_ip="203.0.113.2", dst_port=443, tls_sni="oauth2.googleapis.com",
                    source="kernel"),
        Observation(arm="off", process_exec_id="p3", dst_ip="203.0.113.3", dst_port=443, tls_sni="api.example.com",
                    http_path="/v10", source="kernel"),
        Observation(arm="off", process_exec_id="p4", dst_ip="192.0.2.7", dst_port=9443, source="kernel"),
    ]
    assert env.svc.poll_reproductions() == 1
    items = env.client.get("/internal/discovery/candidates", params={"run_id": run_id}, headers=H).json()["items"]
    got = {c["destination_template"]: (c["state"], c["dynamic_match"], c["path_unverified"], c["matched_arms"])
           for c in items}
    # observed_not_static candidates are stored reproduced (TASK-02 3.4, PR #19).
    assert got == {
        "https://*.googleapis.com/v1/": ("reproduced", "matched", False, ["off", "on"]),
        "https://oauth2.googleapis.com/token": ("reproduced", "matched", True, ["off"]),
        "https://api.example.com/v1": ("candidate", "static_not_observed", None, None),
        "https://api.example.com/": ("reproduced", "observed_not_static", None, ["off"]),
        "https://192.0.2.7:9443/": ("reproduced", "observed_not_static", None, ["off"]),
    }
    assert all(c["reproduction_run_id"] == env.reg.run_id for c in items)
    assert env.store.get_run("hackathon", run_id).state == RunState.completed
    recorded = [e for e in env.store.outbox.values() if e.event_type == "discovery_candidate_recorded"]
    assert len(recorded) == 5
    m = env.svc.metrics(run_id)
    assert m["candidate_count"] == 5
    assert m["reproduced_ratio"] == {"numerator": 2, "denominator": 3}
    assert m["observed_not_static_count"] == 2 and m["unresolved_count"] == 5
    assert m["infra_filtered"] == 0
    filt = env.client.get("/internal/discovery/candidates", params={"run_id": run_id, "state": "reproduced"}, headers=H)
    assert len(filt.json()["items"]) == 4
