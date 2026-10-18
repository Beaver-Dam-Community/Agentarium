import json

import httpx
import pytest

from agentarium_discovery.clients import BudgetExhausted, GatewayError, HttpGateway, HttpRegression

ACTION = "77777777-7777-4777-8777-777777777777"


def gateway(handler):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return HttpGateway(client, "https://identity", "https://gateway", "hackathon", "agent-platform-gemini",
                       "discovery-snapshots", poll_timeout=5)


def test_generate_submits_client_action_and_reads_result():
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.method, str(req.url), json.loads(req.content) if req.content else None, req.headers.get("authorization")))
        if req.url.path == "/internal/service-sessions":
            return httpx.Response(200, json={"service_session_id": "s" * 8, "token": "tok", "tool_budget": {}, "expires_at": "x"})
        if req.url.path == "/v1/actions":
            return httpx.Response(202, json={"action_id": ACTION, "execution_allowed": True})
        return httpx.Response(200, json={"execution_state": "accepted", "result_body": {
            "conversation_id": "c0nv", "text": None, "function_calls": [{"name": "discovery_source_read", "args": {"path": "a"}}], "turn_index": 3}})

    gw = gateway(handler)
    s = gw.open_session("a" * 64)
    assert seen[0][2] == {"profile": "discovery", "snapshot_id": "a" * 64, "tenant": "hackathon"}
    turn = gw.generate(s, "c0nv", [{"kind": "text"}])
    action = seen[1][2]
    assert seen[1][3] == "Bearer tok"
    assert set(action) == {"session_id", "operation_id", "requested_target", "arguments", "client_request_key"}
    assert action["operation_id"] == "model.generate"
    assert action["requested_target"] == {"target_id": "agent-platform-gemini", "profile": "discovery"}
    assert action["arguments"]["tool_declarations"] == []
    assert 8 <= len(action["client_request_key"]) <= 64
    assert (turn.action_id, turn.turn_index, turn.function_calls[0].name) == (ACTION, 3, "discovery_source_read")


def test_reads_use_registered_operations():
    bodies = []

    def handler(req):
        if req.url.path == "/v1/actions":
            bodies.append(json.loads(req.content))
            return httpx.Response(202, json={"action_id": ACTION, "execution_allowed": True})
        return httpx.Response(200, json={"execution_state": "accepted", "result_body": {}})

    gw = gateway(handler)
    from agentarium_discovery.clients import ServiceSession
    s = ServiceSession("sid", "tok", "x")
    assert gw.source_read(s, "a" * 64, "p.py", 1, 10) == ACTION
    assert gw.callgraph_read(s, "a" * 64, "sym", 2) == ACTION
    assert bodies[0]["operation_id"] == "discovery.source.read"
    assert bodies[0]["requested_target"] == {"target_id": "discovery-snapshots", "snapshot_id": "a" * 64, "path": "p.py"}
    assert bodies[0]["arguments"] == {"start_line": 1, "end_line": 10}
    assert bodies[1]["operation_id"] == "discovery.callgraph.read"
    assert bodies[1]["arguments"] == {"depth": 2}


@pytest.mark.parametrize("resp,exc", [
    (httpx.Response(409, json={"request_id": "r", "reason_codes": ["TOOL_BUDGET_EXHAUSTED"]}), BudgetExhausted),
    (httpx.Response(403, json={"request_id": "r", "reason_codes": ["SERVICE_SCOPE_DENIED"]}), GatewayError),
    (httpx.Response(202, json={"action_id": ACTION, "execution_allowed": False}), GatewayError),
])
def test_gateway_errors(resp, exc):
    from agentarium_discovery.clients import ServiceSession
    gw = gateway(lambda req: resp)
    with pytest.raises(exc):
        gw.source_read(ServiceSession("sid", "tok", "x"), "a" * 64, "p.py", 1, 2)


def test_failed_execution_is_error():
    def handler(req):
        if req.url.path == "/v1/actions":
            return httpx.Response(202, json={"action_id": ACTION, "execution_allowed": True})
        return httpx.Response(200, json={"execution_state": "failed", "reason_codes": ["MODEL_BLOCKED"]})

    from agentarium_discovery.clients import ServiceSession
    with pytest.raises(GatewayError) as e:
        gateway(handler).generate(ServiceSession("sid", "tok", "x"), "c", [])
    assert e.value.reason_codes == ["MODEL_BLOCKED"]


def test_regression_request_and_report():
    seen = []

    def handler(req):
        if req.method == "POST":
            seen.append(json.loads(req.content))
            return httpx.Response(202, json={"run_id": "r1", "state": "not_run"})
        if req.url.path.endswith("/pending"):
            return httpx.Response(200, json={"run_id": "pending", "state": "not_run", "report": None})
        return httpx.Response(200, json={"run_id": "r1", "state": "pass", "report": {"state": "pass", "observations": [
            {"arm": "on", "process_exec_id": "p", "dst_ip": "192.0.2.1", "dst_port": 443, "source": "kernel"},
            {"scenario_id": "s", "control": "off", "process_exec_id": "p", "dest_addr": "192.0.2.2", "dest_port": 80,
             "source": "adapter_observation", "source_time": "t"},
        ]}})

    reg = HttpRegression(httpx.Client(transport=httpx.MockTransport(handler)), "https://dispatcher", "regression",
                         "1" * 64, "2" * 64)
    assert reg.request("httpx-basic") == "r1"
    assert seen[0]["run_kind"] == "discovery" and seen[0]["fixture_scope"] == "discovery"
    assert seen[0]["scenario_set_id"] == "httpx-basic"
    assert reg.status("pending").finished is False
    st = reg.status("r1")
    assert st.finished and [o.dst_port for o in st.observations] == [443, 80]


@pytest.mark.parametrize("change", [
    {"conversation_id": "other"}, {"turn_index": None}, {"turn_index": True}, {"turn_index": "3"},
    {"turn_index": -1}, {"function_calls": [{"name": "discovery_source_read", "args": []}]},
    {"text": {}},
])
def test_generate_rejects_malformed_result_and_other_conversation(change):
    from agentarium_discovery.clients import ServiceSession
    body = {"conversation_id": "conversation", "text": "", "turn_index": 0, "function_calls": []}
    body.update(change)
    def handler(req):
        if req.method == "POST":
            return httpx.Response(202, json={"action_id": ACTION, "execution_allowed": True})
        return httpx.Response(200, json={"execution_state": "accepted", "result_body": body})
    with pytest.raises(GatewayError) as e:
        gateway(handler).generate(ServiceSession("sid", "token", "expiry"), "conversation", [])
    assert e.value.reason_codes == ["MODEL_SCHEMA_INVALID"]


def test_generate_rejects_truncated_model_result():
    from agentarium_discovery.clients import ServiceSession
    def handler(req):
        if req.method == "POST":
            return httpx.Response(202, json={"action_id": ACTION, "execution_allowed": True})
        return httpx.Response(200, json={"execution_state": "accepted", "truncated": True})
    with pytest.raises(GatewayError) as e:
        gateway(handler).generate(ServiceSession("sid", "token", "expiry"), "conversation", [])
    assert e.value.reason_codes == ["MODEL_OUTPUT_TRUNCATED"]
