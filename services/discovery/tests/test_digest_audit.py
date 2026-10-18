import os
import stat

import pytest

from agentarium_discovery.audit import publish_pending
from agentarium_discovery.digest import CanonicalDigestCLI, DigestError
from agentarium_discovery.store import InMemoryStore, OutboxEvent, now


def script(tmp_path, body):
    p = tmp_path / "canonical-digest"
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def test_cli_wrapper_passes_json_on_stdin(tmp_path):
    seen = tmp_path / "stdin"
    d = CanonicalDigestCLI(script(tmp_path, f"cat > {seen}\necho {'ab' * 32}\n"))
    assert d.digest({"b": 1, "a": "é"}) == "ab" * 32
    assert seen.read_text(encoding="utf-8") == '{"b": 1, "a": "é"}'


@pytest.mark.parametrize("body", ["echo NOTHEX\n", "exit 3\n", f"echo {'AB' * 32}\n"])
def test_cli_wrapper_rejects_bad_output(tmp_path, body):
    with pytest.raises(DigestError):
        CanonicalDigestCLI(script(tmp_path, body)).digest({})


def test_cli_missing_binary():
    with pytest.raises(DigestError):
        CanonicalDigestCLI(os.path.join("/nonexistent", "canonical-digest")).digest({})


class FakeDigester:
    def __init__(self):
        self.inputs = []

    def digest(self, value):
        self.inputs.append(value)
        return "cd" * 32


class Sink:
    def __init__(self, fail=False):
        self.events, self.fail = [], fail

    def post(self, event):
        if self.fail:
            raise RuntimeError("audit down")
        self.events.append(event)


def test_publisher_builds_audit_events_and_marks_sent():
    store = InMemoryStore()
    e = OutboxEvent("88888888-8888-4888-8888-888888888888", "discovery_candidate_promoted", "hackathon", 3, now(),
                    "google:op", {"candidate_id": "c", "promotion_kind": "deny_fixture", "reviewed_by_actor": "google:op",
                                  "catalog_change_ref": None})
    store.outbox[e.event_id] = e
    dg, sink = FakeDigester(), Sink()
    assert publish_pending(store, sink, dg, "discovery", "0.1.0") == 1
    [ev] = sink.events
    assert ev["payload_digest"] == "cd" * 32
    assert "payload_digest" not in dg.inputs[0] and "received_at" not in dg.inputs[0]
    assert (ev["event_type"], ev["source_id"], ev["source_epoch"], ev["authenticated_actor"]) == (
        "discovery_candidate_promoted", "discovery", "3", "google:op")
    assert ev["safe_payload"]["promotion_kind"] == "deny_fixture"
    assert type(ev["schema_version"]) is int and ev["schema_version"] == 1
    assert dg.inputs[0]["schema_version"] == 1 and dg.inputs[0]["source_epoch"] == "3"
    assert publish_pending(store, sink, dg, "discovery", "0.1.0") == 0


def test_publisher_keeps_event_pending_on_failure():
    store = InMemoryStore()
    e = OutboxEvent("e1", "discovery_candidate_recorded", "hackathon", 1, now(), None, {})
    store.outbox[e.event_id] = e
    with pytest.raises(RuntimeError):
        publish_pending(store, Sink(fail=True), FakeDigester(), "discovery", "0.1.0")
    assert [x.event_id for x in store.pending_events(10)] == ["e1"]
