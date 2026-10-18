"""Outbox delivery of discovery events to TASK-07 `POST /internal/audit/events`.

SPEC-QUESTION: TASK-06's allow table has no discovery -> audit-writer row,
although COMMON registers discovery_candidate_recorded/_promoted with producer
TASK-02. Delivery is implemented; the network row must be added by TASK-06.
"""

from __future__ import annotations

from .clients import AuditSink
from .digest import Digester
from .store import OutboxEvent, Store


def audit_event(e: OutboxEvent, source_id: str, source_version: str, digester: Digester) -> dict:
    event = {
        "event_id": e.event_id,
        "event_type": e.event_type,
        "tenant": e.tenant,
        "source_id": source_id,
        "source_version": source_version,
        "source_epoch": str(e.source_epoch),
        "source_sequence": None,
        "source_time": e.source_time.isoformat().replace("+00:00", "Z"),
        "schema_version": 1,
        "authenticated_actor": e.authenticated_actor,
        "workload_id": None,
        "session_id": None,
        "action_id": None,
        "request_id": None,
        "attempt_id": None,
        "policy_bundle_id": None,
        "policy_epoch": None,
        "catalog_digest": None,
        "catalog_version": None,
        "evidence_refs": [],
        "safe_payload": e.payload,
    }
    # COMMON: payload_digest = canonical digest of the fields except
    # payload_digest and received_at; computed by the Go CLI.
    event["payload_digest"] = digester.digest(dict(event))
    return event


def publish_pending(store: Store, sink: AuditSink, digester: Digester, source_id: str, source_version: str,
                    limit: int = 100) -> int:
    sent = 0
    for e in store.pending_events(limit):
        sink.post(audit_event(e, source_id, source_version, digester))
        store.mark_event_sent(e.event_id)
        sent += 1
    return sent
