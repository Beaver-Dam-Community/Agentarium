"""Storage interface for the discovery tables and an in-memory implementation.

The PostgreSQL implementation (postgres.py) runs against the migration
migrations/*_discovery_candidates.up.sql. Every method is one transaction; a
state change, its transition row and its outbox event commit together.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from .models import (
    AiStatus,
    CandidateState,
    DynamicMatch,
    PromotionKind,
    RunState,
    SnapshotRequestState,
)


def now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class SnapshotRecord:
    snapshot_id: str
    tenant: str
    library: str
    library_version: str
    language: str
    source_uri: str
    source_digest: str
    file_count: int
    created_at: datetime = field(default_factory=now)


@dataclass(frozen=True)
class SnapshotRequestRecord:
    request_id: str
    tenant: str
    library: str
    library_version: str
    language: str
    source_uri: str
    source_digest: str
    state: SnapshotRequestState
    requested_by_actor: str
    job_name: str | None = None
    snapshot_id: str | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    tenant: str
    snapshot_id: str
    scenario_set_id: str
    state: RunState
    created_by_actor: str
    static_analysis_status: AiStatus | None = None
    reproduction_run_id: str | None = None
    model_calls: int = 0
    read_calls: int = 0
    infra_filtered: int = 0
    error: str | None = None
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)


class Origin(StrEnum):
    static = "static"  # model output from static analysis
    observed = "observed"  # observed_not_static, derived from observations


@dataclass(frozen=True)
class CandidateRecord:
    candidate_id: str
    tenant: str
    run_id: str
    snapshot_id: str
    origin: Origin
    library: str
    library_version: str
    call_site: str | None
    trigger_condition: str | None
    destination_template: str
    retry_redirect_behavior: str | None
    evidence_ref: str
    model_run_ref: str | None
    state: CandidateState = CandidateState.candidate
    dynamic_match: DynamicMatch | None = None
    path_unverified: bool | None = None
    matched_arms: tuple[str, ...] | None = None
    reproduction_run_id: str | None = None
    model_annotation: str | None = None
    promotion_kind: PromotionKind | None = None
    reviewed_by_actor: str | None = None
    review_note: str | None = None
    reject_reason: str | None = None
    catalog_change_ref: str | None = None
    seq: int = 0
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)


@dataclass(frozen=True)
class Transition:
    candidate_id: str
    from_state: CandidateState | None
    to_state: CandidateState
    actor: str
    note: str | None
    created_at: datetime = field(default_factory=now)


@dataclass(frozen=True)
class OutboxEvent:
    event_id: str
    event_type: str
    tenant: str
    source_epoch: int
    source_time: datetime
    authenticated_actor: str | None
    payload: dict


class Outcome(StrEnum):
    ok = "ok"
    not_found = "not_found"
    conflict = "conflict"


class Store(Protocol):
    def get_snapshot(self, tenant: str, snapshot_id: str) -> SnapshotRecord | None: ...
    def put_snapshot(self, rec: SnapshotRecord) -> None: ...
    def find_snapshot_request(self, tenant: str, language: str, source_uri: str, source_digest: str) -> SnapshotRequestRecord | None: ...
    def save_snapshot_request(self, rec: SnapshotRequestRecord) -> None: ...

    def create_run(self, rec: RunRecord) -> None: ...
    def get_run(self, tenant: str, run_id: str) -> RunRecord | None: ...
    def claim_queued_run(self) -> RunRecord | None: ...
    def runs_in_state(self, state: RunState) -> list[RunRecord]: ...
    def update_run(self, rec: RunRecord) -> None: ...

    def record_candidate(self, rec: CandidateRecord, event: OutboxEvent) -> CandidateRecord: ...
    def get_candidate(self, tenant: str, candidate_id: str) -> CandidateRecord | None: ...
    def list_candidates(self, tenant: str, run_id: str | None, state: CandidateState | None, after_seq: int, limit: int) -> list[CandidateRecord]: ...
    def run_candidates(self, tenant: str, run_id: str) -> list[CandidateRecord]: ...
    def apply_match(self, candidate_id: str, dynamic_match: DynamicMatch, path_unverified: bool | None, reproduction_run_id: str, matched_arms: tuple[str, ...] | None = None) -> Outcome: ...
    def set_annotation(self, candidate_id: str, text: str) -> None: ...
    def promote(self, tenant: str, candidate_id: str, reproduction_run_id: str, kind: PromotionKind, actor: str, note: str, event: OutboxEvent) -> tuple[Outcome, CandidateRecord | None]: ...
    def reject(self, tenant: str, candidate_id: str, reason: str, actor: str) -> tuple[Outcome, CandidateRecord | None]: ...
    def transitions(self, candidate_id: str) -> list[Transition]: ...

    def pending_events(self, limit: int) -> list[OutboxEvent]: ...
    def mark_event_sent(self, event_id: str) -> None: ...
    def next_producer_epoch(self, source_id: str) -> int: ...


def promotable(dynamic_match: DynamicMatch | None, kind: PromotionKind) -> bool:
    """matched candidates take any promotion kind; observed_not_static ones
    only deny_fixture or sdk_setting_check, never allow_operation: no allow
    from observation alone (TASK-02 3.4, PR #19)."""
    if dynamic_match == DynamicMatch.matched:
        return True
    return dynamic_match == DynamicMatch.observed_not_static and kind != PromotionKind.allow_operation


class InMemoryStore:
    """Reference implementation used by unit tests; mirrors the SQL constraints."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.snapshots: dict[str, SnapshotRecord] = {}
        self.snapshot_requests: dict[str, SnapshotRequestRecord] = {}
        self.runs: dict[str, RunRecord] = {}
        self.candidates: dict[str, CandidateRecord] = {}
        self._transitions: list[Transition] = []
        self.outbox: dict[str, OutboxEvent] = {}
        self.sent: set[str] = set()
        self.epochs: dict[str, int] = {}
        self._seq = 0

    # snapshots
    def get_snapshot(self, tenant, snapshot_id):
        s = self.snapshots.get(snapshot_id)
        return s if s and s.tenant == tenant else None

    def put_snapshot(self, rec):
        with self._lock:
            self.snapshots.setdefault(rec.snapshot_id, rec)

    def find_snapshot_request(self, tenant, language, source_uri, source_digest):
        for r in self.snapshot_requests.values():
            if (r.tenant, r.language, r.source_uri, r.source_digest) == (tenant, language, source_uri, source_digest):
                return r
        return None

    def save_snapshot_request(self, rec):
        with self._lock:
            self.snapshot_requests[rec.request_id] = replace(rec, updated_at=now())

    # runs
    def create_run(self, rec):
        with self._lock:
            assert rec.snapshot_id in self.snapshots, "FK discovery_runs.snapshot_id"
            self.runs[rec.run_id] = rec

    def get_run(self, tenant, run_id):
        r = self.runs.get(run_id)
        return r if r and r.tenant == tenant else None

    def claim_queued_run(self):
        with self._lock:
            for r in sorted(self.runs.values(), key=lambda r: r.created_at):
                if r.state == RunState.queued:
                    claimed = replace(r, state=RunState.analyzing, updated_at=now())
                    self.runs[r.run_id] = claimed
                    return claimed
        return None

    def runs_in_state(self, state):
        return sorted((r for r in self.runs.values() if r.state == state), key=lambda r: r.created_at)

    def update_run(self, rec):
        with self._lock:
            self.runs[rec.run_id] = replace(rec, updated_at=now())

    # candidates
    def _check(self, c: CandidateRecord) -> None:
        # Mirrors the CHECK constraints in the migration.
        if c.origin == Origin.static:
            assert None not in (c.call_site, c.trigger_condition, c.retry_redirect_behavior, c.model_run_ref)
        else:
            assert c.dynamic_match == DynamicMatch.observed_not_static
        recorded = c.dynamic_match in (DynamicMatch.matched, DynamicMatch.observed_not_static)
        assert recorded == (c.matched_arms is not None)
        assert c.matched_arms in (None, ("off",), ("on",), ("off", "on"))
        if c.state in (CandidateState.reproduced, CandidateState.promoted):
            assert recorded and c.reproduction_run_id is not None
        if c.dynamic_match == DynamicMatch.observed_not_static:
            assert c.promotion_kind != PromotionKind.allow_operation
        if c.state == CandidateState.promoted:
            assert c.promotion_kind is not None and c.reviewed_by_actor is not None
        else:
            assert c.promotion_kind is None
        if c.state == CandidateState.rejected:
            assert c.reject_reason is not None

    def _put(self, c: CandidateRecord, frm: CandidateState | None, actor: str, note: str | None) -> CandidateRecord:
        self._check(c)
        c = replace(c, updated_at=now())
        self.candidates[c.candidate_id] = c
        if frm != c.state or frm is None:
            self._transitions.append(Transition(c.candidate_id, frm, c.state, actor, note))
        return c

    def record_candidate(self, rec, event):
        with self._lock:
            assert rec.state == CandidateState.candidate or (
                rec.origin == Origin.observed and rec.state == CandidateState.reproduced)
            self._seq += 1
            rec = self._put(replace(rec, seq=self._seq), None, "service:discovery", None)
            self.outbox[event.event_id] = event
            return rec

    def get_candidate(self, tenant, candidate_id):
        c = self.candidates.get(candidate_id)
        return c if c and c.tenant == tenant else None

    def list_candidates(self, tenant, run_id, state, after_seq, limit):
        out = [
            c for c in self.candidates.values()
            if c.tenant == tenant and c.seq > after_seq
            and (run_id is None or c.run_id == run_id)
            and (state is None or c.state == state)
        ]
        return sorted(out, key=lambda c: c.seq)[:limit]

    def run_candidates(self, tenant, run_id):
        return self.list_candidates(tenant, run_id, None, 0, 1_000_000)

    def apply_match(self, candidate_id, dynamic_match, path_unverified, reproduction_run_id, matched_arms=None):
        with self._lock:
            c = self.candidates.get(candidate_id)
            if c is None:
                return Outcome.not_found
            if c.state != CandidateState.candidate or c.origin != Origin.static:
                return Outcome.conflict
            state = CandidateState.reproduced if dynamic_match == DynamicMatch.matched else CandidateState.candidate
            self._put(
                replace(c, dynamic_match=dynamic_match, path_unverified=path_unverified,
                        matched_arms=tuple(matched_arms) if matched_arms is not None else None,
                        reproduction_run_id=reproduction_run_id, state=state),
                c.state, "service:discovery:matcher", None,
            )
            return Outcome.ok

    def set_annotation(self, candidate_id, text):
        with self._lock:
            c = self.candidates[candidate_id]
            # Annotation never touches state (COMMON AI one-way principle).
            self.candidates[candidate_id] = replace(c, model_annotation=text, updated_at=now())

    def promote(self, tenant, candidate_id, reproduction_run_id, kind, actor, note, event):
        with self._lock:
            c = self.get_candidate(tenant, candidate_id)
            if c is None:
                return Outcome.not_found, None
            if (
                c.state != CandidateState.reproduced
                or not promotable(c.dynamic_match, kind)
                or c.reproduction_run_id != reproduction_run_id
            ):
                return Outcome.conflict, c
            c = self._put(
                replace(c, state=CandidateState.promoted, promotion_kind=kind, reviewed_by_actor=actor, review_note=note),
                CandidateState.reproduced, actor, note,
            )
            self.outbox[event.event_id] = event
            return Outcome.ok, c

    def reject(self, tenant, candidate_id, reason, actor):
        with self._lock:
            c = self.get_candidate(tenant, candidate_id)
            if c is None:
                return Outcome.not_found, None
            if c.state not in (CandidateState.candidate, CandidateState.reproduced):
                return Outcome.conflict, c
            c = self._put(replace(c, state=CandidateState.rejected, reject_reason=reason), c.state, actor, reason)
            return Outcome.ok, c

    def transitions(self, candidate_id):
        return [t for t in self._transitions if t.candidate_id == candidate_id]

    # outbox
    def pending_events(self, limit):
        pending = [e for e in self.outbox.values() if e.event_id not in self.sent]
        return sorted(pending, key=lambda e: e.source_time)[:limit]

    def mark_event_sent(self, event_id):
        self.sent.add(event_id)

    def next_producer_epoch(self, source_id):
        with self._lock:
            self.epochs[source_id] = self.epochs.get(source_id, 0) + 1
            return self.epochs[source_id]
