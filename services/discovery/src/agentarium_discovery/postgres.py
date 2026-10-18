"""PostgreSQL Store for migrations/*_discovery_candidates.up.sql (psycopg 3)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import fields

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .models import AiStatus, CandidateState, DynamicMatch, PromotionKind, RunState, SnapshotRequestState
from .store import (
    CandidateRecord,
    Origin,
    Outcome,
    OutboxEvent,
    RunRecord,
    SnapshotRecord,
    SnapshotRequestRecord,
    Transition,
)

S = "discovery."

_CANDIDATE_COLS = [f.name for f in fields(CandidateRecord)]


def _candidate(row: dict) -> CandidateRecord:
    row = dict(row)
    row["candidate_id"] = str(row["candidate_id"])
    row["run_id"] = str(row["run_id"])
    if row["reproduction_run_id"] is not None:
        row["reproduction_run_id"] = str(row["reproduction_run_id"])
    row["origin"] = Origin(row["origin"])
    row["state"] = CandidateState(row["state"])
    row["dynamic_match"] = DynamicMatch(row["dynamic_match"]) if row["dynamic_match"] else None
    row["promotion_kind"] = PromotionKind(row["promotion_kind"]) if row["promotion_kind"] else None
    row["matched_arms"] = tuple(row["matched_arms"]) if row["matched_arms"] is not None else None
    return CandidateRecord(**{k: row[k] for k in _CANDIDATE_COLS})


def _run(row: dict) -> RunRecord:
    row = dict(row)
    row["run_id"] = str(row["run_id"])
    row["state"] = RunState(row["state"])
    row["static_analysis_status"] = AiStatus(row["static_analysis_status"]) if row["static_analysis_status"] else None
    if row["reproduction_run_id"] is not None:
        row["reproduction_run_id"] = str(row["reproduction_run_id"])
    return RunRecord(**{f.name: row[f.name] for f in fields(RunRecord)})


def _request(row: dict) -> SnapshotRequestRecord:
    row = dict(row)
    row["request_id"] = str(row["request_id"])
    row["state"] = SnapshotRequestState(row["state"])
    return SnapshotRequestRecord(**{f.name: row[f.name] for f in fields(SnapshotRequestRecord)})


class PostgresStore:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    @contextmanager
    def _tx(self, actor: str | None = None) -> Iterator[psycopg.Cursor]:
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.transaction(), conn.cursor() as cur:
                if actor:
                    cur.execute("SELECT set_config('discovery.actor', %s, true)", (actor,))
                yield cur

    # snapshots
    def get_snapshot(self, tenant, snapshot_id):
        with self._tx() as cur:
            cur.execute(f"SELECT * FROM {S}discovery_snapshots WHERE snapshot_id = %s AND tenant = %s", (snapshot_id, tenant))
            row = cur.fetchone()
        return SnapshotRecord(**{f.name: row[f.name] for f in fields(SnapshotRecord)}) if row else None

    def put_snapshot(self, rec):
        with self._tx() as cur:
            cur.execute(
                f"""INSERT INTO {S}discovery_snapshots
                    (snapshot_id, tenant, library, library_version, language, source_uri, source_digest, file_count, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (snapshot_id) DO NOTHING""",
                (rec.snapshot_id, rec.tenant, rec.library, rec.library_version, rec.language,
                 rec.source_uri, rec.source_digest, rec.file_count, rec.created_at),
            )

    def find_snapshot_request(self, tenant, language, source_uri, source_digest):
        with self._tx() as cur:
            cur.execute(
                f"""SELECT * FROM {S}discovery_snapshot_requests
                    WHERE tenant = %s AND language = %s AND source_uri = %s AND source_digest = %s""",
                (tenant, language, source_uri, source_digest),
            )
            row = cur.fetchone()
        return _request(row) if row else None

    def save_snapshot_request(self, rec):
        with self._tx() as cur:
            cur.execute(
                f"""INSERT INTO {S}discovery_snapshot_requests
                    (request_id, tenant, library, library_version, language, source_uri, source_digest, state,
                     requested_by_actor, job_name, snapshot_id, error, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                    ON CONFLICT (request_id) DO UPDATE SET state = EXCLUDED.state, job_name = EXCLUDED.job_name,
                      snapshot_id = EXCLUDED.snapshot_id, error = EXCLUDED.error,
                      requested_by_actor = EXCLUDED.requested_by_actor, updated_at = now()""",
                (rec.request_id, rec.tenant, rec.library, rec.library_version, rec.language, rec.source_uri,
                 rec.source_digest, rec.state.value, rec.requested_by_actor, rec.job_name, rec.snapshot_id,
                 rec.error, rec.created_at),
            )

    # runs
    def create_run(self, rec):
        with self._tx() as cur:
            cur.execute(
                f"""INSERT INTO {S}discovery_runs
                    (run_id, tenant, snapshot_id, scenario_set_id, state, created_by_actor, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (rec.run_id, rec.tenant, rec.snapshot_id, rec.scenario_set_id, rec.state.value,
                 rec.created_by_actor, rec.created_at, rec.updated_at),
            )

    def get_run(self, tenant, run_id):
        with self._tx() as cur:
            cur.execute(f"SELECT * FROM {S}discovery_runs WHERE run_id = %s AND tenant = %s", (run_id, tenant))
            row = cur.fetchone()
        return _run(row) if row else None

    def claim_queued_run(self):
        with self._tx() as cur:
            cur.execute(
                f"""UPDATE {S}discovery_runs SET state = 'analyzing', updated_at = now()
                    WHERE run_id = (SELECT run_id FROM {S}discovery_runs WHERE state = 'queued'
                                    ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1)
                    RETURNING *"""
            )
            row = cur.fetchone()
        return _run(row) if row else None

    def runs_in_state(self, state):
        with self._tx() as cur:
            cur.execute(f"SELECT * FROM {S}discovery_runs WHERE state = %s ORDER BY created_at", (state.value,))
            return [_run(r) for r in cur.fetchall()]

    def update_run(self, rec):
        with self._tx() as cur:
            cur.execute(
                f"""UPDATE {S}discovery_runs SET state = %s, static_analysis_status = %s, reproduction_run_id = %s,
                    model_calls = %s, read_calls = %s, infra_filtered = %s, error = %s, updated_at = now()
                    WHERE run_id = %s""",
                (rec.state.value, rec.static_analysis_status.value if rec.static_analysis_status else None,
                 rec.reproduction_run_id, rec.model_calls, rec.read_calls, rec.infra_filtered, rec.error, rec.run_id),
            )

    # candidates
    def _insert_event(self, cur, e: OutboxEvent) -> None:
        cur.execute(
            f"""INSERT INTO {S}discovery_event_outbox
                (event_id, event_type, tenant, source_epoch, source_time, authenticated_actor, payload)
                VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (e.event_id, e.event_type, e.tenant, e.source_epoch, e.source_time, e.authenticated_actor, Jsonb(e.payload)),
        )

    def record_candidate(self, rec, event):
        cols = [c for c in _CANDIDATE_COLS if c not in ("seq", "updated_at")]
        vals = []
        for c in cols:
            v = getattr(rec, c)
            if isinstance(v, tuple):
                v = list(v)  # text[]
            vals.append(v.value if hasattr(v, "value") else v)
        with self._tx() as cur:
            cur.execute(
                f"INSERT INTO {S}discovery_candidates ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) RETURNING *",
                vals,
            )
            row = cur.fetchone()
            self._insert_event(cur, event)
        return _candidate(row)

    def get_candidate(self, tenant, candidate_id):
        with self._tx() as cur:
            cur.execute(f"SELECT * FROM {S}discovery_candidates WHERE candidate_id = %s AND tenant = %s", (candidate_id, tenant))
            row = cur.fetchone()
        return _candidate(row) if row else None

    def list_candidates(self, tenant, run_id, state, after_seq, limit):
        q = f"SELECT * FROM {S}discovery_candidates WHERE tenant = %s AND seq > %s"
        args: list = [tenant, after_seq]
        if run_id is not None:
            q += " AND run_id = %s"
            args.append(run_id)
        if state is not None:
            q += " AND state = %s"
            args.append(state.value)
        q += " ORDER BY seq LIMIT %s"
        args.append(limit)
        with self._tx() as cur:
            cur.execute(q, args)
            return [_candidate(r) for r in cur.fetchall()]

    def run_candidates(self, tenant, run_id):
        with self._tx() as cur:
            cur.execute(f"SELECT * FROM {S}discovery_candidates WHERE tenant = %s AND run_id = %s ORDER BY seq", (tenant, run_id))
            return [_candidate(r) for r in cur.fetchall()]

    def apply_match(self, candidate_id, dynamic_match, path_unverified, reproduction_run_id, matched_arms=None):
        state = CandidateState.reproduced if dynamic_match == DynamicMatch.matched else CandidateState.candidate
        with self._tx("service:discovery:matcher") as cur:
            cur.execute(
                f"""UPDATE {S}discovery_candidates SET dynamic_match = %s, path_unverified = %s,
                    matched_arms = %s, reproduction_run_id = %s, state = %s
                    WHERE candidate_id = %s AND state = 'candidate' AND origin = 'static' RETURNING candidate_id""",
                (dynamic_match.value, path_unverified, list(matched_arms) if matched_arms is not None else None,
                 reproduction_run_id, state.value, candidate_id),
            )
            if cur.fetchone():
                return Outcome.ok
            cur.execute(f"SELECT 1 FROM {S}discovery_candidates WHERE candidate_id = %s", (candidate_id,))
            return Outcome.conflict if cur.fetchone() else Outcome.not_found

    def set_annotation(self, candidate_id, text):
        with self._tx() as cur:
            cur.execute(f"UPDATE {S}discovery_candidates SET model_annotation = %s WHERE candidate_id = %s", (text, candidate_id))

    def promote(self, tenant, candidate_id, reproduction_run_id, kind, actor, note, event):
        with self._tx(actor) as cur:
            cur.execute(
                f"""UPDATE {S}discovery_candidates SET state = 'promoted', promotion_kind = %s,
                    reviewed_by_actor = %s, review_note = %s
                    WHERE candidate_id = %s AND tenant = %s AND state = 'reproduced' AND reproduction_run_id = %s
                      AND (dynamic_match = 'matched'
                           OR (dynamic_match = 'observed_not_static' AND %s <> 'allow_operation'))
                    RETURNING *""",
                (kind.value, actor, note, candidate_id, tenant, reproduction_run_id, kind.value),
            )
            row = cur.fetchone()
            if row:
                self._insert_event(cur, event)
                return Outcome.ok, _candidate(row)
            cur.execute(f"SELECT * FROM {S}discovery_candidates WHERE candidate_id = %s AND tenant = %s", (candidate_id, tenant))
            cur_row = cur.fetchone()
        return (Outcome.conflict, _candidate(cur_row)) if cur_row else (Outcome.not_found, None)

    def reject(self, tenant, candidate_id, reason, actor):
        with self._tx(actor) as cur:
            cur.execute(
                f"""UPDATE {S}discovery_candidates SET state = 'rejected', reject_reason = %s
                    WHERE candidate_id = %s AND tenant = %s AND state IN ('candidate', 'reproduced') RETURNING *""",
                (reason, candidate_id, tenant),
            )
            row = cur.fetchone()
            if row:
                return Outcome.ok, _candidate(row)
            cur.execute(f"SELECT * FROM {S}discovery_candidates WHERE candidate_id = %s AND tenant = %s", (candidate_id, tenant))
            cur_row = cur.fetchone()
        return (Outcome.conflict, _candidate(cur_row)) if cur_row else (Outcome.not_found, None)

    def transitions(self, candidate_id):
        with self._tx() as cur:
            cur.execute(
                f"""SELECT candidate_id, from_state, to_state, actor, note, created_at
                    FROM {S}discovery_candidate_transitions WHERE candidate_id = %s ORDER BY transition_id""",
                (candidate_id,),
            )
            return [
                Transition(str(r["candidate_id"]), CandidateState(r["from_state"]) if r["from_state"] else None,
                           CandidateState(r["to_state"]), r["actor"], r["note"], r["created_at"])
                for r in cur.fetchall()
            ]

    # outbox
    def pending_events(self, limit):
        with self._tx() as cur:
            cur.execute(
                f"""SELECT * FROM {S}discovery_event_outbox WHERE sent_at IS NULL ORDER BY source_time LIMIT %s""",
                (limit,),
            )
            return [
                OutboxEvent(str(r["event_id"]), r["event_type"], r["tenant"], r["source_epoch"], r["source_time"],
                            r["authenticated_actor"], r["payload"])
                for r in cur.fetchall()
            ]

    def mark_event_sent(self, event_id):
        with self._tx() as cur:
            cur.execute(f"UPDATE {S}discovery_event_outbox SET sent_at = now(), attempts = attempts + 1 WHERE event_id = %s", (event_id,))

    def next_producer_epoch(self, source_id):
        with self._tx() as cur:
            cur.execute(
                f"""INSERT INTO {S}discovery_producer_epochs (source_id, epoch) VALUES (%s, 1)
                    ON CONFLICT (source_id) DO UPDATE SET epoch = {S}discovery_producer_epochs.epoch + 1
                    RETURNING epoch""",
                (source_id,),
            )
            return cur.fetchone()["epoch"]
