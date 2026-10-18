"""Discovery service logic: snapshots, runs, candidate state machine, promotion.

Candidate states (COMMON enum `discovery_candidate.state`):

    candidate --matcher--> reproduced --operator promote--> promoted
        |                      |
        +--operator reject-----+--> rejected

Only the deterministic matcher moves a candidate to `reproduced`; only an
operator moves `reproduced` to `promoted`. Model output alone stays
`candidate`, so promoting it is 409 and changes nothing (COMMON AI one-way
principle, TASK-02 section 7 "discovery promotion invariant").
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime

from . import matcher
from .analyzer import Analyzer
from .auth import Caller
from .clients import GatewayError, Regression, SnapshotJobs
from .digest import BytesDigester, DigestError
from .models import (
    AiStatus,
    CandidateList,
    CandidateState,
    DiscoveryCandidate,
    DynamicMatch,
    PromoteRequest,
    PromotionKind,
    RejectRequest,
    RunCreate,
    RunCreated,
    RunState,
    SnapshotCreate,
    SnapshotRequestState,
    SnapshotStatus,
)
from .snapshots import ReadRejected, SnapshotNotFound, SnapshotStore
from .store import (
    CandidateRecord,
    Origin,
    Outcome,
    OutboxEvent,
    RunRecord,
    SnapshotRecord,
    SnapshotRequestRecord,
    Store,
    now,
)

PAGE_SIZE = 100

# SPEC-QUESTION: report states (COMMON) are pass, fail, incomplete, not_run,
# invalid_environment, unsupported; which of them carry a complete discovery
# observation list is not stated. Only pass and fail are matched.
MATCHABLE_REPORT_STATES = {"pass", "fail"}

RECORDED = "discovery_candidate_recorded"
PROMOTED = "discovery_candidate_promoted"

SERVICE_ACTOR_PREFIX = "service:"


class ApiError(Exception):
    def __init__(self, status: int, reason_codes: list[str] | None = None, retry_after: int | None = None) -> None:
        super().__init__(status, reason_codes)
        self.status = status
        self.reason_codes = reason_codes or []
        self.retry_after = retry_after


def unauthenticated() -> ApiError:
    return ApiError(401, ["AUTH_REQUIRED"])


def forbidden() -> ApiError:
    # SPEC-QUESTION: no reason code covers "caller lacks the operator role";
    # reason_codes stays empty.
    return ApiError(403)


def not_found() -> ApiError:
    return ApiError(404, ["RESOURCE_NOT_FOUND"])


def schema_invalid() -> ApiError:
    return ApiError(422, ["SCHEMA_INVALID"])


def state_conflict() -> ApiError:
    # SPEC-QUESTION: no reason code is registered for "candidate not reproduced";
    # TASK-02/COMMON fix only the 409 status.
    return ApiError(409)


class Annotator:
    """Optional Gemini explanation of matcher results.

    The text is stored in model_annotation only; nothing here can change state.
    """

    def annotate(self, run: RunRecord, candidates: list[CandidateRecord]) -> dict[str, str]:
        return {}


@dataclass
class Config:
    tenant: str
    source_id: str = "discovery"
    source_version: str = "0.1.0"
    # Discovery bucket (lock storage.discovery_bucket). Source archives are
    # staged there as sources/<source_digest>.<ext>; unset rejects every request.
    discovery_bucket: str | None = None
    # Agentarium infrastructure of the scenario environment; its observations
    # are counted as infra_filtered and never matched (TASK-02 3.4, PR #19).
    infra: matcher.InfraDestinations | None = None


log = logging.getLogger(__name__)

_HEX64 = re.compile(r"[0-9a-f]{64}")
_SOURCE_URI = re.compile(r"^gs://([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])/sources/([0-9a-f]{64})\.(tar\.gz|tgz|tar|zip|whl)$")


def valid_source_uri(source_uri: str, source_digest: str, bucket: str | None) -> bool:
    """TASK-02 3.4 (PR #8): the operator stages the archive at
    gs://<discovery bucket>/sources/<source_digest>.<ext>. No https or VCS URL is
    accepted, so the snapshot Job never makes an outbound fetch (SSRF)."""
    m = _SOURCE_URI.fullmatch(source_uri)
    return bool(m) and bucket is not None and m.group(1) == bucket and m.group(2) == source_digest


def to_api(c: CandidateRecord) -> DiscoveryCandidate:
    return DiscoveryCandidate(
        candidate_id=c.candidate_id,
        library=c.library,
        library_version=c.library_version,
        call_site=c.call_site,
        trigger_condition=c.trigger_condition,
        destination_template=c.destination_template,
        retry_redirect_behavior=c.retry_redirect_behavior,
        evidence_ref=c.evidence_ref,
        model_run_ref=c.model_run_ref,
        dynamic_match=c.dynamic_match,
        path_unverified=c.path_unverified,
        matched_arms=list(c.matched_arms) if c.matched_arms is not None else None,
        reproduction_run_id=c.reproduction_run_id,
        state=c.state,
        promotion_kind=c.promotion_kind,
        reviewed_by_actor=c.reviewed_by_actor,
        catalog_change_ref=c.catalog_change_ref,
    )


def encode_cursor(seq: int) -> str:
    return base64.urlsafe_b64encode(f"seq:{seq}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
    except (binascii.Error, UnicodeDecodeError) as e:
        raise schema_invalid() from e
    tag, _, num = raw.partition(":")
    if tag != "seq" or not num.isdigit():
        raise schema_invalid()
    return int(num)


class DiscoveryService:
    def __init__(
        self,
        store: Store,
        snapshots: SnapshotStore,
        jobs: SnapshotJobs,
        analyzer: Analyzer,
        regression: Regression,
        config: Config,
        digester: BytesDigester | None = None,
        annotator: Annotator | None = None,
        new_id: Callable[[], str] = lambda: str(uuid.uuid4()),
        clock: Callable[[], datetime] = now,
    ) -> None:
        self.store = store
        self.snapshots = snapshots
        self.jobs = jobs
        self.analyzer = analyzer
        self.regression = regression
        if config.infra is None:
            # Without it infrastructure observations would silently become
            # observed_not_static candidates.
            raise ValueError("Config.infra (Agentarium infrastructure destinations) is required")
        self.config = config
        # Verifies manifest.json returned by the snapshot Job; without it no
        # snapshot is accepted.
        self.digester = digester
        self.annotator = annotator or Annotator()
        self.new_id = new_id
        self.clock = clock
        self.epoch = store.next_producer_epoch(config.source_id)

    @property
    def tenant(self) -> str:
        return self.config.tenant

    def _event(self, event_type: str, payload: dict, actor: str | None) -> OutboxEvent:
        return OutboxEvent(self.new_id(), event_type, self.tenant, self.epoch, self.clock(), actor, payload)

    @staticmethod
    def _operator(caller: Caller) -> str:
        if caller.san is None:
            raise unauthenticated()
        if not caller.is_operator:
            raise forbidden()
        assert caller.actor is not None
        # Console actors are people: `promoted` needs human review (COMMON enum).
        # The service: namespace is ServiceSession.authenticated_actor and this
        # service's own transition actor; such a reviewer would also count in
        # ai_created_allow_count, so it never acts on a console route.
        if caller.actor.startswith(SERVICE_ACTOR_PREFIX):
            raise forbidden()
        return caller.actor

    # --- snapshots -------------------------------------------------------

    def create_snapshot(self, caller: Caller, body: SnapshotCreate) -> tuple[int, SnapshotStatus]:
        actor = self._operator(caller)
        if not valid_source_uri(body.source_uri, body.source_digest, self.config.discovery_bucket):
            raise schema_invalid()
        req = self.store.find_snapshot_request(self.tenant, body.language.value, body.source_uri, body.source_digest)
        if req is None or req.state == SnapshotRequestState.failed:
            req = SnapshotRequestRecord(
                request_id=req.request_id if req else self.new_id(),
                tenant=self.tenant, library=body.library, library_version=body.library_version,
                language=body.language.value, source_uri=body.source_uri, source_digest=body.source_digest,
                state=SnapshotRequestState.queued, requested_by_actor=actor,
            )
            self.store.save_snapshot_request(req)
            try:
                job = self.jobs.launch(req.request_id, req.language, req.source_uri, req.source_digest,
                                       req.library, req.library_version)
            except Exception as e:  # dependency failure: keep the request queued
                raise ApiError(503, [], retry_after=2) from e
            req = replace(req, state=SnapshotRequestState.running, job_name=job)
            self.store.save_snapshot_request(req)
        elif req.state == SnapshotRequestState.running and req.job_name:
            req = self._refresh_snapshot_request(req)
        status = SnapshotStatus(state=req.state, snapshot_id=req.snapshot_id, library=req.library,
                                library_version=req.library_version, language=req.language,
                                source_digest=req.source_digest)
        terminal = req.state in (SnapshotRequestState.succeeded, SnapshotRequestState.failed)
        return (200 if terminal else 202), status

    def _refresh_snapshot_request(self, req: SnapshotRequestRecord) -> SnapshotRequestRecord:
        assert req.job_name
        st = self.jobs.status(req.job_name)
        if st.state == "running":
            return req
        sid = (st.result or {}).get("snapshot_id")
        error = st.error or "snapshot job failed"
        if st.state == "succeeded":
            error = self._verify_snapshot(req, sid)
        if error is None:
            assert isinstance(sid, str)
            file_count = len(self.snapshots.load(sid).manifest["files"])
            self.store.put_snapshot(SnapshotRecord(
                snapshot_id=sid, tenant=self.tenant, library=req.library, library_version=req.library_version,
                language=req.language, source_uri=req.source_uri, source_digest=req.source_digest,
                file_count=file_count))
            req = replace(req, state=SnapshotRequestState.succeeded, snapshot_id=sid, error=None)
        else:
            req = replace(req, state=SnapshotRequestState.failed, error=error)
        self.store.save_snapshot_request(req)
        return req

    def _verify_snapshot(self, req: SnapshotRequestRecord, sid: object) -> str | None:
        """The Job ran untrusted source with bucket write access, so its
        termination message is not trusted (PR #12 review): the snapshot must be
        in the bucket, canonical digest(manifest.json) must equal snapshot_id,
        and the manifest must record this request's language and source_digest.
        Returns the failure reason, or None when the snapshot is accepted."""
        if not isinstance(sid, str) or not _HEX64.fullmatch(sid):
            return "snapshot_id missing or malformed"
        try:
            raw = self.snapshots.manifest_bytes(sid)
        except SnapshotNotFound:
            return "snapshot not found in bucket"
        if self.digester is None:
            return "no digester configured to verify the snapshot"
        try:
            digest = self.digester.digest_bytes(raw)
        except DigestError as e:
            return f"manifest digest failed: {e}"
        if digest != sid:
            return "manifest digest does not match snapshot_id"
        try:
            manifest = json.loads(raw)
        except ValueError:
            return "manifest is not JSON"
        if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
            return "manifest has no file list"
        if manifest.get("language") != req.language:
            return "manifest language does not match the request"
        if manifest.get("source_digest") != req.source_digest:
            return "manifest source_digest does not match the request"
        if not isinstance(manifest.get("scanner_version"), str):
            return "manifest has no scanner_version"
        try:
            self.snapshots.load(sid)
        except (SnapshotNotFound, ValueError):
            return "snapshot files incomplete"
        return None

    def _snapshot(self, snapshot_id: str) -> SnapshotRecord:
        snap = self.store.get_snapshot(self.tenant, snapshot_id)
        if snap is None or not self.snapshots.exists(snapshot_id):
            raise not_found()
        return snap

    def read_source(self, caller: Caller, snapshot_id: str, path: str, start_line: int, end_line: int) -> dict:
        self._evidence_reader(caller)
        self._snapshot(snapshot_id)
        try:
            return self.snapshots.read_source(snapshot_id, path, start_line, end_line)
        except ReadRejected as e:
            raise schema_invalid() from e
        except SnapshotNotFound as e:
            raise not_found() from e

    def read_callgraph(self, caller: Caller, snapshot_id: str, symbol: str, depth: int) -> dict:
        self._evidence_reader(caller)
        self._snapshot(snapshot_id)
        try:
            return self.snapshots.read_callgraph(snapshot_id, symbol, depth)
        except ReadRejected as e:
            raise schema_invalid() from e
        except SnapshotNotFound as e:
            raise not_found() from e

    @staticmethod
    def _evidence_reader(caller: Caller) -> None:
        if caller.san is None:
            raise unauthenticated()
        if not caller.is_evidence_reader:
            raise forbidden()

    # --- runs ------------------------------------------------------------

    def create_run(self, caller: Caller, body: RunCreate) -> RunCreated:
        actor = self._operator(caller)
        self._snapshot(body.snapshot_id)
        run = RunRecord(run_id=self.new_id(), tenant=self.tenant, snapshot_id=body.snapshot_id,
                        scenario_set_id=body.scenario_set_id, state=RunState.queued, created_by_actor=actor)
        self.store.create_run(run)
        return RunCreated(run_id=run.run_id, state="queued")

    def process_next_run(self) -> bool:
        """Static analysis, then request the TASK-13 reproduction run."""
        run = self.store.claim_queued_run()
        if run is None:
            return False
        # The run is now `analyzing`. Any failure (GCS read, malformed model
        # output, transport error, ...) must end it in a terminal state with a
        # reason; otherwise it stays `analyzing` forever (PR #12 review).
        try:
            self._analyze_claimed(run)
        except Exception as e:
            log.exception("discovery run %s failed", run.run_id)
            current = self.store.get_run(run.tenant, run.run_id) or run
            if current.state not in (RunState.completed, RunState.failed, RunState.reproducing):
                self.store.update_run(replace(current, state=RunState.failed,
                                              error=f"static analysis failed: {type(e).__name__}"))
        return True

    def _analyze_claimed(self, run: RunRecord) -> None:
        snap = self.store.get_snapshot(run.tenant, run.snapshot_id)
        if snap is None:
            self.store.update_run(replace(run, state=RunState.failed, error="snapshot missing"))
            return
        result = self.analyzer.analyze(snap, self.snapshots.load(snap.snapshot_id))
        for cand, model_run_ref in result.candidates:
            rec = CandidateRecord(
                candidate_id=self.new_id(), tenant=run.tenant, run_id=run.run_id, snapshot_id=run.snapshot_id,
                origin=Origin.static, library=snap.library, library_version=cand.library_version,
                call_site=cand.call_site, trigger_condition=cand.trigger_condition,
                destination_template=cand.destination_template,
                retry_redirect_behavior=cand.retry_redirect_behavior, evidence_ref=cand.evidence_ref,
                model_run_ref=model_run_ref,
            )
            self.store.record_candidate(rec, self._recorded_event(rec))
        run = replace(run, static_analysis_status=result.status, model_calls=result.model_calls,
                      read_calls=result.read_calls)
        try:
            repro = self.regression.request(run.scenario_set_id)
        except GatewayError as e:
            self.store.update_run(replace(run, state=RunState.failed, error=f"reproduction request failed: {e}"))
            return
        self.store.update_run(replace(run, state=RunState.reproducing, reproduction_run_id=repro))

    def _recorded_event(self, rec: CandidateRecord) -> OutboxEvent:
        return self._event(RECORDED, {
            "candidate_id": rec.candidate_id, "library": rec.library, "library_version": rec.library_version,
            "call_site": rec.call_site, "model_run_ref": rec.model_run_ref,
        }, None)

    def poll_reproductions(self) -> int:
        done = 0
        for run in self.store.runs_in_state(RunState.reproducing):
            assert run.reproduction_run_id
            try:
                st = self.regression.status(run.reproduction_run_id)
            except GatewayError:
                continue
            if not st.finished:
                continue
            if st.state in MATCHABLE_REPORT_STATES:
                try:
                    self.reconcile(run, st.observations or [], st.observation_indexes, st.rejected_observations)
                except Exception:
                    # One bad run must not stop the other runs from being reconciled.
                    log.exception("reconciling discovery run %s failed", run.run_id)
                    continue
            else:
                # No usable observation list: leave dynamic_match unset rather
                # than calling every candidate static_not_observed.
                self.store.update_run(replace(run, state=RunState.completed,
                                              error=f"reproduction report state {st.state}"))
            done += 1
        return done

    def reconcile(self, run: RunRecord, observations: list, observation_indexes: list[int] | None = None,
                  rejected: list[str] | None = None) -> None:
        """Deterministic matcher over this run's open static candidates.

        `observation_indexes` maps each observation to its index in the report,
        so evidence refs still point at the right report entry when invalid
        entries were skipped; `rejected` lists those skipped entries."""
        assert run.reproduction_run_id
        repro = run.reproduction_run_id
        open_static = [c for c in self.store.run_candidates(run.tenant, run.run_id)
                       if c.origin == Origin.static and c.state == CandidateState.candidate and c.dynamic_match is None]
        assert self.config.infra is not None  # checked in __init__
        result = matcher.match([(c.candidate_id, c.destination_template) for c in open_static], observations,
                               infra=self.config.infra)
        for cid, m in result.candidates.items():
            self.store.apply_match(cid, m.dynamic_match, m.path_unverified, repro, m.matched_arms)
        snap = self.store.get_snapshot(run.tenant, run.snapshot_id)
        assert snap is not None
        for o in result.observed:
            rec = CandidateRecord(
                candidate_id=self.new_id(), tenant=run.tenant, run_id=run.run_id, snapshot_id=run.snapshot_id,
                origin=Origin.observed, library=snap.library, library_version=snap.library_version,
                call_site=None, trigger_condition=None, destination_template=o.destination_template,
                retry_redirect_behavior=None,
                evidence_ref=f"regression-run:{repro}#observations/" + ",".join(
                    str(observation_indexes[i] if observation_indexes is not None else i) for i in o.observation_indexes),
                model_run_ref=None, dynamic_match=DynamicMatch.observed_not_static, matched_arms=o.matched_arms,
                reproduction_run_id=repro,
                # The observation itself is the reproduction (TASK-02 3.4, PR #19).
                state=CandidateState.reproduced,
            )
            self.store.record_candidate(rec, self._recorded_event(rec))
        own = self.store.run_candidates(run.tenant, run.run_id)
        try:
            notes = self.annotator.annotate(run, own)
        except Exception:
            notes = {}  # annotation is optional and never affects state
        # Keys come from model output: only this run's candidates may be annotated.
        own_ids = {c.candidate_id for c in own}
        for cid, text in notes.items():
            if cid in own_ids and isinstance(text, str):
                self.store.set_annotation(cid, text)
        done = replace(self.store.get_run(run.tenant, run.run_id) or run, state=RunState.completed,
                       infra_filtered=result.infra_filtered)
        if rejected:
            done = replace(done, error=f"skipped {len(rejected)} invalid observation(s): " + "; ".join(rejected)[:500])
        self.store.update_run(done)

    # --- candidates ------------------------------------------------------

    def list_candidates(self, caller: Caller, run_id: str | None, state: CandidateState | None,
                        cursor: str | None) -> CandidateList:
        self._operator(caller)
        after = decode_cursor(cursor)
        rows = self.store.list_candidates(self.tenant, run_id, state, after, PAGE_SIZE + 1)
        more = len(rows) > PAGE_SIZE
        rows = rows[:PAGE_SIZE]
        return CandidateList(items=[to_api(c) for c in rows],
                             next_cursor=encode_cursor(rows[-1].seq) if more else None)

    def promote(self, caller: Caller, candidate_id: str, body: PromoteRequest) -> DiscoveryCandidate:
        actor = self._operator(caller)
        event = self._event(PROMOTED, {
            "candidate_id": candidate_id, "promotion_kind": body.promotion_kind.value,
            "reviewed_by_actor": actor, "catalog_change_ref": None,
        }, actor)
        # The store re-checks state = reproduced, the reproduction run and the
        # promotion kind (store.promotable) in the same statement that writes
        # `promoted`: matched candidates take any kind, observed_not_static ones
        # only deny_fixture or sdk_setting_check (TASK-02 3.4, PR #19).
        outcome, rec = self.store.promote(self.tenant, candidate_id, body.reproduction_run_id,
                                          body.promotion_kind, actor, body.review_note, event)
        if outcome == Outcome.not_found:
            raise not_found()
        if outcome == Outcome.conflict:
            raise state_conflict()
        assert rec is not None
        return to_api(rec)

    def reject(self, caller: Caller, candidate_id: str, body: RejectRequest) -> DiscoveryCandidate:
        actor = self._operator(caller)
        outcome, rec = self.store.reject(self.tenant, candidate_id, body.reason, actor)
        if outcome == Outcome.not_found:
            raise not_found()
        if outcome == Outcome.conflict:
            raise state_conflict()
        assert rec is not None
        return to_api(rec)

    # --- metrics (TASK-02 3.4) -------------------------------------------

    def ai_created_allow_count(self) -> int:
        """Allow-kind promotions that lack dynamic reproduction or a human reviewer."""
        promoted = self.store.list_candidates(self.tenant, None, CandidateState.promoted, 0, 1_000_000)
        return sum(
            1 for c in promoted
            if c.promotion_kind == PromotionKind.allow_operation and not (
                c.dynamic_match == DynamicMatch.matched and c.reproduction_run_id
                and c.reviewed_by_actor and not c.reviewed_by_actor.startswith("service:")
            )
        )

    def metrics(self, run_id: str) -> dict:
        run = self.store.get_run(self.tenant, run_id)
        cs = self.store.run_candidates(self.tenant, run_id)
        static = [c for c in cs if c.origin == Origin.static]
        matched = [c for c in static if c.dynamic_match == DynamicMatch.matched]
        return {
            "candidate_count": len(cs),
            "reproduced_ratio": {"numerator": len(matched), "denominator": len(static)},
            "observed_not_static_count": sum(1 for c in cs if c.origin == Origin.observed),
            "promoted_allow_count": sum(1 for c in cs if c.promotion_kind == PromotionKind.allow_operation),
            "promoted_deny_count": sum(1 for c in cs if c.promotion_kind in (PromotionKind.deny_fixture,
                                                                              PromotionKind.sdk_setting_check)),
            "unresolved_count": sum(1 for c in cs if c.state in (CandidateState.candidate, CandidateState.reproduced)),
            "static_analysis_status": (run.static_analysis_status if run else None) or AiStatus.not_run,
            "infra_filtered": run.infra_filtered if run else 0,
        }
