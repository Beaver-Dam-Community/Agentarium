"""Strict API and domain models (COMMON "common data structures", TASK-02 3.4)."""

from __future__ import annotations

import ipaddress
import json
import re
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

HEX64 = r"^[0-9a-f]{64}$"
UUID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

Digest = Annotated[str, StringConstraints(pattern=HEX64)]
Uuid = Annotated[str, StringConstraints(pattern=UUID_RE)]


class Strict(BaseModel):
    """Input model. Validate with model_validate_json so enums parse in strict mode."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Out(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Language(StrEnum):
    go = "go"
    python = "python"


class CandidateState(StrEnum):
    candidate = "candidate"
    reproduced = "reproduced"
    promoted = "promoted"
    rejected = "rejected"


class DynamicMatch(StrEnum):
    observed_not_static = "observed_not_static"
    static_not_observed = "static_not_observed"
    matched = "matched"


class PromotionKind(StrEnum):
    allow_operation = "allow_operation"
    deny_fixture = "deny_fixture"
    sdk_setting_check = "sdk_setting_check"


# SPEC-QUESTION: TASK-02 fixes only `queued` for a discovery run. The other
# states below are this service's internal progress markers.
class RunState(StrEnum):
    queued = "queued"
    analyzing = "analyzing"
    reproducing = "reproducing"
    completed = "completed"
    failed = "failed"


# SPEC-QUESTION: snapshot request progress is not defined by the spec.
class SnapshotRequestState(StrEnum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"


class AiStatus(StrEnum):
    """COMMON AI one-way principle: AI failure is recorded as not_run."""

    completed = "completed"
    not_run = "not_run"


# --- requests --------------------------------------------------------------

Text = Annotated[str, StringConstraints(min_length=1, max_length=4096)]


class SnapshotCreate(Strict):
    library: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    library_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    language: Language
    source_uri: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    source_digest: Digest


# SPEC-QUESTION: scenario_set_id format is not defined; accept a short token.
ScenarioSetId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,128}$")]


class RunCreate(Strict):
    snapshot_id: Digest
    scenario_set_id: ScenarioSetId


class PromoteRequest(Strict):
    promotion_kind: PromotionKind
    reproduction_run_id: Uuid
    review_note: Text


class RejectRequest(Strict):
    reason: Text


# --- responses ---------------------------------------------------------------


class RunCreated(Out):
    run_id: str
    state: Literal["queued"]


class SnapshotStatus(Out):
    state: SnapshotRequestState
    snapshot_id: str | None
    library: str
    library_version: str
    language: Language
    source_digest: str


class DiscoveryCandidate(Out):
    """COMMON DiscoveryCandidate plus TASK-02 `path_unverified`."""

    candidate_id: str
    library: str
    library_version: str
    # SPEC-QUESTION: COMMON lists call_site, trigger_condition,
    # retry_redirect_behavior and model_run_ref as required, but an
    # observed_not_static candidate has no model output. They are null there.
    call_site: str | None
    trigger_condition: str | None
    destination_template: str
    retry_redirect_behavior: str | None
    evidence_ref: str
    model_run_ref: str | None
    dynamic_match: DynamicMatch | None
    path_unverified: bool | None
    # COMMON matched_arms?: control arms that reproduced it, sorted (PR #19).
    matched_arms: list[Literal["off", "on"]] | None
    reproduction_run_id: str | None
    state: CandidateState
    promotion_kind: PromotionKind | None
    reviewed_by_actor: str | None
    catalog_change_ref: str | None


class CandidateList(Out):
    items: list[DiscoveryCandidate]
    next_cursor: str | None


class ErrorBody(Out):
    request_id: str
    reason_codes: list[str]


# --- model structured output (TASK-02 3.4 static analysis row) --------------

Short = Annotated[str, StringConstraints(min_length=1, max_length=512)]
Long = Annotated[str, StringConstraints(min_length=1, max_length=1024)]


class ModelCandidate(Strict):
    call_site: Short
    library_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    trigger_condition: Long
    destination_template: Short
    retry_redirect_behavior: Long
    evidence_ref: Short


class ModelCandidateOutput(Strict):
    candidates: Annotated[list[ModelCandidate], Field(max_length=64)]


# --- dynamic observations (TASK-02 3.4 dynamic row) --------------------------

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,253}$")


def _ip(v: str) -> str:
    return str(ipaddress.ip_address(v))


def _hostname(v: str | None) -> str | None:
    if v is None:
        return None
    if not HOSTNAME_RE.fullmatch(v):
        raise ValueError("invalid hostname")
    return v.rstrip(".").lower() or None


Host = Annotated[str | None, AfterValidator(_hostname)]


class Observation(Strict):
    arm: Literal["on", "off"]
    process_exec_id: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    dst_ip: Annotated[str, AfterValidator(_ip)]
    dst_port: Annotated[int, Field(ge=1, le=65535)]
    tls_sni: Host = None
    dns_name: Host = None
    http_method: Annotated[str, StringConstraints(pattern=r"^[A-Z]{1,16}$")] | None = None
    http_path: Annotated[str, StringConstraints(pattern=r"^/", max_length=8192)] | None = None
    source: Literal["kernel", "adapter", "egress_log"]


class Task13Observation(Strict):
    """TASK-13 3.6 wording of the same observation list."""

    scenario_id: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    control: Literal["on", "off"]
    process_exec_id: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    dest_addr: Annotated[str, AfterValidator(_ip)]
    dest_port: Annotated[int, Field(ge=1, le=65535)]
    sni: Host = None
    dns_name: Host = None
    source: Literal["kernel", "adapter_observation"]
    source_time: str

    def to_observation(self) -> Observation:
        return Observation(
            arm=self.control,
            process_exec_id=self.process_exec_id,
            dst_ip=self.dest_addr,
            dst_port=self.dest_port,
            tls_sni=self.sni,
            dns_name=self.dns_name,
            source="kernel" if self.source == "kernel" else "adapter",
        )


def parse_observation(item: dict) -> Observation:
    """Accept either observation shape.

    SPEC-QUESTION: TASK-02 3.4 (`arm, dst_ip, dst_port, tls_sni, ...,
    source: kernel|adapter|egress_log`) and TASK-13 3.6 (`control, dest_addr,
    dest_port, sni, ..., source: kernel|adapter_observation`) name the same
    list differently. Both are accepted and mapped to the TASK-02 shape.
    """
    raw = json.dumps(item)
    if isinstance(item, dict) and "arm" in item:
        return Observation.model_validate_json(raw)
    return Task13Observation.model_validate_json(raw).to_observation()
