"""Narrow clients for the services discovery calls.

- identity `POST /internal/service-sessions` and gateway `POST /v1/actions`
  (+ `/result`): the only path for model.generate and discovery.* reads.
- TASK-13 `POST/GET /internal/regression-runs` (run_kind = discovery).
- TASK-07 `POST /internal/audit/events`.
- Kubernetes Jobs for the snapshot scanner.

Each has a Protocol; unit tests use fakes. The HTTP implementations are
exercised only by integration tests.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Protocol

import httpx
from pydantic import ValidationError

from .models import Observation, parse_observation

# --- gateway -----------------------------------------------------------------


class GatewayError(RuntimeError):
    def __init__(self, message: str, reason_codes: list[str] | None = None) -> None:
        super().__init__(message)
        self.reason_codes = reason_codes or []


class BudgetExhausted(GatewayError):
    pass


@dataclass(frozen=True)
class ServiceSession:
    service_session_id: str
    token: str
    expires_at: str


@dataclass(frozen=True)
class FunctionCall:
    name: str
    args: dict


@dataclass(frozen=True)
class ModelTurn:
    action_id: str
    turn_index: int
    text: str | None
    function_calls: list[FunctionCall] = field(default_factory=list)


class Gateway(Protocol):
    def open_session(self, snapshot_id: str) -> ServiceSession: ...
    def generate(self, session: ServiceSession, conversation_id: str, messages: list[dict]) -> ModelTurn: ...
    def source_read(self, session: ServiceSession, snapshot_id: str, path: str, start_line: int, end_line: int) -> str: ...
    def callgraph_read(self, session: ServiceSession, snapshot_id: str, symbol: str, depth: int) -> str: ...


def parse_model_result(action_id: str, body: object, conversation_id: str) -> ModelTurn:
    """Read the model adapter's sanitized result; never coerce malformed refs."""
    if not isinstance(body, dict) or body.get("conversation_id") != conversation_id:
        raise GatewayError("model result has another or missing conversation", ["MODEL_SCHEMA_INVALID"])
    index, text, raw_calls = body.get("turn_index"), body.get("text"), body.get("function_calls")
    if type(index) is not int or index < 0 or (text is not None and not isinstance(text, str)) or not isinstance(raw_calls, list):
        raise GatewayError("invalid model result", ["MODEL_SCHEMA_INVALID"])
    calls = []
    for call in raw_calls:
        if not isinstance(call, dict) or set(call) != {"name", "args"} or not isinstance(call["name"], str) or not isinstance(call["args"], dict):
            raise GatewayError("invalid model function call", ["MODEL_SCHEMA_INVALID"])
        calls.append(FunctionCall(call["name"], call["args"]))
    return ModelTurn(action_id, index, text, calls)


class HttpGateway:
    TERMINAL = {"accepted", "effect_verified", "failed", "unknown", "denied", "preflight_rejected", "effect_mismatch"}

    def __init__(self, client: httpx.Client, identity_url: str, gateway_url: str, tenant: str,
                 model_target_id: str, snapshots_target_id: str, poll_timeout: float = 60.0) -> None:
        self.client = client
        self.identity_url = identity_url.rstrip("/")
        self.gateway_url = gateway_url.rstrip("/")
        self.tenant = tenant
        self.model_target_id = model_target_id
        self.snapshots_target_id = snapshots_target_id
        self.poll_timeout = poll_timeout

    def open_session(self, snapshot_id: str) -> ServiceSession:
        r = self.client.post(f"{self.identity_url}/internal/service-sessions",
                             json={"profile": "discovery", "snapshot_id": snapshot_id, "tenant": self.tenant})
        _raise(r)
        b = r.json()
        return ServiceSession(b["service_session_id"], b["token"], b["expires_at"])

    def _submit(self, s: ServiceSession, operation_id: str, target: dict, arguments: dict) -> dict:
        action = {
            "session_id": s.service_session_id,
            "operation_id": operation_id,
            "requested_target": target,
            "arguments": arguments,
            "client_request_key": secrets.token_hex(16),
        }
        auth = {"Authorization": f"Bearer {s.token}"}
        r = self.client.post(f"{self.gateway_url}/v1/actions", json=action, headers=auth)
        _raise(r)
        b = r.json()
        if not b.get("execution_allowed", False):
            raise GatewayError("action not allowed for execution", b.get("reason_codes"))
        action_id = b["action_id"]
        deadline = time.monotonic() + self.poll_timeout
        while time.monotonic() < deadline:
            rr = self.client.get(f"{self.gateway_url}/v1/actions/{action_id}/result", headers=auth)
            if rr.status_code == 200:
                res = rr.json()
                if res.get("execution_state") in self.TERMINAL:
                    if res["execution_state"] not in ("accepted", "effect_verified"):
                        raise GatewayError(f"action {action_id} ended {res['execution_state']}", res.get("reason_codes"))
                    if res.get("action_id", action_id) != action_id:
                        raise GatewayError("result action differs from submitted action")
                    return {**res, "action_id": action_id}
            elif rr.status_code not in (202, 404):
                _raise(rr)
            time.sleep(0.5)
        raise GatewayError(f"action {action_id} result timeout")

    def generate(self, session, conversation_id, messages):
        res = self._submit(session, "model.generate",
                           {"target_id": self.model_target_id, "profile": "discovery"},
                           {"conversation_id": conversation_id, "messages": messages, "tool_declarations": []})
        if res.get("truncated"):
            raise GatewayError("model output was truncated", ["MODEL_OUTPUT_TRUNCATED"])
        return parse_model_result(res["action_id"], res.get("result_body"), conversation_id)

    def source_read(self, session, snapshot_id, path, start_line, end_line):
        res = self._submit(session, "discovery.source.read",
                           {"target_id": self.snapshots_target_id, "snapshot_id": snapshot_id, "path": path},
                           {"start_line": start_line, "end_line": end_line})
        return res["action_id"]

    def callgraph_read(self, session, snapshot_id, symbol, depth):
        res = self._submit(session, "discovery.callgraph.read",
                           {"target_id": self.snapshots_target_id, "snapshot_id": snapshot_id, "symbol": symbol},
                           {"depth": depth})
        return res["action_id"]


def _raise(r: httpx.Response) -> None:
    if r.status_code < 300:
        return
    try:
        codes = list(r.json().get("reason_codes") or [])
    except ValueError:
        codes = []
    if "TOOL_BUDGET_EXHAUSTED" in codes:
        raise BudgetExhausted("tool budget exhausted", codes)
    raise GatewayError(f"HTTP {r.status_code} from {r.request.url}", codes)


# --- regression runs (TASK-13) ------------------------------------------------


@dataclass(frozen=True)
class RegressionStatus:
    run_id: str
    finished: bool
    state: str | None
    observations: list[Observation] | None
    # Report index of each entry in `observations` (None: positions are the
    # report indexes), and the report entries that failed validation and were
    # skipped as "<index>: <reason>".
    observation_indexes: list[int] | None = None
    rejected_observations: list[str] = field(default_factory=list)


class Regression(Protocol):
    def request(self, scenario_set_id: str) -> str: ...
    def status(self, run_id: str) -> RegressionStatus: ...


class HttpRegression:
    """SPEC-QUESTION: TASK-02 sends `scenario_set_id`, but the TASK-13 request
    fields are run_kind, proposal_id?, candidate_digest, baseline_bundle_digest,
    fixture_scope, extra_fixture_ids?, environment_id. Both sets are sent; the
    two digests and environment_id are installation inputs. The report key for
    the observation list is not fixed; `observations` is read.
    """

    def __init__(self, client: httpx.Client, url: str, environment_id: str,
                 candidate_digest: str, baseline_bundle_digest: str) -> None:
        self.client = client
        self.url = url.rstrip("/")
        self.environment_id = environment_id
        self.candidate_digest = candidate_digest
        self.baseline_bundle_digest = baseline_bundle_digest

    def request(self, scenario_set_id: str) -> str:
        r = self.client.post(f"{self.url}/internal/regression-runs", json={
            "run_kind": "discovery",
            "fixture_scope": "discovery",
            "scenario_set_id": scenario_set_id,
            "candidate_digest": self.candidate_digest,
            "baseline_bundle_digest": self.baseline_bundle_digest,
            "environment_id": self.environment_id,
        })
        _raise(r)
        return r.json()["run_id"]

    def status(self, run_id: str) -> RegressionStatus:
        r = self.client.get(f"{self.url}/internal/regression-runs/{run_id}")
        _raise(r)
        b = r.json()
        report = b.get("report")
        if report is None:
            return RegressionStatus(run_id, False, b.get("state"), None)
        # One invalid observation is recorded and skipped; it must not block the
        # whole run or every later poll (PR #12 review).
        valid: list[Observation] = []
        indexes: list[int] = []
        rejected: list[str] = []
        for i, o in enumerate(report.get("observations") or []):
            try:
                valid.append(parse_observation(o))
                indexes.append(i)
            except (ValidationError, ValueError, TypeError) as e:
                rejected.append(f"{i}: {type(e).__name__}")
        return RegressionStatus(run_id, True, report.get("state", b.get("state")), valid, indexes, rejected)


# --- audit (TASK-07) ----------------------------------------------------------


class AuditSink(Protocol):
    def post(self, event: dict) -> None: ...


class HttpAudit:
    def __init__(self, client: httpx.Client, url: str) -> None:
        self.client = client
        self.url = url.rstrip("/")

    def post(self, event: dict) -> None:
        r = self.client.post(f"{self.url}/internal/audit/events", json=event)
        # 409 EVENT_ID_CONFLICT must surface; a duplicate with the same body is fine.
        _raise(r)


# --- snapshot Jobs --------------------------------------------------------------


@dataclass(frozen=True)
class JobStatus:
    state: str  # running | succeeded | failed
    result: dict | None = None
    error: str | None = None


class SnapshotJobs(Protocol):
    def launch(self, request_id: str, language: str, source_uri: str, source_digest: str,
               library: str, library_version: str) -> str: ...
    def status(self, job_name: str) -> JobStatus: ...


def kubernetes_failure_reason(job_status: dict, pods: list[dict]) -> str | None:
    """The reason Kubernetes reported when the Job ended without our
    termination message (TASK-02 3.4, PR #22): the container's terminated
    reason (OOMKilled), the Pod's reason (Evicted, e.g. emptyDir or
    ephemeral-storage over its limit), or the Job's Failed condition
    (DeadlineExceeded after activeDeadlineSeconds, which also deletes the Pod)."""
    def with_message(reason: str, msg: object) -> str:
        return f"{reason}: {msg}" if isinstance(msg, str) and msg else reason

    for p in pods:
        pst = p.get("status", {})
        for cs in pst.get("containerStatuses", []):
            term = cs.get("state", {}).get("terminated") or {}
            reason = term.get("reason")
            # "Error" and "Completed" only say the process exited. The
            # terminated message is our own (unparsable) termination log, so it
            # is not appended.
            if isinstance(reason, str) and reason not in ("", "Error", "Completed", "ContainerStatusUnknown"):
                return reason
        if isinstance(pst.get("reason"), str) and pst["reason"]:
            return with_message(pst["reason"], pst.get("message"))
    for c in job_status.get("conditions") or []:
        if c.get("type") == "Failed" and c.get("status") == "True" and isinstance(c.get("reason"), str) and c["reason"]:
            return with_message(c["reason"], c.get("message"))
    return None


class KubernetesJobs:
    """Creates batch/v1 Jobs running tools/discovery-snapshot in agent-observe.

    The Job reads the staged archive gs://<bucket>/sources/<source_digest>.<ext>
    and writes gs://<bucket>/snapshots/ through the Cloud Storage API with its
    own KSA `discovery-snapshot` (bucket objects create/get/list only, no DB);
    the service KSA `discovery` only reads the bucket (TASK-02 3.4, PR #8). No
    Cloud Storage FUSE volume or sidecar is used: the role admission policy
    rejects the injected sidecar image. The Pod satisfies the role admission
    policy (control placement, digest image, label == KSA) and PSS restricted.
    """

    API = "https://kubernetes.default.svc"
    TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    DEFAULT_SERVICE_ACCOUNT = "discovery-snapshot"
    NONROOT_UID = 65532  # distroless nonroot
    _IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")

    def __init__(self, namespace: str, image: str, bucket: str,
                 service_account: str = DEFAULT_SERVICE_ACCOUNT,
                 client: httpx.Client | None = None) -> None:
        if not self._IMAGE.fullmatch(image):
            raise ValueError("snapshot Job image must be a digest reference (<repo>@sha256:<digest>)")
        self.namespace = namespace
        self.image = image
        self.service_account = service_account
        self.bucket = bucket
        self.client = client or httpx.Client(verify=self.CA, timeout=10.0)

    def _headers(self) -> dict:
        with open(self.TOKEN) as f:
            return {"Authorization": f"Bearer {f.read().strip()}"}

    def job_manifest(self, name, request_id, language, source_uri, source_digest, library, library_version) -> dict:
        return {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": name, "labels": {"app.kubernetes.io/name": self.service_account,
                                                  "agentarium.internal/snapshot-request": request_id}},
            "spec": {
                "backoffLimit": 0, "ttlSecondsAfterFinished": 86400, "activeDeadlineSeconds": 3600,
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": self.service_account}},
                    "spec": {
                        "serviceAccountName": self.service_account, "restartPolicy": "Never",
                        "automountServiceAccountToken": False,
                        "schedulerName": "default-scheduler",
                        "nodeSelector": {"node-restriction.kubernetes.io/agentarium-role": "control"},
                        "securityContext": {"runAsNonRoot": True, "runAsUser": self.NONROOT_UID,
                                            "runAsGroup": self.NONROOT_UID,
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{
                            "name": "scanner", "image": self.image,
                            "args": ["--language", language, "--source-uri", source_uri,
                                     "--source-digest", source_digest, "--library", library,
                                     "--library-version", library_version, "--out-root", f"gs://{self.bucket}",
                                     "--work-dir", "/work"],
                            "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                                "capabilities": {"drop": ["ALL"]}},
                            "resources": {
                                "requests": {"cpu": "250m", "memory": "512Mi", "ephemeral-storage": "256Mi"},
                                # TASK-02 3.4 archive limits (PR #22): archive 256MiB
                                # + extracted 1GiB + scan output on the work dir.
                                "limits": {"cpu": "2", "memory": "2Gi", "ephemeral-storage": "2560Mi"},
                            },
                            "volumeMounts": [{"name": "work", "mountPath": "/work"}],
                        }],
                        "volumes": [{"name": "work", "emptyDir": {"sizeLimit": "2Gi"}}],
                    },
                },
            },
        }

    def launch(self, request_id, language, source_uri, source_digest, library, library_version):
        name = f"discovery-snapshot-{request_id[:8]}-{secrets.token_hex(3)}"
        job = self.job_manifest(name, request_id, language, source_uri, source_digest, library, library_version)
        r = self.client.post(f"{self.API}/apis/batch/v1/namespaces/{self.namespace}/jobs", json=job, headers=self._headers())
        r.raise_for_status()
        return name

    def status(self, job_name):
        h = self._headers()
        r = self.client.get(f"{self.API}/apis/batch/v1/namespaces/{self.namespace}/jobs/{job_name}", headers=h)
        if r.status_code == 404:
            # Deleted by ttlSecondsAfterFinished (or by hand): the result is gone,
            # so the request fails instead of staying `running` (PR #12 review).
            return JobStatus("failed", None, "job_gone")
        r.raise_for_status()
        st = r.json().get("status", {})
        if not st.get("succeeded") and not st.get("failed"):
            return JobStatus("running")
        pods = self.client.get(f"{self.API}/api/v1/namespaces/{self.namespace}/pods",
                               params={"labelSelector": f"job-name={job_name}"}, headers=h)
        pods.raise_for_status()
        items = pods.json().get("items", [])
        message = None
        for p in items:
            for cs in p.get("status", {}).get("containerStatuses", []):
                term = cs.get("state", {}).get("terminated")
                if term and term.get("message"):
                    message = term["message"]
        try:
            result = json.loads(message) if message else None
        except ValueError:
            result = None
        if not isinstance(result, dict):
            result = None
        if st.get("succeeded") and result and "snapshot_id" in result:
            return JobStatus("succeeded", result)
        error = (result or {}).get("error")
        if not isinstance(error, str) or not error:
            error = kubernetes_failure_reason(st, items) or "snapshot job failed"
        return JobStatus("failed", None, error[:500])
