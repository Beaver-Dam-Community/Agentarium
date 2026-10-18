"""FastAPI routes for /internal/discovery/* (TASK-02 4, COMMON "internal API responsibilities").

Bodies are parsed strictly: 1MiB limit, valid UTF-8, no duplicate or
case-only-different keys, no NaN/Infinity, unknown fields rejected (Pydantic
strict, extra=forbid). Errors return only {request_id, reason_codes}.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

import psycopg
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import auth
from .models import (
    UUID_RE,
    CandidateState,
    PromoteRequest,
    RejectRequest,
    RunCreate,
    SnapshotCreate,
)
from .service import ApiError, DiscoveryService, schema_invalid, unauthenticated

MAX_BODY = 1 << 20
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(UUID_RE)
_INT = re.compile(r"^[1-9][0-9]{0,8}$")

PREFIX = "/internal/discovery"


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    seen: set[str] = set()
    for k, _ in pairs:
        if k.lower() in seen:
            raise ValueError("duplicate key")
        seen.add(k.lower())
    return dict(pairs)


def _check_strings(v: Any) -> None:
    if isinstance(v, str):
        v.encode("utf-8")  # lone surrogates from \\uD800 escapes fail here
    elif isinstance(v, dict):
        for k, x in v.items():
            _check_strings(k)
            _check_strings(x)
    elif isinstance(v, list):
        for x in v:
            _check_strings(x)


async def parse_body[M: BaseModel](request: Request, model: type[M]) -> M:
    # Reject on Content-Length before reading, and never buffer more than
    # MAX_BODY + 1 bytes of a body without one (chunked).
    length = request.headers.get("content-length")
    if length is not None:
        if not length.isdigit():
            raise schema_invalid()
        if int(length) > MAX_BODY:
            raise ApiError(413, ["BODY_TOO_LARGE"])
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > MAX_BODY:
            raise ApiError(413, ["BODY_TOO_LARGE"])
    raw = bytes(buf)
    try:
        text = raw.decode("utf-8")
        _check_strings(json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant))
        return model.model_validate_json(raw)
    except (UnicodeError, ValueError, ValidationError) as e:
        raise schema_invalid() from e


def query(request: Request, allowed: set[str]) -> dict[str, str]:
    items = request.query_params.multi_items()
    keys = [k for k, _ in items]
    if len(keys) != len(set(keys)) or not set(keys) <= allowed:
        raise schema_invalid()
    return dict(items)


def _int(q: dict[str, str], name: str) -> int:
    v = q.get(name)
    if v is None or not _INT.fullmatch(v):
        raise schema_invalid()
    return int(v)


def _hex(v: str) -> str:
    if not _HEX64.fullmatch(v):
        raise schema_invalid()
    return v


def _uuid(v: str) -> str:
    if not _UUID.fullmatch(v):
        raise schema_invalid()
    return v


def _error(request_id: str, status: int, codes: list[str], retry_after: int | None = None) -> JSONResponse:
    headers = {"Retry-After": str(retry_after)} if retry_after is not None else None
    return JSONResponse({"request_id": request_id, "reason_codes": codes}, status_code=status, headers=headers)


def create_app(service: DiscoveryService, peer: auth.PeerIdentity) -> FastAPI:
    app = FastAPI(title="agentarium-discovery", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def request_id(request: Request, call_next):
        request.state.request_id = str(uuid.uuid4())
        return await call_next(request)

    @app.exception_handler(ApiError)
    async def api_error(request: Request, e: ApiError):
        return _error(request.state.request_id, e.status, e.reason_codes, e.retry_after)

    @app.exception_handler(psycopg.Error)
    async def store_error(request: Request, e: psycopg.Error):
        return _error(request.state.request_id, 503, ["STATE_STORE_UNAVAILABLE"], 2)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, e: RequestValidationError):
        return _error(request.state.request_id, 422, ["SCHEMA_INVALID"])

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, e: StarletteHTTPException):
        codes = ["RESOURCE_NOT_FOUND"] if e.status_code == 404 else []
        return _error(request.state.request_id, e.status_code, codes)

    def caller(request: Request) -> auth.Caller:
        """Resolve the mTLS peer first: an unauthenticated request gets 401
        before its body or query is parsed (PR #12 review)."""
        c = auth.resolve(request, peer)
        if c.san is None:
            raise unauthenticated()
        return c

    @app.post(f"{PREFIX}/snapshots")
    async def create_snapshot(request: Request):
        who = caller(request)
        body = await parse_body(request, SnapshotCreate)
        status, out = await run_in_threadpool(service.create_snapshot, who, body)
        return JSONResponse(out.model_dump(mode="json"), status_code=status)

    @app.get(f"{PREFIX}/snapshots/{{snapshot_id}}/files")
    async def read_files(snapshot_id: str, request: Request):
        who = caller(request)
        q = query(request, {"path", "start_line", "end_line"})
        if "path" not in q:
            raise schema_invalid()
        return await run_in_threadpool(service.read_source, who, _hex(snapshot_id), q["path"],
                                       _int(q, "start_line"), _int(q, "end_line"))

    @app.get(f"{PREFIX}/snapshots/{{snapshot_id}}/callgraph")
    async def read_callgraph(snapshot_id: str, request: Request):
        who = caller(request)
        q = query(request, {"symbol", "depth"})
        if "symbol" not in q:
            raise schema_invalid()
        return await run_in_threadpool(service.read_callgraph, who, _hex(snapshot_id), q["symbol"],
                                       _int(q, "depth"))

    @app.post(f"{PREFIX}/runs", status_code=202)
    async def create_run(request: Request):
        who = caller(request)
        body = await parse_body(request, RunCreate)
        return (await run_in_threadpool(service.create_run, who, body)).model_dump(mode="json")

    @app.get(f"{PREFIX}/candidates")
    async def list_candidates(request: Request):
        who = caller(request)
        q = query(request, {"run_id", "state", "cursor"})
        run_id = _uuid(q["run_id"]) if q.get("run_id") else None
        state = None
        if q.get("state"):
            try:
                state = CandidateState(q["state"])
            except ValueError as e:
                raise schema_invalid() from e
        out = await run_in_threadpool(service.list_candidates, who, run_id, state, q.get("cursor") or None)
        return out.model_dump(mode="json")

    @app.post(f"{PREFIX}/candidates/{{candidate_id}}/promote")
    async def promote(candidate_id: str, request: Request):
        who = caller(request)
        body = await parse_body(request, PromoteRequest)
        out = await run_in_threadpool(service.promote, who, _uuid(candidate_id), body)
        return out.model_dump(mode="json")

    @app.post(f"{PREFIX}/candidates/{{candidate_id}}/reject")
    async def reject(candidate_id: str, request: Request):
        who = caller(request)
        body = await parse_body(request, RejectRequest)
        out = await run_in_threadpool(service.reject, who, _uuid(candidate_id), body)
        return out.model_dump(mode="json")

    return app
