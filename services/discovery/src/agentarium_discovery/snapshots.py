"""Snapshot storage and the two read tools (TASK-02 3.2/3.4, COMMON discovery).

The snapshot root holds snapshots/<snapshot_id>/{manifest.json, src/<path>,
callgraph.json, call_sites.json} as written by tools/discovery-snapshot.

In GKE the root is the discovery bucket (lock key storage.discovery_bucket),
read through the Cloud Storage API with the `discovery` KSA's Workload
Identity, not through Cloud Storage FUSE (TASK-02 3.4, PR #8). A local
directory root is kept for tests and development. Snapshots are write-once,
so loaded documents are cached per snapshot_id.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

RESPONSE_LIMIT = 64 * 1024
MAX_LINES = 400
MAX_PATH_BYTES = 512
MAX_SYMBOL_BYTES = 256
MAX_DEPTH = 3
CACHE_SNAPSHOTS = 32

_SNAPSHOT_ID = re.compile(r"^[0-9a-f]{64}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")


class SnapshotNotFound(LookupError):
    pass


class SnapshotCorrupt(SnapshotNotFound):
    """A stored file does not match its manifest SHA-256; nothing is served."""


class ReadRejected(ValueError):
    """Request outside the fixed snapshot (422 SCHEMA_INVALID)."""


@dataclass(frozen=True)
class SnapshotFiles:
    manifest: dict
    callgraph: dict[str, list[str]]
    call_sites: dict


class ObjectMissing(LookupError):
    pass


class SnapshotBackend(Protocol):
    """Read-only access to snapshot objects by key (`snapshots/<id>/<name>`)."""

    def read(self, key: str) -> bytes:
        """Object bytes; raises ObjectMissing when the object does not exist."""
        ...


class LocalBackend:
    """Directory root for tests and development."""

    def __init__(self, root: str | os.PathLike) -> None:
        self.root = Path(root).resolve()

    def read(self, key: str) -> bytes:
        p = (self.root / key).resolve()
        # Keys are built from validated parts; this also stops symlinks out of the root.
        if not p.is_relative_to(self.root):
            raise ObjectMissing(key)
        try:
            return p.read_bytes()
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError) as e:
            raise ObjectMissing(key) from e


class GCSBackend:
    """gs://<bucket> root read with the Cloud Storage API (Application Default
    Credentials; Workload Identity in GKE). `client` is a google.cloud.storage
    Client or a test double with the same bucket().blob().download_as_bytes()."""

    def __init__(self, bucket: str, client: Any | None = None) -> None:
        if not _BUCKET.fullmatch(bucket):
            raise ValueError(f"invalid bucket name {bucket!r}")
        if client is None:
            from google.cloud import storage

            client = storage.Client()
        self._bucket = client.bucket(bucket)

    def read(self, key: str) -> bytes:
        from google.api_core import exceptions

        try:
            return self._bucket.blob(key).download_as_bytes()
        except exceptions.NotFound as e:
            raise ObjectMissing(key) from e


def backend_for(root: str | os.PathLike) -> SnapshotBackend:
    """`gs://<bucket>` selects GCSBackend; anything else is a local directory."""
    s = os.fspath(root)
    if s.startswith("gs://"):
        bucket = s[len("gs://"):].rstrip("/")
        if "/" in bucket:
            raise ValueError("snapshot root must be gs://<bucket> without a path")
        return GCSBackend(bucket)
    return LocalBackend(s)


class SnapshotStore:
    def __init__(self, root: str | os.PathLike | SnapshotBackend) -> None:
        self.backend: SnapshotBackend = (
            backend_for(root) if isinstance(root, (str, os.PathLike)) else root
        )
        self._cache: OrderedDict[str, SnapshotFiles] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(snapshot_id: str, name: str) -> str:
        if not _SNAPSHOT_ID.fullmatch(snapshot_id):
            raise SnapshotNotFound(snapshot_id)
        return f"snapshots/{snapshot_id}/{name}"

    def _read(self, snapshot_id: str, name: str) -> bytes:
        try:
            return self.backend.read(self._key(snapshot_id, name))
        except ObjectMissing as e:
            raise SnapshotNotFound(snapshot_id) from e

    def manifest_bytes(self, snapshot_id: str) -> bytes:
        """manifest.json exactly as stored (uncached), for digest verification."""
        return self._read(snapshot_id, "manifest.json")

    def exists(self, snapshot_id: str) -> bool:
        try:
            self.load(snapshot_id)
        except SnapshotNotFound:
            return False
        return True

    def load(self, snapshot_id: str) -> SnapshotFiles:
        with self._lock:
            hit = self._cache.get(snapshot_id)
            if hit is not None:
                self._cache.move_to_end(snapshot_id)
                return hit
        # manifest.json is written last; without it the snapshot is incomplete.
        manifest = json.loads(self._read(snapshot_id, "manifest.json"))
        files = SnapshotFiles(manifest,
                              json.loads(self._read(snapshot_id, "callgraph.json")),
                              json.loads(self._read(snapshot_id, "call_sites.json")))
        with self._lock:
            self._cache[snapshot_id] = files
            while len(self._cache) > CACHE_SNAPSHOTS:
                self._cache.popitem(last=False)
        return files

    def manifest_paths(self, snapshot_id: str) -> set[str]:
        return {f["path"] for f in self.load(snapshot_id).manifest["files"]}

    def _manifest_sha256(self, snapshot_id: str, path: str) -> str | None:
        for f in self.load(snapshot_id).manifest["files"]:
            if f["path"] == path:
                return f["sha256"]
        return None

    # discovery.source.read
    def read_source(self, snapshot_id: str, path: str, start_line: int, end_line: int) -> dict:
        if not (1 <= len(path.encode()) <= MAX_PATH_BYTES) or ".." in path.split("/") or path.startswith("/"):
            raise ReadRejected("path")
        if start_line < 1 or not (start_line <= end_line <= start_line + MAX_LINES - 1):
            raise ReadRejected("line range")
        want = self._manifest_sha256(snapshot_id, path)
        if want is None:
            raise ReadRejected("path not in snapshot manifest")
        data = self._read(snapshot_id, "src/" + path)
        # The object must be the file the manifest (and so snapshot_id) covers.
        if hashlib.sha256(data).hexdigest() != want:
            raise SnapshotCorrupt(snapshot_id)
        text = data.decode("utf-8", errors="replace")
        all_lines = text.splitlines()
        lines = all_lines[start_line - 1 : end_line]
        body = {"snapshot_id": snapshot_id, "path": path, "start_line": start_line,
                "end_line": start_line + len(lines) - 1 if lines else start_line - 1,
                "lines": lines, "truncated": False}
        return _fit(body, "lines")

    # discovery.callgraph.read
    def read_callgraph(self, snapshot_id: str, symbol: str, depth: int) -> dict:
        if not (1 <= len(symbol.encode()) <= MAX_SYMBOL_BYTES):
            raise ReadRejected("symbol")
        if not 1 <= depth <= MAX_DEPTH:
            raise ReadRejected("depth")
        graph = self.load(snapshot_id).callgraph
        if symbol not in graph:
            raise ReadRejected("symbol not in snapshot")
        edges: dict[str, list[str]] = {}
        queue = deque([(symbol, 0)])
        while queue:
            sym, level = queue.popleft()
            if sym in edges or level >= depth:
                continue
            callees = graph.get(sym, [])
            edges[sym] = list(callees)
            for c in callees:
                if c in graph:
                    queue.append((c, level + 1))
        body = {"snapshot_id": snapshot_id, "symbol": symbol, "depth": depth,
                "edges": [{"symbol": k, "callees": v} for k, v in edges.items()], "truncated": False}
        return _fit(body, "edges")


def _size(body: dict) -> int:
    return len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode())


def _fit(body: dict, key: str) -> dict:
    """Drop trailing items until the JSON response is within 64KiB."""
    items = body[key]
    while items and _size(body) > RESPONSE_LIMIT:
        body["truncated"] = True
        items.pop()
        if key == "lines":
            body["end_line"] = body["start_line"] + len(items) - 1
    if _size(body) > RESPONSE_LIMIT:
        raise ReadRejected("response too large")
    return body
