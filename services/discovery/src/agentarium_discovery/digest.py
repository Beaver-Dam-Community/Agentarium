"""Wrapper around the Go CLI packages/canonical/cmd/canonical-digest.

Python never implements JCS or hashing (COMMON "normalization and hashing").

SPEC-QUESTION: the CLI interface is not fixed by COMMON or TASK-02. This
assumes JSON on stdin and the lowercase hex digest on stdout.
"""

from __future__ import annotations

import json
import re
import subprocess
from typing import Protocol

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class DigestError(RuntimeError):
    pass


class Digester(Protocol):
    def digest(self, value: object) -> str: ...


class BytesDigester(Protocol):
    def digest_bytes(self, doc: bytes) -> str: ...


class CanonicalDigestCLI:
    def __init__(self, binary: str = "canonical-digest", timeout: float = 10.0) -> None:
        self.binary = binary
        self.timeout = timeout

    def digest(self, value: object) -> str:
        return self.digest_bytes(json.dumps(value, ensure_ascii=False, allow_nan=False).encode())

    def digest_bytes(self, doc: bytes) -> str:
        """Digest of a stored JSON document as-is (e.g. manifest.json), the same
        computation the Go snapshot writer used for snapshot_id."""
        try:
            proc = subprocess.run([self.binary], input=doc, capture_output=True, timeout=self.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise DigestError(f"canonical-digest failed: {e}") from e
        if proc.returncode != 0:
            raise DigestError(f"canonical-digest exit {proc.returncode}: {proc.stderr.decode(errors='replace').strip()}")
        out = proc.stdout.decode().strip()
        if not _HEX64.fullmatch(out):
            raise DigestError(f"canonical-digest returned {out!r}")
        return out
