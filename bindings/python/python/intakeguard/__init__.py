"""IntakeGuard inspect() slice (ADR 0002 bake-off). Not a released package; no security claims beyond
spec/format-guarantees.md.

Treat verdict "error" exactly like "rejected". Reports follow report version 0.2 (spec 0.1.1).

- inspect(): every check, never an output artifact. An image the policy would re-encode comes
  back "rejected" (UNSUPPORTED_FEATURE) with policyDecision "transform".
- sanitize(): the same checks, then decode-reencode for JPEG/PNG/WebP. On verdict "transformed",
  use Report.output (new bytes) and never the original.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, BinaryIO, Optional, Union

from ._native import ENGINE_VERSION, STREAM_CHUNK, CancelToken, CompiledPolicy
from ._native import process_bytes as _process_bytes
from ._native import process_stream as _process_stream

__all__ = ["inspect", "sanitize", "Report", "Rejected", "Policy", "CancelToken", "ENGINE_VERSION", "STREAM_CHUNK"]


class Rejected(Exception):
    """Raised by Report.safe_bytes() when nothing may be used. Carries the report."""

    def __init__(self, message: str, report: "Report"):
        super().__init__(message)
        self.report = report


class Policy:
    """A validated policy. Construct once and reuse."""

    def __init__(self, policy: Union[str, dict]):
        self._raw = policy if isinstance(policy, str) else json.dumps(policy)
        self._compiled = CompiledPolicy(self._raw)

    @property
    def digest(self) -> str:
        return self._compiled.digest


@dataclass(frozen=True)
class Report:
    json: str
    decision: str  # accept | transform | reject | error; equals the report's policyDecision
    bytes_read: int
    output: Optional[bytes] = None  # present only when verdict == "transformed"

    @property
    def data(self) -> dict[str, Any]:
        return json.loads(self.json)

    @property
    def verdict(self) -> str:
        return self.data["verdict"]

    @property
    def usable(self) -> bool:
        """True only for verdict == "accepted" (the original may be used). Prefer safe_bytes()."""
        return self.verdict == "accepted"

    def safe_bytes(self, original: Union[bytes, bytearray, None] = None) -> bytes:
        """The only bytes it is safe to pass on.

        - transformed: the sanitized output (never the original)
        - accepted: the original, which must be passed in (the engine never hands it back)
        - rejected / error / anything else: raises Rejected
        """
        v = self.verdict
        if v == "transformed":
            if self.output is None:
                raise Rejected("transformed report without output bytes", self)
            return self.output
        if v == "accepted":
            if original is None:
                raise ValueError("verdict is accepted: pass the original bytes to safe_bytes(original)")
            import hashlib
            if hashlib.sha256(bytes(original)).hexdigest() != self.data["original"]["sha256"] or \
                    self.data["original"].get("complete") is False:
                raise Rejected("original does not match the inspected bytes", self)
            return bytes(original)
        raise Rejected(f"verdict {v}: {', '.join(self.data.get('reasonCodes', []))}", self)


def _run(data, policy, filename, mime, cancel, sanitize: bool) -> Report:
    pol = policy if isinstance(policy, Policy) else Policy(policy)
    if isinstance(data, (bytes, bytearray)):
        r = _process_bytes(data, pol._compiled, filename, mime, cancel, sanitize)
    else:
        r = _process_stream(data, pol._compiled, filename, mime, cancel, sanitize)
    return Report(*r)


def inspect(data: Union[bytes, bytearray, BinaryIO], policy: Union[Policy, str, dict], *,
            filename: Optional[str] = None, mime: Optional[str] = None,
            cancel: Optional[CancelToken] = None) -> Report:
    """Run every check. Never produces an output artifact."""
    return _run(data, policy, filename, mime, cancel, False)


def sanitize(data: Union[bytes, bytearray, BinaryIO], policy: Union[Policy, str, dict], *,
             filename: Optional[str] = None, mime: Optional[str] = None,
             cancel: Optional[CancelToken] = None) -> Report:
    """Run every check, then decode-reencode images when the policy says so.

    verdict "transformed": use report.output only. "accepted": the original may be used.
    "rejected"/"error": use nothing.
    """
    return _run(data, policy, filename, mime, cancel, True)
