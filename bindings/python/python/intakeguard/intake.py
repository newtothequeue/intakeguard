"""Framework-neutral intake helpers shared by the LangChain and LlamaIndex integrations.

Everything security-relevant lives here once, so every integration behaves the same:
- `checked_read()`: open only a regular file (never block on a FIFO; optionally refuse symlinks), read
  it once through IntakeGuard's streaming API (maxBytes enforced while reading), and keep exactly the bytes
  that were inspected.
- `allowed()`: the only bytes that may be handed on (`Report.safe_bytes()`), plus their MIME type.
- `work_file()`: a private (mkdtemp + O_EXCL + 0600) file named for that MIME type
  (holiday.webp -> holiday.jpg), removed afterwards unless kept.
- `walk_inbox()`: the files of a directory, never leaving it: symlinks are skipped unless
  follow_symlinks=True, and targets outside the directory are skipped unless allow_outside=True too.
- `FileResult`: one audit record per file (loaded / rejected / no-loader / skipped-*).

IntakeGuard checks files against a declared policy. It is not malware scanning and not a prompt-injection
defense; see spec/format-guarantees.md for what a verdict does and does not mean.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional, Union

from . import Policy, Rejected, Report, sanitize

#: File extension written for each output MIME type.
EXTENSIONS: dict[str, str] = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "application/pdf": ".pdf",
}
_EXT_ALIASES = {".jpeg": ".jpg", ".jpe": ".jpg", ".jfif": ".jpg"}

#: Metadata keys added to every document (also excluded from embeddings / LLM context where supported).
METADATA_KEYS = (
    "intakeguard_verdict", "intakeguard_reason_codes", "intakeguard_warnings", "intakeguard_original_sha256",
    "intakeguard_detected_mime", "intakeguard_output_mime", "intakeguard_output_sha256",
    "intakeguard_transformations", "intakeguard_policy_digest", "intakeguard_engine", "intakeguard_work_path",
)


class IntakeGuardRejected(Rejected):
    """The file was rejected (or errored). `report` carries the full IntakeGuard report."""


class NoLoaderConfigured(ValueError):
    """IntakeGuard allowed the file, but no downstream loader/reader was given for its (output) MIME type."""


class NotARegularFile(OSError):
    """The path is a symlink (with follow_symlinks=False), a FIFO, a device or a directory."""


def as_policy(policy: Union[Policy, str, dict]) -> Policy:
    return policy if isinstance(policy, Policy) else Policy(policy)


def output_name(original_name: str, mime: str) -> str:
    """The file name to use for bytes of type `mime`.

    Keeps the original stem and replaces the extension when it doesn't match the MIME type, so a
    later re-check doesn't fail with TYPE_MISMATCH_EXTENSION (e.g. photo.webp -> photo.jpg).
    """
    want = EXTENSIONS.get(mime)
    if want is None:
        raise ValueError(f"no extension known for {mime!r}")
    p = Path(original_name)
    have = _EXT_ALIASES.get(p.suffix.lower(), p.suffix.lower())
    return p.name if have == want else p.stem + want


class _Tee:
    """File wrapper for the streaming API that keeps exactly the bytes IntakeGuard pulled."""

    def __init__(self, f):
        self.f, self.buf = f, bytearray()

    def read(self, n: int = -1) -> bytes:
        b = self.f.read(n)
        self.buf += b
        return b


def open_regular(path: Union[str, os.PathLike], follow_symlinks: bool = True):
    """Open for binary reading, only if it is a regular file. Never blocks on a FIFO."""
    path = os.fspath(path)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    if not follow_symlinks:
        if os.path.islink(path):
            raise NotARegularFile(f"{path}: is a symlink")
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        if not follow_symlinks and os.path.islink(path):
            raise NotARegularFile(f"{path}: is a symlink") from e
        raise
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise NotARegularFile(f"{path}: not a regular file")
    return os.fdopen(fd, "rb")


def checked_read(path: Union[str, os.PathLike], policy: Policy, *, claimed_mime: Optional[str] = None,
                 follow_symlinks: bool = True) -> tuple[Report, bytes]:
    """sanitize() over one streaming read. Returns the report and exactly the bytes inspected."""
    with open_regular(path, follow_symlinks) as f:
        tee = _Tee(f)
        report = sanitize(tee, policy, filename=Path(path).name, mime=claimed_mime)
    return report, bytes(tee.buf)


def allowed(report: Report, original: bytes) -> tuple[str, bytes]:
    """(mime, bytes) that may be handed on; raises IntakeGuardRejected for rejected/error."""
    try:
        data = report.safe_bytes(original)
    except Rejected as e:
        raise IntakeGuardRejected(str(e), report) from None
    d = report.data
    mime = (d.get("output") or {}).get("mime") if d["verdict"] == "transformed" else \
        (d.get("detectedType") or {}).get("mime")
    return mime, data


@contextlib.contextmanager
def work_file(original_name: str, mime: str, data: bytes, *, work_dir: Optional[str] = None,
              keep: bool = False) -> Iterator[str]:
    """A private file holding `data`, named for `mime`. Removed on exit unless `keep`."""
    tmp = tempfile.mkdtemp(prefix="intakeguard-", dir=work_dir)
    path = os.path.join(tmp, output_name(original_name, mime))
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as w:
            w.write(data)
        yield path
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)


def metadata(report: Report, source: str, work_path: Optional[str] = None) -> dict:
    """IntakeGuard fields for a document's metadata (`source` is the caller's path, not the work file)."""
    d = report.data
    out = d.get("output") or {}
    return {
        "source": source,
        "intakeguard_verdict": d["verdict"],
        "intakeguard_reason_codes": list(d.get("reasonCodes", [])),
        "intakeguard_warnings": list(d.get("warnings", [])),
        "intakeguard_original_sha256": d["original"]["sha256"],
        "intakeguard_detected_mime": (d.get("detectedType") or {}).get("mime"),
        "intakeguard_output_mime": out.get("mime"),
        "intakeguard_output_sha256": out.get("sha256"),
        "intakeguard_transformations": [t["id"] for t in d.get("transformations", [])],
        "intakeguard_policy_digest": d["policyDigest"],
        "intakeguard_engine": d["engineVersion"],
        "intakeguard_work_path": work_path,
    }


@dataclass
class FileResult:
    """One audit record per directory entry.

    status:
      loaded               IntakeGuard allowed the file and its loader/reader produced `documents` documents
      rejected             verdict rejected or error; nothing was loaded
      no-loader            IntakeGuard allowed it, but no loader/reader is configured for its (output) type
      skipped-symlink      a symlink (or under a symlinked directory) and follow_symlinks is False
      skipped-outside      resolves outside the inbox and allow_outside is False
      skipped-not-regular  a FIFO, device or other non-regular file
    `report` is None for the skipped-* statuses (IntakeGuard never read the file).
    """
    path: str
    status: str
    report: Optional[Report] = None
    documents: int = 0


def _gate(p: Path, inbox: Path, root: Path, follow_symlinks: bool, allow_outside: bool) -> Optional[str]:
    """None if `p` may be read, "dir" for directories, else the skipped-* status."""
    cur = inbox
    for part in p.relative_to(inbox).parts:
        cur = cur / part
        if cur.is_symlink() and not follow_symlinks:
            return "skipped-symlink"
    try:
        real = p.resolve(strict=True)
    except OSError:
        return "skipped-not-regular"  # dangling link or vanished file
    if real != root and root not in real.parents and not allow_outside:
        return "skipped-outside"
    try:
        mode = os.stat(p).st_mode
    except OSError:
        return "skipped-not-regular"
    if stat.S_ISDIR(mode):
        return "dir"
    return None if stat.S_ISREG(mode) else "skipped-not-regular"


def walk_inbox(inbox: Union[str, os.PathLike], *, glob: str = "*", recursive: bool = False,
               follow_symlinks: bool = False, allow_outside: bool = False) -> Iterator[tuple[Path, Optional[str]]]:
    """(path, None) for each file that may be read, (path, "skipped-...") for each that may not."""
    if allow_outside and not follow_symlinks:
        raise ValueError("allow_outside=True requires follow_symlinks=True")
    inbox = Path(inbox)
    root = inbox.resolve(strict=True)
    entries = sorted(inbox.rglob(glob) if recursive else inbox.glob(glob))
    for p in entries:
        status = _gate(p, inbox, root, follow_symlinks, allow_outside)
        if status != "dir":
            yield p, status
