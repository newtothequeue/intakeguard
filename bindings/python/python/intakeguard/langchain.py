"""LangChain integration: run IntakeGuard *before* your document loader.

    from intakeguard import Policy
    from intakeguard.langchain import IntakeGuardLoader

    loader = IntakeGuardLoader(
        "upload.pdf",
        policy=Policy(open("policy.json").read()),
        loaders={"application/pdf": MyPdfLoader},   # any (path) -> BaseLoader
    )
    docs = loader.load()

What it does, per file:
1. Reads the file once, through IntakeGuard's streaming API (so `maxBytes` is enforced while reading).
2. `sanitize()` under your policy.
3. Hands your downstream loader only bytes IntakeGuard allows (`Report.safe_bytes()`):
   - transformed: the new output, written to a private work file named for `output.mime`.
     A WebP that became JPEG or PNG is renamed `.jpg`/`.png`.
   - accepted: the exact bytes that were inspected, copied to a private work file (never the path you
     passed, which could change after inspection).
   - rejected / error: nothing. `on_reject="raise"` (the default) raises `IntakeGuardRejected`;
     `on_reject="skip"` yields no documents for that file.
   Only regular files are opened (never blocking on a FIFO). `follow_symlinks=False` refuses a symlink.
   `IntakeGuardDirectoryLoader` by default never reads outside its directory: symlinks are skipped and
   targets outside the directory are skipped; `follow_symlinks=True` / `allow_outside=True` opt in.
4. Adds IntakeGuard fields to every document's metadata under `intakeguard_*`.

This is pre-flight intake checking under a declared policy. It is not malware scanning and not a
prompt-injection defense; see spec/format-guarantees.md for what a verdict does and does not mean.

Requires `langchain-core` (pip install "intakeguard[langchain]").
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterator, Mapping, Optional, Union

from langchain_core.document_loaders import BaseLoader
from langchain_core.documents import Document

from . import Policy, Report
from .intake import (EXTENSIONS, FileResult, NoLoaderConfigured, NotARegularFile, IntakeGuardRejected,  # noqa: F401
                     allowed, as_policy, checked_read, metadata, output_name, walk_inbox, work_file)

LoaderFactory = Callable[[str], BaseLoader]


class IntakeGuardLoader(BaseLoader):
    """Check one file with IntakeGuard, then load only what IntakeGuard allows."""

    def __init__(
        self,
        file_path: Union[str, os.PathLike],
        *,
        policy: Union[Policy, str, dict],
        loaders: Mapping[str, LoaderFactory],
        claimed_mime: Optional[str] = None,
        on_reject: str = "raise",
        work_dir: Optional[Union[str, os.PathLike]] = None,
        keep_work_files: bool = False,
        follow_symlinks: bool = True,
    ):
        if on_reject not in ("raise", "skip"):
            raise ValueError("on_reject must be 'raise' or 'skip'")
        self.file_path = str(file_path)
        self.policy = as_policy(policy)
        self.loaders = dict(loaders)
        self.claimed_mime = claimed_mime
        self.on_reject = on_reject
        self.work_dir = str(work_dir) if work_dir is not None else None
        self.keep_work_files = keep_work_files
        #: False: refuse a symlink as the final path component (O_NOFOLLOW), checked at open time.
        self.follow_symlinks = follow_symlinks
        #: The IntakeGuard report of the last load, for audit logging.
        self.report: Optional[Report] = None
        #: Where the bytes handed to the downstream loader were written (if kept).
        self.work_path: Optional[str] = None

    def lazy_load(self) -> Iterator[Document]:
        report, original = checked_read(self.file_path, self.policy, claimed_mime=self.claimed_mime,
                                        follow_symlinks=self.follow_symlinks)
        self.report = report
        try:
            mime, safe = allowed(report, original)
        except IntakeGuardRejected as e:
            if self.on_reject == "skip":
                return
            raise IntakeGuardRejected(f"{self.file_path}: {e}", report) from None
        factory = self.loaders.get(mime)
        if factory is None:
            raise NoLoaderConfigured(f"{self.file_path}: no downstream loader configured for {mime}")
        with work_file(Path(self.file_path).name, mime, safe, work_dir=self.work_dir,
                       keep=self.keep_work_files) as work:
            if self.keep_work_files:
                self.work_path = work
            meta = metadata(report, self.file_path, work if self.keep_work_files else None)
            for doc in factory(work).lazy_load():
                doc.metadata = {**doc.metadata, **meta, "source": self.file_path}
                yield doc


class IntakeGuardDirectoryLoader(BaseLoader):
    """Every regular file in a directory through `IntakeGuardLoader`. Only allowed files are loaded.

    By default files are only read from inside `path`: symlinks are skipped, and anything that resolves
    outside `path` is skipped (so a link planted in a shared inbox or an extracted archive can't pull
    local files into the index). Both are explicit opt-ins:
      follow_symlinks=True  follow symlinks whose targets are inside `path`
      allow_outside=True    also allow targets outside `path` (requires follow_symlinks=True)
    `results` has one `FileResult` per entry seen.
    """

    def __init__(self, path: Union[str, os.PathLike], *, policy: Union[Policy, str, dict],
                 loaders: Mapping[str, LoaderFactory], glob: str = "*", recursive: bool = False,
                 work_dir: Optional[Union[str, os.PathLike]] = None, keep_work_files: bool = False,
                 follow_symlinks: bool = False, allow_outside: bool = False):
        if allow_outside and not follow_symlinks:
            raise ValueError("allow_outside=True requires follow_symlinks=True")
        self.path = Path(path)
        self.policy = as_policy(policy)
        self.loaders = loaders
        self.glob = glob
        self.recursive = recursive
        self.work_dir = work_dir
        self.keep_work_files = keep_work_files
        self.follow_symlinks = follow_symlinks
        self.allow_outside = allow_outside
        self.results: list[FileResult] = []

    def lazy_load(self) -> Iterator[Document]:
        for p, skipped in walk_inbox(self.path, glob=self.glob, recursive=self.recursive,
                                     follow_symlinks=self.follow_symlinks, allow_outside=self.allow_outside):
            if skipped is not None:
                self.results.append(FileResult(str(p), skipped))
                continue
            ld = IntakeGuardLoader(p, policy=self.policy, loaders=self.loaders, on_reject="skip",
                                work_dir=self.work_dir, keep_work_files=self.keep_work_files,
                                follow_symlinks=self.follow_symlinks)
            n, status = 0, "loaded"
            try:
                for doc in ld.lazy_load():
                    n += 1
                    yield doc
                if ld.report is not None and ld.report.verdict not in ("accepted", "transformed"):
                    status = "rejected"
            except NoLoaderConfigured:
                status = "no-loader"
            except NotARegularFile as e:
                status = "skipped-symlink" if "symlink" in str(e) else "skipped-not-regular"
            self.results.append(FileResult(str(p), status, ld.report, n))
