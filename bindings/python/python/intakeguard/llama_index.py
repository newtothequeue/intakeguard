"""LlamaIndex integration: run IntakeGuard *before* your readers.

    from intakeguard import Policy
    from intakeguard.llama_index import IntakeGuardDirectoryReader

    reader = IntakeGuardDirectoryReader(
        "inbox/",
        policy=Policy(open("policy.json").read()),
        readers={"application/pdf": PDFReader()},   # MIME type -> any BaseReader with load_data(path)
    )
    docs = reader.load_data()
    for r in reader.results:                          # one FileResult per file, for your audit log
        ...

Per file (shared with the LangChain integration, see `intakeguard.intake`):
1. Only regular files are opened. The file is read once through IntakeGuard's streaming API, so maxBytes
   is enforced while reading.
2. `sanitize()` under your policy. Your reader only gets `Report.safe_bytes()`, written to a private work
   file named for `output.mime` (holiday.webp -> holiday.jpg):
   - transformed: the new output;
   - accepted: the exact bytes inspected;
   - rejected / error: nothing (`on_reject="raise"` raises `IntakeGuardRejected`; `"skip"` returns []).
3. Every Document gets `intakeguard_*` metadata. Those keys are excluded from embeddings and LLM context by
   default (`exclude_intakeguard_metadata=True`), and `file_path` / `file_name` point at your original
   file, not the work file.

`IntakeGuardDirectoryReader` never leaves its directory by default: symlinks are skipped and targets
outside the directory are skipped; `follow_symlinks=True` / `allow_outside=True` opt in.

**Prefer `IntakeGuardDirectoryReader` over `SimpleDirectoryReader`.** If you must use SimpleDirectoryReader,
pass `**simple_directory_kwargs(reader)`. Its `required_exts` stops SimpleDirectoryReader from reading
other extensions with its own default readers, which would bypass IntakeGuard. SimpleDirectoryReader
applies no symlink or inbox rules of its own.

IntakeGuard checks files against a declared policy. It is not malware scanning and not a prompt-injection
defense; see spec/format-guarantees.md for what a verdict does and does not mean.

Requires `llama-index-core` (pip install "intakeguard[llama-index]").
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional, Union

from llama_index.core.readers.base import BaseReader
from llama_index.core.schema import Document

from . import Policy, Report
from .intake import (EXTENSIONS, METADATA_KEYS, FileResult, NoLoaderConfigured, NotARegularFile,  # noqa: F401
                     IntakeGuardRejected, allowed, as_policy, checked_read, metadata, output_name,
                     walk_inbox, work_file)

#: Extensions IntakeGuard can detect and the policy schema can allow.
SUPPORTED_EXTENSIONS = [".pdf", ".jpg", ".jpeg", ".png", ".webp"]


class IntakeGuardReader(BaseReader):
    """A LlamaIndex file reader that checks each file with IntakeGuard, then delegates to `readers[mime]`."""

    def __init__(self, *, policy: Union[Policy, str, dict], readers: Mapping[str, BaseReader],
                 on_reject: str = "raise", follow_symlinks: bool = True,
                 work_dir: Optional[Union[str, os.PathLike]] = None,
                 exclude_intakeguard_metadata: bool = True):
        if on_reject not in ("raise", "skip"):
            raise ValueError("on_reject must be 'raise' or 'skip'")
        self.policy = as_policy(policy)
        self.readers = dict(readers)
        self.on_reject = on_reject
        self.follow_symlinks = follow_symlinks
        self.work_dir = str(work_dir) if work_dir is not None else None
        self.exclude_intakeguard_metadata = exclude_intakeguard_metadata
        #: Report of the most recent file, for audit logging.
        self.last_report: Optional[Report] = None

    def lazy_load_data(self, file: Union[str, os.PathLike], extra_info: Optional[dict] = None,
                       fs: Any = None, claimed_mime: Optional[str] = None, **kwargs: Any) -> Iterator[Document]:
        if fs is not None:
            # SimpleDirectoryReader only passes fs for non-local filesystems. IntakeGuard reads local files.
            raise NotImplementedError("IntakeGuardReader reads local files only (no fsspec filesystem)")
        source = os.fspath(file)
        report, original = checked_read(source, self.policy, claimed_mime=claimed_mime,
                                        follow_symlinks=self.follow_symlinks)
        self.last_report = report
        try:
            mime, safe = allowed(report, original)
        except IntakeGuardRejected as e:
            if self.on_reject == "skip":
                return
            raise IntakeGuardRejected(f"{source}: {e}", report) from None
        reader = self.readers.get(mime)
        if reader is None:
            raise NoLoaderConfigured(f"{source}: no downstream reader configured for {mime}")
        meta = metadata(report, source)
        with work_file(Path(source).name, mime, safe, work_dir=self.work_dir) as work:
            docs = reader.load_data(Path(work), extra_info=dict(extra_info or {}))
            for doc in docs:
                md = dict(doc.metadata)
                # Point path fields back at the caller's file, never the (deleted) work file.
                for k, v in list(md.items()):
                    if isinstance(v, str) and v.startswith(os.path.dirname(work)):
                        md[k] = source if k != "file_name" else Path(source).name
                md.update(meta)
                doc.metadata = md
                if self.exclude_intakeguard_metadata:
                    keys = ("source",) + METADATA_KEYS
                    doc.excluded_embed_metadata_keys = sorted(set(doc.excluded_embed_metadata_keys) | set(keys))
                    doc.excluded_llm_metadata_keys = sorted(set(doc.excluded_llm_metadata_keys) | set(keys))
                yield doc

    def load_data(self, file: Union[str, os.PathLike], extra_info: Optional[dict] = None,
                  **kwargs: Any) -> list[Document]:
        return list(self.lazy_load_data(file, extra_info=extra_info, **kwargs))


def simple_directory_kwargs(reader: IntakeGuardReader) -> dict:
    """kwargs for SimpleDirectoryReader that route every supported extension through `reader` and stop
    SimpleDirectoryReader from reading anything else with its own default readers."""
    return {"file_extractor": {ext: reader for ext in SUPPORTED_EXTENSIONS},
            "required_exts": list(SUPPORTED_EXTENSIONS)}


class IntakeGuardDirectoryReader(BaseReader):
    """Every regular file in a directory through `IntakeGuardReader`. Only allowed files are loaded.

    By default files are only read from inside `input_dir`: symlinks are skipped, and anything that
    resolves outside it is skipped. Opt-ins: `follow_symlinks=True` (targets inside), and
    `allow_outside=True` together with it (targets outside). `results` has one `FileResult` per entry.
    """

    def __init__(self, input_dir: Union[str, os.PathLike], *, policy: Union[Policy, str, dict],
                 readers: Mapping[str, BaseReader], glob: str = "*", recursive: bool = False,
                 follow_symlinks: bool = False, allow_outside: bool = False,
                 work_dir: Optional[Union[str, os.PathLike]] = None, exclude_intakeguard_metadata: bool = True):
        if allow_outside and not follow_symlinks:
            raise ValueError("allow_outside=True requires follow_symlinks=True")
        self.input_dir = Path(input_dir)
        self.glob = glob
        self.recursive = recursive
        self.follow_symlinks = follow_symlinks
        self.allow_outside = allow_outside
        self.reader = IntakeGuardReader(policy=policy, readers=readers, on_reject="skip",
                                     follow_symlinks=follow_symlinks, work_dir=work_dir,
                                     exclude_intakeguard_metadata=exclude_intakeguard_metadata)
        self.results: list[FileResult] = []

    def lazy_load_data(self, *args: Any, **kwargs: Any) -> Iterator[Document]:
        for p, skipped in walk_inbox(self.input_dir, glob=self.glob, recursive=self.recursive,
                                     follow_symlinks=self.follow_symlinks, allow_outside=self.allow_outside):
            if skipped is not None:
                self.results.append(FileResult(str(p), skipped))
                continue
            self.reader.last_report = None
            n, status = 0, "loaded"
            extra = {"file_path": str(p), "file_name": p.name}
            try:
                for doc in self.reader.lazy_load_data(p, extra_info=extra):
                    n += 1
                    yield doc
                r = self.reader.last_report
                if r is not None and r.verdict not in ("accepted", "transformed"):
                    status = "rejected"
            except NoLoaderConfigured:
                status = "no-loader"
            except NotARegularFile as e:
                status = "skipped-symlink" if "symlink" in str(e) else "skipped-not-regular"
            self.results.append(FileResult(str(p), status, self.reader.last_report, n))

    def load_data(self, *args: Any, **kwargs: Any) -> list[Document]:
        return list(self.lazy_load_data())
