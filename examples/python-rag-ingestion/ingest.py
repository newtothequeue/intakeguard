#!/usr/bin/env python3
"""IntakeGuard as a pre-flight check in a Python RAG ingestion pipeline (LangChain).

    python examples/python-rag-ingestion/ingest.py --demo            # build a demo inbox, ingest it
    python examples/python-rag-ingestion/ingest.py INBOX_DIR          # ingest your own files
    python examples/python-rag-ingestion/ingest.py --demo --check     # also assert the expected outcomes

Pipeline, per file:
  IntakeGuard sanitize (policy) -> only allowed bytes -> your loader (PDF text / image reference)
  -> text splitter -> chunks (hand these to your embedder / vector store).

Images that IntakeGuard re-encodes are stored under a name derived from `output.mime`: a lossy WebP becomes
`.jpg`, a lossy WebP with transparency becomes `.png`. Keeping the old extension would make a later
re-check of the stored file fail with TYPE_MISMATCH_EXTENSION.

IntakeGuard checks files against a declared policy; it is not antivirus and not a prompt-injection defense.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from langchain_core.document_loaders import BaseLoader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pypdf import PdfReader

import intakeguard
from intakeguard.langchain import IntakeGuardDirectoryLoader, output_name

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_inbox import HERE, RENAMES, REPO, WANT, build_demo  # noqa: E402


# ---------------------------------------------------------------- downstream loaders (yours go here)

class PdfTextLoader(BaseLoader):
    """One Document per page, text via pypdf. Runs only on bytes IntakeGuard accepted."""

    def __init__(self, path: str):
        self.path = path

    def lazy_load(self):
        for i, page in enumerate(PdfReader(self.path).pages):
            yield Document(page_content=page.extract_text() or "", metadata={"page": i})


class ImageStore:
    """Stores sanitized images (for OCR/captioning later) and returns a reference Document.

    The work file IntakeGuard hands over is already named from `output.mime`, so the stored name has the
    right extension. Name collisions get a numeric suffix.
    """

    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def loader(self, path: str) -> BaseLoader:
        store = self

        class _L(BaseLoader):
            def lazy_load(self):
                src = Path(path)
                dst = store.root / src.name
                n = 1
                while dst.exists():
                    dst = store.root / f"{src.stem}-{n}{src.suffix}"
                    n += 1
                shutil.copyfile(src, dst)
                yield Document(page_content="", metadata={"image_path": str(dst)})

        return _L()


# ---------------------------------------------------------------- pipeline

def run(inbox: Path, out: Path, policy_path: Path) -> dict:
    policy = intakeguard.Policy(policy_path.read_text())
    images = ImageStore(out / "images")
    loaders = {
        "application/pdf": PdfTextLoader,
        "image/jpeg": images.loader,
        "image/png": images.loader,
        "image/webp": images.loader,
    }
    loader = IntakeGuardDirectoryLoader(inbox, policy=policy, loaders=loaders)
    docs = list(loader.lazy_load())

    splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
    chunks = splitter.split_documents([d for d in docs if d.page_content.strip()])

    out.mkdir(parents=True, exist_ok=True)
    audit = []
    for fr in loader.results:
        d = fr.report.data if fr.report else {}
        audit.append({
            "file": Path(fr.path).name,
            "status": fr.status,  # loaded / rejected / no-loader / skipped-*
            "documents": fr.documents,
            "verdict": d.get("verdict"),
            "reasonCodes": d.get("reasonCodes", []),
            "outputMime": (d.get("output") or {}).get("mime"),
            "storedAs": next((Path(x.metadata["image_path"]).name for x in docs
                              if x.metadata.get("source") == fr.path and "image_path" in x.metadata), None),
            "originalSha256": (d.get("original") or {}).get("sha256"),
        })
    (out / "audit.jsonl").write_text("".join(json.dumps(a) + "\n" for a in audit))

    print(f"{'file':28} {'status':16} {'verdict':12} {'stored as / reason codes'}")
    for a in audit:
        detail = a["storedAs"] or ", ".join(a["reasonCodes"]) or "-"
        print(f"{a['file']:28} {a['status']:16} {a['verdict'] or '-':12} {detail}")
    print(f"\n{len(docs)} documents -> {len(chunks)} text chunks ready for embedding; "
          f"images stored in {out / 'images'}; audit log {out / 'audit.jsonl'}")
    return {"docs": docs, "chunks": chunks, "audit": audit, "policy": policy, "inbox": str(inbox)}


def recheck(result: dict) -> list[str]:
    """Re-check every stored image under the same policy. Returns problems (empty = all good)."""
    problems = []
    policy = result["policy"]
    for d in result["docs"]:
        p = d.metadata.get("image_path")
        if not p:
            continue
        b = Path(p).read_bytes()
        r = intakeguard.sanitize(b, policy, filename=Path(p).name)
        if r.verdict not in ("accepted", "transformed"):
            problems.append(f"re-check of stored {Path(p).name}: {r.verdict} {r.data['reasonCodes']}")
    return problems


def check(result: dict) -> None:
    """Assertions for --demo --check (used in CI and as executable documentation)."""
    by = {a["file"]: a for a in result["audit"]}
    want = WANT
    errs = [f"{f}: {by.get(f, {}).get('verdict')} != {v}" for f, v in want.items() if by.get(f, {}).get("verdict") != v]
    errs += [f"{f}: status {by[f]['status']}" for f, v in want.items()
             if f in by and by[f]["status"] != ("rejected" if v == "rejected" else "loaded")]
    if hasattr(Path, "symlink_to") and (Path(result["inbox"]) / "planted-link.pdf").is_symlink() and \
            by.get("planted-link.pdf", {}).get("status") != "skipped-symlink":
        errs.append(f"planted symlink not skipped: {by.get('planted-link.pdf')}")
    renames = RENAMES
    errs += [f"{f} stored as {by[f]['storedAs']}, expected {n}" for f, n in renames.items() if by[f]["storedAs"] != n]
    errs += recheck(result)
    # Why the rename matters: the same JPEG bytes under the old .webp name fail the extension check.
    holiday = next(Path(d.metadata["image_path"]) for d in result["docs"]
                   if d.metadata.get("image_path", "").endswith("holiday.jpg"))
    r = intakeguard.sanitize(holiday.read_bytes(), result["policy"], filename="holiday.webp")
    if "TYPE_MISMATCH_EXTENSION" not in r.data["reasonCodes"] or r.verdict != "rejected":
        errs.append(f"expected TYPE_MISMATCH_EXTENSION for a JPEG kept as .webp, got {r.verdict} {r.data['reasonCodes']}")
    assert output_name("holiday.webp", "image/jpeg") == "holiday.jpg"
    assert output_name("photo.JPEG", "image/jpeg") == "photo.JPEG"
    # Rejected files never reach a loader; accepted PDFs produce text.
    loaded = {Path(d.metadata["source"]).name for d in result["docs"]}
    errs += [f"{f} reached a loader" for f, v in want.items() if v == "rejected" and f in loaded]
    if not any("Hello from the SafeFile corpus" in c.page_content for c in result["chunks"]):
        errs.append("no text extracted from the accepted PDFs")
    if errs:
        print("\nCHECK FAILED:\n  " + "\n  ".join(errs))
        sys.exit(1)
    print("check: all expectations met (verdicts, renames, re-check, TYPE_MISMATCH_EXTENSION without rename)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("inbox", nargs="?", help="directory of files to ingest")
    ap.add_argument("--demo", action="store_true", help="build a demo inbox from corpus/build")
    ap.add_argument("--check", action="store_true", help="assert the demo's expected outcomes")
    ap.add_argument("--out", default=str(HERE / "out"), help="where to store images and the audit log")
    ap.add_argument("--policy", default=str(REPO / "corpus" / "policies" / "strict.json"))
    a = ap.parse_args()
    out = Path(a.out)
    if a.demo:
        shutil.rmtree(out, ignore_errors=True)
        inbox = out / "inbox"
        build_demo(inbox)
    elif a.inbox:
        inbox = Path(a.inbox)
    else:
        ap.error("give an inbox directory or --demo")
    if a.check and not a.demo:
        ap.error("--check only applies to --demo")
    result = run(inbox, out, Path(a.policy))
    if a.check:
        check(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
