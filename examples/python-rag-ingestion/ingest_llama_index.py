#!/usr/bin/env python3
"""IntakeGuard as a pre-flight check in a LlamaIndex ingestion pipeline.

    python examples/python-rag-ingestion/ingest_llama_index.py --demo            # build the demo inbox, ingest it
    python examples/python-rag-ingestion/ingest_llama_index.py INBOX_DIR          # ingest your own files
    python examples/python-rag-ingestion/ingest_llama_index.py --demo --check     # also assert the expected outcomes

The same pipeline as ingest.py (LangChain), with LlamaIndex readers and a SentenceSplitter.
Re-encoded images are stored under names derived from `output.mime` (holiday.webp -> holiday.jpg).
IntakeGuard's metadata is attached to every Document but kept out of embeddings and LLM context.

IntakeGuard checks files against a declared policy; it is not antivirus and not a prompt-injection defense.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.readers.base import BaseReader
from llama_index.core.schema import Document, MetadataMode
from pypdf import PdfReader

import intakeguard
from intakeguard.llama_index import IntakeGuardDirectoryReader

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_inbox import HERE, RENAMES, REPO, WANT, build_demo  # noqa: E402


class PdfTextReader(BaseReader):
    """One Document per page via pypdf. Runs only on bytes IntakeGuard accepted."""

    def load_data(self, file, extra_info=None, **kwargs):
        return [Document(text=page.extract_text() or "", metadata={**(extra_info or {}), "page_label": str(i + 1)})
                for i, page in enumerate(PdfReader(str(file)).pages)]


class ImageStoreReader(BaseReader):
    """Copies the sanitized image (already named from output.mime) into a store; returns a reference."""

    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def load_data(self, file, extra_info=None, **kwargs):
        src = Path(file)
        dst = self.root / src.name
        n = 1
        while dst.exists():
            dst = self.root / f"{src.stem}-{n}{src.suffix}"
            n += 1
        shutil.copyfile(src, dst)
        return [Document(text="", metadata={**(extra_info or {}), "image_path": str(dst)})]


def run(inbox: Path, out: Path, policy_path: Path) -> dict:
    policy = intakeguard.Policy(policy_path.read_text())
    images = ImageStoreReader(out / "images")
    readers = {"application/pdf": PdfTextReader(), "image/jpeg": images, "image/png": images, "image/webp": images}
    reader = IntakeGuardDirectoryReader(inbox, policy=policy, readers=readers)
    docs = reader.load_data()
    nodes = SentenceSplitter(chunk_size=512, chunk_overlap=32).get_nodes_from_documents(
        [d for d in docs if d.text.strip()])

    out.mkdir(parents=True, exist_ok=True)
    audit = []
    for fr in reader.results:
        d = fr.report.data if fr.report else {}
        audit.append({
            "file": Path(fr.path).name, "status": fr.status, "documents": fr.documents,
            "verdict": d.get("verdict"), "reasonCodes": d.get("reasonCodes", []),
            "outputMime": (d.get("output") or {}).get("mime"),
            "storedAs": next((Path(x.metadata["image_path"]).name for x in docs
                              if x.metadata.get("source") == fr.path and "image_path" in x.metadata), None),
        })
    (out / "audit.jsonl").write_text("".join(json.dumps(a) + "\n" for a in audit))
    print(f"{'file':28} {'status':16} {'verdict':12} {'stored as / reason codes'}")
    for a in audit:
        print(f"{a['file']:28} {a['status']:16} {a['verdict'] or '-':12} {a['storedAs'] or ', '.join(a['reasonCodes']) or '-'}")
    print(f"\n{len(docs)} documents -> {len(nodes)} nodes ready for embedding; audit log {out / 'audit.jsonl'}")
    return {"docs": docs, "nodes": nodes, "audit": audit, "policy": policy, "inbox": str(inbox)}


def check(result: dict) -> None:
    by = {a["file"]: a for a in result["audit"]}
    errs = [f"{f}: {by.get(f, {}).get('verdict')} != {v}" for f, v in WANT.items() if by.get(f, {}).get("verdict") != v]
    errs += [f"{f}: status {by[f]['status']}" for f, v in WANT.items()
             if f in by and by[f]["status"] != ("rejected" if v == "rejected" else "loaded")]
    if (Path(result["inbox"]) / "planted-link.pdf").is_symlink() and \
            by.get("planted-link.pdf", {}).get("status") != "skipped-symlink":
        errs.append(f"planted symlink not skipped: {by.get('planted-link.pdf')}")
    errs += [f"{f} stored as {by[f]['storedAs']}, expected {n}" for f, n in RENAMES.items() if by[f]["storedAs"] != n]
    for d in result["docs"]:
        p = d.metadata.get("image_path")
        if p:
            r = intakeguard.sanitize(Path(p).read_bytes(), result["policy"], filename=Path(p).name)
            if r.verdict not in ("accepted", "transformed"):
                errs.append(f"re-check of stored {Path(p).name}: {r.verdict} {r.data['reasonCodes']}")
        if "intakeguard_" in d.get_content(metadata_mode=MetadataMode.EMBED):
            errs.append(f"intakeguard metadata leaked into the embedding text of {d.metadata.get('file_name')}")
    if not any("Hello from the SafeFile corpus" in n.get_content() for n in result["nodes"]):
        errs.append("no text extracted from the accepted PDFs")
    if errs:
        print("\nCHECK FAILED:\n  " + "\n  ".join(errs))
        sys.exit(1)
    print("check: all expectations met (verdicts, statuses, renames, re-check, metadata kept out of embeddings)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("inbox", nargs="?")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--out", default=str(HERE / "out-llama-index"))
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
