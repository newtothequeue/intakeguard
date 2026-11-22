"""The demo inbox shared by ingest.py (LangChain) and ingest_llama_index.py (no framework imports)."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

# (corpus fixture id, file name in the inbox)
DEMO = [
    ("benign-pdf-1page", "quarterly-report.pdf"),
    ("benign-pdf-uri-link", "links.pdf"),
    ("benign-pdf-tagged-structelem-attributes", "accessible-memo.pdf"),
    ("pdf-active-openaction-js", "invoice.pdf"),
    ("pdf-evasion-js-in-objstm", "contract.pdf"),
    ("pdf-embedded-file", "attachment.pdf"),
    ("img-meta-jpeg-exif-gps", "phone-photo.jpg"),
    ("benign-webp-lossy-to-jpeg", "holiday.webp"),
    ("benign-webp-lossy-alpha-to-png", "logo.webp"),
    ("type-exe-named-png", "avatar.png"),
    ("polyglot-jpeg-pdf", "scan.jpg"),
]

#: Expected IntakeGuard verdict per demo file.
WANT = {
    "quarterly-report.pdf": "accepted", "links.pdf": "accepted", "accessible-memo.pdf": "accepted",
    "invoice.pdf": "rejected", "contract.pdf": "rejected", "attachment.pdf": "rejected",
    "phone-photo.jpg": "transformed", "holiday.webp": "transformed", "logo.webp": "transformed",
    "avatar.png": "rejected", "scan.jpg": "rejected",
}

#: Expected stored names of re-encoded images (named from output.mime).
RENAMES = {"holiday.webp": "holiday.jpg", "logo.webp": "logo.png", "phone-photo.jpg": "phone-photo.jpg"}


def build_demo(inbox: Path) -> None:
    build = REPO / "corpus" / "build"
    if not build.exists():
        sys.exit("corpus/build is missing: run `make corpus` first")
    inbox.mkdir(parents=True, exist_ok=True)
    for fid, name in DEMO:
        src = next((build / fid).iterdir())
        shutil.copyfile(src, inbox / name)
    # A symlink planted in the inbox, pointing at a file outside it: must never be read.
    outside = inbox.parent / "outside-the-inbox.pdf"
    shutil.copyfile(next((build / "benign-pdf-1page").iterdir()), outside)
    try:
        (inbox / "planted-link.pdf").symlink_to(outside)
    except (OSError, NotImplementedError):
        pass  # platforms without symlinks
