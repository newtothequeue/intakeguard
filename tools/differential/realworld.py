#!/usr/bin/env python3
"""Real-file false-positive sweep with independent output checks (ADR 0003, verification role).

Written by a reviewer who did not write the engine. It judges the engine with *independent* tools
(qpdf/pikepdf for PDFs, Pillow for images), never with the engine's own harness.

    python tools/differential/realworld.py ~/Downloads ~/Documents        # your own files
    python tools/differential/realworld.py --sample                        # files found on this machine
    python tools/differential/realworld.py ~/Downloads --json report.json  # machine-readable

Everything runs locally. No file contents or paths leave the machine.

What counts as a problem:
  FALSE POSITIVE  an ordinary file the engine rejects, though the independent tools found nothing wrong
  LEAK            sanitized output still carries metadata (EXIF/XMP/ICC/text chunks/APPn/COM)
  CONTRACT        output identical to the original, hash mismatch, dimension change, failed idempotence,
                  or safe_bytes() misbehaving
  DISAGREE        the engine accepted a file the independent tools flag (encrypted, over the page limit,
                  active content). Worth a look, possibly a bypass

Requires (verification-only, not core deps): intakeguard wheel, Pillow, pikepdf; qpdf is optional.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXT_MIME = {".pdf": "application/pdf", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".png": "image/png", ".webp": "image/webp"}
ACTIVE_S = {"/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/RichMediaExecute", "/Rendition",
            "/Movie", "/Sound", "/GoTo3DView", "/GoToE"}
MAX_FILE = 64 * 1024 * 1024


def find_files(paths: list[str], limit: int) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        p = Path(p).expanduser()
        it = [p] if p.is_file() else (q for q in p.rglob("*") if q.is_file())
        for q in it:
            if q.suffix.lower() in EXT_MIME and os.access(q, os.R_OK):
                try:
                    if 0 < q.stat().st_size <= MAX_FILE:
                        out.append(q)
                except OSError:
                    pass
            if len(out) >= limit:
                return out
    return out


def sample_paths() -> list[str]:
    cands = ["/usr/share", "/usr/lib", "/usr/local/lib", str(Path.home() / "Downloads"),
             str(Path.home() / "Documents"), str(Path.home() / "Pictures")]
    return [c for c in cands if Path(c).exists()]


# ------------------------------------------------------------------ independent PDF reference

def pdf_reference(data: bytes, max_pages: int) -> dict:
    """What independent tools say about a PDF. 'expect' is accept | reject | unknown."""
    import pikepdf
    ref = {"expect": "accept", "why": []}
    if shutil.which("qpdf"):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pdf") as tmp:  # qpdf does not read PDFs from stdin
            tmp.write(data)
            tmp.flush()
            q = subprocess.run(["qpdf", "--check", tmp.name], capture_output=True)
        txt = (q.stdout + q.stderr).decode("utf-8", "replace")
        if "operation succeeded with warnings" in txt:
            # Warnings (linearization hints, duplicate font keys...) aren't a rejection signal. Keep them as
            # notes, because duplicate keys are a parser-differential smell worth seeing.
            warns = sorted({w.split(": ", 2)[-1][:60] for w in txt.splitlines() if w.startswith("WARNING")})
            ref["why"].append("qpdf warnings: " + "; ".join(warns[:2]))
        elif "No syntax or stream encoding errors" not in txt:
            ref["expect"] = "reject"
            ref["why"].append("qpdf: " + (txt.strip().splitlines() or ["errors"])[-1][:80])
    try:
        pdf = pikepdf.open(io.BytesIO(data))
    except pikepdf.PasswordError:
        return {"expect": "reject", "why": ["encrypted"]}
    except Exception as e:  # noqa: BLE001 - any parse failure means "reference says damaged"
        return {"expect": "reject", "why": [f"pikepdf: {type(e).__name__}"]}
    with pdf:
        if pdf.is_encrypted:
            return {"expect": "reject", "why": ["encrypted"]}
        try:
            n = len(pdf.pages)
        except Exception:  # noqa: BLE001
            return {"expect": "reject", "why": ["page tree unreadable"]}
        if n > max_pages:
            ref["expect"] = "reject"
            ref["why"].append(f"{n} pages > {max_pages}")
        found = _active_actions(pdf)
        if found:
            ref["expect"] = "reject"
            ref["why"].append("active: " + ", ".join(sorted(found))[:80])
        root = pdf.Root
        if "/Names" in root and ("/EmbeddedFiles" in root.Names or "/JavaScript" in root.Names):
            ref["expect"] = "reject"
            ref["why"].append("names tree: embedded files / JavaScript")
        if "/AcroForm" in root and "/XFA" in root.AcroForm:
            ref["expect"] = "reject"
            ref["why"].append("XFA")
    return ref


def _active_actions(pdf) -> set[str]:
    """Walk action-bearing places (OpenAction, AA, annotation/outline /A, /Next chains); collect active types."""
    import pikepdf
    found: set[str] = set()
    seen: set = set()

    def action(a):
        while isinstance(a, pikepdf.Dictionary):
            og = a.objgen if a.is_indirect else None
            if og in seen and og is not None:
                return
            if og is not None:
                seen.add(og)
            s = str(a.get("/S")) if "/S" in a else None
            if "/JS" in a or s is None or s in ACTIVE_S:
                found.add(s or "<no /S>")
            nxt = a.get("/Next")
            if isinstance(nxt, pikepdf.Array):
                for x in nxt:
                    action(x)
                return
            a = nxt

    def aa(d):
        if isinstance(d, pikepdf.Dictionary) and "/AA" in d:
            for k in d.AA.keys():
                action(d.AA[k])

    root = pdf.Root
    oa = root.get("/OpenAction")
    if isinstance(oa, pikepdf.Dictionary):
        action(oa)
    aa(root)
    for page in pdf.pages:
        aa(page.obj)
        for annot in page.obj.get("/Annots", []) or []:
            if isinstance(annot, pikepdf.Dictionary):
                if "/A" in annot:
                    action(annot.A)
                aa(annot)
    if "/Outlines" in root:
        stack, n = [root.Outlines.get("/First")], 0
        while stack and n < 10000:
            item = stack.pop(); n += 1
            if not isinstance(item, pikepdf.Dictionary):
                continue
            if "/A" in item:
                action(item.A)
            stack += [item.get("/Next"), item.get("/First")]
    if "/AcroForm" in root:
        for f in root.AcroForm.get("/Fields", []) or []:
            aa(f)
    return found


# ------------------------------------------------------------------ independent image output checks

def image_output_problems(original: bytes, out: bytes, report: dict, engine, policy, src_size) -> list[str]:
    from PIL import Image
    probs: list[str] = []
    if out == original:
        probs.append("CONTRACT: output identical to original")
    if hashlib.sha256(out).hexdigest() != report["output"]["sha256"]:
        probs.append("CONTRACT: output.sha256 mismatch")
    try:
        o = Image.open(io.BytesIO(out)); o.load()
    except Exception as e:  # noqa: BLE001
        return probs + [f"CONTRACT: output does not decode ({type(e).__name__})"]
    if o.getexif():
        probs.append("LEAK: EXIF")
    for k in ("exif", "icc_profile", "xmp", "XML:com.adobe.xmp", "comment"):
        if k in o.info:
            probs.append(f"LEAK: {k}")
    if o.format == "PNG":
        for ch in (b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME", b"iCCP"):
            if ch in out:
                probs.append(f"LEAK: PNG {ch.decode()}")
    if o.format == "JPEG":
        i = 2
        while i < len(out) - 4 and out[i] == 0xFF and out[i + 1] != 0xDA:
            m = out[i + 1]
            seg = struct.unpack(">H", out[i + 2:i + 4])[0]
            if 0xE1 <= m <= 0xEF or m == 0xFE:
                probs.append(f"LEAK: JPEG marker FF{m:02X}")
            i += 2 + seg
    if b"xmpmeta" in out or b"http://ns.adobe.com/xap" in out:
        probs.append("LEAK: XMP packet bytes")
    if src_size and sorted(o.size) != sorted(src_size):
        probs.append(f"CONTRACT: dimensions {src_size} -> {o.size}")
    again = engine.sanitize(out, policy, filename=None, mime=report["output"]["mime"])
    if again.verdict == "rejected" or "IMAGE_METADATA_PRESENT" in again.data["reasonCodes"]:
        probs.append(f"CONTRACT: idempotence ({again.verdict} {again.data['reasonCodes']})")
    return probs


# ------------------------------------------------------------------ main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="files or folders to sweep")
    ap.add_argument("--sample", action="store_true", help="sweep common folders on this machine")
    ap.add_argument("--limit", type=int, default=2000)
    ap.add_argument("--policy", default=str(ROOT / "corpus/policies/strict.json"))
    ap.add_argument("--json", help="write a machine-readable report here (contains file paths: keep local)")
    ap.add_argument("--quiet", action="store_true", help="only print problems and the summary")
    args = ap.parse_args()
    if not args.paths and not args.sample:
        ap.error("give paths, or --sample")

    import intakeguard
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = None  # the engine enforces pixel limits; Pillow only reads headers here
    pol_raw = json.loads(Path(args.policy).read_text())
    policy = intakeguard.Policy(json.dumps(pol_raw))
    max_pages = pol_raw.get("limits", {}).get("maxPdfPages", 100)

    files = find_files(args.paths + (sample_paths() if args.sample else []), args.limit)
    results, counts = [], {"ok": 0, "FALSE POSITIVE": 0, "LEAK": 0, "CONTRACT": 0, "DISAGREE": 0, "ref-reject": 0}
    for f in files:
        data = f.read_bytes()
        mime = EXT_MIME[f.suffix.lower()]
        rep = intakeguard.sanitize(data, policy, filename=f.name, mime=mime)
        d = rep.data
        probs: list[str] = []
        note = ""
        if mime == "application/pdf":
            ref = pdf_reference(data, max_pages)
            note = "; ".join(ref["why"])
            if rep.verdict in ("rejected", "error") and ref["expect"] == "accept":
                det = [c.get("detail", "") for c in d["checks"] if c["status"] == "failed"][:1]
                probs.append(f"FALSE POSITIVE: {d['reasonCodes']} {det}")
            elif rep.verdict == "accepted" and ref["expect"] == "reject":
                probs.append(f"DISAGREE: engine accepted; reference says {note}")
            elif ref["expect"] == "reject":
                counts["ref-reject"] += 1
        else:
            try:
                src = Image.open(io.BytesIO(data))
                src_size, animated = src.size, getattr(src, "is_animated", False)
                ref_ok = True
            except Exception:  # noqa: BLE001
                src_size, animated, ref_ok = None, False, False
            if rep.verdict == "transformed":
                probs += image_output_problems(data, rep.output, d, intakeguard, policy, src_size)
                if rep.safe_bytes() != rep.output:
                    probs.append("CONTRACT: safe_bytes() != output")
            elif rep.verdict == "rejected" and ref_ok and not animated:
                over = src_size and src_size[0] * src_size[1] > pol_raw.get("limits", {}).get("maxImagePixels", 40_000_000)
                if not over:
                    probs.append(f"FALSE POSITIVE: {d['reasonCodes']}")
            elif rep.verdict == "accepted":
                probs.append("CONTRACT: image accepted without re-encode under decode-reencode policy")
        for p in probs:
            counts[p.split(":")[0]] += 1
        if not probs:
            counts["ok"] += 1
        results.append({"file": str(f), "bytes": len(data), "verdict": rep.verdict,
                        "codes": d["reasonCodes"], "problems": probs, "reference": note})
        if probs or not args.quiet:
            mark = "ok " if not probs else "!! "
            print(f"{mark}{rep.verdict:11} {str(f)[-70:]:70} {'; '.join(probs)}")

    total = len(results)
    print(f"\n{total} files | ok {counts['ok']} | false positives {counts['FALSE POSITIVE']} | "
          f"leaks {counts['LEAK']} | contract {counts['CONTRACT']} | disagreements {counts['DISAGREE']} | "
          f"rejected by both engine and reference {counts['ref-reject']}")
    if args.json:
        Path(args.json).write_text(json.dumps({"engine": intakeguard.ENGINE_VERSION, "counts": counts,
                                               "results": results}, indent=1))
    return 1 if (counts["FALSE POSITIVE"] or counts["LEAK"] or counts["CONTRACT"] or counts["DISAGREE"]) else 0


if __name__ == "__main__":
    sys.exit(main())
