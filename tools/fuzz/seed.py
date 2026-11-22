#!/usr/bin/env python3
"""Fill tools/fuzz/corpus/<target>/ with seeds from the generated conformance corpus (corpus/build/).

    make corpus && python tools/fuzz/seed.py

Fixtures are generated, never committed, so seeds aren't committed either. Each fixture goes to the
target for its format (by magic bytes) and to sanitize_any.

If Pillow is installed, small real-encoder variants are added too (progressive/CMYK/grayscale JPEG,
palette/16-bit/alpha PNG, lossy/lossless/alpha/animated WebP), to reach decoder paths the corpus
doesn't. Without Pillow the script is stdlib-only and uses the corpus alone.
"""

import hashlib
import shutil
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "corpus" / "build"
OUT = Path(__file__).resolve().parent / "corpus"
TARGETS = ("sanitize_any", "pdf", "pdf_filters", "png", "jpeg", "webp")


def target_for(b: bytes):
    if b.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if b.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "webp"
    if b"%PDF-" in b[:1024]:
        return "pdf"
    return None


def pillow_variants():
    try:
        import io
        from PIL import Image
    except ImportError:
        return []
    base = Image.new("RGB", (24, 16))
    base.putdata([((x * 11) % 256, (y * 17) % 256, (x * y) % 256) for y in range(16) for x in range(24)])
    rgba = base.convert("RGBA")
    rgba.putalpha(Image.linear_gradient("L").resize((24, 16)))
    out = []

    def save(t, im, fmt, **kw):
        b = io.BytesIO()
        im.save(b, fmt, **kw)
        out.append((t, b.getvalue()))

    save("jpeg", base, "JPEG", quality=80)
    save("jpeg", base, "JPEG", quality=60, progressive=True)
    save("jpeg", base, "JPEG", quality=90, subsampling=0)
    save("jpeg", base.convert("L"), "JPEG")
    save("jpeg", base.convert("CMYK"), "JPEG")
    ex = Image.Exif()
    ex[0x0112] = 6  # orientation: rotate 90 CW
    save("jpeg", base, "JPEG", exif=ex.tobytes())
    save("png", base, "PNG")
    save("png", rgba, "PNG")
    save("png", base.convert("P", palette=Image.ADAPTIVE, colors=16), "PNG")
    save("png", base.convert("L"), "PNG")
    save("png", base.convert("LA"), "PNG")
    save("png", base.convert("I;16"), "PNG")
    save("png", base.convert("1"), "PNG")
    save("webp", base, "WEBP", quality=70)
    save("webp", base, "WEBP", lossless=True)
    save("webp", rgba, "WEBP", quality=70)
    save("webp", rgba, "WEBP", lossless=True)
    save("webp", base, "WEBP", save_all=True, append_images=[rgba.convert("RGB")], duration=100)
    return out


def filter_seeds():
    """pdf_filters inputs: [role, f1, f2, f3] + encoded data, with selectors as in fuzz_targets/pdf_filters.rs.
    Uses the corpus encoders (stdlib only)."""
    sys.path.insert(0, str(ROOT / "corpus" / "generators"))
    from _lib import enc_ascii85, enc_ascii_hex, enc_lzw, enc_run_length

    HEX, A85, RL, LZW, LZW0, FLATE, CRYPT, STOP = 0, 1, 2, 3, 4, 5, 9, 255
    enc = {HEX: enc_ascii_hex, A85: enc_ascii85, RL: enc_run_length, LZW: enc_lzw,
           LZW0: lambda d: enc_lzw(d, early_change=0), FLATE: zlib.compress, CRYPT: lambda d: d}
    text = b"BT /F1 12 Tf 72 720 Td (visible) Tj ET\nBT 3 Tr (hidden) Tj ET\n" * 40
    chains = [[f] for f in enc] + [[A85, FLATE], [HEX, LZW], [FLATE, RL], [RL, LZW0], [CRYPT, HEX, A85], [HEX, A85, RL]]
    out = []
    for role in (0, 1):
        for chain in chains:
            data = text
            for f in reversed(chain):  # the first filter decodes first, so it is applied last
                data = enc[f](data)
            sel = (chain + [STOP, STOP, STOP])[:3]
            out.append(("pdf_filters", bytes([role] + sel) + data))
    return out


def main() -> int:
    if not BUILD.exists():
        sys.exit("corpus/build is missing: run `make corpus` first")
    counts = {}
    for t in TARGETS:
        (OUT / t).mkdir(parents=True, exist_ok=True)
    for f in sorted(p for p in BUILD.rglob("*") if p.is_file()):
        b = f.read_bytes()
        if len(b) > 1 << 20:  # the fuzz policy's maxBytes; bigger seeds only exercise the limit
            continue
        name = hashlib.sha1(b).hexdigest()
        for t in {"sanitize_any", target_for(b)} - {None}:
            dst = OUT / t / name
            if not dst.exists():
                shutil.copyfile(f, dst)
                counts[t] = counts.get(t, 0) + 1
    for t, b in pillow_variants() + filter_seeds():
        name = hashlib.sha1(b).hexdigest()
        # pdf_filters inputs are not files (a 4-byte header + stream data), so they stay in their own target.
        for tt in [t] if t == "pdf_filters" else [t, "sanitize_any"]:
            dst = OUT / tt / name
            if not dst.exists():
                dst.write_bytes(b)
                counts[tt] = counts.get(tt, 0) + 1
    print("seeds added:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none (already seeded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
