"""Independent checks of sanitized image outputs (manifest `outputAssertions`).

Decoding and metadata checks use Pillow plus byte-level walks written here, not the engine's own
parsers, so an engine bug can't vouch for itself.

Definitions used for the assertions the manifest schema names but doesn't define:
- decodes: Pillow opens and fully loads the output.
- same-dimensions: the output's Pillow size equals the original's Pillow size.
- reinspect-passes: sanitize(output) under the same policy gives verdict transformed (or accepted)
  with no IMAGE_METADATA_PRESENT / IMAGE_GPS_PRESENT.
- idempotent (spec 0.1.2): sanitize(output) is never rejected and reports no
  IMAGE_METADATA_PRESENT; for lossless outputs a second transformed output is pixel-identical.
- same-dimensions: compared against Pillow's size of the original, or, when Pillow can't open a
  hostile original, against the header dimensions from an independent byte walk.

Every check is wrapped: a hostile original or output is recorded as a failure, never a crash.
- differs-from-original: output sha256 != original sha256.
"""

from __future__ import annotations

import hashlib
import io
import math
import struct

from PIL import Image

XMP_NS = b"http://ns.adobe.com/xap/1.0/"


def _pil(b: bytes) -> Image.Image:
    im = Image.open(io.BytesIO(b))
    im.load()
    return im


def jpeg_segments(b: bytes) -> list[int]:
    """Markers of the segments before the first SOS."""
    out, p = [], 2
    while p + 4 <= len(b):
        if b[p] != 0xFF:
            raise ValueError(f"no marker at {p}")
        m = b[p + 1]
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
            p += 2
            continue
        out.append(m)
        if m in (0xDA, 0xD9):
            break
        p += 2 + struct.unpack(">H", b[p + 2:p + 4])[0]
    return out


def png_chunks(b: bytes) -> list[bytes]:
    out, p = [], 8
    while p + 8 <= len(b):
        n = struct.unpack(">I", b[p:p + 4])[0]
        out.append(b[p + 4:p + 8])
        p += 12 + n
    return out


def webp_chunks(b: bytes) -> list[bytes]:
    out, p = [], 12
    while p + 8 <= len(b):
        n = struct.unpack("<I", b[p + 4:p + 8])[0]
        out.append(b[p:p + 4])
        p += 8 + n + (n & 1)
    return out


def _has_exif(b: bytes, im: Image.Image) -> bool:
    return b"Exif\x00\x00" in b or len(im.getexif()) > 0 or (
        b[:8] == b"\x89PNG\r\n\x1a\n" and b"eXIf" in png_chunks(b)) or (
        b[:4] == b"RIFF" and b"EXIF" in webp_chunks(b))


def header_dims(b: bytes) -> tuple[int, int] | None:
    """Declared (width, height) from the format header, by a bounds-checked byte walk that never
    raises. Independent of both the engine and Pillow, so it works on hostile originals too."""
    try:
        if b[:8] == b"\x89PNG\r\n\x1a\n" and b[12:16] == b"IHDR":
            return struct.unpack(">II", b[16:24])
        if b[:2] == b"\xff\xd8":
            p = 2
            while p + 4 <= len(b) and b[p] == 0xFF:
                m = b[p + 1]
                if m in (0x01,) or 0xD0 <= m <= 0xD7:
                    p += 2
                    continue
                n = struct.unpack(">H", b[p + 2:p + 4])[0]
                if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
                    h, w = struct.unpack(">HH", b[p + 5:p + 9])
                    return (w, h)
                if m in (0xDA, 0xD9):
                    return None
                p += 2 + n
            return None
        if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
            ty, body = b[12:16], b[20:]
            if ty == b"VP8X":
                return (1 + int.from_bytes(body[4:7], "little"), 1 + int.from_bytes(body[7:10], "little"))
            if ty == b"VP8L":
                v = int.from_bytes(body[1:5], "little")
                return ((v & 0x3FFF) + 1, ((v >> 14) & 0x3FFF) + 1)
            if ty == b"VP8 ":
                return (struct.unpack("<H", body[6:8])[0] & 0x3FFF, struct.unpack("<H", body[8:10])[0] & 0x3FFF)
    except (struct.error, IndexError, ValueError):
        return None
    return None


def try_pil(b: bytes):
    """(image, None) or (None, error). Hostile originals must not abort the judge."""
    try:
        return _pil(b), None
    except Exception as e:  # noqa: BLE001 -- any decoder failure is data, not a harness crash
        return None, f"{type(e).__name__}: {str(e)[:120]}"


def psnr(a: Image.Image, b: Image.Image) -> float:
    from PIL import ImageChops, ImageStat
    a, b = a.convert("RGB"), b.convert("RGB")
    if a.size != b.size:
        return float("nan")
    diff = ImageChops.difference(a, b)
    if diff.getbbox() is None:
        return math.inf
    mse = sum(v * v for v in ImageStat.Stat(diff).rms) / 3
    return 10 * math.log10(255 ** 2 / mse)


def check(assertions: list[str], original: bytes, out: bytes, out_mime: str, resanitize) -> tuple[list[str], dict]:
    """Returns (failures, measurements). `resanitize(bytes) -> Report`. Never raises."""
    from PIL import ImageOps
    bad: list[str] = []
    info: dict = {}
    im, err = try_pil(out)
    if im is None:
        return [f"decodes: Pillow failed on the output: {err}"], info
    orig, oerr = try_pil(original)
    if orig is None:
        info["originalUndecodableByPillow"] = oerr
    orig_dims = orig.size if orig is not None else header_dims(original)
    info["outBytes"] = len(out)
    info["outDims"] = list(im.size)
    lossless = out_mime == "image/png" or (out_mime == "image/webp" and b"VP8L" in webp_chunks(out))
    info["lossless"] = lossless
    if orig is not None:
        try:
            upright = ImageOps.exif_transpose(orig)
            info["psnrVsUprightOriginal"] = round(psnr(upright, im), 2) if not lossless else None
            if lossless:
                info["pixelExactVsOriginal"] = upright.convert("RGBA").tobytes() == im.convert("RGBA").tobytes()
        except Exception as e:  # noqa: BLE001
            info["fidelityNotMeasured"] = f"{type(e).__name__}: {str(e)[:120]}"
    for a in assertions:
        try:
            ok = _one(a, original, out, out_mime, im, orig_dims, lossless, resanitize, info)
        except Exception as e:  # noqa: BLE001
            bad.append(f"{a}: check crashed: {type(e).__name__}: {str(e)[:120]}")
            continue
        if ok is None:
            bad.append(f"{a}: unknown assertion")
        elif not ok:
            bad.append(f"{a} failed")
    return bad, info


def _one(a, original, out, out_mime, im, orig_dims, lossless, resanitize, info):
    if a == "decodes":
        return True
    if a == "same-dimensions":
        return orig_dims is not None and tuple(im.size) == tuple(orig_dims)
    if a == "differs-from-original":
        return hashlib.sha256(out).digest() != hashlib.sha256(original).digest()
    if a == "no-exif":
        return not _has_exif(out, im)
    if a == "no-gps":
        return not _has_exif(out, im) or len(im.getexif().get_ifd(0x8825)) == 0
    if a == "no-xmp":
        return XMP_NS not in out and b"XML:com.adobe.xmp" not in out and not (
            out[:4] == b"RIFF" and b"XMP " in webp_chunks(out))
    if a == "no-jpeg-app1-app15":
        return not any(0xE1 <= m <= 0xEF for m in jpeg_segments(out))
    if a == "no-jpeg-com":
        return 0xFE not in jpeg_segments(out)
    if a == "no-png-text-chunks":
        return not ({b"tEXt", b"zTXt", b"iTXt", b"tIME", b"iCCP"} & set(png_chunks(out)))
    if a == "no-png-exif-chunk":
        return b"eXIf" not in png_chunks(out)
    if a == "has-alpha":
        # The output carries an alpha channel, and (when Pillow can read the original) transparency
        # survived: same alpha values as the original wherever the original is not opaque-only.
        if "A" not in im.getbands():
            return False
        alpha = im.getchannel("A")
        info["outAlphaMin"] = alpha.getextrema()[0]
        orig, _ = try_pil(original)
        if orig is not None and "A" in orig.convert("RGBA").getbands():
            oa = orig.convert("RGBA").getchannel("A")
            info["origAlphaMin"] = oa.getextrema()[0]
            if oa.size == alpha.size:
                info["alphaExactVsOriginal"] = oa.tobytes() == alpha.tobytes()
                return info["alphaExactVsOriginal"]
            return oa.getextrema()[0] == 255 or alpha.getextrema()[0] < 255
        return True
    if a == "reinspect-passes":
        d2 = resanitize(out).data
        return d2["verdict"] in ("transformed", "accepted") and not (
            {"IMAGE_METADATA_PRESENT", "IMAGE_GPS_PRESENT"} & set(d2["reasonCodes"]))
    if a == "idempotent":
        # Spec 0.1.2 (ADR 0004 #6): a second sanitize is never rejected and finds no metadata.
        r2 = resanitize(out)
        d2 = r2.data
        info["secondPassVerdict"] = d2["verdict"]
        ok = d2["verdict"] in ("transformed", "accepted") and "IMAGE_METADATA_PRESENT" not in d2["reasonCodes"]
        if ok and d2["verdict"] == "transformed" and lossless:
            im2, _ = try_pil(r2.output)
            ok = im2 is not None and im2.convert("RGBA").tobytes() == im.convert("RGBA").tobytes()
        return ok
    return None
