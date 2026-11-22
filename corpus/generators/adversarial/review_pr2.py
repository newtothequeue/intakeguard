"""Adversarial fixtures from the independent review of PR #2 (2026-11-21), plus the two builder rules
the builder asked a red-teamer to cover.
"""

import zlib

from _lib import JPEG_8X8, pdf_build, pdf_simple_objects, pdf_stream, png_rgb

JS = b"<< /S /JavaScript /JS (app.alert\\('safefile-corpus'\\);) >>"


def _iccp_bomb(mib: int = 1024) -> bytes:
    """8x8 PNG whose iCCP profile inflates to `mib` MiB (~1 MB on disk). ICC profiles are dropped by
    the transform anyway, so the engine must never inflate this beyond its budget."""
    c = zlib.compressobj(9)
    one = b"\x00" * (1 << 20)
    z = b"".join(c.compress(one) for _ in range(mib)) + c.flush()
    return png_rgb(8, 8, extra_chunks=[(b"iCCP", b"bomb\x00\x00" + z)])


def generate() -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    out["img-bomb-png-iccp"] = _iccp_bomb()

    # Builder rule (PR #1): object sections after the final %%EOF, with no xref covering them.
    # Lenient readers that rebuild the xref may load them. Here the trailing object holds a JS action.
    base = pdf_build(pdf_simple_objects())
    out["pdf-objects-after-final-eof"] = base + b"6 0 obj\n" + JS + b"\nendobj\n"

    # Builder rule (PR #2): stream filters outside the standard set can't be inspected.
    objs = pdf_simple_objects()
    objs[4] = pdf_stream(b"/Filter /SafeFileUnknownDecode ", b"opaque-bytes")
    out["pdf-filter-nonstandard"] = pdf_build(objs)

    # Benign-looking JPEG carrying a full second image after EOI (a common smuggling trick).
    out["jpeg-data-after-eoi"] = JPEG_8X8 + JPEG_8X8
    assert JS and zlib
    return out
