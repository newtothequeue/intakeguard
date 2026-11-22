"""Benign guard for spec 0.1.4 (ADR 0007): an ordinary multi-kilobyte page using LZW, as old PDF producers
(PostScript distillers, scanner software) wrote them. It exercises the LZW 9->12-bit width changes and a
table reset, and must be accepted with no warnings.
"""

from _lib import enc_lzw, pdf_build, pdf_raw_stream, pdf_simple_objects


def _page_text() -> bytes:
    lines = [f"BT /F1 10 Tf 72 {760 - 12 * (i % 60)} Td (Line {i}: quarterly revenue grew in region {i % 7}) Tj ET"
             for i in range(600)]
    return "\n".join(lines).encode()


def generate() -> dict[str, bytes]:
    objs = pdf_simple_objects()
    objs[4] = pdf_raw_stream(b"/Filter /LZWDecode ", enc_lzw(_page_text()))
    return {"benign-pdf-lzw-content": pdf_build(objs)}
