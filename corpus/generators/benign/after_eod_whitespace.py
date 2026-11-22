"""False-positive guards for spec 0.1.5 (ADR 0008): PDF whitespace after an end-of-data marker is allowed."""

import zlib

from _lib import enc_ascii85, enc_ascii_hex, enc_lzw, enc_run_length, pdf_build, pdf_raw_stream, pdf_simple_objects

CONTENT = b"BT /F1 24 Tf 72 720 Td (Hello from the SafeFile corpus) Tj ET"
WS = b"\r\n \t\n"


def _pdf(filter_name: bytes, encoded: bytes) -> bytes:
    objs = pdf_simple_objects()
    objs[4] = pdf_raw_stream(b"/Filter " + filter_name + b" ", encoded)
    return pdf_build(objs)


def generate() -> dict[str, bytes]:
    return {
        "benign-pdf-eod-whitespace-runlength": _pdf(b"/RunLengthDecode", enc_run_length(CONTENT) + WS),
        "benign-pdf-eod-whitespace-ascii85": _pdf(b"/ASCII85Decode", enc_ascii85(CONTENT) + WS),
        "benign-pdf-eod-whitespace-asciihex": _pdf(b"/ASCIIHexDecode", enc_ascii_hex(CONTENT) + WS),
        "benign-pdf-eod-whitespace-lzw": _pdf(b"/LZWDecode", enc_lzw(CONTENT) + WS),
        "benign-pdf-eod-whitespace-flate": _pdf(b"/FlateDecode", zlib.compress(CONTENT, 9) + WS),
    }
