"""T1/T2/T3: type spoofing, disguised executables, unsupported types, polyglots."""

from _lib import GIF_1X1, JPEG_8X8, jpeg_insert_segment, pdf_build, pdf_simple_objects, pe_stub, png_rgb


def generate() -> dict[str, bytes]:
    pdf = pdf_build(pdf_simple_objects())
    # PDF readers accept a %PDF- header within the first 1024 bytes, so a PDF placed in a JPEG
    # COM segment right after SOI makes a file that is valid as both formats.
    polyglot = jpeg_insert_segment(JPEG_8X8, 0xFE, pdf, after_app0=False)
    assert polyglot.find(b"%PDF-") < 1024
    return {
        "type-png-named-jpg": png_rgb(8, 8),
        "type-exe-named-png": pe_stub(),
        "type-zero-bytes": b"",
        "type-gif-unsupported": GIF_1X1,
        "polyglot-jpeg-pdf": polyglot,
    }
