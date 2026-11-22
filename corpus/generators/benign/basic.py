"""Benign, ordinary files. These guard against false positives."""

from _lib import JPEG_8X8, WEBP_8X8, pdf_build, pdf_simple_objects, png_rgb


def generate() -> dict[str, bytes]:
    link_objs = pdf_simple_objects(page_extra=b"/Annots [6 0 R] ")
    link_objs[6] = (b"<< /Type /Annot /Subtype /Link /Rect [72 700 300 730] /Border [0 0 0] "
                    b"/A << /S /URI /URI (https://example.com/) >> >>")
    return {
        "benign-png-8x8": png_rgb(8, 8),
        "benign-jpeg-8x8": JPEG_8X8,
        "benign-webp-8x8": WEBP_8X8,
        "benign-pdf-1page": pdf_build(pdf_simple_objects()),
        "benign-pdf-uri-link": pdf_build(link_objs),
    }
