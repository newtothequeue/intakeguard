"""Benign guards from real-world producers (ADR 0003). These must be accepted.

Each one reproduces the specific construct that caused a false positive in the 2026-11-21 real-file sweep.
"""

from _lib import FONT, pdf_build, pdf_simple_objects


def generate() -> dict[str, bytes]:
    out: dict[str, bytes] = {}

    # LibreOffice / Word: /OpenAction is a destination array (open on page 1), not an action.
    out["benign-pdf-openaction-destination"] = pdf_build(
        pdf_simple_objects(catalog_extra=b"/OpenAction [3 0 R /XYZ null null 0] "))

    # An explicit, inert GoTo action as the OpenAction.
    out["benign-pdf-openaction-goto"] = pdf_build(
        pdf_simple_objects(catalog_extra=b"/OpenAction << /S /GoTo /D [3 0 R /Fit] >> "))

    # pikepdf/qpdf blank pages: a Flate content stream with /Length 0 and no data.
    objs = pdf_simple_objects()
    objs[4] = b"<< /Length 0 /Filter /FlateDecode >>\nstream\n\nendstream"
    out["benign-pdf-empty-flate-stream"] = pdf_build(objs)

    # Pillow Image.save(..., "PDF"): the free-list head (object 0) has generation 65536.
    out["benign-pdf-xref-free-gen-65536"] = pdf_build(pdf_simple_objects(), free_gen=65536)

    # Outline with an inert GoTo plus a Named action (common in generated reports).
    outl = pdf_simple_objects(catalog_extra=b"/Outlines 6 0 R ")
    outl[6] = b"<< /Type /Outlines /First 7 0 R /Last 7 0 R /Count 1 >>"
    outl[7] = (b"<< /Title (Summary) /Parent 6 0 R /A << /S /GoTo /D [3 0 R /Fit] "
               b"/Next << /S /Named /N /FirstPage >> >> >>")
    out["benign-pdf-outline-goto-named"] = pdf_build(outl)
    assert FONT  # keep import used
    return out
