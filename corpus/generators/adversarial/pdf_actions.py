"""Adversarial guards for the action-type rule (ADR 0003) and the narrow xref tolerance.

These prove the relaxation for destinations/GoTo didn't open a bypass. All must be rejected.
"""

from _lib import pdf_build, pdf_incremental_update, pdf_simple_objects

JS = b"<< /S /JavaScript /JS (app.alert\\('safefile-corpus'\\);) >>"


def generate() -> dict[str, bytes]:
    out: dict[str, bytes] = {}

    # Inert-looking GoTo whose /Next chain runs JavaScript (two hops deep, via an indirect object).
    o = pdf_simple_objects(catalog_extra=b"/OpenAction << /S /GoTo /D [3 0 R /Fit] /Next 6 0 R >> ")
    o[6] = b"<< /S /Named /N /FirstPage /Next 7 0 R >>"
    o[7] = JS
    out["pdf-active-goto-next-chain-js"] = pdf_build(o)

    # A /Next cycle with JS inside. The engine must detect the cycle and still find the JS.
    o = pdf_simple_objects(catalog_extra=b"/OpenAction 6 0 R ")
    o[6] = b"<< /S /GoTo /D [3 0 R /Fit] /Next 7 0 R >>"
    o[7] = b"<< /S /JavaScript /JS (app.alert\\(1\\);) /Next 6 0 R >>"
    out["pdf-active-next-cycle-js"] = pdf_build(o)

    # A Rendition action carrying /JS (Rendition is not on the inert allowlist, and /JS forces active anyway).
    out["pdf-active-rendition-js"] = pdf_build(pdf_simple_objects(
        catalog_extra=b"/OpenAction << /S /Rendition /OP 0 /JS (app.alert\\(1\\);) >> "))

    # An inert type that smuggles a /JS key. The rule says any /JS key makes the action active.
    out["pdf-active-goto-with-js-key"] = pdf_build(pdf_simple_objects(
        catalog_extra=b"/OpenAction << /S /GoTo /D [3 0 R /Fit] /JS (app.alert\\(1\\);) >> "))

    # An action dictionary with no /S at all. Unknown means active (fail closed).
    out["pdf-active-action-missing-s"] = pdf_build(pdf_simple_objects(
        catalog_extra=b"/OpenAction << /Type /Action /F (payload) >> "))

    # Page-level /AA (page-open trigger) running JavaScript.
    out["pdf-active-page-aa-js"] = pdf_build(pdf_simple_objects(page_extra=b"/AA << /O " + JS + b" >> "))

    # /Launch as the OpenAction.
    out["pdf-active-launch"] = pdf_build(pdf_simple_objects(
        catalog_extra=b"/OpenAction << /S /Launch /F (calc.exe) >> "))

    # Outline (bookmark) item whose action is JavaScript, and one whose indirect action is /Launch.
    o = pdf_simple_objects(catalog_extra=b"/Outlines 6 0 R ")
    o[6] = b"<< /Type /Outlines /First 7 0 R /Last 7 0 R /Count 1 >>"
    o[7] = b"<< /Title (Click me) /Parent 6 0 R /A " + JS + b" >>"
    out["pdf-active-outline-js"] = pdf_build(o)
    o[7] = b"<< /Title (Click me) /Parent 6 0 R /A 8 0 R >>"
    o[8] = b"<< /S /Launch /F (calc.exe) >>"
    out["pdf-active-outline-launch-indirect"] = pdf_build(o)

    # AcroForm field-level /AA (keystroke trigger) running JavaScript.
    o = pdf_simple_objects(catalog_extra=b"/AcroForm << /Fields [6 0 R] >> ")
    o[6] = b"<< /FT /Tx /T (name) /AA << /K " + JS + b" >> >>"
    out["pdf-active-form-field-aa-js"] = pdf_build(o)

    # The generation-65536 tolerance applies only to object 0. On an in-use entry it is still malformed.
    out["pdf-xref-gen-out-of-range"] = pdf_build(pdf_simple_objects(), entry_gens={3: 65536})

    # The builder-found bypass: a clean revision 1, plus an appended revision with JS whose xref is damaged.
    base = pdf_build(pdf_simple_objects())
    upd = pdf_incremental_update(base, {1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>", 6: JS}, size=7)
    cut = upd.rindex(b"xref") + 12  # inside the second xref section
    out["pdf-evasion-damaged-last-xref"] = upd[:cut]
    return out
