"""Parser-differential guards: duplicated dictionary keys (found via the realworld.py sweep, 2026-11-21).

qpdf/pikepdf follow 'last occurrence wins'; another parser may take the first. Whichever duplicate the
engine reads, any occurrence that is active must cause rejection. The engine already does this; these
fixtures pin it against regressions.
"""

from _lib import pdf_build, pdf_simple_objects

LAUNCH = b"<< /S /Launch /F (calc.exe) >>"


def generate() -> dict[str, bytes]:
    return {
        # Inert /S first, active /S last (qpdf resolves this to /Launch).
        "pdf-dupkey-s-goto-then-launch": pdf_build(pdf_simple_objects(
            catalog_extra=b"/OpenAction << /S /GoTo /D [3 0 R /Fit] /S /Launch /F (calc.exe) >> ")),
        # Active first, inert last (qpdf resolves this to /GoTo; a first-wins parser sees /Launch).
        "pdf-dupkey-s-launch-then-goto": pdf_build(pdf_simple_objects(
            catalog_extra=b"/OpenAction << /S /Launch /F (calc.exe) /S /GoTo /D [3 0 R /Fit] >> ")),
        # A destination OpenAction first, an active action OpenAction last.
        "pdf-dupkey-openaction-dest-then-launch": pdf_build(pdf_simple_objects(
            catalog_extra=b"/OpenAction [3 0 R /Fit] /OpenAction " + LAUNCH + b" ")),
        # An empty /Names first, a JavaScript names tree last.
        "pdf-dupkey-names-empty-then-js": pdf_build(pdf_simple_objects(
            catalog_extra=b"/Names << >> /Names << /JavaScript << /Names [(a) << /S /JavaScript /JS (1) >>] >> >> ")),
    }
