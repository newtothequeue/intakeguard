"""Benign guards from the independent review of PR #2 (2026-11-21). These must not be rejected.

Each one reproduces a false positive found in the reviewer's real-file sweep.
"""

from _lib import pdf_build, pdf_simple_objects

# 8x8 single-channel (grayscale) baseline JPEG, frozen from a standard encoder. Scanned documents
# are commonly grayscale, so this is a frequent real-world input for RAG pipelines.
JPEG_GRAY_8X8 = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb00430006040506050406060506070706080a100a0a09090a140e0f0c1017141818171416161a1d251f1a1b231c1616202c20232627292a29191f2d302d283025282928ffc0000b080008000801011100ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffda0008010100003f002bffd9"
)


def generate() -> dict[str, bytes]:
    # Tagged (accessible) PDF as written by LibreOffice: StructElem /A holds layout ATTRIBUTES,
    # not an action. /A is an action only on annotations and outline items (format-guarantees.md#pdf).
    objs = pdf_simple_objects(
        catalog_extra=b"/MarkInfo << /Marked true >> /StructTreeRoot 6 0 R ",
        page_extra=b"/StructParents 0 ",
        content=b"/P << /MCID 0 >> BDC BT /F1 24 Tf 72 720 Td (Accessible report) Tj ET EMC",
    )
    objs[6] = b"<< /Type /StructTreeRoot /K [7 0 R] /ParentTree 9 0 R >>"
    objs[7] = b"<< /Type /StructElem /S /Document /P 6 0 R /K [8 0 R] >>"
    objs[8] = (b"<< /Type /StructElem /S /P /P 7 0 R /Pg 3 0 R /K [0] "
               b"/A << /O /Layout /Placement /Block >> >>")
    objs[9] = b"<< /Nums [0 [8 0 R]] >>"
    return {
        "benign-jpeg-grayscale-8x8": JPEG_GRAY_8X8,
        "benign-pdf-tagged-structelem-attributes": pdf_build(objs),
    }
