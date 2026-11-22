# DRAFT: launch post (owner review required before posting; it makes security claims)

## Title options
- Show HN: IntakeGuard, a pre-flight check for PDFs and images before they reach your RAG pipeline
- Show HN: Your RAG pipeline extracts text your users can't see. IntakeGuard checks files first

## Post

Most RAG pipelines take an uploaded PDF and hand it straight to a document loader: pypdf, pdfminer, PyMuPDF,
unstructured. The loader's job is to extract text, not to judge the file. Building IntakeGuard, we kept finding
files where the *checker* and the *extractor* see different documents.

The clearest example: put one stray `<` (an unterminated hex string) into a PDF's page content, then some invisible
text after it. A scanner that follows the PDF grammar strictly stops reading at the `<`. pdfminer, the extractor
behind `unstructured` and LangChain's PDFMiner loader, recovers, keeps going, and extracts the invisible
instruction into your context window. pypdf throws; PyMuPDF stops. Three readers, three answers, from one file.

IntakeGuard is a small, local-first library (Rust core, Python API) that runs **before** your loader:

- PDFs: rejects JavaScript and other active actions however they're hidden (object streams, hex-escaped names,
  incremental updates, `/Next` chains, duplicate keys), embedded files, encryption, decompression bombs, and
  malformed structure that readers disagree about. Invisible text gets a warning.
- Images: decodes and re-encodes JPEG/PNG/WebP into new bytes with GPS/EXIF/XMP removed, after checking declared
  dimensions so image bombs never reach a decoder.
- Everything else is rejected. It fails closed.

It drops into LangChain and LlamaIndex as a loader/reader wrapper, and your existing loaders only ever see files
that passed.

How we test it, since "security library" claims are cheap:
- 80+ generated hostile and edge-case files, each cross-checked against qpdf/pikepdf/Pillow, gated on Linux, macOS
  and Windows in CI
- nightly coverage-guided fuzzing of every parser
- differential testing against qpdf and the major text extractors (that's how the `<` case was found)
- a script you can run on your own files to check for false positives, entirely locally

What it is **not**: antivirus, full content disarm (PDFs are checked, not rewritten), or a prompt-injection
defense. The exact guarantees are in one file, `spec/format-guarantees.md`. It's an alpha, and it hasn't had an
external audit yet.

`pip install intakeguard`. Feedback we'd love most: run the false-positive sweep on your own documents and tell us
the summary line, and tell us what your ingestion pipeline looks like.

## Before posting: owner checklist
- [ ] Every claim above still matches `spec/format-guarantees.md` and the current release
- [ ] The `<` example: if spec 0.1.6 has shipped, say "IntakeGuard now rejects these"; if not, say "the next release rejects these"
- [ ] Links work (repo, PyPI, spec, demo)
- [ ] You're around for a few hours after posting to answer questions
