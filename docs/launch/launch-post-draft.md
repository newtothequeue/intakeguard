# DRAFT: launch post (owner review required before posting; it makes security claims)

Written for release 0.1.0a1. Claims checked against `spec/format-guarantees.md` (spec 0.1.5) on 2026-11-22.

## Submission
- **Title:** Show HN: IntakeGuard, a pre-flight check for PDFs and images before they reach your RAG pipeline
- **URL:** https://github.com/newtothequeue/intakeguard
- Post the body below as your own first comment straight after submitting.

## Post

Most RAG pipelines take an uploaded PDF and hand it straight to a document loader: pypdf, pdfminer, PyMuPDF,
unstructured. The loader's job is to extract text, not to judge the file. Building IntakeGuard, we kept finding
files where the *checker* and the *extractor* see different documents.

The clearest example: put one stray `<` (an unterminated hex string) into a PDF's page content, then some invisible
text after it. A scanner that follows the PDF grammar strictly stops reading at the `<`. pdfminer, the extractor
behind `unstructured` and LangChain's PDFMiner loader, recovers, keeps going, and extracts the invisible
instruction into your context window. pypdf throws; PyMuPDF stops. Three readers, three answers, from one file.
To be upfront: today's alpha (0.1.0a1) doesn't reject this case yet. The rule is specified, its test files are
written, and it ships in the next release. We found it with the differential tests below, which is why they exist.

IntakeGuard is a small, local-first library (Rust core, Python API) that runs **before** your loader:

- PDFs: rejects JavaScript and other active actions, including when hidden in object streams, hex-escaped names,
  incremental updates, `/Next` chains or duplicate keys. Also rejects embedded files, encryption, decompression
  bombs and structurally malformed files. Suspected invisible text gets a warning (a heuristic).
- Images: decodes and re-encodes JPEG/PNG/WebP into new bytes with EXIF (including GPS)/XMP/ICC removed, after
  checking declared dimensions so pixel bombs never reach the decoder.
- Everything else is rejected. It fails closed.

It drops into LangChain and LlamaIndex as a loader/reader wrapper, so your existing loaders only ever see files
that passed.

How we test it, since "security library" claims are cheap:
- 80 generated hostile and edge-case files, each with a recorded oracle, gated on Linux, macOS and Windows in CI
- nightly coverage-guided fuzzing of every parser
- differential testing against qpdf and the major text extractors
- a script in the repo you can run on your own files to check for false positives, entirely locally

What it is **not**: antivirus, full content disarm (PDFs are checked, not rewritten), or a prompt-injection
defense. The exact guarantees are in one file, `spec/format-guarantees.md`. It's an alpha, and it hasn't had an
external audit yet.

`pip install intakeguard`. The feedback we'd value most: run the false-positive sweep on your own documents and
tell us the summary line, and tell us what your ingestion pipeline looks like.

## Before posting: owner checklist
- [ ] Every claim above still matches `spec/format-guarantees.md` and the current release
- [ ] The `<` example: once spec 0.1.6 has shipped (0.1.0a2), change the "To be upfront" sentences to
      "IntakeGuard now rejects these" and update the fixture count
- [ ] Links work (repo, PyPI, spec)
- [ ] Post on a weekday morning, about 8–10am Pacific (Tuesday to Thursday is best)
- [ ] You're around for a few hours after posting to answer questions
