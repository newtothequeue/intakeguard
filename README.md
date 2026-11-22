# IntakeGuard

**A pre-flight check for untrusted PDFs and images, run before they reach your RAG pipeline or app.**

[![status: alpha](https://img.shields.io/badge/status-alpha-orange)](#status-alpha) ·
Apache-2.0 · Python 3.9+ · Linux · macOS · Windows

Your users upload PDFs and images. Then a document loader parses them, text goes into embeddings, and an LLM reads
the result. But the bytes are attacker-controlled:

- PDFs can carry **JavaScript, auto-run actions, embedded files**, and tricks that hide them from naive scanners.
- **Text a human can't see** (invisible render mode, off-page) still gets extracted into your LLM's context.
- Malformed files make document parsers **disagree** about what's in them. A cleverly broken file can show your
  checker one thing and your text extractor another.
- **Compression bombs** turn a 2 MB upload into gigabytes of memory.
- Photos carry **GPS location and device metadata**.

IntakeGuard checks each file against a strict policy **locally, before your loader sees it**. You get back either a
verdict that explains itself, or a **new sanitized copy**. It never hands you the original bytes as if they were safe.

```bash
pip install intakeguard
```

## Quickstart

```python
import intakeguard

policy = intakeguard.Policy({"version": "0.1", "allow": ["application/pdf", "image/jpeg", "image/png", "image/webp"]})

data = open("upload.pdf", "rb").read()
report = intakeguard.sanitize(data, policy, filename="upload.pdf")

report.verdict                 # "accepted" | "transformed" | "rejected" | "error"
report.data["reasonCodes"]     # e.g. ["PDF_ACTIVE_CONTENT"]
clean = report.safe_bytes(data)  # the only bytes to pass on; raises intakeguard.Rejected otherwise
```

- **PDFs** are inspected and either `accepted` unchanged or `rejected` with a reason.
- **JPEG/PNG/WebP** are decoded and re-encoded as **new bytes**, with EXIF, GPS, XMP, ICC and text chunks removed
  (`transformed`). `safe_bytes()` returns the clean copy.
- **Everything else** is rejected (fail closed).

## LangChain and LlamaIndex

```python
from intakeguard.langchain import IntakeGuardDirectoryLoader
from langchain_community.document_loaders import PyPDFLoader   # pip install langchain-community pypdf

loader = IntakeGuardDirectoryLoader("inbox/", policy=policy, loaders={"application/pdf": PyPDFLoader})
docs = loader.load()     # only files IntakeGuard allowed reach PyPDFLoader
loader.results           # per-file audit: loaded / rejected / no-loader / skipped-symlink / ...
```

```python
from intakeguard.llama_index import IntakeGuardDirectoryReader
from llama_index.readers.file import PDFReader   # pip install llama-index-readers-file

reader = IntakeGuardDirectoryReader("inbox/", policy=policy, readers={"application/pdf": PDFReader()})
docs = reader.load_data()  # IntakeGuard audit fields are excluded from embeddings and LLM prompts by default
```

Install the extras with `pip install "intakeguard[langchain]"` or `"intakeguard[llama-index]"`. A complete runnable demo
lives in [`examples/python-rag-ingestion`](examples/python-rag-ingestion) (`python ingest.py --demo`).

## What it checks

| | |
|---|---|
| **Type** | Real format from bytes and structure, not the extension or `Content-Type`; polyglots; disguised executables |
| **Limits** | Bytes (enforced while streaming), pixels, dimensions, pages, objects, decompressed bytes, processing time |
| **PDF active content** | JavaScript, Launch, SubmitForm and other actions, found through OpenAction, page, annotation, outline and form-field triggers and `/Next` chains, inside object streams, behind hex-escaped names, in incremental updates, and with duplicate keys |
| **PDF structure** | Encryption, embedded files, XFA, malformed or truncated files, data after end-of-data markers, decompression bombs, all five standard stream encodings |
| **Hidden text** | Best-effort *warning* for invisible text (render mode 3/7). **Not** a prompt-injection defense |
| **Images** | Dimension bombs (checked before decoding), metadata removal, EXIF orientation applied, transparency kept |

The precise list of what each verdict does and **does not** mean is in
[`spec/format-guarantees.md`](spec/format-guarantees.md). It is the only place IntakeGuard makes claims.

## What it is not

IntakeGuard is **not antivirus**, **not** full content disarm and reconstruction (PDFs are checked, not rewritten),
and **not a prompt-injection defense**. A file that passes contains only what the policy allows; that doesn't make
its *content* trustworthy. Pair it with malware scanning if you need malware scanning.

## How it is tested

- A **conformance corpus** of 80+ hostile and edge-case files, each generated from a script and cross-checked against
  independent tools (qpdf, pikepdf, Pillow). Every build on every platform must match all of them.
- **Coverage-guided fuzzing** of every parser in CI, nightly.
- **Differential testing** against qpdf, plus text extractors (pdfminer, pypdf, PyMuPDF), to catch inputs that
  parsers read differently.
- A **real-file sweep** for false positives: `make realworld PATHS=~/Documents` runs it on your own files, locally.
- Every change is reviewed independently of whoever wrote it; reviews are in
  [`docs/conformance/`](docs/conformance).

## Status: alpha

The policy, report format and reason codes may still change before 1.0. The engine has **not had an external
security audit** yet. Known issues are listed in [CHANGELOG.md](CHANGELOG.md). Please report security issues
privately (see [SECURITY.md](SECURITY.md)), and tell us about your pipeline in Discussions; that shapes what comes next.

## License

Apache-2.0. See [LICENSE](LICENSE).
