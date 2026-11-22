# Python RAG ingestion with a IntakeGuard pre-flight check (LangChain and LlamaIndex)

IntakeGuard runs **before** your document loader. Each file is checked against a declared policy, and the
loader only ever sees bytes IntakeGuard allows:

| Verdict | What the loader gets |
|---|---|
| `transformed` (images) | the new, re-encoded output, never the original |
| `accepted` (PDFs that pass every check) | a private copy of exactly the bytes that were inspected |
| `rejected` / `error` | nothing; the file is recorded in the audit log |

IntakeGuard checks files against a policy. It is **not** antivirus, not full CDR and not a prompt-injection
defense. See `spec/format-guarantees.md` for exactly what a verdict means.

## Run it

```bash
make corpus
```

```bash
cd bindings/python && maturin build --release -o ../../target/wheels && cd ../..
```

```bash
pip install target/wheels/*.whl -r examples/python-rag-ingestion/requirements.txt
```

```bash
python examples/python-rag-ingestion/ingest.py --demo --check
```

`--demo` builds an inbox from corpus fixtures (benign and hostile PDFs, a GPS-tagged photo, a lossy WebP,
a WebP logo with transparency, an executable named `.png`, a JPEG/PDF polyglot, and a symlink planted in
the inbox that points at a file outside it) and ingests it:

```
file                         status           verdict      stored as / reason codes
accessible-memo.pdf          loaded           accepted     -
attachment.pdf               rejected         rejected     PDF_EMBEDDED_FILE
avatar.png                   rejected         rejected     TYPE_UNKNOWN
contract.pdf                 rejected         rejected     PDF_ACTIVE_CONTENT
holiday.webp                 loaded           transformed  holiday.jpg
invoice.pdf                  rejected         rejected     PDF_ACTIVE_CONTENT
links.pdf                    loaded           accepted     PDF_EXTERNAL_LINK
logo.webp                    loaded           transformed  logo.png
phone-photo.jpg              loaded           transformed  phone-photo.jpg
planted-link.pdf             skipped-symlink  -            -
quarterly-report.pdf         loaded           accepted     -
scan.jpg                     rejected         rejected     TYPE_POLYGLOT
```

To ingest your own files: `python examples/python-rag-ingestion/ingest.py path/to/inbox`.

**LlamaIndex:** `ingest_llama_index.py` is the same pipeline, built with `IntakeGuardDirectoryReader`, LlamaIndex
readers and a `SentenceSplitter`. It produces the same table:

```bash
python examples/python-rag-ingestion/ingest_llama_index.py --demo --check
```

## Using it in your own pipeline

```python
import intakeguard
from intakeguard.langchain import IntakeGuardDirectoryLoader

loader = IntakeGuardDirectoryLoader("inbox/", policy=intakeguard.Policy(open("policy.json").read()),
                                 loaders={"application/pdf": MyPdfLoader, "image/jpeg": MyImageLoader,
                                          "image/png": MyImageLoader})
docs = loader.load()                 # only allowed files reach your loaders
for r in loader.results:             # one FileResult per file, for your audit log
    print(r.path, r.status, r.report.verdict if r.report else None, r.documents)
```

`r.status` is one of:
- `loaded`
- `rejected` (verdict `rejected` or `error`)
- `no-loader` (allowed, but no loader is configured for its type)
- `skipped-symlink`, `skipped-outside`, `skipped-not-regular`

**By default, files are only read from inside the inbox.** Symlinks are skipped, and anything that resolves
outside the inbox is skipped. `follow_symlinks=True` opts in to symlinks whose targets are inside the inbox;
`allow_outside=True`, together with it, also allows targets outside. So a link planted in a shared upload
folder or an extracted archive can't pull local files into your index. FIFOs and devices are skipped
without blocking.

`loaders` maps each MIME type to any `(path) -> BaseLoader`. For one file, use `IntakeGuardLoader`, which
raises `IntakeGuardRejected` (or, with `on_reject="skip"`, yields nothing).

### LlamaIndex

```python
from intakeguard.llama_index import IntakeGuardDirectoryReader

reader = IntakeGuardDirectoryReader("inbox/", policy=policy,
                                 readers={"application/pdf": PDFReader(), "image/png": MyImageReader()})
docs = reader.load_data()            # same inbox rules and FileResult statuses as above
```

- **Readers:** `readers` maps MIME types to any LlamaIndex `BaseReader`. For a single file, use `IntakeGuardReader`.
- **Metadata:** IntakeGuard's `intakeguard_*` metadata is excluded from embeddings and LLM context by default
  (`exclude_intakeguard_metadata=True`). `file_path` and `file_name` point at your original file.
- **Prefer `IntakeGuardDirectoryReader`.** If you use LlamaIndex's `SimpleDirectoryReader`, pass
  `**simple_directory_kwargs(reader)`. Its `required_exts` stops SimpleDirectoryReader from reading other
  extensions with its default readers, which would bypass IntakeGuard. SimpleDirectoryReader applies no symlink
  or inbox rules of its own.

## Output formats change: name files from `output.mime`

Re-encoding can change the format. With the default `outputFormat: same`:
- lossy WebP becomes JPEG;
- lossy WebP with transparency becomes PNG;
- everything else keeps its format.

The loader hands your code a file named for the format actually produced (`holiday.webp` → `holiday.jpg`).
If you store outputs yourself, do the same with `intakeguard.langchain.output_name(name, report.data["output"]["mime"])`.
A JPEG kept under a `.webp` name fails a later re-check with `TYPE_MISMATCH_EXTENSION`, and `--check` shows
that happening.

## What's in the output

- `out/images/`: sanitized images, ready for OCR or captioning;
- `out/audit.jsonl`: one line per file, with status, verdict, reason codes, output MIME, stored name and original sha256;
- text chunks from accepted PDFs, ready for your embedder or vector store (the example only counts them).
