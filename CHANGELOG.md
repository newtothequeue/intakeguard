# Changelog

All notable changes are recorded here. Versions follow semver; until 1.0, minor versions may change the policy,
report format or reason codes (`spec/versioning.md`). **Any change that turns a previously rejected corpus fixture into
an accepted one is a security-relevant change** and is called out explicitly.

## 0.1.0a1 (first public alpha)

### Engine (native Rust, Python bindings, abi3 wheels for Linux x86_64/aarch64, macOS arm64/x86_64, Windows x86_64)
- `inspect()` and `sanitize()` with a declarative JSON policy, a JSON report with stable reason codes and per-check
  status, and `Report.safe_bytes()`. Fail-closed throughout: unknown, malformed, encrypted, ambiguous, or errored
  input is never `accepted`.
- **PDF inspection (spec 0.1.5):** active content found through every action path (OpenAction, page/annotation/
  form-field `/AA`, annotation and outline `/A`, `/Next` chains with cycle detection, names tree), an inert-action
  allowlist (unknown means active), object streams, hex-escaped names, every incremental update, duplicate keys,
  encryption, embedded files, XFA, page/object/decompression limits, best-effort hidden-text warnings, in-house
  decoders for Flate, ASCIIHex, ASCII85, RunLength and LZW (with predictors and chains), and rejection of data after
  any end-of-data marker.
- **Images:** JPEG, PNG and WebP are decoded and re-encoded as new bytes. Dimension and pixel limits are checked
  before decoding. EXIF/XMP/IPTC/ICC/text metadata is removed, EXIF orientation is applied, and transparency is kept
  (lossy WebP with alpha becomes PNG; lossy WebP without alpha becomes JPEG q90). Animated images are rejected.
- Streaming input with `maxBytes` enforced while reading, caller cancellation, and processing-time limits.

### Integrations
- `intakeguard.langchain`: `IntakeGuardLoader`, `IntakeGuardDirectoryLoader`.
- `intakeguard.llama_index`: `IntakeGuardReader`, `IntakeGuardDirectoryReader`. Audit metadata is kept out of embeddings and
  LLM prompts by default.
- Directory loaders never read outside the inbox (symlinks and escapes are skipped unless you opt in) and record a
  per-file audit status.
- `examples/python-rag-ingestion`: runnable LangChain and LlamaIndex demos.

### Verification
- Conformance corpus: 80 generated fixtures with expected outcomes, gated on every platform in CI.
- Coverage-guided fuzzing (cargo-fuzz, 6 targets), nightly.
- Differential tools: `realworld.py` (false-positive sweep on your own files), `filters_vs_qpdf.py`,
  `content_syntax_survey.py`.

### Known issues (alpha)
- **Malformed strings in content streams** (a hex string with non-hex bytes, or an unclosed hex or literal string)
  are not yet rejected. Hidden text after such an error can go unflagged while pdfminer-based loaders extract it.
  The fix is specified (spec 0.1.6, ADR 0009) and lands in the next release.
- **Hidden-text detection is a heuristic.** It is a warning, not a guarantee, and not a prompt-injection defense.
- **PDFs are inspected, not sanitized.** A PDF is either accepted unchanged or rejected.
- **Corpus expected outcomes are not yet human-reviewed**, and the engine has not had an external security audit.
- **Directory loaders:** a hard link inside the inbox is treated as a regular file; in recursive mode, an attacker who
  can modify the inbox *during* a load could race a directory swap (`docs/conformance/review-pr3-4.md`).
- **Codec time:** a single image decode/encode cannot be interrupted, so `maxProcessingMs` can be overrun by up to one
  codec call (about 1 s at the default pixel limit). Use a worker process for hard deadlines.
- **Colour:** ICC profiles are dropped and pixels treated as sRGB, so wide-gamut images may shift colour.
- **Formats:** only PDF, JPEG, PNG and WebP. Office files, SVG, archives and everything else are rejected.
