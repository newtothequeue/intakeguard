# ADR 0002 bake-off: native Rust candidate (PyO3)

**Date:** 2026-11-22 · **Engine:** `intakeguard-core/0.0.1-bakeoff` · **Raw data:** `bakeoff-native-rust.json`
**Host:** Linux x86_64, 4 vCPU Intel Xeon @ 2.30 GHz, Python 3.13.18, Rust 1.97 · **Reproduce:** `make bakeoff`

The author of the engine also ran these measurements. It did not set or change any expected
outcome. The verdicts come from `corpus/manifest.jsonl` as committed. **All 27 corpus labels are
still `unreviewed`.** Under the ADR's decision rule ("100% of reviewed fixtures"), there are no
reviewed fixtures yet, so these numbers can't settle the decision on their own.

## What was built

| Piece | Path | Notes |
|---|---|---|
| Core engine | `core/` (~2,100 lines of Rust) | `inspect_bytes()`, `inspect_reader()`; catches panics at the API boundary and returns `error` |
| Python binding | `bindings/python/` (PyO3 0.25, maturin, abi3-py39) | GIL released while running; `CancelToken`; accepts bytes or a file object |
| Harness | `tools/benchmark/bakeoff.py` | Conformance, schema/invariant checks, latency, RSS, cancellation, streams, mutation run |
| Regression tests | `core/tests/regressions.rs` | Includes the bypass found during this run (below) |

Slice coverage: type detection (magic bytes, polyglot screen, extension/claimed-MIME mismatch), byte
limit while streaming, PNG/JPEG/WebP header walks (dimensions checked before any pixel work;
metadata and GPS detection), and PDF. For PDFs it walks the strict xref chain across **every
revision** (tables, xref streams, hybrid `/XRefStm`, `/Prev`), checks that every xref offset holds
the object it claims, flags unreferenced objects as malformed, decodes object streams, applies a
file-wide running decompression budget, normalizes hex-escaped names, scans for active content,
embedded files, links and hidden text (render mode 3/7), checks `/Encrypt` in any trailer, and
walks the page tree. Reason codes and severities are read from `spec/reasons.yaml` at compile time.

**Out of scope for this slice:** decode-reencode. The `inspect()` slice has no image encoder.

## Results against the ADR's measures

### Conformance on the 27 seed fixtures

| Score | Result | Meaning |
|---|---|---|
| Pre-transform policy decision | **27 / 27** | The verdict, `detectedMime`, and include/anyOf/exclude codes all match, counting a "transform" decision as `transformed` |
| Report verdict as emitted | **22 / 27** | The 5 misses are exactly the 5 `transformed` image fixtures. The slice can't produce the required output artifact, so it fails closed: `rejected` + `UNSUPPORTED_FEATURE` |
| Report schema + invariants | **0 violations** | Every report validates against `verdict.schema.json` and uses only registered codes. No `accepted` report has a failed or skipped check (except `scanner` when none is configured). Bytes API and stream API agree on every fixture |
| `outputAssertions` | not evaluable | No output artifact exists in an inspect-only slice |

### Latency (in-process via the Python binding; native figures in the JSON)

| Fixture class | p50 | p95 |
|---|---|---|
| Images, type checks, rejects (≤ 12 KB) | 0.010–0.018 ms | 0.011–0.020 ms |
| Small PDFs (1 page, active content, ObjStm, incremental) | 0.022–0.039 ms | 0.030–0.054 ms |
| `pdf-pages-over-limit` (150 pages, 23 KB) | 0.24 ms | 0.27 ms |
| `pdf-bomb-flate` (aborts at the 100 MiB budget) | 21.5 ms | 25.1 ms |

The binding adds about 5–8 µs per call over native Rust.

### Peak RSS and resource bounds (fresh native process per fixture, VmHWM)

| Fixture with `resourceBounds` | Bound | Measured peak | Engine delta | p95 vs time bound |
|---|---|---|---|---|
| `img-bomb-png-dimensions` (10¹⁰ px declared) | 64 MiB | 2.45 MiB | +0.14 MiB | 0.016 ms / 200 ms |
| `img-bomb-jpeg-dimensions` | 64 MiB | 2.44 MiB | +0.16 MiB | 0.019 ms / 200 ms |
| `limit-bytes-over-png` | 32 MiB | 2.46 MiB | +0.13 MiB | — |
| `pdf-bomb-flate` (256 MiB inflate) | 160 MiB | 6.90 MiB | +4.34 MiB | 25 ms / 3000 ms |

Every fixture is within its bounds. The bomb's 4 MiB is the per-stream hidden-text scan window.
Decoded bytes beyond that are counted against the budget but not retained. The provisional
160 MiB bound in the manifest could be lowered a lot; that is a human decision on the oracle.

### Cancellation and deadlines

- `CancelToken.cancel()` from another thread, applied to the flate bomb with the budget lifted to
  1 TiB: the call returns **p50 0.49 ms, p95 1.1 ms, max 1.4 ms** after cancel, with verdict
  `error` (`ENGINE_INTERNAL_ERROR`, detail "cancelled by caller"). Without cancellation that decode
  takes about 60 ms.
- `maxProcessingMs=10` on the same input returns after **11.9 ms** with `LIMIT_TIME_EXCEEDED`.
  Every loop over untrusted data checks the clock about every 64 iterations, and inflate checks
  between 64 KiB output chunks.

### Over-limit streams

For an unbounded file object, the engine pulls **exactly `maxBytes + 1` bytes** and then rejects
with `LIMIT_BYTES_EXCEEDED`: 4,097 bytes for a 4 KiB limit and 10,485,761 bytes for 10 MiB
(12 ms). That is tighter than the `maxBytes + one chunk` guarantee. `detectedType` is null because
nothing past the limit is parsed.

### Mutation run (robustness check, not a fuzzer)

30,000 seeded mutants of the 26 non-empty, non-bomb fixtures, with 1–3 of bit flips, truncation,
insertion, boundary integers or slice duplication each: **0 panics, 0 schema-invalid reports
(sampled 1 in 10), worst case 2.5 ms.** There are 213 accepted mutants. All come from seeds that
are acceptable PDFs, plus 4 that were checked by hand: in 3 the appended malicious revision was
deleted entirely, and in 1 the `/Encrypt` key was destroyed.

**A real bypass was found and fixed during this run.** If the *last* revision's xref, trailer or
`startxref` was damaged, the engine fell back to the previous `%%EOF`. It validated the clean
first revision and accepted the file, while the appended `/OpenAction` JavaScript objects were
still physically present. An xref-reconstructing reader such as qpdf may still load them. The fix:
any `N G obj` header not covered by the xref chain makes the file malformed (fail closed). The
regression test is `damaged_incremental_update_is_not_accepted`. The corpus needs a fixture for
this (see below).

### Packaging effort

| Target | Result | Effort |
|---|---|---|
| Linux x86_64, abi3 (one wheel for CPython ≥ 3.9) | 442–471 KB wheel | `maturin build`, about 12 s release build |
| manylinux2014 (glibc 2.17) | builds; `.so` needs only GLIBC_2.17 | `--zig --compatibility manylinux2014` (pip-installed `ziglang`), about 18 s |
| Linux aarch64 (Graviton) | builds | cross-compiled with zig, about 13 s, no Docker. **Not executed** |
| sdist | builds | `maturin sdist` |
| abi3 on CPython 3.9.25 and 3.13.18 | manylinux2014 wheel passes a smoke test on 3.9; full harness runs on 3.13 | one wheel per platform |
| macOS / Windows / musllinux | **not attempted** (no hosts) | maturin supports them; CI matrix work remains |

### Serverless (Lambda, Cloud Run)

**Not measured.** No cloud account was used. Indirect evidence: the manylinux2014 wheel needs
glibc ≥ 2.17, and Lambda's Amazon Linux 2 and 2023 runtimes provide 2.26 and 2.34. Cloud Run runs
any container. There are no runtime dependencies, about 2.5 MiB baseline RSS natively, and no
threads, files or network access. A real cold-start and memory test on both platforms is still
needed before claiming support.

## Open items that need a human (none applied by this run)

1. **Dependency gate (CONTRIBUTING.md):** `core/` adds `miniz_oxide 0.8` (pure Rust inflate), which
   parses untrusted input. It is used on this branch for the bake-off and needs sign-off before
   merge. The alternative is an in-house bounded inflater. The other dependencies (`sha2`,
   `serde`, `serde_json`) don't parse untrusted bytes. JSON parsing applies only to the policy.
2. **Spec gap: inspect-only `transformed`.** The verdict schema has no way to say "would be
   transformed" without an `output` object. Options: ship the encoder before calling the slice
   conformant, or add a report field or verdict for inspect-only callers (a spec change).
3. **Spec gap: cancellation code.** There is no reason code for a caller-initiated cancel, so it
   is reported as `ENGINE_INTERNAL_ERROR`. A dedicated code (e.g. `ENGINE_CANCELLED`,
   severity error) is a spec change.
4. **Spec gap: `original` for a cut-off stream.** When the stream limit trips, `original.sha256`
   and `bytes` describe the prefix that was read, not the whole input. This should be stated in
   the schema.
5. **Strictness choices the spec doesn't yet state** (all fail closed here, and each needs a
   fixture plus a decision): bytes before `%PDF-` → `TYPE_POLYGLOT`; unreferenced PDF objects →
   `STRUCTURE_MALFORMED`; bytes after PNG `IEND`, JPEG `EOI` or the RIFF container →
   `STRUCTURE_MALFORMED`; Flate checksum errors → malformed; filters other than Flate on content
   streams mark `pdf.hidden-content` as `skipped`; ICC profiles are not counted as metadata.
6. **Red-team fixture to add** (the builder must not label it): a damaged last revision. Take
   `pdf-evasion-incremental-update` and truncate it inside the second xref. Expected: rejected.
7. **Not yet done:** coverage-guided fuzzing (`cargo-fuzz` needs nightly), the napi-rs Node
   binding, and both other candidates (WASM, TypeScript). Without them this is a measurement of
   one candidate, not a comparison.

## Reading against the decision rule

Correctness: the engine matches the human-owned oracle on every fixture it can be judged on.
Resource budgets: every fixture is far inside its bounds. Isolation: limits are enforced inside the
parser, as the ADR's isolation note asks for native builds. The gaps are decode-reencode, the
three spec gaps above, label review, and the other two candidates. Whether this is enough to adopt
the default is the human's call.

---

## Update: spec 0.1.1 (ADR 0003), 2026-11-22

`bakeoff-native-rust.json` now holds the 0.1.1 run on the 44-fixture corpus. Expected outcomes
were not touched.

| | Before (0.1 engine) | After (0.1.1 engine) |
|---|---|---|
| Pre-transform decision | 40 / 44 | **44 / 44** |
| Report verdict as emitted | 35 / 44 | 39 / 44 (the 5 misses are still the `transformed` image fixtures, which need decode-reencode) |
| Invariant violations | 0 | 0 (now also checks that `policyDecision` matches the binding's decision, and that `original.complete=false` never comes with a usable verdict) |
| `--gate` | fails | **passes** |
| Mutation run, 30k cases | — | 0 panics, 0 schema-invalid, worst 0.5 ms |

The four fixtures that changed: `benign-pdf-openaction-destination` and `-openaction-goto` went
from `PDF_ACTIVE_CONTENT` to accepted, and `benign-pdf-empty-flate-stream` and
`-xref-free-gen-65536` went from `STRUCTURE_MALFORMED` to accepted. All 12 adversarial guards
are rejected with the expected codes.

What changed in the engine:
- **Active content is decided by action type.** Actions are found through `/OpenAction`, `/AA`
  (any dict), `/A`, and `/Next` chains (iterative, with cycle detection and a cap of 1,000 steps).
  An action is active unless its `/S` is on the inert allowlist and it has no `/JS`. A destination
  `/OpenAction` is not an action. A non-empty `/JavaScript` name tree, `/XFA`, and `/RichMedia`
  annotations are active. As defense in depth, any `/JS` key, and any dict whose `/S` is a listed
  active type, count as active even when no trigger reaches them.
- **Tolerances**, exactly as narrow as the spec: a Flate stream with `/Length 0` is empty content,
  and generation 65536 is allowed only on the object-0 free entry.
- `ENGINE_CANCELLED` is used for caller cancellation. Reports are version 0.2: `policyDecision`,
  plus `original.complete` (false, with a warning, when a stream limit stopped reading).
- **New fail-closed rule (a judgment call for review):** data after the final `%%EOF` that contains
  `endobj`, `endstream`, `trailer` or `startxref` is `STRUCTURE_MALFORMED`. The 0.1.1 mutation run
  found damaged-last-revision variants whose object headers were mangled (`1 0 ob*`), so the
  unreferenced-object check didn't fire, while their `/S /JavaScript` sections still sat after
  `%%EOF` and drew only a trailing-data warning. Plain trailing text (`pdf-trailing-data`) is still a
  warning. Each case is covered by a regression test. A corpus fixture for this should come from
  red-team, not from the builder.

---

## Update: decode-reencode for JPEG / PNG / WebP, 2026-11-22

`bakeoff-native-rust.json` now holds this run. Expected outcomes were not touched.

**Dependencies** (approved by the project owner on 2026-11-22, per-format and pure Rust):
`png 0.17`, `zune-jpeg 0.4` (decode), `jpeg-encoder 0.6`, `image-webp 0.2`. Our header walk still runs
first, so declared dimension bombs never reach a decoder. Each decoded buffer is sized from the header
and checked against `maxDecompressedBytes` before allocation.

**API:** `inspect_*` never produces an artifact. `sanitize_*` (Python: `intakeguard.sanitize()`) runs the
same checks, re-encodes, then **re-inspects the output under the same policy** before returning it.
A failed re-inspection is `TRANSFORM_FAILED`. A decoder error on corrupt pixel data is
`STRUCTURE_MALFORMED`. Both fail closed.

| | Before | After |
|---|---|---|
| Report verdict as emitted | 39 / 44 | **44 / 44** |
| Pre-transform decision | 44 / 44 | 44 / 44 |
| `outputAssertions` (checked with Pillow + independent byte walks, `tools/benchmark/outputs.py`) | not evaluable | **38 / 38** |
| Invariant violations (now also: output bytes match `output.sha256`, never present unless `transformed`, `inspect()` never transforms) | 0 | 0 |
| Mutation run, 30k cases through `sanitize()` (so decoders and encoders are exercised) | — | 0 panics, 0 invariant violations, 0 `error` |
| `--gate` (now also requires report 44/44 and every output assertion) | — | **passes** |

Lossless outputs (PNG, WebP) are pixel-exact to the original. Sanitizing an output a second time
reproduces it byte-for-byte, and that case is reported as `accepted` (see question 1 below).

### Cost on realistic sizes (synthetic photo-like images, native, one process each)

| Image | In MB | Out MB | ms | Peak RSS MiB | Raised `maxBytes` | Unmodified strict policy |
|---|---|---|---|---|---|---|
| 1920×1080 JPEG | 0.46 | 0.71 | 39 | 10 | transformed | transformed |
| 1920×1080 PNG | 2.96 | 3.79 | 213 | 19 | transformed | transformed |
| 1920×1080 WebP lossy | 0.23 | 3.57 | 67 | 21 | transformed | transformed |
| 1920×1080 WebP lossless | 2.08 | 3.70 | 61 | 23 | transformed | transformed |
| 4000×3000 JPEG | 2.65 | 4.12 | 231 | 44 | transformed | transformed |
| 4000×3000 PNG | 17.2 | 21.9 | 1,255 | 96 | transformed | rejected (input > 10 MiB) |
| 4000×3000 WebP lossy | 1.30 | 20.8 | 413 | 112 | transformed | **error: output > 10 MiB fails re-inspection** |
| 4000×3000 WebP lossless | 12.1 | 21.5 | 400 | 116 | transformed | rejected (input > 10 MiB) |
| 6000×6000, all formats | — | — | 3–156 | 7–52 | rejected: 108 MB of pixels > `maxDecompressedBytes` | same |

### Questions for the spec owner (the engine fails closed on each today)
1. **Byte-identical re-encode.** The schema says a `transformed` output must differ from the original.
   When the input is already exactly what the engine emits, the engine returns `accepted`, with
   `policyDecision: transform` and `image.transform` passed. Is that the intended reading of
   "idempotent"?
2. **Color management.** `format-guarantees.md` says v0.1 "converts to sRGB and drops the profile".
   This build **drops ICC profiles without converting** (CMYK JPEG goes through zune-jpeg's naive
   conversion). Wide-gamut and CMYK images will shift color. Real conversion needs a color-management
   library, which is another dependency gate. Alternatively, the guarantee text could change.
3. **EXIF orientation** is dropped, not applied, so rotated phone photos come out sideways. The spec
   says "if configured", and the policy has no such field yet.
4. **`maxDecompressedBytes` vs `maxImagePixels`.** With the defaults (100 MiB vs 40 MP), an RGB image
   above about 35 MP is rejected even though it is within the pixel limit.
5. **Lossy WebP → lossless WebP** (chosen 2026-11-22) produced outputs 16× larger in this test. A
   12 MP lossy WebP fails under the strict policy because its output exceeds `maxBytes`.
6. **Deadlines inside codecs.** Decoders and encoders can't be interrupted. `maxProcessingMs` and
   cancellation are checked between decode, encode and re-inspection, so a 12 MP PNG (about 1.3 s)
   can overshoot by that much.

**Also fixed (found by this mutation run):** an unknown PDF stream filter name on a content stream
left `pdf.hidden-content` skipped while the file was accepted. Non-standard filter names are now
`UNSUPPORTED_FEATURE`.

---

## Update: spec 0.1.2 (ADR 0004) and the PR #2 review findings, 2026-11-22

`bakeoff-native-rust.json` now holds this run on the 53-fixture corpus of `spec/v0.1.2`. Neither `spec/`
nor the expected outcomes were edited.

| | PR #2 engine on `spec/v0.1.2` | After |
|---|---|---|
| Report verdict as emitted | 48 / 53 (per the reviewer) | **53 / 53** |
| Pre-transform decision | — | **53 / 53** |
| `outputAssertions` | — | **72 / 72** |
| Invariant violations (now also covers `Report.safe_bytes()` on every fixture) | — | 0 |
| `img-bomb-png-iccp` peak RSS (bound 48 MiB) | ~130 MiB | **4.5 MiB**, 3 ms |
| `benign-png-36mp` (bound 640 MiB / 8 s) | rejected | **transformed**, 107 MiB, 269 ms, pixel-exact |
| 30k mutants through `sanitize()` | — | 0 panics, 0 invariant violations |
| `--gate` (full and `--quick`; now also requires every fixture within its `resourceBounds`) | fails | **passes** |

### Review findings (`docs/conformance/review-pr2.md`)
| # | Fix |
|---|---|
| 1 `/A` on a StructElem | `/A` is an action only on annotations (`/Type /Annot`, `/Subtype` + `/Rect`, or listed in an `/Annots` array) and outline items (`/Title` plus a tree link). Active `/S` types and `/JS` keys are still flagged anywhere, so a JavaScript action hidden in StructElem `/A` is still rejected (regression test) |
| 2 Grayscale JPEG | The channel layout comes from the decoder's reported colour space (Luma → 1 channel) |
| 3 iCCP bomb | The PNG decoder now receives a copy with only IHDR, PLTE, tRNS, IDAT and IEND, so iCCP, zTXt and iTXt are never inflated. iCCP and WebP ICCP now count as metadata (`IMAGE_METADATA_PRESENT`) |
| 4 Harness crash | `outputs.py` never raises. Hostile originals that Pillow can't open (like the iCCP bomb) fall back to an independent header byte walk for `same-dimensions`, and every assertion is wrapped. PSNR now uses `ImageChops`/`ImageStat` (fast at 36 MP) |
| 5 `safe_bytes()` | `Report.safe_bytes(original)` returns the output for `transformed`, the original for `accepted` (after checking its sha256 against the report and that it was read completely), and raises `intakeguard.Rejected` otherwise |

### Spec 0.1.2 items
- **Budgets:** pixel buffers are checked against `maxImagePixels`/`maxImageDimension` using the dimensions the decoder reports, before allocation. They are no longer checked against `maxDecompressedBytes`.
- **`maxBytes` is input-only:** the output is re-inspected without the input byte limit.
- **Output format:** lossy WebP → JPEG q90 (`image.format-converted`), and all JPEG output is q90. An alpha channel going to JPEG is composited over white.
- **EXIF orientation** (`images.applyOrientation`, default true) is applied to the pixels for orientations 2–8. On the fixture, the output matches Pillow's `exif_transpose` of the original at 54 dB.
- **Filters:** the abbreviations (`/Fl`, `/AHx`, …) are now non-standard on streams (inline images only), so they are `UNSUPPORTED_FEATURE`.
- **Idempotence** is checked as ADR 0004 #6 defines it.

### Large synthetic images, after
Lossy WebP 12 MP: 1.3 MB → **3.6 MB JPEG** (was 20.8 MB lossless), transformed under the strict policy.
36 MP images are now transformed (JPEG 0.7 s / 125 MiB, lossy WebP 1.4 s / 165 MiB). The 36 MP PNG and
lossless WebP synthetic inputs are 65 MB, so the strict policy rejects them on input size, which is correct.

### Open items for the owner
1. **Image codec crates (ADR 0004 #10).** The owner approved `png 0.17`, `zune-jpeg 0.4`, `jpeg-encoder 0.6` and
   `image-webp 0.2` in the builder session on 2026-11-22 (per-format crates; lossy WebP → lossless was the second
   answer, since superseded by #3). The reviewer couldn't see that, so `CONTRIBUTING.md`'s approved list still needs the
   owner's direct confirmation.
2. **`benign-png-36mp` hash drift.** Its generator produces sha256 `27a7d934…`, 117,508 bytes, both here and on CI's
   ubuntu-latest runner. The manifest records `5c123edc…`, 117,117 bytes, presumably from a different zlib build.
   `make check` (the `spec-and-corpus` job) fails on `spec/v0.1.2` itself for this reason. Fixing it means updating
   that row's `sha256`/`bytes` (corpus-owner work), and ideally a generator that doesn't depend on the zlib build.
