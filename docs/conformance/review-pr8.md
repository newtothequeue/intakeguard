# Independent review of PR #8: spec 0.1.4 legacy PDF decoders (reviewer, 2026-11-22)

## Scope
`core/src/pdf/filters.rs` (+979 lines: ASCIIHex, ASCII85, RunLength, LZW with EarlyChange 0/1, PNG and TIFF
predictors, chains, one shared decompression budget), the new `pdf_filters` fuzz target, and the narrowed
idempotence rule in the fuzz harness.

## Separation of duties
No changes to `spec/`, `corpus/`, `CONTRIBUTING.md`, `docs/adr/` or `core/Cargo.toml` (no new dependency).

## Code review
- **Harness rule** (`tools/fuzz/src/lib.rs`) is **stricter** than before: an output over `maxBytes` must be rejected
  with exactly `LIMIT_BYTES_EXCEEDED` on a second pass; anything within must be accepted or transformed.
- **Predictor parameters are bounded before multiplying** (Columns ≤ 2²⁰, Colors ≤ 32, BPC ∈ {1,2,4,8,16}):
  the product is ≤ 2²⁹, so there is no integer overflow even with release-mode wrapping. Row size is capped at 1 MiB.
- Indirect `/DecodeParms` → `UNSUPPORTED_FEATURE` (fail closed); invalid EarlyChange or Predictor → malformed.
- Every decoded byte is counted against the shared budget at each stage flush.

## Results (Linux x86_64, rebuilt from `d7d3280`)
| Check | Result |
|---|---|
| Reviewer's independent fixture check | **69/69**, and no `accepted` with a skipped check |
| Builder gate | 2/2 (69/69, 0 invariant violations) |
| cargo test / pytest / demo | 36 / 22 / pass |
| `realworld.py` (600 system + 13 producer files) | all OK |
| Blind probes | 25/25 |
| RunLength 128 MiB bomb | rejected `LIMIT_DECOMPRESSED_BYTES_EXCEEDED` in ~200 ms, +0 MiB RSS |

## Differential battery vs qpdf (4,500 PDFs: random 1–3 filter chains, 35% randomly corrupted)
0 engine errors, 0 slow (>500 ms), **0 accepted-with-skipped**. **8 misses** (0.18%): corrupted streams that the
engine `accepted` without the hidden-text warning while qpdf decoded hidden text from them. All 8 were corrupted.

**Root cause:** data after a filter's end-of-data marker. The engine stops at EOD, as the PDF spec says. **qpdf's
RunLength decoder ignores an early EOD byte (128) and keeps decoding**, so it recovers content after it.
For ASCII85 (`~>`), ASCIIHex (`>`), LZW (EOD code) and Flate (end of the zlib stream), qpdf and the engine agree
(both ignore trailing data), but other readers may not. It is the same class of parser differential.

**Impact is confined to the hidden-text heuristic.** Two object-stream attacks using an early RunLength EOD (a
catalog split across EOD, and a JS object only after EOD) were both **rejected** (`STRUCTURE_TRUNCATED`), because
every object in an object stream has to parse completely. There is **no active-content bypass**.

**Recommendation (spec change, owner decision):** treat **non-whitespace data after a filter's end-of-data marker**
inside a stream as `STRUCTURE_MALFORMED`, for every filter. That fails closed on the differential, whichever way
a downstream reader goes. Trailing whitespace/EOL stays allowed (common after Flate data). Re-run `realworld.py`
after implementing, to confirm no false positives.

**Verdict:** merge. The early-EOD rule is a follow-up (spec 0.1.5).

## Correction (2026-11-22)
"8 misses" above was produced by a naive oracle; 7 of the 8 were `3 Tr` inside unclosed string literals, which is
visible text, not hidden text. See the correction in ADR 0008. The early-EOD finding and the PR #8 verdict are unchanged.
