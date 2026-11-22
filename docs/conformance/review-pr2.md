# Independent review of PRs #1–#2 (reviewer, 2026-11-21)

Written by a reviewer who did not write the engine. It sets corpus expectations; it did not edit `core/`.

## Method
- Rebuilt PR #2 from source.
- Checked outputs independently with Pillow and raw byte or marker scans, without using `tools/benchmark/outputs.py`.
- Probed images with real encoders (Pillow: progressive, CMYK, gray, ICC, 16-bit, palette+tRNS, RGBA, lossy/lossless WebP, EXIF/GPS/XMP/iTXt).
- Probed the decoders with hostile inputs: APNG and animated WebP; zTXt, iTXt and iCCP inflation bombs; a 40 MP all-zero IDAT; bad CRC; data after IEND/EOI.
- Re-ran the ADR 0003 real-file PDF sweep (142 files).

## Confirmed good
- **No metadata survives sanitize.** No EXIF, GPS, XMP, PNG text/eXIf/tIME/iCCP chunks, JPEG APP1–APP15/COM, or planted strings in any output.
- Every output is new bytes, matches `output.sha256` and keeps the input dimensions.
- Lossless sources (PNG, lossless WebP) come back pixel-exact. JPEG re-encode is ~51–52 dB PSNR. CMYK → RGB is visually correct (51 dB against Pillow).
- Animated PNG/WebP → `UNSUPPORTED_FEATURE`. zTXt/iTXt bombs are skipped without inflating (+≤1 MiB).
- The pikepdf empty-Flate and Pillow gen-65536 false positives from ADR 0003 are fixed.
- Both builder rules already behave as their new fixtures expect.

## Findings (all have fixtures; 48/50 match)
| # | Severity | Finding | Fixture |
|---|---|---|---|
| 1 | **High (false positive)** | `/A` on a tagged-PDF `StructElem` (layout attributes) is treated as an action → `PDF_ACTIVE_CONTENT`. The spec scopes `/A` to annotations and outline items only. LibreOffice tags by default, and the same LibreOffice memo from ADR 0003 is still rejected for this reason | `benign-pdf-tagged-structelem-attributes` |
| 2 | **High (false positive)** | Every grayscale JPEG is rejected (`decoder returned N bytes, expected 3N`): the transformer assumes 3 channels | `benign-jpeg-grayscale-8x8` |
| 3 | Medium (DoS / limit bypass) | The PNG decoder inflates `iCCP` outside IntakeGuard's `maxDecompressedBytes` budget: a 1 MB file → ~130 MiB RSS (the ceiling is presumably the crate's internal cap), verdict `transformed`. ICC is dropped anyway, so skip the chunk before decoding | `img-bomb-png-iccp` (RSS bound 48 MiB) |
| 4 | Low (harness) | `tools/benchmark/outputs.py:_pil` opens the *original* with Pillow and crashes on hostile inputs, so the whole run aborts. Hostile originals must not break the judge | n/a |
| 5 | Info (API) | `Report.usable` is False for `transformed`, which is correct but easy to misread. Suggest a single `report.safe_bytes()` that returns the output for transformed, the original for accepted, and raises otherwise. That is the T13 control in one call | n/a |
| 6 | Info | Lossy WebP → lossless re-encode is 13–30× larger. This confirms the builder's spec question | n/a |

## Not covered here
Fuzzing, other platforms, and the RAG example. All 50 labels are still `unreviewed`.
