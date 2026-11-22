# Format guarantees (spec 0.1.5, draft — human review required)

This is the **only** place IntakeGuard's security claims live. Docs, README and error messages
must not claim more than this.

**General statement:** IntakeGuard enforces declared file policies and produces validated or sanitized
artifacts for supported formats, reducing the risks of untrusted file intake. It does not guarantee
that content is malware-free, safe for all viewers, or free of prompt injection.

## All formats
| Guarantee | Condition |
|---|---|
| Inputs larger than `maxBytes` are rejected without buffering more than `maxBytes` + one chunk | Streaming API used |
| A detected type outside `allow` is rejected | Always |
| `accepted` means every applicable check has `status: passed` | Always |
| A `transformed` verdict's `output.sha256` differs from `original.sha256`, and the output is new bytes | Always |
| Any internal failure yields `error` (consumers treat it as rejected), never `accepted` | Always |
| A caller-initiated cancel yields `error` with `ENGINE_CANCELLED`, never `accepted` | Always |
| When a stream limit stops reading early, `original.sha256`/`bytes` describe only the bytes read, and the report says so | Streaming API used |
| `maxBytes` limits the **input**. Output size is not limited by `maxBytes` | Always |
| `maxProcessingMs` is checked between processing stages and inside IntakeGuard's own parsers. A single image codec decode or encode cannot be interrupted, so the limit can be overrun by up to one codec call (about 1 s at the default pixel limit). Run IntakeGuard in a worker process if a hard deadline is required | Always |

## JPEG / PNG / WebP (mode `decode-reencode`)
**Guaranteed:**
- Declared dimensions are checked **before** pixel decoding (from the JPEG SOF, PNG IHDR, and WebP VP8/VP8L/VP8X headers)
- The output contains **no** EXIF, XMP, IPTC, ICC profiles, JPEG COM segments, APPn segments other than
  APP0/JFIF, PNG tEXt/zTXt/iTXt/eXIf/tIME/iCCP chunks, or WebP EXIF/XMP/ICCP chunks
- Metadata and ICC chunks that the transform discards are never inflated beyond the
  `maxDecompressedBytes` budget (skipping them without decoding is preferred)
- The output decodes successfully
- **Idempotence:** sanitizing an output again **under the same policy, when the output is within
  `maxBytes`**, is never `rejected` and reports no `IMAGE_METADATA_PRESENT`. The second verdict may be
  `accepted` or `transformed`. An output larger than `maxBytes` is, as an input, over the limit, and a second
  pass rejects it with `LIMIT_BYTES_EXCEEDED`. That is expected, not a violation (spec 0.1.4).
- **EXIF orientation is applied** to the pixels before the metadata is removed, so the output displays
  upright with no orientation tag. Output dimensions equal input dimensions after orientation
  (orientations 5–8 swap width and height). Without EXIF orientation, dimensions are unchanged.
- **Output format** with `outputFormat: same` (the default): JPEG → JPEG, PNG → PNG, lossless WebP → lossless WebP,
  and **lossy WebP → JPEG at quality 90** (a lossless re-encode of a lossy source is 10–30× larger).
  **Exception (spec 0.1.3): lossy WebP with an alpha channel (`ALPH` chunk) → lossless PNG**, because JPEG has no
  transparency. Transparency is never silently flattened.
  `output.mime` always states the format actually produced.
- JPEG output is encoded at quality 90.

**Fidelity:**
- PNG and lossless WebP sources: pixel-exact output (same pixel values, same channels/bit depth or a lossless widening)
- JPEG and lossy WebP sources: one lossy re-encode (q90). Not bit-identical.

**Colour:**
- The ICC profile is **dropped** and pixel values are treated as sRGB. **No colour management is applied.**
  Images authored in a wide-gamut or other non-sRGB profile (e.g. Display P3, Adobe RGB, print CMYK) may show a
  visible colour shift. CMYK JPEGs are converted to RGB without a profile.

**Not guaranteed:**
- That steganographic data in pixels is removed
- Colour accuracy for non-sRGB sources (see Colour)
- Animated images (rejected as `UNSUPPORTED_FEATURE` in v0.1)

**Structure (rejected as `STRUCTURE_MALFORMED`):** bytes after PNG `IEND`, after JPEG `EOI`, or after the
end of the WebP RIFF container.

**Budgets:** the decoded pixel buffer is governed by `maxImagePixels` and `maxImageDimension`, not by
`maxDecompressedBytes`. Any image within the pixel limits must not be rejected for its decoded size.

## PDF (v0.1: inspect and reject only, no sanitization)
**Guaranteed** (under the default strict policy), rejected if any of these appear in **any revision**,
including inside object streams and after normalizing hex-escaped names:
- An **active action**. An action is any dictionary reached through `/OpenAction`, `/AA` (on the catalog,
  a page, an annotation or a form field), an annotation `/A`, an outline item `/A`, a `/Next` chain
  (followed transitively, with cycles detected), or the `/Names /JavaScript` tree. An action is active
  **unless** its `/S` is on this inert allowlist **and** it has no `/JS` key:
  - `/GoTo`, `/Named`, `/Thread`, `/Hide`, `/SetOCGState`, `/Trans`, `/ResetForm`
  - `/URI` and `/GoToR` are also inert, but are reported as `PDF_EXTERNAL_LINK` (warn)

  Any other `/S`, including `/JavaScript`, `/Launch`, `/SubmitForm`, `/ImportData`, `/RichMediaExecute`,
  `/Rendition`, `/Movie`, `/Sound`, `/GoTo3DView`, `/GoToE`, a missing `/S`, or any type this spec doesn't
  list, is active (fail closed).
- An `/OpenAction` whose value is a **destination** (an array such as `[page /XYZ …]`, or a name or
  string naming a destination) is not an action, and is not active. Office suites write this to
  choose the opening page.
- A non-empty `/Names /JavaScript` tree, `/RichMedia` annotations, or an `/XFA` entry in `/AcroForm`
- `/EmbeddedFile`, `/EmbeddedFiles`, `/FileAttachment` annotations
- An `/Encrypt` entry in any trailer
- A page count above `maxPdfPages`, an object count above `maxPdfObjects`, or total decompressed
  stream bytes above `maxDecompressedBytes`
- A truncated or structurally malformed file (no `%PDF-` header, a broken or missing xref that cannot be
  reconstructed under strict rules, an unterminated object)
- An `N G obj` section that no xref in the chain covers, **including object sections after the final
  `%%EOF`** (`STRUCTURE_MALFORMED`). Lenient readers that rebuild the xref may load such objects. (Builder rule
  from PRs #1/#2, adopted in 0.1.2.)
- A stream filter outside the standard set (`UNSUPPORTED_FEATURE`). The standard set is ASCIIHexDecode,
  ASCII85Decode, LZWDecode, FlateDecode, RunLengthDecode, CCITTFaxDecode, JBIG2Decode, DCTDecode, JPXDecode and
  Crypt, plus the standard abbreviations in inline images only. A filter the engine cannot decode leaves the checks
  that depend on its content `skipped`, and a skipped check is never reported as passed. (Builder rule from PR #2,
  adopted in 0.1.2.)
- **Decoding (spec 0.1.4).** The engine decodes **FlateDecode, ASCIIHexDecode, ASCII85Decode, RunLengthDecode
  and LZWDecode** (with `/EarlyChange` 0 or 1, and the Flate/LZW `/Predictor` values the spec defines), alone or
  chained in any order, in every stream whose contents a check needs: content streams, object streams and
  cross-reference streams. Every decoded byte counts against `maxDecompressedBytes`. A truncated or invalid
  encoding is `STRUCTURE_MALFORMED`.
- **No data after end-of-data (spec 0.1.5).** In any filter stage that has an end-of-data marker (ASCII85 `~>`,
  ASCIIHex `>`, RunLength byte 128, the LZW EOD code, the end of a zlib/deflate stream), **any byte other than
  PDF whitespace (NUL, TAB, LF, FF, CR, SPACE) after the marker makes the stream `STRUCTURE_MALFORMED`.**
  Readers disagree about such data (qpdf's RunLength decoder ignores an early EOD and keeps decoding), so the engine
  must not inspect one interpretation while a downstream reader uses another.
- **A content stream (or object or xref stream) whose filter chain includes a filter the engine does not decode
  is `rejected` (`UNSUPPORTED_FEATURE`).** It is never `accepted` with a dependent check `skipped`. Image-only
  filters (DCT, JPX, JBIG2, CCITTFax) on image XObjects are not decoded and need not be: no check depends on their
  contents, and they only count against the file-size limits.

**Warned, not rejected (by default):** URI and GoToR actions, data after `%%EOF`, suspected hidden text.

**Tolerated producer quirks** (accepted, because common writers emit them and qpdf/pdf.js accept them).
Each tolerance is as narrow as stated; anything broader stays malformed:
- A Flate stream with `/Length 0` and no data counts as empty content (written by pikepdf/qpdf
  for blank pages). A non-empty Flate stream that doesn't end cleanly is still malformed.
- In a classic xref table, the free-list head (object 0) may have generation `65536` instead of
  `65535` (written by Pillow). Any other entry whose generation is above 65535 is still malformed.

**Not guaranteed:**
- That a PDF which passes the checks is free of exploits against a particular viewer
- Removal of anything (v0.1 never modifies PDFs)
- Detection of hidden text or prompt injection (the heuristic warning is best-effort)

## Unsupported in v0.1 (always rejected)
GIF, SVG, TIFF, HEIC, AVIF, BMP, Office formats, archives, executables, text, HTML, audio/video.
