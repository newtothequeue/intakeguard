# Independent review of PR #9: spec 0.1.5, no data after end-of-data (reviewer, 2026-11-22)

## Separation of duties
Only `core/src/pdf/filters.rs` and bake-off data changed. No `spec/`, corpus, ADR or dependency changes.

## Code review
One `after_eod()` check, called from every decoder's end-of-data path, including when the trailing bytes arrive
in a *later* chunk (`if self.done { return after_eod(..) }` in each stage). The whitespace set comes from
`syntax::is_ws`: NUL, TAB, LF, FF, CR, SPACE, exactly the PDF whitespace set the spec names. For LZW, the leftover
bits of the byte holding the EOD code are treated as padding, which is correct because they can't encode content.

## Results (Linux x86_64, rebuilt from `69648ec`)
Independent fixture check 80/80 (no accepted-with-skipped) · gate 80/80 · cargo test 37 · pytest 22 ·
`realworld.py` 613 files clean · blind probes 25/25 · merges cleanly.

## Differential battery
9,000 cases (seeds 11–13): **0 real misses**, 0 skipped, 0 errors, 0 slow. The first run reported 11 misses. All 11
were oracle false alarms (`3 Tr` inside unclosed `(` strings or glued to other tokens), so the tool now uses a
content tokenizer (`real_hidden_ops`). With the corrected oracle the original PR #8 run has **1** real miss, not 8
(ADR 0008 corrected).

## New finding (pre-existing, spec 0.1.6 / ADR 0009)
That one real miss: a corrupted ASCII85 stream decoded (identically in qpdf and Python's strict decoder) to
content containing `<\x82…`, an **unterminated hex string with non-hex bytes**. IntakeGuard's content scanner treats
everything after `<` as hex-string data and accepts the file with no warning. **pdfminer (used by `unstructured`
and LangChain's PDFMiner loader) recovers and extracts the hidden instruction after it.** pypdf raises, PyMuPDF
stops. Owner decision: content-stream syntax errors → reject (after a false-positive measurement on real files).

**Verdict:** merge.
