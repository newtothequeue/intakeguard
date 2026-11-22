# Independent review of PR #7: coverage-guided fuzzing + 3 engine fixes (reviewer, 2026-11-22)

## Scope
`tools/fuzz/` (cargo-fuzz workspace: 5 targets, dictionaries, `seed.py`, shared invariant harness),
`.github/workflows/fuzz.yml` (60 s smoke on PRs, 25 min/target nightly, crash artifacts), and three engine
fixes the fuzzer found (PDF hidden-text scan past 4 MiB, PNG-predictor Flate in non-content streams, a
zune-jpeg upsampler panic on exotic sampling).

## Separation of duties
No changes to `spec/`, the manifest, `CONTRIBUTING.md` or `docs/adr/`. `core/Cargo.toml` adds `miniz_oxide` as a
**dev-dependency only** (tests build Flate streams), which is already approved as a runtime dependency.
**Process note:** the builder wrote `tools/fuzz/`, which CONTRIBUTING.md assigns to the verification role. The
reviewer read the invariants in `tools/fuzz/src/lib.rs` line by line instead.

## Fuzz invariants (`tools/fuzz/src/lib.rs`): strict and correct
Engine panics and `ENGINE_INTERNAL_ERROR` are crashes · every reason code is registered · output iff
`transformed`, with a new sha256 matching the report · original sha256 matches the input · `accepted` has
**no failed and no skipped check** (except `scanner` with none configured, and `type.mismatch` when nothing was
claimed) · re-sanitizing an output is never rejected and finds no metadata. One exemption (an output over
`maxBytes`) is narrowly scoped and documented. It is resolved by spec 0.1.4.

## Engine fixes
All three are real, each has a regression test, and each fails closed or removes a false positive. The
hidden-text fix (it used to scan only the first 4 MiB of a content stream, then `accepted` with the check
skipped) is a genuine spec violation that the fuzzer caught.

## Reviewer finding (pre-existing, not introduced by #7)
**Content streams using ASCII85, ASCIIHex, RunLength or LZW** (alone, or chained with Flate) are
`accepted` with `pdf.hidden-content` **skipped**. That violates the spec guarantee "`accepted` means every
applicable check has `status: passed`", the same invariant the fuzz harness asserts. The fuzzer just didn't
generate such files. Object streams using these filters are rejected (`UNSUPPORTED_FEATURE`), so there is no
active-content bypass; qpdf/pikepdf resolve the hidden JS in those files, confirming the reject is right.
Owner decision (2026-11-22): **add in-house decoders** (spec 0.1.4, ADR 0007).

## Regression (Linux x86_64, rebuilt from `1096b11`)
cargo test 23/23 · gate 2/2 (58/58) · pytest 22/22 · `realworld.py` 600/600 · blind probes 25/25 · merges cleanly.
Not run locally: the fuzzer (needs nightly Rust; CI's smoke run reports no crashes).

**Verdict:** merge.
