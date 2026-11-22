# Fuzzing the IntakeGuard core

Coverage-guided fuzzing with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). It is
a separate Cargo workspace, so the stable build never sees it.

| Target | Input | What it exercises |
|---|---|---|
| `sanitize_any` | raw bytes, no claimed type | type detection, polyglots, every format; also asserts the in-memory and streaming (7-byte reads) APIs agree |
| `pdf` | prefixed with `%PDF-1.7\n` if missing | xref chain, object streams, filters, actions, hidden-text scan |
| `pdf_filters` | `[role, f1, f2, f3]` + raw stream data, placed in a fixed valid PDF | stream decoders (spec 0.1.4): ASCIIHex, ASCII85, RunLength, LZW (EarlyChange 0/1), Flate, PNG/TIFF predictors, Crypt Identity, chains of up to three; as a content stream (decoded and scanned) or an image XObject (counted only) |
| `png` | prefixed with the PNG signature if missing | chunk walk, metadata, png decoder + encoder |
| `jpeg` | prefixed with `FF D8 FF` if missing | marker walk, SOF/EXIF, zune-jpeg + jpeg-encoder |
| `webp` | wrapped in a RIFF/WEBP container if needed | chunk walk, image-webp decoder + encoders |

## What counts as a crash
`src/lib.rs`: the engine catches its own panics and reports verdict `error` (fail closed). The harness turns
that back into a crash, so a panic anywhere, including inside a codec, is found. Every input is also
checked against the report contract:
- `ENGINE_INTERNAL_ERROR` never appears;
- only codes registered in `spec/reasons.yaml` appear;
- output bytes exist if and only if the verdict is `transformed`, are new, and match `output.sha256`;
- `accepted` has no failed check, and no skipped check other than `scanner` (none configured) and
  `type.mismatch` when no filename or MIME type was claimed;
- idempotence (spec 0.1.4): sanitizing an output within `maxBytes` again is `accepted` or `transformed` and finds
  no metadata; an output larger than `maxBytes` is rejected on the second pass with exactly `LIMIT_BYTES_EXCEEDED`.

Limit hits (`LIMIT_*`) are normal verdicts, not crashes. The fuzz policy is the strict policy with smaller
limits, so runs stay fast.

## Run it locally
```bash
rustup toolchain install nightly --profile minimal
```

```bash
cargo install cargo-fuzz --locked
```

```bash
make corpus && python tools/fuzz/seed.py
```

```bash
cargo +nightly fuzz run -O --fuzz-dir tools/fuzz pdf -- -max_total_time=300 -rss_limit_mb=2048 -timeout=10 -dict=tools/fuzz/dict/pdf.dict
```

Seeds come from the generated conformance corpus, plus small Pillow-encoded variants when Pillow is
installed. Corpora, artifacts and the fuzz build are gitignored.

## CI
`.github/workflows/fuzz.yml`:
- **Nightly:** 25 minutes per target, with the corpus carried over between runs.
- **Pull requests that touch `core/` or `tools/fuzz/`:** a 60-second smoke run per target.
- **Manual:** choose the duration.

A crash fails the job. The raw input and a minimized one (`cargo fuzz tmin`) are uploaded as the
`fuzz-crash-<target>` artifact.

## When it finds something
1. **Builder:** reproduce with `cargo +nightly fuzz run --fuzz-dir tools/fuzz <target> <crash-file>`, fix the
   engine, and add a regression test in `core/tests/regressions.rs` that builds the input in code. Hostile
   fuzz outputs are never committed.
2. **Red-team:** turn the minimized input into a deterministic generator fixture in
   `corpus/generators/adversarial/`, with its own expected verdict (`review.status: "unreviewed"`). The builder
   who fixed the bug does not set that label.

## Resolved: idempotence and outputs over `maxBytes`
Spec 0.1.2 said both "`maxBytes` limits the input; output size is not limited by `maxBytes`" and "sanitizing an
output again is never `rejected`". The jpeg target found a 333-byte JPEG whose declared (noisy) image re-encodes to
1.18 MB, over the fuzz policy's 1 MiB `maxBytes`, so both couldn't hold. Spec 0.1.4 (ADR 0007) scopes idempotence
to outputs within `maxBytes`. The harness now asserts exactly that rule (see the list above); the earlier exemption
is gone.

## Findings so far
First local runs (2026-11-22, about 12 minutes per target over two rounds) found three engine bugs, all fixed with
regression tests:
- **pdf:** text past the first 4 MiB of a content stream was never scanned for hidden text, so the file was
  `accepted` with `pdf.hidden-content` skipped. The scan is now streaming and covers every byte.
- **(found while fixing that):** a Flate image stream with a PNG predictor made the whole PDF `UNSUPPORTED_FEATURE`
  (a false positive). Non-content streams are now only counted against the budget.
- **jpeg:** an exotic SOF sampling layout made zune-jpeg panic. Such layouts are now `UNSUPPORTED_FEATURE` before any
  decoder runs.
