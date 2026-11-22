# ADR 0002: Core runtime bake-off

**Status:** Accepted, 2026-11-21 (owner decision). Native Rust is the server default. The same core can be compiled to WASM later for the browser demo and edge runtimes. WASM and TypeScript were not measured; the owner accepted on the native results plus the independent review (docs/conformance/review-pr2.md).

## Default hypothesis
**Native Rust core** shipped through PyO3/maturin (Python wheels) and napi-rs (Node prebuilt
binaries) for server use. **Rust → WASM** only for the browser demo and edge runtimes.
Change the default only if the measurements below disagree.

## Candidates
| Candidate | Advantage | Key risk |
|---|---|---|
| Native Rust (PyO3 + napi-rs) | Fast, bounded parsing; well-trodden packaging (pydantic-core, polars, ruff) | Platform build matrix; isolation must come from host process controls |
| Rust → WASM (wasmtime / wazero / Node) | Portable; sandbox primitives | Host config determines real limits; memory copies; large-file throughput |
| TypeScript | Fastest Node integration | Duplicated logic across languages; dependence on JS parser security |

## Slice to implement in each candidate
`inspect()` on the seed corpus: type detection, byte limit while streaming, PNG/JPEG
dimension check, PDF page count and active-content detection (including object streams and
hex-escaped names), producing a `verdict.schema.json`-valid report.

## Measure
Conformance pass rate on the corpus · p50/p95 latency · peak RSS · response to cancellation ·
behavior on over-limit streams · wheel/npm packaging effort · whether it works on serverless (Lambda, Cloud Run).

## Isolation note
WASM does not enforce timeouts or memory caps by itself. Those depend on how the host is
configured (fuel or epoch interruption, memory limits, deny-by-default WASI). For native builds,
enforce limits inside the parser itself and offer an optional worker-process mode with OS limits.

## Decision rule
Pick the default after the slice meets correctness (100% of reviewed fixtures) and resource budgets.

## Results so far

### Native Rust (PyO3) — measured 2026-11-22
Full report: `docs/conformance/bakeoff-native-rust.md` (raw data in `bakeoff-native-rust.json`).

- Conformance: 27/27 on the pre-transform policy decision. 22/27 on emitted verdicts: the 5 misses
  are the `transformed` image fixtures, which fail closed because the slice has no encoder.
  Every report validates against the schema.
- Latency p95: ≤ 0.06 ms for every fixture except the 150-page PDF (0.27 ms) and the flate bomb
  (25 ms, aborted at the budget).
- Peak RSS: ≤ 6.9 MiB for every fixture, against bounds of 32–160 MiB.
- Cancellation returns within about 1 ms; `maxProcessingMs` overshoot is about 2 ms.
- Over-limit streams pull `maxBytes + 1` bytes.
- 30k mutants: 0 panics. One bypass (damaged last revision) was found and fixed.
- Packaging: abi3 manylinux2014 x86_64 and aarch64 wheels build with zig and no Docker.
  macOS/Windows were not attempted. Serverless was not measured.

### Rust → WASM, TypeScript
Not yet measured.

**Superseded by the Status line above (accepted 2026-11-21).**
the report lists spec gaps and a dependency gate (`miniz_oxide`) for human decision.
