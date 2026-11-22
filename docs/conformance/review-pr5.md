# Independent review of PR #5: macOS and Windows wheels (reviewer, 2026-11-21)

## Scope
`.github/workflows/ci.yml` (4-platform matrix), `tools/benchmark/bakeoff.py` (portability, stricter memory
gate, exact cancellation check), `core/examples/inspect_file.rs` (per-OS peak-memory measurement),
`bindings/python/tests/test_langchain.py` (portable symlink creation).

## Separation of duties
No changes to `spec/`, `corpus/`, `CONTRIBUTING.md`, `docs/adr/` or `core/Cargo.toml`. The FFI in `inspect_file.rs`
lives in a benchmark example, not the library, and adds no dependency.

## What the reviewer could and couldn't verify
- **Couldn't:** the macOS and Windows runs themselves. This environment is Linux only, and GitHub CI status
  isn't readable from here. The builder reports CI green on all four platforms.
- **Could (Linux x86_64, rebuilt from `57f6d9d`):** corpus hash check passes; conformance gate passes 3 runs out
  of 3 (58/58, cancellation 6/6 each run, with no timing flakes); wrapper tests 12/12; `realworld.py` 600/600.
  Merges cleanly.

## Review notes
- **CI design is right:** on each platform it builds and hash-checks the corpus (so generator determinism is
  tested across OSes), builds and installs the wheel, then runs the full gate, the wrapper tests and the RAG demo.
  `fail-fast: false` keeps one platform's failure from hiding another's. Wheels and results are uploaded as
  artifacts.
- **Gate got stricter:** a `maxPeakRssMiB` bound that couldn't be measured now fails, instead of passing
  silently.
- **Memory measurement per OS:** Linux uses VmHWM; macOS uses `getrusage`, where `ru_maxrss` is in bytes and the
  struct layout is correct for 64-bit; Windows uses `K32GetProcessMemoryInfo` (PeakWorkingSetSize). All
  measure the child for itself.
- **Windows symlink tests skip only on WinError 1314** (account cannot create symlinks); any other error fails.
  GitHub-hosted Windows runners normally can create symlinks, so the tests should run, but this isn't verified
  from here.
- **Minor (not blocking):** the cancellation check counts a run that returns `accepted` after `cancel()` was
  called as wrong. If the engine finished before it noticed the cancel, `accepted` is legitimate, so a very fast
  machine could flake the gate. That is a safe failure direction (false alarm, never a false pass).
- **Windows note for the backlog:** `O_NOFOLLOW` doesn't exist on Windows. With `follow_symlinks=False`, the
  loader relies on the `islink` check plus the `resolve()` inside-the-inbox gate, which also catches directory
  junctions. The TOCTOU window noted in `review-pr3-4.md` is a little wider there.

**Verdict:** merge. Owner: confirm on GitHub that the Windows job's pytest output shows the symlink tests
**passed** (not skipped).
