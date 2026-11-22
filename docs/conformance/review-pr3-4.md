# Independent review of PRs #3–#4 (reviewer, 2026-11-21)

Written by a reviewer who did not write the engine, the wrapper or the example.

## Scope
- PR #3: spec 0.1.3 (lossy WebP with alpha → PNG) plus the `has-alpha` harness assertion
- PR #4: `intakeguard.langchain` (IntakeGuardLoader / IntakeGuardDirectoryLoader) and `examples/python-rag-ingestion`

## Separation of duties
No changes to `spec/`, `corpus/`, `CONTRIBUTING.md` or `docs/adr/` in either PR. No new `core/` dependencies.

## Results (rebuilt from source at `c226886`)
| Check | Result |
|---|---|
| Builder gate (`bakeoff.py --quick --gate`) | 58/58, 0 invariant violations |
| Reviewer's independent fixture check (Pillow and byte scans, not the builder's harness) | **58/58** |
| Alpha: 300×200 lossy WebP logo with mixed alpha | → `image/png` RGBA, **alpha channel bit-exact**, opaque RGB exact |
| Lossy WebP without alpha | still → `image/jpeg` (0.1.2 behaviour unchanged) |
| `tools/differential/realworld.py --sample` (600 files) + 13 producer samples | 0 false positives, 0 leaks, 0 contract violations, 0 disagreements |
| Blind red-team probes (round 1) | 25/25 |
| `ingest.py --demo --check` | all expectations met (verdicts, renames, re-check) |

## Wrapper review: correct
- One streaming read (`maxBytes` enforced while reading); the bytes inspected are exactly the bytes kept (`_Tee`)
- `safe_bytes(original)` re-hashes the original, so it can't be swapped between inspection and use
- Work file: `mkdtemp`, then `O_CREAT|O_EXCL`, `0600`; named from `output.mime`; removed afterwards unless kept
- Rejected or error → raise (default) or skip; never loads anything
- Docs make no claims beyond `spec/format-guarantees.md`

## Findings
| # | Severity | Finding |
|---|---|---|
| 1 | **Medium (fix before pilots)** | `IntakeGuardDirectoryLoader` follows **symlinks**: a link in the inbox to a file outside it (`inbox/innocent.png -> /private/secret-scan.png`) was sanitized and loaded. Anyone who can create files in the inbox (archive extraction, shared upload folders) can pull local files into the RAG index. Fix: skip symlinks by default (`p.is_symlink()`), and skip anything whose `resolve()` falls outside `self.path.resolve()`. Make following an explicit opt-in. Add a test |
| 2 | Low | Directory loader: files IntakeGuard **allowed** but with **no configured loader** are swallowed silently (`NoLoaderConfigured`). They appear in `results` alongside loaded files, so an audit log can't tell "loaded" from "not loaded". Record a status per file (loaded / rejected / no-loader) |
| 3 | Info | Not covered: macOS and Windows wheels (requested separately), and a LlamaIndex wrapper (CONTRIBUTING.md step 3 mentions it) |

## Recommendation
Merge #3 now. Merge #4 once finding 1 is fixed (a small change plus a test); finding 2 can ride along.

## Re-review of PR #4 after fixes (`ef6d51e`)
Finding 1 (symlinks) and finding 2 (per-file status) are **fixed**. Attempted bypasses, with the default policy:

| Attempt | Result |
|---|---|
| Symlinked file to outside the inbox | `skipped-symlink` |
| Symlinked directory to outside (recursive) | `skipped-symlink` |
| Symlink to a file *inside* the inbox | `skipped-symlink` by default; loaded only with `follow_symlinks=True` |
| Dangling symlink | skipped |
| FIFO named `.png` | `skipped-not-regular` (no hang) |
| Glob escape `glob="../private/*"` | `skipped-outside` |
| `follow_symlinks=True`, link pointing outside | `skipped-outside` |

Regression: builder gate 58/58; wrapper tests 12/12 on a clean corpus build; demo `--check` passes;
`realworld.py` 600/600.

**Residual (low, not blocking):**
- **Hard links:** a hard link in the inbox to a file elsewhere is a regular file inside the inbox, so it is
  loaded. Mitigated on most Linux systems by `fs.protected_hardlinks` and by safe archive extraction.
  Optional hardening: a `reject_hardlinks` flag (`st_nlink > 1`).
- **TOCTOU in recursive mode:** an attacker who can modify the inbox *during* a load could swap an
  intermediate directory for a symlink between the gate check and `open()` (`O_NOFOLLOW` covers only the
  last component). Full fix: walk with `dir_fd` and `O_NOFOLLOW` per component (`openat`).

Corpus tooling fix from this review: `verify.py --build-only` now rebuilds `corpus/build/` from scratch.
The reviewer's first test run failed on a stale `<id>.bin` left by an older build, which a consumer
using `next(dir.iterdir())` could pick up.

**Verdict:** merge.
