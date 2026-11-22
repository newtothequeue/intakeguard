# Independent review of PR #6: LlamaIndex reader + shared intake (reviewer, 2026-11-21)

## Scope
`intakeguard/intake.py` (new shared safety primitives), `intakeguard/langchain.py` (refactored onto it),
`intakeguard/llama_index.py` (IntakeGuardReader / IntakeGuardDirectoryReader), `ingest_llama_index.py`, and the bakeoff
cancellation fix.

## Separation of duties
No changes to `spec/`, `corpus/`, `CONTRIBUTING.md`, `docs/adr/` or `core/`.

## Refactor risk (security code moved into `intake.py`): every protection preserved
Regular-file-only open with `O_NONBLOCK`, plus `O_NOFOLLOW` when not following symlinks · the `_Tee` read
(the bytes inspected are the bytes kept) · `safe_bytes(original)` re-hash · `mkdtemp` + `O_EXCL` + `0600`
work files named from `output.mime` · the inbox gate (per-component symlink check, `resolve()` must stay
inside the inbox, `allow_outside` needs `follow_symlinks`). Both wrappers now share one implementation, so a
future fix lands in both.

## LlamaIndex reader: same bypass suite as PR #4 (Linux)
| Attempt | Default | `follow_symlinks=True` |
|---|---|---|
| Symlinked file to outside | skipped-symlink | skipped-outside |
| Symlinked directory to outside (recursive) | skipped-symlink | skipped-outside |
| Dangling symlink | skipped | skipped-not-regular |
| FIFO `.pdf` | skipped-not-regular | skipped-not-regular |
| Glob escape `../private/*` | skipped-outside | n/a |
| PDF with OpenAction JS | rejected, not passed downstream | rejected |
| Lossy WebP with alpha | loaded; downstream saw `logo.png` | same |

`intakeguard_*` metadata is excluded from both embedding and LLM metadata by default
(`exclude_intakeguard_metadata=True`), so audit fields don't leak into vectors or prompts.

## Cancellation fix
"Finished before noticing cancel" counts as a pass only when the report's (verdict, reason codes, every check
status) is identical to the uncancelled run. An aborted run can only be `error`, so a partial result can't pass
this way. This resolves the minor flake noted in `review-pr5.md`.

## Regression (Linux x86_64, rebuilt from `89f5da3`)
Gate 3/3 (58/58, cancellation 6/6 each run) · wrapper tests 22/22 · both demos `--check` pass ·
`realworld.py` 600/600 · merges cleanly. macOS and Windows: as reported by the builder's CI (not visible from here).

**Verdict:** merge. Residual low items from `review-pr3-4.md` (hard links, recursive-mode TOCTOU) apply equally
to the LlamaIndex reader through the shared gate.
