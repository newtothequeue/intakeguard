# ADR 0006: Final name is IntakeGuard; the rename is deferred to the repo migration

**Status:** Accepted. Owner decision, 2026-11-21.

## Context
`safefile` is taken on PyPI by an unrelated, active project (atomic file writes). A name check on
2026-11-21 found **IntakeGuard** free on PyPI, npm and crates.io. The GitHub org looked free, but that was
not confirmed, because GitHub blocked lookups from the checking environment.

## Decision
- The product name is **IntakeGuard** (packages `intakeguard` on PyPI, npm and crates.io).
- **Development continues as `safefile` in this repo.** Nothing is renamed now.
- The rename happens as the **final step**, when the project moves to a repo under a different GitHub account.

## Rules until the migration
- **Never publish** anything (PyPI, npm, crates.io, Docker, GitHub releases) under `safefile`. It is taken on
  PyPI and is not the product name.
- Keep the name in as few places as possible (`tools/project.py`, package metadata), so the rename stays cheap.

## Migration checklist (when the owner says go)
1. Owner confirms the GitHub org/user name `intakeguard` (or the chosen account) and does a trademark search.
2. Create the new repo under the new account. Decide whether to carry over git history or start fresh;
   branch names and commit messages in the history mention `safefile`.
3. Rename everything: `tools/project.py`, Cargo crate names (`safefile-core`), the Python package and module
   (`safefile` → `intakeguard`), `pyproject.toml`, imports, docs, README, CONTRIBUTING.md, spec titles and
   `$id` URLs (`safefile.dev`), CI, the Makefile, and the `ENGINE_VERSION` string.
4. Corpus: fixture content doesn't change, but some generators embed the string `safefile-corpus`
   (JS payload text). Either keep it (hashes stay stable) or rename it and re-hash with a history note.
5. Run `make check`, `bakeoff.py --gate` and `make realworld` in the new repo, and require all green.
6. Owner approves the first publish (human gate): reserve the names, then release as alpha.
