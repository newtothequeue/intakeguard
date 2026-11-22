# Contributing to IntakeGuard

These rules apply to every contribution, by people or tools. They are how IntakeGuard keeps its security claims honest.

> Naming note: corpus fixture bytes contain the string `safefile-corpus` (an earlier working name) on purpose,
> because changing it would change every fixture hash. `safefile` on PyPI is an unrelated project.

## What this project is

IntakeGuard is local-first, verifiable file intake and sanitization for apps and AI pipelines.
It checks an untrusted file against a declared policy and returns one of two things: a
**verdict that can be inspected**, or a **separate sanitized artifact**. It never hands the
original bytes back as if they were safe.

It is **not** antivirus, not full CDR, and not a prompt-injection defense. See
`spec/format-guarantees.md` for exactly what we do and don't claim.

**Lead workflow:** pre-flight checks for Python RAG/LLM document ingestion. The check runs
*before* the document loader (PyMuPDF, unstructured, docling, etc.). Node/Express
upload middleware is the second workflow.

**Current phase:** alpha (0.1.0a1). The only security claims are the ones in `spec/format-guarantees.md`.

## Sources of truth (in priority order)

1. `spec/`: the contract. Policy schema, verdict schema, reason codes, guarantees, threat model.
2. `corpus/`: the test oracle. Fixture generators plus `manifest.jsonl` expected outcomes.
3. `docs/adr/`: architecture decisions and their status.

When implementation and spec disagree, **do not change the spec to match the code.**
Open a spec-change note in `docs/adr/` or ask a maintainer.

## Non-negotiable rules

- **Fail closed.** Unknown, unsupported, malformed, encrypted, ambiguous, or errored → `rejected`.
  Adapters MUST treat a verdict of `error` exactly like `rejected`.
- **Never return the original bytes as sanitized output.** A transformed artifact is new bytes
  with a new handle and its own `outputSha256`. The original stays quarantined.
- **No claims beyond `spec/format-guarantees.md`.** No README line, docs page, error message
  or code comment may promise more than that file does.
- **Reason codes are immutable.** Never rename or reuse an ID in `spec/reasons.yaml`.
  Deprecate it, then add a new one.
- **A check that wasn't run is not a pass.** Reports list checks as `passed`, `failed`, or `skipped`.
- **Limits are enforced while streaming**, before the input is fully buffered wherever possible.
- **No network access** in the core, the tests, or the corpus tools. No real malware anywhere in the repo.

## Roles and separation of duties

| Role | May edit | Must NOT edit |
|---|---|---|
| Builder (core/bindings/adapters/CLI) | `core/`, `bindings/`, `adapters/`, `cli/`, `examples/` | `spec/`, `corpus/manifest.jsonl` expected fields |
| Red-team | `corpus/generators/adversarial/`, new manifest rows with `review.status: "unreviewed"` | Existing oracle labels, `spec/` |
| Verification | `tools/differential/`, `tools/fuzz/`, reports | Expected verdicts (it proposes changes, it doesn't apply them) |
| Docs/distribution | `docs/`, `README.md`, `examples/` | Anything that widens claims beyond `spec/format-guarantees.md` |

Whoever implements a feature must never be the one who sets its expected verdict, and every change is reviewed by someone who didn't write it.

## Maintainer gates (stop and ask)

- Any change to `spec/` (schemas, reason codes, guarantees, threat model)
- Moving a fixture's `review.status` to `reviewed`
- Any public text that makes a security claim, and any outreach post
- Publishing packages or releases
- Adding a dependency to `core/` that parses untrusted input

## Approved `core/` dependencies

`miniz_oxide 0.8` (inflate; approved 2026-11-21, ADR 0003) · `png 0.17` · `zune-jpeg 0.4` · `jpeg-encoder 0.6` ·
`image-webp 0.2` (image codecs; approved 2026-11-21, ADR 0004) · `sha2` · `serde` ·
`serde_json` (policy only).
Anything else that touches untrusted bytes needs maintainer sign-off.

## Repository layout

```
spec/        contracts (source of truth)
corpus/      generators/{benign,adversarial}/, manifest.jsonl, manifest.schema.json
             build/ (generated fixtures, gitignored)
core/        engine (native Rust; ADR 0002 accepted)
bindings/    node/, python/, go/ (go is experimental until justified)
adapters/    express/, fastapi/ first
cli/         inspect, sanitize, audit, fix --dry-run, verify
tools/       corpus-verify/, differential/, fuzz/, benchmark/
examples/    python-rag-ingestion/, express-upload/
docs/        adr/, integration/, security-guarantees/, conformance/
```

## Commands

```bash
make check     # lint the spec + build the corpus + verify hashes and manifest consistency
make corpus    # regenerate fixtures into corpus/build/
```

Requirements: Python ≥ 3.11 with `jsonschema` and `pyyaml` (`pip install -r tools/requirements.txt`).

## Corpus conventions

- Fixtures are **generator scripts, not committed binaries.** Generators use only the Python
  standard library, run deterministically, and take no input.
  Each one writes exactly the files its manifest rows declare.
- Every manifest row has `sha256`, an expected verdict under a named policy, reason codes,
  an `oracle` (how we know it's correct) and `review` (who checked it, or `unreviewed`).
- Expected outcomes refer to policies in `corpus/policies/`.
- Keep adversarial fixtures minimal: the smallest file that shows the behavior.

## Code conventions (for when the core exists)

- Every rejection path emits a reason code that is registered in `spec/reasons.yaml`.
- Every new code path that touches untrusted bytes needs a corpus fixture before it merges.
- Treat any panic, unbounded allocation, or unbounded loop on untrusted input as a security bug.
- Binding outputs must be checked against the shared conformance runner, not just their own unit tests.

## Roadmap

1. **Next release (0.1.0a2):** spec 0.1.6 (ADR 0009). In page and form XObject content, a hex string with non-hex
   bytes, an unclosed hex string, or an unclosed literal string → `STRUCTURE_MALFORMED`; inline image data is
   exempt. The spec text, fixtures and engine change land together.
2. **Hardening (low):** directory loaders: an optional `reject_hardlinks`, and a `dir_fd`/`openat` walk to close the
   recursive-mode TOCTOU (`docs/conformance/review-pr3-4.md`).
3. **Before 1.0:** maintainer review of every corpus label (`review.status`), and an external security review.

## Verification tools you can run on your own files (local only)

```bash
make realworld PATHS="~/Downloads ~/Documents"                       # false-positive sweep + output checks
python tools/differential/content_syntax_survey.py ~/Downloads       # content-syntax survey (ADR 0009)
python tools/differential/filters_vs_qpdf.py --cases 3000            # stream-decoding differential vs qpdf
```
