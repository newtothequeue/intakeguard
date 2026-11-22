# Conformance corpus

The corpus is the **test oracle**. Every engine, binding and adapter has to produce the expected
outcome for every reviewed fixture.

- `generators/`: deterministic, stdlib-only Python scripts that **build** fixtures. No hostile
  binaries are committed (that keeps antivirus from quarantining the repo on clone and keeps git history clean).
- `manifest.jsonl`: one row per fixture, with the expected verdict and reason codes under a named
  policy, output assertions, resource bounds, the **oracle** (how we know it's correct) and the
  **review** status. Schema: `manifest.schema.json`.
- `policies/`: the policies that fixtures reference.
- `build/`: generated output (gitignored). Run `make corpus`.

## Current set (spec 0.1.1): 44 fixtures
- **Seed (v0.1), 27:** 5 benign · 5 type/polyglot · 6 image (metadata, bombs, truncation, byte limit) ·
  11 PDF (active content, 3 evasion techniques, embedded file, encryption, page limit, flate bomb, truncation, trailing data, hidden text)
- **ADR 0003, 17:** 5 benign real-producer guards (LibreOffice destination OpenAction, GoTo, empty Flate,
  Pillow gen 65536, outline GoTo/Named) · 12 adversarial guards so the relaxation can't become a bypass
  (Next chains and cycles, Rendition/GoTo with /JS, missing /S, page/outline/form-field actions, Launch,
  in-use gen 65536, damaged last revision)

Every evasion fixture was cross-checked with independent parsers (qpdf/pikepdf for PDFs, Pillow for images),
which confirms the hostile structure really resolves the way the label says.

**All labels are `unreviewed`.** A human must review each one before it counts toward a maturity label.

## Adding a fixture (red-team workflow)
1. Add a generator function (or a new module under `generators/adversarial/`) that returns `{id: bytes}`.
2. Run `python tools/corpus-verify/verify.py --print-hashes` to get its sha256 and size.
3. Add a manifest row with `review.status: "unreviewed"` and an honest `oracle` (source, reference, confidence).
4. `make check`. CI fails on hash drift, unknown codes or policies, orphans, or inconsistent outcomes.

## Rules
- Minimal: the smallest file that shows the behavior
- Inert payloads only (e.g. `app.alert`), never real exploit code
- If a generator's output changes, the hash check fails. That is intentional: the label needs re-review.
