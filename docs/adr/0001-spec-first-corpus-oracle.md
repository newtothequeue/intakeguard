# ADR 0001: Spec first, with the corpus as the oracle

**Status:** Accepted (Stage 0)

## Context
Implementation code is cheap to produce; correct security behavior is not.
We need a contract that machines can check, which every implementation (core, bindings,
adapters) must satisfy, and which is maintained separately from whoever writes the code.

## Decision
- `spec/` is the source of truth: policy schema, verdict schema, reason-code registry,
  per-format guarantees, threat model.
- `corpus/` is the test oracle: deterministic generator scripts plus `manifest.jsonl` rows that
  state the expected verdict, reason codes and output properties under a named policy.
  Each row records its oracle source and its review status.
- Hostile fixtures are **generated, not committed**. This keeps antivirus from quarantining the
  repo on clone and keeps malicious binaries out of git history, and it makes red-team
  contributions reviewable as code.
- Whoever implements a feature never sets its expected outcomes.

## Consequences
- CI fails if a generator's output hash drifts, a manifest row references an unknown reason code
  or policy, or a schema stops validating.
- Every bypass fix lands with a new fixture.
- Generator determinism has to be preserved (stdlib only, no timestamps, no randomness without a fixed seed).
