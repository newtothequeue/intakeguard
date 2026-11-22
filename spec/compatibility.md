# Compatibility and maturity

Every published component carries a maturity label. Labels come from evidence, not intent.

| Label | Requires |
|---|---|
| experimental | Builds; passes the reviewed corpus fixtures for its declared formats |
| beta | All of the above, plus a fuzz harness in CI, differential tests, ≥1 external integration, and a documented limitations table |
| stable | All of the above, plus external security review of its guarantees, and no open high-severity issues |

## Current matrix

| Component | Formats | Label |
|---|---|---|
| spec | n/a | draft |
| corpus | JPEG, PNG, WebP, PDF | seed (labels unreviewed) |
| core | — | not started (see ADR 0002) |
| python binding | — | not started |
| node binding | — | not started |
| go binding | — | not planned before Stage 3 |
