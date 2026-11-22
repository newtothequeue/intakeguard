# Security Policy

## Reporting a vulnerability

Please **do not open a public issue.** Use GitHub's private vulnerability reporting
(Security tab → "Report a vulnerability").

Useful things to include: affected version or commit, policy used, a minimal reproducing file
(or a generator script, which we prefer), the expected and actual verdict, and the impact.

## What counts

- A policy **bypass**: a file the spec says must be rejected or transformed is accepted unchanged
- **Original bytes leaking** through an API that presents them as sanitized output
- **Resource exhaustion** beyond configured limits (memory, CPU, time, temp disk)
- Crashes, panics or hangs on untrusted input
- A claim in the docs that isn't backed by `spec/format-guarantees.md`

Out of scope: content that the spec explicitly does not guarantee against (see the non-guarantees
in `spec/format-guarantees.md`), such as malware inside an otherwise policy-compliant file.

## Our commitments (target, pre-1.0)

- Acknowledge within 3 business days
- Publish an advisory for confirmed issues, including bypasses we find ourselves
- Add a regression fixture to the corpus for every fixed issue
