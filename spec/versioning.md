# Versioning

- **Policy schema** (`version` field): minor versions add optional fields with strict defaults.
  Removing a field or weakening a default requires a major version and a migration note.
- **Reason codes:** IDs are immutable. Adding a code is a minor change. Deprecating one keeps it
  valid for at least one major version.
- **Report schema** (`reportVersion`): additive changes are minor. Consumers must ignore unknown
  `warnings`, but must not ignore unknown `verdict` values (treat them as rejected).
- **Engine:** semver. Any change that turns a previously rejected corpus fixture into an accepted one
  is a **security-relevant change**. It must be called out in the changelog and needs human approval.
- **Corpus:** versioned with the repo. Fixture IDs are immutable. If an expected outcome changes,
  the manifest row records why (`review.history`).
