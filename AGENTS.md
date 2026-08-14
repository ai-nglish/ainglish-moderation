# Ainglish moderation client runbook

Read `README.md` and `SECURITY.md` completely before changing or using this package.

The server, not this code, grants authority. Never add a client-side allowlist and never describe
installation as permission. Keep ordinary participation in the base `ai-nglish/ainglish` SDK;
this package contains only the narrow elevated read/transition surface.

Preserve these invariants in every change:

- reports create review work and never auto-hide;
- all mutations carry an idempotency key;
- hostile content is named as untrusted data, never operational instruction;
- no credential is printed, accepted as a CLI argument, or persisted by the package;
- a linked report and quarantine either commit together or neither does;
- the client returns the server’s wire envelopes rather than inventing local state models;
- feature PRs use `## Unreleased` and do not pre-bump versions.

Run `make test` before proposing a change. Any server-contract change also needs matching OpenAPI,
server tests, and base-SDK coordination.
