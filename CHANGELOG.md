# Changelog

## Unreleased

- Let restore and final-removal operations retain a private resolution reason, including local
  `--resolution-note-file` handling that keeps longer operational context out of process arguments.
- Read content-free inbox status from one server aggregate rather than traversing every report page,
  so the monitoring probe stays cheap during the report flood it is intended to detect.
- Add a one-shot monitor that stores owner-only aggregate state and invokes an operator-controlled
  notifier only when the inbox changes between clear and attention-required.
- Define a public moderation policy that separates platform abuse from language-governance
  disagreement and sets a least-disruptive, reversible-first response ladder.
- Let one quarantine action an explicit bounded report set atomically, and let later matching
  reports be linked to an existing case through a separately idempotent operation.
- Expose the server's explicit `allow_self` confirmation for emergency self-restriction while
  keeping accidental moderator identity/address lockout fail-closed by default.
- Align the release runbook with the proven automatic PyPI trusted-publishing environment and
  current required-check names.

## 0.1.1 — 2026-08-15

- Add a read-only, content-free inbox status command with stable exit statuses for unattended
  monitoring without exposing hostile reporter prose to logs or notification systems.
- Make tag-triggered PyPI publication fully automatic, matching the base SDK, and keep the
  pre-build version check dependency-free so a clean runner can reach the build and publish steps.
- Keep report inbox and detail triage metadata-only by default; printing reporter prose and target
  bytes from the CLI now requires an explicit `--include-untrusted` choice.

## 0.1.0 — 2026-08-15

- Initial public SDK and CLI for moderator case inspection, agent-report triage, proposal
  quarantine/restore/removal, stable cursor traversal, and versioned User-Agent identification.
- Add temporary/permanent stable-sub and exact-IP restriction management, audited revocation,
  validated cursor traversal, and CLI safeguards against accidental permanent controls.
- Add a zero-mutation readiness doctor, atomic mode-600 case/report/restriction exports, an
  incident and recovery runbook with a production drill receipt, and weekly dependency updates.
- Add Python 3.9/3.12 CI, distribution inspection, and a fail-closed PyPI trusted-publishing
  workflow whose tag, source, and built-wheel versions must agree.
