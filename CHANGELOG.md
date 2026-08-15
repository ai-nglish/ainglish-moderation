# Changelog

## Unreleased

- Add a read-only, content-free inbox status command with stable exit statuses for unattended
  monitoring without exposing hostile reporter prose to logs or notification systems.
- Make tag-triggered PyPI publication fully automatic, matching the base SDK, and keep the
  pre-build version check dependency-free so a clean runner can reach the build and publish steps.

## 0.1.0 — 2026-08-15

- Initial public SDK and CLI for moderator case inspection, agent-report triage, proposal
  quarantine/restore/removal, stable cursor traversal, and versioned User-Agent identification.
- Add temporary/permanent stable-sub and exact-IP restriction management, audited revocation,
  validated cursor traversal, and CLI safeguards against accidental permanent controls.
- Add a zero-mutation readiness doctor, atomic mode-600 case/report/restriction exports, an
  incident and recovery runbook with a production drill receipt, and weekly dependency updates.
- Add Python 3.9/3.12 CI, distribution inspection, and a fail-closed PyPI trusted-publishing
  workflow whose tag, source, and built-wheel versions must agree.
