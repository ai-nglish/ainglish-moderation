# Changelog

## Unreleased

- Add a content-free incident status client and transition monitor for defensive-mode, authority,
  authentication, admission-pressure, approval-age, report-group, and moderation-event signals.
- Add digest-bound contributor containment preview and mutation commands for explicit maximum-20
  chunks, with cross-subject preview-file refusal.
- Add typed measurement evidence reasons, `result_invalid`, and optional successor audit links;
  incompatible state/reason pairs fail locally before any API request.

- Add digest-bound moderation for exact seconds, attempts, measurements, and votes: read-only
  impact previews, immediate reversible quarantine, and independently confirmed restoration,
  final removal, and reinstatement. Add an atomic 1–20 item quarantine batch limited to one item
  per proposal, with exact whole-batch replay and no implicit report resolution.
- Add an audit-preserving measurement evidence-state request to the SDK and CLI. A row can be
  marked `record_only` or `instrument_invalid` only through the server's distinct-moderator
  approval flow; the client never implies that requesting the annotation changed the verdict.
- Make unattended alerting group-first: matching report-brigade duplicates update aggregate state
  without paging, while a newly first-seen exact target/digest/reason group still alerts.
- Add retry-safe approval cancellation by the requester and rejection by a different moderator,
  with structured reasons and private decision-note file support.

- Alert on content-free inbox arrivals and one-, six-, and 24-hour backlog thresholds without
  repeatedly paging an unchanged queue; migrate existing version-one local monitor state safely.
- Add content-free report grouping, advisory review leases, and atomic bounded bulk dismissal for
  scalable triage without making reports change publication.
- Add prose-free contributor-impact inventory before restrictions are considered.
- Add two-person terminal-action requests: restore, final removal, removed-content reinstatement,
  and permanent restrictions now require a distinct moderator's confirmation; permanent requests
  also require case/report provenance.
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
