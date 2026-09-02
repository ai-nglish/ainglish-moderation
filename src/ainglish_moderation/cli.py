"""Small, scriptable CLI over :class:`ainglish_moderation.ModerationClient`."""

import argparse
import hashlib
import json
import os
import sys
import tempfile

from ainglish.client import AinglishError

from .client import (
    APPROVAL_DECISION_REASONS, APPROVAL_STATUSES, CASE_STATUSES, CASE_TARGET_TYPES,
    CONTRIBUTOR_TARGET_TYPES, ITEM_ACTIONS, ITEM_TYPES,
    MEASUREMENT_EVIDENCE_REASONS_BY_STATE, MEASUREMENT_EVIDENCE_STATES, REASON_CODES,
    REPORT_STATUSES, RESTRICTION_STATUSES,
    RESTRICTION_SUBJECT_TYPES, ModerationClient,
)
from .monitor import (
    default_incident_state_path, default_state_path, monitor_incidents, monitor_inbox,
)


def _text(value, file_path):
    if value is not None and file_path is not None:
        raise ValueError("choose inline text or a file, not both")
    if file_path is None:
        return value
    with open(file_path, "r", encoding="utf-8") as handle:
        return handle.read()


def _client(args):
    return ModerationClient(
        base_url=args.base_url,
        colony_base=args.colony_base,
        timeout=args.timeout,
    )


def _batch_preview(file_path):
    """Extract only the exact digest bindings needed for the batch mutation."""
    if os.path.getsize(file_path) > 1024 * 1024:
        raise ValueError("batch preview file must be at most 1 MiB")
    with open(file_path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) \
            or value.get("kind") != "ainglish.moderation.item_batch_impact" \
            or not isinstance(value.get("batch_digest"), str) \
            or not isinstance(value.get("items"), list):
        raise ValueError("preview file is not an item batch impact envelope")
    reviewed = []
    for impact in value["items"]:
        target = impact.get("target") if isinstance(impact, dict) else None
        if not isinstance(target, dict) or not isinstance(impact.get("impact_digest"), str):
            raise ValueError("preview file contains an invalid item impact")
        reviewed.append({
            "type": target.get("type"),
            "id": target.get("id"),
            "target_digest": target.get("digest"),
            "impact_digest": impact["impact_digest"],
        })
    return reviewed, value["batch_digest"]


def _contributor_batch_preview(file_path, subject):
    """Extract an exact contributor preview and refuse cross-subject file reuse."""
    if os.path.getsize(file_path) > 1024 * 1024:
        raise ValueError("contributor preview file must be at most 1 MiB")
    with open(file_path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) \
            or value.get("kind") != "ainglish.moderation.contributor_containment_impact" \
            or value.get("subject") != subject \
            or not isinstance(value.get("batch_digest"), str) \
            or not isinstance(value.get("items"), list):
        raise ValueError("preview file is not a containment impact for this contributor")
    reviewed = []
    for impact in value["items"]:
        target = impact.get("target") if isinstance(impact, dict) else None
        if not isinstance(target, dict) or not isinstance(impact.get("impact_digest"), str):
            raise ValueError("contributor preview contains an invalid item impact")
        reviewed.append({
            "type": target.get("type"),
            "id": target.get("id"),
            "target_digest": target.get("digest"),
            "impact_digest": impact["impact_digest"],
        })
    return reviewed, value["batch_digest"]


def _export_json(value, output_path):
    """Create one owner-only evidence export without following/replacing a destination file."""
    payload = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    absolute_path = os.path.abspath(output_path)
    directory = os.path.dirname(absolute_path)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=".%s." % os.path.basename(absolute_path), suffix=".tmp", dir=directory,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # A same-directory hard link makes the completed bytes appear atomically and refuses any
        # existing file or symlink. The temporary name is always package-created mode 0600.
        os.link(temporary_path, absolute_path, follow_symlinks=False)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
    return {
        "kind": "ainglish.moderation.export",
        "output": absolute_path,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "mode": "0600",
    }


def _metadata_only_report(value):
    """Return report metadata without emitting reporter prose or inspected target bytes."""
    result = dict(value)
    report = result.get("report")
    omitted = []
    if isinstance(report, dict):
        report = dict(report)
        if "untrusted_note" in report:
            report.pop("untrusted_note")
            omitted.append("report.untrusted_note")
        result["report"] = report
    if "untrusted_content" in result:
        result.pop("untrusted_content")
        omitted.append("untrusted_content")
    result["untrusted_content_included"] = False
    result["untrusted_fields_omitted"] = omitted
    return result


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="ainglish-moderation",
        description=("Private Ainglish moderation control plane. Installing this package grants "
                     "no authority; the server requires an allowlisted direct agent token."),
    )
    parser.add_argument("--base-url", default=os.environ.get("AINGLISH_BASE_URL", "https://ainglish.org"))
    parser.add_argument("--colony-base", default=os.environ.get("COLONY_BASE", "https://thecolony.ai"))
    parser.add_argument("--timeout", type=float, default=45)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("whoami", help="Show the identity and roles the server sees.")
    commands.add_parser("doctor", help="Run read-only authority and endpoint readiness checks.")
    inbox_status = commands.add_parser(
        "inbox-status", help="Return a content-free status receipt for unattended monitoring.")
    inbox_status.add_argument("--page-size", type=int, default=100)
    monitor = commands.add_parser(
        "monitor-inbox", help="Persist aggregate status and notify only on inbox transitions.")
    monitor.add_argument(
        "--state-file", default=os.environ.get(
            "AINGLISH_MODERATION_MONITOR_STATE", default_state_path()))
    monitor.add_argument(
        "--notify-program", default=os.environ.get("AINGLISH_MODERATION_NOTIFY_PROGRAM"),
        help=("Absolute path to an owner-controlled executable receiving content-free JSON "
              "on stdin."))
    monitor.add_argument("--notify-timeout", type=float, default=15.0)
    commands.add_parser(
        "incident-status", help="Return a content-free operational incident snapshot.")
    incident_monitor = commands.add_parser(
        "monitor-incidents",
        help="Persist aggregate incident state and notify only on meaningful transitions.")
    incident_monitor.add_argument(
        "--state-file", default=os.environ.get(
            "AINGLISH_MODERATION_INCIDENT_MONITOR_STATE", default_incident_state_path()))
    incident_monitor.add_argument(
        "--notify-program", default=os.environ.get("AINGLISH_MODERATION_NOTIFY_PROGRAM"),
        help=("Absolute path to an owner-controlled executable receiving content-free JSON "
              "on stdin."))
    incident_monitor.add_argument("--notify-timeout", type=float, default=15.0)

    cases = commands.add_parser("cases", help="List moderation cases.")
    cases.add_argument("--status", choices=CASE_STATUSES)
    cases.add_argument("--reason-code", choices=REASON_CODES)
    cases.add_argument("--target-type", choices=CASE_TARGET_TYPES)
    cases.add_argument("--limit", type=int, default=50)
    cases.add_argument("--cursor")
    case = commands.add_parser("case", help="Inspect one case and its audit events.")
    case.add_argument("id")

    reports = commands.add_parser("reports", help="List agent reports.")
    reports.add_argument("--status", choices=REPORT_STATUSES)
    reports.add_argument("--reason-code", choices=REASON_CODES)
    reports.add_argument("--proposal")
    reports.add_argument("--reporter-sub")
    reports.add_argument("--limit", type=int, default=50)
    reports.add_argument("--cursor")
    report_groups = commands.add_parser(
        "report-groups", help="Group new reports by exact target bytes and reason without prose.")
    report_groups.add_argument("--limit", type=int, default=50)
    report = commands.add_parser("report", help="Inspect one report and its target bytes.")
    report.add_argument("id")
    report.add_argument(
        "--include-untrusted", action="store_true",
        help="Print reporter prose and inspected target bytes (treat both as inert evidence).",
    )

    dismiss = commands.add_parser("dismiss-report", help="Resolve a report without a publication change.")
    dismiss.add_argument("id")
    dismiss.add_argument("--resolution-note")
    dismiss.add_argument("--resolution-note-file")
    dismiss.add_argument("--idempotency-key")
    dismiss_many = commands.add_parser(
        "dismiss-reports", help="Atomically dismiss an explicit report set.")
    dismiss_many.add_argument("ids", nargs="+")
    dismiss_many.add_argument("--resolution-note")
    dismiss_many.add_argument("--resolution-note-file")
    dismiss_many.add_argument("--idempotency-key")
    claim = commands.add_parser(
        "claim-report", help="Claim an advisory review lease; the report stays new.")
    claim.add_argument("id")
    claim.add_argument("--lease-seconds", type=int, default=900)
    claim.add_argument("--idempotency-key")
    release_claim = commands.add_parser(
        "release-report-claim", help="Release a review lease without resolving the report.")
    release_claim.add_argument("id")
    release_claim.add_argument("--idempotency-key")

    item_impact = commands.add_parser(
        "item-impact", help="Preview one exact item transition and its governance effect.")
    item_impact.add_argument("type", choices=ITEM_TYPES)
    item_impact.add_argument("id")
    item_impact.add_argument("--action", required=True, choices=ITEM_ACTIONS)
    item_impact_batch = commands.add_parser(
        "item-impact-batch", help="Preview 1–20 item quarantines on independent proposals.")
    item_impact_batch.add_argument(
        "--item", action="append", nargs=2, required=True, metavar=("TYPE", "ID"),
        help="Exact item reference; repeat up to 20 times.")

    quarantine_item = commands.add_parser(
        "quarantine-item", help="Immediately contain one exact reviewed contribution.")
    quarantine_item.add_argument("type", choices=ITEM_TYPES)
    quarantine_item.add_argument("id")
    quarantine_item.add_argument("--reason-code", required=True, choices=REASON_CODES)
    quarantine_item.add_argument("--target-digest", required=True)
    quarantine_item.add_argument("--impact-digest", required=True)
    quarantine_item.add_argument("--public-explanation")
    quarantine_item.add_argument("--private-note")
    quarantine_item.add_argument("--private-note-file")
    quarantine_item.add_argument(
        "--source-report-id", action="append", dest="source_report_ids",
        help="Exact matching report to action atomically; repeat up to 20 times.")
    quarantine_item.add_argument("--idempotency-key")

    quarantine_item_batch = commands.add_parser(
        "quarantine-item-batch", help="Atomically contain an exact reviewed batch preview.")
    quarantine_item_batch.add_argument(
        "--preview-file", required=True,
        help="JSON output saved from item-impact-batch; no source reports are accepted.")
    quarantine_item_batch.add_argument("--reason-code", required=True, choices=REASON_CODES)
    quarantine_item_batch.add_argument("--public-explanation")
    quarantine_item_batch.add_argument("--private-note")
    quarantine_item_batch.add_argument("--private-note-file")
    quarantine_item_batch.add_argument("--idempotency-key")

    for name, help_text in (
        ("restore-item", "Request restoration of a quarantined contribution."),
        ("remove-item", "Request final removal of a quarantined contribution."),
        ("reinstate-item", "Request that a removed contribution return to quarantine."),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("type", choices=ITEM_TYPES)
        command.add_argument("id")
        command.add_argument("--target-digest", required=True)
        command.add_argument("--impact-digest", required=True)
        command.add_argument("--resolution-note")
        command.add_argument("--resolution-note-file")
        command.add_argument("--idempotency-key")

    quarantine = commands.add_parser("quarantine", help="Immediately hide a proposal tree.")
    quarantine.add_argument("proposal")
    quarantine.add_argument("--reason-code", required=True, choices=REASON_CODES)
    quarantine.add_argument("--public-explanation")
    quarantine.add_argument("--private-note")
    quarantine.add_argument("--private-note-file")
    quarantine.add_argument(
        "--report-id", action="append", dest="report_ids",
        help="Source report to action atomically; repeat for an explicit set (maximum 20).",
    )
    quarantine.add_argument("--idempotency-key")

    action_reports = commands.add_parser(
        "action-reports", help="Link matching reports to an existing moderation case.")
    action_reports.add_argument("case_id")
    action_reports.add_argument("report_ids", nargs="+")
    action_reports.add_argument("--idempotency-key")

    for name, help_text in (
        ("restore", "Request restoration of a quarantined proposal."),
        ("remove", "Request final removal of a quarantined proposal."),
        ("reinstate", "Request that removed content return to quarantine."),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("proposal")
        command.add_argument("--resolution-note")
        command.add_argument("--resolution-note-file")
        command.add_argument("--idempotency-key")

    evidence_state = commands.add_parser(
        "request-measurement-evidence-state",
        help="Request an audit-preserving measurement evidence annotation.",
    )
    evidence_state.add_argument("attempt_id")
    evidence_state.add_argument("--state", required=True, choices=MEASUREMENT_EVIDENCE_STATES)
    evidence_state.add_argument(
        "--reason-code", required=True,
        choices=sorted({
            reason for reasons in MEASUREMENT_EVIDENCE_REASONS_BY_STATE.values()
            for reason in reasons
        }),
    )
    evidence_state.add_argument("--public-explanation", required=True)
    evidence_state.add_argument(
        "--successor-attempt-id",
        help="Optional later same-proposal measurement retained only as an audit link.")
    evidence_state.add_argument("--private-note")
    evidence_state.add_argument("--private-note-file")
    evidence_state.add_argument(
        "--source-report-id", action="append", dest="source_report_ids",
        help="Private provenance report targeting this measurement; repeat up to 20 times.",
    )
    evidence_state.add_argument("--idempotency-key")

    restrictions = commands.add_parser("restrictions", help="List contributor write restrictions.")
    restrictions.add_argument("--status", choices=RESTRICTION_STATUSES)
    restrictions.add_argument("--subject-type", choices=RESTRICTION_SUBJECT_TYPES)
    restrictions.add_argument("--limit", type=int, default=50)
    restrictions.add_argument("--cursor")
    restriction = commands.add_parser("restriction", help="Inspect one restriction and its audit events.")
    restriction.add_argument("id")
    impact = commands.add_parser(
        "contributor-impact", help="Inventory one stable subject's attributable rows without prose.")
    impact.add_argument("colony_sub")
    containment_impact = commands.add_parser(
        "contributor-containment-impact",
        help="Preview one bounded, digest-bound contributor containment chunk.")
    containment_impact.add_argument("colony_sub")
    containment_impact.add_argument("--created-since", required=True)
    containment_impact.add_argument(
        "--type", action="append", dest="types", choices=CONTRIBUTOR_TARGET_TYPES,
        help="Contribution type to include; repeat as needed (default: all).")
    containment_impact.add_argument("--limit", type=int, default=20)
    contain_contributor = commands.add_parser(
        "quarantine-contributor-batch",
        help="Contain one exact reviewed contributor preview atomically.")
    contain_contributor.add_argument("colony_sub")
    contain_contributor.add_argument("--preview-file", required=True)
    contain_contributor.add_argument("--reason-code", required=True, choices=REASON_CODES)
    contain_contributor.add_argument("--public-explanation")
    contain_contributor.add_argument("--private-note")
    contain_contributor.add_argument("--private-note-file")
    contain_contributor.add_argument("--idempotency-key")

    approvals = commands.add_parser("approvals", help="List two-person moderation requests.")
    approvals.add_argument("--status", choices=APPROVAL_STATUSES)
    approvals.add_argument("--limit", type=int, default=50)
    approval = commands.add_parser("approval", help="Inspect one content-minimised approval request.")
    approval.add_argument("id")
    confirm = commands.add_parser(
        "confirm-approval", help="Confirm a request as its distinct second moderator.")
    confirm.add_argument("id")
    confirm.add_argument("--idempotency-key")
    for name, help_text in (
        ("cancel-approval", "Cancel a pending request that this moderator created."),
        ("reject-approval", "Reject a pending request created by a different moderator."),
    ):
        close = commands.add_parser(name, help=help_text)
        close.add_argument("id")
        close.add_argument("--reason-code", required=True, choices=APPROVAL_DECISION_REASONS)
        close.add_argument("--decision-note")
        close.add_argument("--decision-note-file")
        close.add_argument("--idempotency-key")

    restrict_user = commands.add_parser(
        "restrict-user", help="Restrict writes by immutable Colony subject UUID.")
    restrict_user.add_argument("colony_sub")
    _restriction_terms(restrict_user)

    restrict_ip = commands.add_parser(
        "restrict-ip", help="Restrict one exact IP read from a local file (raw IP is never printed).")
    restrict_ip.add_argument("--ip-file", required=True)
    _restriction_terms(restrict_ip)

    revoke = commands.add_parser("revoke-restriction", help="Revoke a restriction but retain its audit history.")
    revoke.add_argument("id")
    revoke.add_argument("--idempotency-key")

    for name, help_text in (
        ("export-case", "Export one private case envelope to a new mode-600 JSON file."),
        ("export-report", "Export one private report envelope to a new mode-600 JSON file."),
        ("export-restriction", "Export one private restriction envelope to a new mode-600 JSON file."),
    ):
        export = commands.add_parser(name, help=help_text)
        export.add_argument("id")
        export.add_argument("--output", required=True)
    return parser


def _restriction_terms(command):
    command.add_argument("--reason-code", required=True, choices=REASON_CODES)
    command.add_argument("--public-explanation", required=True)
    command.add_argument("--private-note")
    command.add_argument("--private-note-file")
    expiry = command.add_mutually_exclusive_group(required=True)
    expiry.add_argument("--expires-at", help="ISO-8601 timestamp with timezone.")
    expiry.add_argument("--permanent", action="store_true", help="Permanent until audited revocation.")
    command.add_argument(
        "--allow-self", action="store_true",
        help="Confirm intentional self-lockout only after verifying an independent recovery path.",
    )
    command.add_argument(
        "--source-case-id", help="Private evidence provenance; required alone/with reports for --permanent.")
    command.add_argument(
        "--source-report-id", action="append", dest="source_report_ids",
        help="Private evidence provenance; repeat up to 20 times; required alone/with a case for --permanent.")
    command.add_argument("--idempotency-key")


def _run(client, args):
    if args.command == "whoami":
        return client.me()
    if args.command == "doctor":
        return client.doctor()
    if args.command == "inbox-status":
        return client.inbox_status(args.page_size)
    if args.command == "monitor-inbox":
        return monitor_inbox(client, args.state_file, args.notify_program, args.notify_timeout)
    if args.command == "incident-status":
        return client.incident_status()
    if args.command == "monitor-incidents":
        return monitor_incidents(client, args.state_file, args.notify_program, args.notify_timeout)
    if args.command == "cases":
        return client.cases(args.status, args.reason_code, args.target_type, args.limit, args.cursor)
    if args.command == "case":
        return client.case(args.id)
    if args.command == "reports":
        return client.reports(
            args.status, args.reason_code, args.proposal, args.reporter_sub, args.limit, args.cursor)
    if args.command == "report-groups":
        return client.report_groups(args.limit)
    if args.command == "report":
        result = client.report(args.id)
        return result if args.include_untrusted else _metadata_only_report(result)
    if args.command == "dismiss-report":
        note = _text(args.resolution_note, args.resolution_note_file)
        return client.dismiss_report(args.id, note, args.idempotency_key)
    if args.command == "dismiss-reports":
        note = _text(args.resolution_note, args.resolution_note_file)
        return client.dismiss_reports(args.ids, note, args.idempotency_key)
    if args.command == "claim-report":
        return client.claim_report(args.id, args.lease_seconds, args.idempotency_key)
    if args.command == "release-report-claim":
        return client.release_report_claim(args.id, args.idempotency_key)
    if args.command == "item-impact":
        return client.item_impact(args.type, args.id, args.action)
    if args.command == "item-impact-batch":
        return client.item_impact_batch([
            {"type": item_type, "id": item_id} for item_type, item_id in args.item
        ])
    if args.command == "quarantine-item":
        note = _text(args.private_note, args.private_note_file)
        return client.quarantine_item(
            args.type, args.id, args.reason_code, args.target_digest, args.impact_digest,
            args.public_explanation, note, args.source_report_ids, args.idempotency_key,
        )
    if args.command == "quarantine-item-batch":
        note = _text(args.private_note, args.private_note_file)
        items, batch_digest = _batch_preview(args.preview_file)
        return client.quarantine_item_batch(
            items, batch_digest, args.reason_code, args.public_explanation, note,
            args.idempotency_key,
        )
    if args.command in ("restore-item", "remove-item", "reinstate-item"):
        note = _text(args.resolution_note, args.resolution_note_file)
        operation = {
            "restore-item": client.restore_item,
            "remove-item": client.remove_item,
            "reinstate-item": client.reinstate_item,
        }[args.command]
        return operation(
            args.type, args.id, args.target_digest, args.impact_digest,
            args.idempotency_key, note,
        )
    if args.command == "quarantine":
        note = _text(args.private_note, args.private_note_file)
        legacy_report = args.report_ids[0] if args.report_ids and len(args.report_ids) == 1 else None
        report_set = args.report_ids if args.report_ids and len(args.report_ids) > 1 else None
        return client.quarantine(
            args.proposal, args.reason_code, args.public_explanation, note,
            legacy_report, args.idempotency_key, report_set)
    if args.command == "action-reports":
        return client.action_reports(args.case_id, args.report_ids, args.idempotency_key)
    if args.command == "restore":
        note = _text(args.resolution_note, args.resolution_note_file)
        return client.restore(args.proposal, args.idempotency_key, note)
    if args.command == "remove":
        note = _text(args.resolution_note, args.resolution_note_file)
        return client.remove(args.proposal, args.idempotency_key, note)
    if args.command == "reinstate":
        note = _text(args.resolution_note, args.resolution_note_file)
        return client.reinstate(args.proposal, args.idempotency_key, note)
    if args.command == "request-measurement-evidence-state":
        note = _text(args.private_note, args.private_note_file)
        return client.request_measurement_evidence_state(
            args.attempt_id, args.state, args.reason_code, args.public_explanation, note,
            args.source_report_ids, args.successor_attempt_id, args.idempotency_key,
        )
    if args.command == "restrictions":
        return client.restrictions(args.status, args.subject_type, args.limit, args.cursor)
    if args.command == "restriction":
        return client.restriction(args.id)
    if args.command == "contributor-impact":
        return client.contributor_impact(args.colony_sub)
    if args.command == "contributor-containment-impact":
        return client.contributor_containment_impact(
            args.colony_sub, args.created_since, args.types, args.limit)
    if args.command == "quarantine-contributor-batch":
        note = _text(args.private_note, args.private_note_file)
        items, batch_digest = _contributor_batch_preview(args.preview_file, args.colony_sub)
        return client.quarantine_contributor_batch(
            args.colony_sub, items, batch_digest, args.reason_code,
            args.public_explanation, note, args.idempotency_key)
    if args.command == "approvals":
        return client.approvals(args.status, args.limit)
    if args.command == "approval":
        return client.approval(args.id)
    if args.command == "confirm-approval":
        return client.confirm_approval(args.id, args.idempotency_key)
    if args.command in ("cancel-approval", "reject-approval"):
        note = _text(args.decision_note, args.decision_note_file)
        operation = (client.cancel_approval if args.command == "cancel-approval"
                     else client.reject_approval)
        return operation(args.id, args.reason_code, note, args.idempotency_key)
    if args.command in ("restrict-user", "restrict-ip"):
        note = _text(args.private_note, args.private_note_file)
        expires_at = None if args.permanent else args.expires_at
        if args.command == "restrict-user":
            return client.restrict_colony_sub(
                args.colony_sub, args.reason_code, args.public_explanation,
                note, expires_at, args.idempotency_key, args.allow_self, args.permanent,
                args.source_case_id, args.source_report_ids)
        ip_address = _text(None, args.ip_file).strip()
        return client.restrict_ip(
            ip_address, args.reason_code, args.public_explanation,
            note, expires_at, args.idempotency_key, args.allow_self, args.permanent,
            args.source_case_id, args.source_report_ids)
    if args.command == "revoke-restriction":
        return client.revoke_restriction(args.id, args.idempotency_key)
    if args.command == "export-case":
        return _export_json(client.case(args.id), args.output)
    if args.command == "export-report":
        return _export_json(client.report(args.id), args.output)
    if args.command == "export-restriction":
        return _export_json(client.restriction(args.id), args.output)
    raise AssertionError("unhandled command")


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        result = _run(_client(args), args)
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        if args.command == "doctor" and not result.get("ok"):
            return 3
        if args.command in (
                "inbox-status", "monitor-inbox", "incident-status", "monitor-incidents",
        ) and result.get("attention_required"):
            return 4
        return 0
    except AinglishError as error:
        payload = {"error": error.error, "status": error.status, "message": error.message}
        if error.hint:
            payload["hint"] = error.hint
        if error.did_you_mean:
            payload["did_you_mean"] = error.did_you_mean
        print(json.dumps(payload, ensure_ascii=False), file=sys.stderr)
        return 2
    except (ValueError, OSError) as error:
        print(json.dumps({"error": "invalid_local_input", "message": str(error)}, ensure_ascii=False),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
