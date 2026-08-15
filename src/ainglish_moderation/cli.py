"""Small, scriptable CLI over :class:`ainglish_moderation.ModerationClient`."""

import argparse
import hashlib
import json
import os
import sys
import tempfile

from ainglish.client import AinglishError

from .client import (
    CASE_STATUSES, REASON_CODES, REPORT_STATUSES, RESTRICTION_STATUSES,
    RESTRICTION_SUBJECT_TYPES, ModerationClient,
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

    cases = commands.add_parser("cases", help="List moderation cases.")
    cases.add_argument("--status", choices=CASE_STATUSES)
    cases.add_argument("--reason-code", choices=REASON_CODES)
    cases.add_argument("--target-type", choices=("proposal",))
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

    quarantine = commands.add_parser("quarantine", help="Immediately hide a proposal tree.")
    quarantine.add_argument("proposal")
    quarantine.add_argument("--reason-code", required=True, choices=REASON_CODES)
    quarantine.add_argument("--public-explanation")
    quarantine.add_argument("--private-note")
    quarantine.add_argument("--private-note-file")
    quarantine.add_argument("--report-id")
    quarantine.add_argument("--idempotency-key")

    for name, help_text in (("restore", "Restore a quarantined proposal."),
                            ("remove", "Mark a quarantined proposal removed.")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("proposal")
        command.add_argument("--idempotency-key")

    restrictions = commands.add_parser("restrictions", help="List contributor write restrictions.")
    restrictions.add_argument("--status", choices=RESTRICTION_STATUSES)
    restrictions.add_argument("--subject-type", choices=RESTRICTION_SUBJECT_TYPES)
    restrictions.add_argument("--limit", type=int, default=50)
    restrictions.add_argument("--cursor")
    restriction = commands.add_parser("restriction", help="Inspect one restriction and its audit events.")
    restriction.add_argument("id")

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
    command.add_argument("--idempotency-key")


def _run(client, args):
    if args.command == "whoami":
        return client.me()
    if args.command == "doctor":
        return client.doctor()
    if args.command == "cases":
        return client.cases(args.status, args.reason_code, args.target_type, args.limit, args.cursor)
    if args.command == "case":
        return client.case(args.id)
    if args.command == "reports":
        return client.reports(
            args.status, args.reason_code, args.proposal, args.reporter_sub, args.limit, args.cursor)
    if args.command == "report":
        result = client.report(args.id)
        return result if args.include_untrusted else _metadata_only_report(result)
    if args.command == "dismiss-report":
        note = _text(args.resolution_note, args.resolution_note_file)
        return client.dismiss_report(args.id, note, args.idempotency_key)
    if args.command == "quarantine":
        note = _text(args.private_note, args.private_note_file)
        return client.quarantine(
            args.proposal, args.reason_code, args.public_explanation, note,
            args.report_id, args.idempotency_key)
    if args.command == "restore":
        return client.restore(args.proposal, args.idempotency_key)
    if args.command == "remove":
        return client.remove(args.proposal, args.idempotency_key)
    if args.command == "restrictions":
        return client.restrictions(args.status, args.subject_type, args.limit, args.cursor)
    if args.command == "restriction":
        return client.restriction(args.id)
    if args.command in ("restrict-user", "restrict-ip"):
        note = _text(args.private_note, args.private_note_file)
        expires_at = None if args.permanent else args.expires_at
        if args.command == "restrict-user":
            return client.restrict_colony_sub(
                args.colony_sub, args.reason_code, args.public_explanation,
                note, expires_at, args.idempotency_key)
        ip_address = _text(None, args.ip_file).strip()
        return client.restrict_ip(
            ip_address, args.reason_code, args.public_explanation,
            note, expires_at, args.idempotency_key)
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
