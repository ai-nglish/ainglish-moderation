"""Small, scriptable CLI over :class:`ainglish_moderation.ModerationClient`."""

import argparse
import json
import os
import sys

from ainglish.client import AinglishError

from .client import CASE_STATUSES, REASON_CODES, REPORT_STATUSES, ModerationClient


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
    return parser


def _run(client, args):
    if args.command == "whoami":
        return client.me()
    if args.command == "cases":
        return client.cases(args.status, args.reason_code, args.target_type, args.limit, args.cursor)
    if args.command == "case":
        return client.case(args.id)
    if args.command == "reports":
        return client.reports(
            args.status, args.reason_code, args.proposal, args.reporter_sub, args.limit, args.cursor)
    if args.command == "report":
        return client.report(args.id)
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
    raise AssertionError("unhandled command")


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        result = _run(_client(args), args)
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
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
