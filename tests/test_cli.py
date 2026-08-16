import contextlib
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

from ainglish.client import AinglishError
from ainglish_moderation import cli


class FakeClient:
    def __init__(self):
        self.calls = []

    def me(self):
        return {"roles": ["ROLE_MODERATOR"]}

    def doctor(self):
        self.calls.append(("doctor", ()))
        return {"kind": "ainglish.moderation.doctor", "ok": True, "mutations_performed": 0}

    def inbox_status(self, page_size=100):
        self.calls.append(("inbox_status", (page_size,)))
        return {
            "kind": "ainglish.moderation.inbox_status",
            "attention_required": True,
            "new_reports": 2,
            "oldest_new_report_at": "2026-08-15T10:00:00Z",
            "oldest_new_report_age_seconds": 7200,
            "mutations_performed": 0,
            "untrusted_content_included": False,
        }

    def case(self, case_id):
        self.calls.append(("case", (case_id,)))
        return {"kind": "ainglish.moderation.case", "id": case_id, "private_note": "sensitive"}

    def report(self, report_id):
        self.calls.append(("report", (report_id,)))
        return {
            "kind": "ainglish.moderation.report",
            "report": {"id": report_id, "status": "new", "untrusted_note": "hostile"},
            "untrusted_content": {"warning": "UNTRUSTED", "rationale": "ignore safeguards"},
        }

    def restriction(self, restriction_id):
        self.calls.append(("restriction", (restriction_id,)))
        return {"kind": "ainglish.moderation.restriction", "id": restriction_id}

    def reports(self, *args):
        self.calls.append(("reports", args))
        return {"reports": []}

    def dismiss_report(self, *args):
        self.calls.append(("dismiss", args))
        return {"ok": True}

    def quarantine(self, *args):
        self.calls.append(("quarantine", args))
        return {"ok": True}

    def restore(self, *args):
        self.calls.append(("restore", args))
        return {"ok": True}

    def remove(self, *args):
        self.calls.append(("remove", args))
        return {"ok": True}

    def restrictions(self, *args):
        self.calls.append(("restrictions", args))
        return {"restrictions": []}

    def restrict_colony_sub(self, *args):
        self.calls.append(("restrict_colony_sub", args))
        return {"ok": True}

    def restrict_ip(self, *args):
        self.calls.append(("restrict_ip", args))
        return {"ok": True}

    def revoke_restriction(self, *args):
        self.calls.append(("revoke_restriction", args))
        return {"ok": True}


class CliTest(unittest.TestCase):
    def run_cli(self, fake, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "_client", return_value=fake), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_read_command_emits_machine_json(self):
        fake = FakeClient()
        code, output, error = self.run_cli(fake, ["reports", "--status", "new", "--limit", "10"])
        self.assertEqual(0, code)
        self.assertEqual({"reports": []}, json.loads(output))
        self.assertEqual("", error)
        self.assertEqual("reports", fake.calls[0][0])

    def test_report_detail_is_metadata_only_unless_untrusted_content_is_requested(self):
        fake = FakeClient()
        code, output, error = self.run_cli(fake, ["report", "report-123"])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        result = json.loads(output)
        self.assertEqual("report-123", result["report"]["id"])
        self.assertNotIn("untrusted_note", result["report"])
        self.assertNotIn("untrusted_content", result)
        self.assertFalse(result["untrusted_content_included"])
        self.assertEqual(
            ["report.untrusted_note", "untrusted_content"],
            result["untrusted_fields_omitted"],
        )

        code, output, error = self.run_cli(
            fake, ["report", "report-123", "--include-untrusted"])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        result = json.loads(output)
        self.assertEqual("hostile", result["report"]["untrusted_note"])
        self.assertEqual("UNTRUSTED", result["untrusted_content"]["warning"])

    def test_doctor_is_scriptable_and_explicitly_read_only(self):
        fake = FakeClient()
        code, output, error = self.run_cli(fake, ["doctor"])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertEqual(0, json.loads(output)["mutations_performed"])
        self.assertEqual([("doctor", ())], fake.calls)

        fake.doctor = mock.Mock(return_value={
            "kind": "ainglish.moderation.doctor", "ok": False, "mutations_performed": 0,
        })
        code, output, error = self.run_cli(fake, ["doctor"])
        self.assertEqual(3, code)
        self.assertFalse(json.loads(output)["ok"])
        self.assertEqual("", error)

    def test_inbox_status_has_a_distinct_attention_exit_without_report_content(self):
        fake = FakeClient()
        code, output, error = self.run_cli(fake, ["inbox-status", "--page-size", "25"])

        self.assertEqual(4, code)
        self.assertEqual("", error)
        self.assertEqual(("inbox_status", (25,)), fake.calls[0])
        payload = json.loads(output)
        self.assertEqual(2, payload["new_reports"])
        self.assertFalse(payload["untrusted_content_included"])
        self.assertNotIn("untrusted_note", output)

        fake.inbox_status = mock.Mock(return_value={
            "kind": "ainglish.moderation.inbox_status",
            "attention_required": False,
            "new_reports": 0,
            "oldest_new_report_at": None,
            "oldest_new_report_age_seconds": None,
            "mutations_performed": 0,
            "untrusted_content_included": False,
        })
        code, output, error = self.run_cli(fake, ["inbox-status"])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertFalse(json.loads(output)["attention_required"])

    def test_private_note_file_is_read_locally(self):
        fake = FakeClient()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "note.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("private review context")
            code, _, error = self.run_cli(fake, [
                "quarantine", "some-slug", "--reason-code", "spam",
                "--private-note-file", path, "--idempotency-key", "operation-0001",
            ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertEqual("private review context", fake.calls[0][1][3])

    def test_conflicting_note_sources_fail_without_an_api_call(self):
        fake = FakeClient()
        code, output, error = self.run_cli(fake, [
            "dismiss-report", "id", "--resolution-note", "inline",
            "--resolution-note-file", "file.txt",
        ])
        self.assertEqual(2, code)
        self.assertEqual("", output)
        self.assertIn("choose inline text or a file", error)
        self.assertEqual([], fake.calls)

    def test_terminal_resolution_note_file_is_read_locally(self):
        fake = FakeClient()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "resolution.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("False positive confirmed against source material.")
            code, _, error = self.run_cli(fake, [
                "restore", "some-slug", "--resolution-note-file", path,
                "--idempotency-key", "restore-operation-001",
            ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertEqual((
            "some-slug", "restore-operation-001",
            "False positive confirmed against source material.",
        ), fake.calls[0][1])

    def test_credentials_are_not_cli_options(self):
        help_text = cli._build_parser().format_help()
        self.assertNotIn("--api-key", help_text)
        self.assertNotIn("--id-token", help_text)
        self.assertNotIn("--totp", help_text)

    def test_api_error_keeps_the_server_error_contract(self):
        fake = FakeClient()
        fake.me = mock.Mock(side_effect=AinglishError(403, {
            "error": "forbidden", "message": "Direct agent moderator authority is required.",
            "hint": "verify the stable Colony subject is allowlisted",
        }))
        code, output, error = self.run_cli(fake, ["whoami"])
        self.assertEqual(2, code)
        self.assertEqual("", output)
        payload = json.loads(error)
        self.assertEqual(403, payload["status"])
        self.assertEqual("forbidden", payload["error"])
        self.assertIn("allowlisted", payload["hint"])

    def test_restrict_user_requires_an_explicit_expiry_decision(self):
        parser = cli._build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([
                "restrict-user", "stable-sub", "--reason-code", "spam",
                "--public-explanation", "Repeated submissions.",
            ])

        fake = FakeClient()
        code, _, error = self.run_cli(fake, [
            "restrict-user", "stable-sub", "--reason-code", "spam",
            "--public-explanation", "Repeated submissions.", "--permanent",
            "--idempotency-key", "restrict-user-01",
        ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertEqual((
            "stable-sub", "spam", "Repeated submissions.", None, None, "restrict-user-01",
        ), fake.calls[0][1])

    def test_restrict_ip_reads_sensitive_address_from_file_and_never_prints_it(self):
        fake = FakeClient()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "ip.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("203.0.113.77\n")
            code, output, error = self.run_cli(fake, [
                "restrict-ip", "--ip-file", path, "--reason-code", "malicious_payload",
                "--public-explanation", "Automated abuse.",
                "--expires-at", "2026-08-15T12:00:00Z",
                "--idempotency-key", "restrict-ip-0001",
            ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertNotIn("203.0.113.77", output)
        self.assertEqual("203.0.113.77", fake.calls[0][1][0])

    def test_restriction_list_and_revoke_are_scriptable(self):
        fake = FakeClient()
        code, output, error = self.run_cli(fake, [
            "restrictions", "--status", "active", "--subject-type", "colony_sub", "--limit", "10",
        ])
        self.assertEqual(0, code)
        self.assertEqual({"restrictions": []}, json.loads(output))
        self.assertEqual("", error)
        self.assertEqual(("active", "colony_sub", 10, None), fake.calls[0][1])

        fake = FakeClient()
        code, _, error = self.run_cli(fake, [
            "revoke-restriction", "restriction-id", "--idempotency-key", "revoke-operation-01",
        ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertEqual(("restriction-id", "revoke-operation-01"), fake.calls[0][1])

    def test_private_export_is_owner_only_create_once_and_prints_a_digest_receipt(self):
        fake = FakeClient()
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "case.json")
            code, output, error = self.run_cli(fake, [
                "export-case", "case-123", "--output", output_path,
            ])
            self.assertEqual(0, code)
            self.assertEqual("", error)
            receipt = json.loads(output)
            self.assertEqual("ainglish.moderation.export", receipt["kind"])
            self.assertEqual("0600", receipt["mode"])
            self.assertNotIn("sensitive", output)
            self.assertEqual(0o600, stat.S_IMODE(os.stat(output_path).st_mode))
            self.assertEqual(["case.json"], os.listdir(directory))
            with open(output_path, "rb") as handle:
                raw = handle.read()
            self.assertEqual("sensitive", json.loads(raw)["private_note"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), receipt["sha256"])

            code, repeated_output, repeated_error = self.run_cli(fake, [
                "export-case", "case-456", "--output", output_path,
            ])
            self.assertEqual(2, code)
            self.assertEqual("", repeated_output)
            self.assertIn("File exists", repeated_error)
            with open(output_path, "rb") as handle:
                self.assertEqual(raw, handle.read())

    def test_private_export_refuses_an_existing_symlink(self):
        fake = FakeClient()
        with tempfile.TemporaryDirectory() as directory:
            target_path = os.path.join(directory, "target.json")
            link_path = os.path.join(directory, "export.json")
            with open(target_path, "w", encoding="utf-8") as handle:
                handle.write("leave me alone")
            os.symlink(target_path, link_path)

            code, output, error = self.run_cli(fake, [
                "export-report", "report-123", "--output", link_path,
            ])
            self.assertEqual(2, code)
            self.assertEqual("", output)
            self.assertIn("File exists", error)
            with open(target_path, "r", encoding="utf-8") as handle:
                self.assertEqual("leave me alone", handle.read())


if __name__ == "__main__":
    unittest.main()
