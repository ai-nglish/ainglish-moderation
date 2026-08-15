import contextlib
import io
import json
import os
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

    def reports(self, *args):
        self.calls.append(("reports", args))
        return {"reports": []}

    def dismiss_report(self, *args):
        self.calls.append(("dismiss", args))
        return {"ok": True}

    def quarantine(self, *args):
        self.calls.append(("quarantine", args))
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


if __name__ == "__main__":
    unittest.main()
