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
            "new_report_groups": 1,
            "duplicate_reports": 1,
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

    def report_groups(self, *args):
        self.calls.append(("report_groups", args))
        return {"groups": []}

    def dismiss_report(self, *args):
        self.calls.append(("dismiss", args))
        return {"ok": True}

    def dismiss_reports(self, *args):
        self.calls.append(("dismiss_reports", args))
        return {"ok": True}

    def claim_report(self, *args):
        self.calls.append(("claim_report", args))
        return {"ok": True}

    def release_report_claim(self, *args):
        self.calls.append(("release_report_claim", args))
        return {"ok": True}

    def item_impact(self, *args):
        self.calls.append(("item_impact", args))
        return {"kind": "ainglish.moderation.item_impact"}

    def item_impact_batch(self, *args):
        self.calls.append(("item_impact_batch", args))
        return {"kind": "ainglish.moderation.item_batch_impact"}

    def quarantine_item(self, *args):
        self.calls.append(("quarantine_item", args))
        return {"ok": True}

    def quarantine_item_batch(self, *args):
        self.calls.append(("quarantine_item_batch", args))
        return {"ok": True}

    def restore_item(self, *args):
        self.calls.append(("restore_item", args))
        return {"approval": {"status": "pending"}}

    def remove_item(self, *args):
        self.calls.append(("remove_item", args))
        return {"approval": {"status": "pending"}}

    def reinstate_item(self, *args):
        self.calls.append(("reinstate_item", args))
        return {"approval": {"status": "pending"}}

    def quarantine(self, *args):
        self.calls.append(("quarantine", args))
        return {"ok": True}

    def restore(self, *args):
        self.calls.append(("restore", args))
        return {"ok": True}

    def remove(self, *args):
        self.calls.append(("remove", args))
        return {"ok": True}

    def reinstate(self, *args):
        self.calls.append(("reinstate", args))
        return {"ok": True}

    def request_measurement_evidence_state(self, *args):
        self.calls.append(("request_measurement_evidence_state", args))
        return {"approval": {"status": "pending"}, "evidence_changed": False}

    def action_reports(self, *args):
        self.calls.append(("action_reports", args))
        return {"ok": True}

    def restrictions(self, *args):
        self.calls.append(("restrictions", args))
        return {"restrictions": []}

    def contributor_impact(self, *args):
        self.calls.append(("contributor_impact", args))
        return {"kind": "ainglish.moderation.contributor_impact"}

    def approvals(self, *args):
        self.calls.append(("approvals", args))
        return {"approvals": []}

    def approval(self, *args):
        self.calls.append(("approval", args))
        return {"approval": {"id": args[0]}}

    def confirm_approval(self, *args):
        self.calls.append(("confirm_approval", args))
        return {"approval": {"status": "confirmed"}}

    def cancel_approval(self, *args):
        self.calls.append(("cancel_approval", args))
        return {"approval": {"status": "cancelled"}}

    def reject_approval(self, *args):
        self.calls.append(("reject_approval", args))
        return {"approval": {"status": "rejected"}}

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

    def test_monitor_inbox_uses_a_distinct_attention_exit(self):
        fake = FakeClient()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                cli, "monitor_inbox", return_value={
                    "kind": "ainglish.moderation.inbox_transition",
                    "attention_required": True,
                    "transition": "initial_attention",
                    "untrusted_content_included": False,
                }) as monitor:
            state_path = os.path.join(directory, "state.json")
            code, output, error = self.run_cli(fake, [
                "monitor-inbox", "--state-file", state_path,
            ])
        self.assertEqual(4, code)
        self.assertEqual("", error)
        self.assertTrue(json.loads(output)["attention_required"])
        monitor.assert_called_once_with(fake, state_path, None, 15.0)

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

    def test_repeated_report_ids_and_later_case_linking_are_explicit(self):
        fake = FakeClient()
        code, _, error = self.run_cli(fake, [
            "quarantine", "some-slug", "--reason-code", "spam",
            "--report-id", "report-1", "--report-id", "report-2",
            "--idempotency-key", "multi-report-operation",
        ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertEqual((
            "some-slug", "spam", None, None, None, "multi-report-operation",
            ["report-1", "report-2"],
        ), fake.calls[0][1])

        fake = FakeClient()
        code, _, error = self.run_cli(fake, [
            "action-reports", "case-1", "report-1", "report-2",
            "--idempotency-key", "later-report-operation",
        ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertEqual((
            "case-1", ["report-1", "report-2"], "later-report-operation",
        ), fake.calls[0][1])

    def test_scalable_triage_commands_are_explicit_and_scriptable(self):
        fake = FakeClient()
        cases = (
            (["report-groups", "--limit", "12"], "report_groups", (12,)),
            (["claim-report", "report-1", "--lease-seconds", "600",
              "--idempotency-key", "claim-operation-001"],
             "claim_report", ("report-1", 600, "claim-operation-001")),
            (["release-report-claim", "report-1", "--idempotency-key", "release-operation-001"],
             "release_report_claim", ("report-1", "release-operation-001")),
            (["dismiss-reports", "report-1", "report-2", "--resolution-note", "same incident",
              "--idempotency-key", "dismiss-set-operation-001"],
             "dismiss_reports", (["report-1", "report-2"], "same incident",
                                 "dismiss-set-operation-001")),
        )
        for argv, name, arguments in cases:
            fake.calls.clear()
            code, output, error = self.run_cli(fake, argv)
            self.assertEqual(0, code)
            self.assertEqual("", error)
            self.assertTrue(json.loads(output)["ok"] if name != "report_groups" else True)
            self.assertEqual((name, arguments), fake.calls[0])

    def test_item_preview_quarantine_and_terminal_commands_are_exact(self):
        fake = FakeClient()
        digest_a = "a" * 64
        digest_b = "b" * 64
        commands = (
            (["item-impact", "attempt", "attempt-id", "--action", "quarantine"],
             ("item_impact", ("attempt", "attempt-id", "quarantine"))),
            (["quarantine-item", "vote", "vote-1", "--reason-code", "spam",
              "--target-digest", digest_a, "--impact-digest", digest_b,
              "--public-explanation", "Not part of the register.",
              "--source-report-id", "report-1", "--source-report-id", "report-2",
              "--idempotency-key", "quarantine-item-operation-001"],
             ("quarantine_item", (
                 "vote", "vote-1", "spam", digest_a, digest_b,
                 "Not part of the register.", None, ["report-1", "report-2"],
                 "quarantine-item-operation-001"))),
            (["restore-item", "second", "second-1", "--target-digest", digest_a,
              "--impact-digest", digest_b, "--resolution-note", "False positive.",
              "--idempotency-key", "restore-item-operation-001"],
             ("restore_item", (
                 "second", "second-1", digest_a, digest_b,
                 "restore-item-operation-001", "False positive."))),
            (["remove-item", "measurement", "measurement-1", "--target-digest", digest_a,
              "--impact-digest", digest_b, "--idempotency-key", "remove-item-operation-001"],
             ("remove_item", (
                 "measurement", "measurement-1", digest_a, digest_b,
                 "remove-item-operation-001", None))),
            (["reinstate-item", "attempt", "attempt-1", "--target-digest", digest_a,
              "--impact-digest", digest_b,
              "--idempotency-key", "reinstate-item-operation-001"],
             ("reinstate_item", (
                 "attempt", "attempt-1", digest_a, digest_b,
                 "reinstate-item-operation-001", None))),
        )
        for argv, expected in commands:
            fake.calls.clear()
            code, _, error = self.run_cli(fake, argv)
            self.assertEqual(0, code)
            self.assertEqual("", error)
            self.assertEqual(expected, fake.calls[0])

    def test_item_batch_preview_and_saved_preview_quarantine_are_exact(self):
        fake = FakeClient()
        code, output, error = self.run_cli(fake, [
            "item-impact-batch",
            "--item", "second", "second-1",
            "--item", "vote", "vote-2",
        ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertEqual("ainglish.moderation.item_batch_impact", json.loads(output)["kind"])
        self.assertEqual(("item_impact_batch", ([
            {"type": "second", "id": "second-1"},
            {"type": "vote", "id": "vote-2"},
        ],)), fake.calls[0])

        target_digest = "a" * 64
        impact_digest = "b" * 64
        batch_digest = "c" * 64
        preview = {
            "kind": "ainglish.moderation.item_batch_impact",
            "batch_digest": batch_digest,
            "items": [{
                "target": {"type": "vote", "id": "vote-2", "digest": target_digest},
                "impact_digest": impact_digest,
                "unrelated_server_field": "ignored",
            }],
            "unrelated_server_field": "ignored",
        }
        fake.calls.clear()
        with tempfile.TemporaryDirectory() as directory:
            preview_path = os.path.join(directory, "preview.json")
            note_path = os.path.join(directory, "note.txt")
            with open(preview_path, "w", encoding="utf-8") as handle:
                json.dump(preview, handle)
            with open(note_path, "w", encoding="utf-8") as handle:
                handle.write("private incident evidence")
            code, _, error = self.run_cli(fake, [
                "quarantine-item-batch", "--preview-file", preview_path,
                "--reason-code", "junk", "--private-note-file", note_path,
                "--idempotency-key", "quarantine-batch-operation-001",
            ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertEqual(("quarantine_item_batch", ([{
            "type": "vote", "id": "vote-2", "target_digest": target_digest,
            "impact_digest": impact_digest,
        }], batch_digest, "junk", None, "private incident evidence",
            "quarantine-batch-operation-001")), fake.calls[0])

    def test_invalid_item_batch_preview_refuses_without_an_api_call(self):
        fake = FakeClient()
        with tempfile.TemporaryDirectory() as directory:
            preview_path = os.path.join(directory, "preview.json")
            with open(preview_path, "w", encoding="utf-8") as handle:
                json.dump({"kind": "unexpected", "items": []}, handle)
            code, output, error = self.run_cli(fake, [
                "quarantine-item-batch", "--preview-file", preview_path,
                "--reason-code", "junk",
            ])
        self.assertEqual(2, code)
        self.assertEqual("", output)
        self.assertIn("not an item batch impact envelope", error)
        self.assertEqual([], fake.calls)

    def test_two_person_and_impact_commands_are_scriptable(self):
        fake = FakeClient()
        for argv, expected in (
            (["reinstate", "some-slug", "--resolution-note", "new evidence",
              "--idempotency-key", "reinstate-operation-001"],
             ("reinstate", ("some-slug", "reinstate-operation-001", "new evidence"))),
            (["approvals", "--status", "pending", "--limit", "10"],
             ("approvals", ("pending", 10))),
            (["approval", "approval-1"], ("approval", ("approval-1",))),
            (["confirm-approval", "approval-1", "--idempotency-key", "confirm-operation-001"],
             ("confirm_approval", ("approval-1", "confirm-operation-001"))),
            (["cancel-approval", "approval-1", "--reason-code", "no_longer_needed",
              "--decision-note", "superseded", "--idempotency-key", "cancel-operation-001"],
             ("cancel_approval", ("approval-1", "no_longer_needed", "superseded",
                                  "cancel-operation-001"))),
            (["reject-approval", "approval-1", "--reason-code", "insufficient_evidence",
              "--idempotency-key", "reject-operation-001"],
             ("reject_approval", ("approval-1", "insufficient_evidence", None,
                                  "reject-operation-001"))),
            (["contributor-impact", "stable-sub"],
             ("contributor_impact", ("stable-sub",))),
            (["request-measurement-evidence-state", "attempt-1", "--state", "record_only",
              "--public-explanation", "Useful record, but not a settlement voice.",
              "--source-report-id", "report-1", "--idempotency-key", "evidence-operation-001"],
             ("request_measurement_evidence_state", (
                 "attempt-1", "record_only", "Useful record, but not a settlement voice.",
                 None, ["report-1"], "evidence-operation-001"))),
        ):
            fake.calls.clear()
            code, _, error = self.run_cli(fake, argv)
            self.assertEqual(0, code)
            self.assertEqual("", error)
            self.assertEqual(expected, fake.calls[0])

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
            "--source-report-id", "report-1",
            "--idempotency-key", "restrict-user-01",
        ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertEqual((
            "stable-sub", "spam", "Repeated submissions.", None, None, "restrict-user-01", False,
            True, None, ["report-1"],
        ), fake.calls[0][1])

        fake = FakeClient()
        code, _, error = self.run_cli(fake, [
            "restrict-user", "moderator-sub", "--reason-code", "compromised_account",
            "--public-explanation", "Emergency containment.", "--expires-at", "2026-08-15T12:00:00Z",
            "--allow-self", "--idempotency-key", "self-restrict-001",
        ])
        self.assertEqual(0, code)
        self.assertEqual("", error)
        self.assertTrue(fake.calls[0][1][6])
        self.assertFalse(fake.calls[0][1][7])

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
