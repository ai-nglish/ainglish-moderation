import json
import os
import stat
import tempfile
import unittest
from unittest import mock

from ainglish_moderation.monitor import monitor_inbox


def _receipt(attention, count=0):
    return {
        "kind": "ainglish.moderation.inbox_status",
        "attention_required": attention,
        "new_reports": count,
        "oldest_new_report_age_seconds": 120 if attention else None,
        "untrusted_note": "never forward or persist this",
        "untrusted_content_included": False,
        "mutations_performed": 0,
    }


class FakeClient:
    def __init__(self, values):
        self.values = iter(values)

    def inbox_status(self):
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return value


class MonitorTest(unittest.TestCase):
    def _notifier(self, directory, exit_status=0):
        events_path = os.path.join(directory, "events.jsonl")
        notifier_path = os.path.join(directory, "notify")
        with open(notifier_path, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/python3\n")
            handle.write("import sys\n")
            handle.write("with open(%r, 'a', encoding='utf-8') as output:\n" % events_path)
            handle.write("    output.write(sys.stdin.read())\n")
            handle.write("raise SystemExit(%d)\n" % exit_status)
        os.chmod(notifier_path, 0o700)
        return notifier_path, events_path

    def _events(self, path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return [json.loads(line) for line in handle]
        except FileNotFoundError:
            return []

    def test_initial_clear_is_stored_privately_without_a_notification(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = os.path.join(directory, "state.json")
            notifier, events = self._notifier(directory)
            result = monitor_inbox(FakeClient([_receipt(False)]), state_path, notifier)

            self.assertEqual("initial_clear", result["transition"])
            self.assertFalse(result["notified"])
            self.assertEqual([], self._events(events))
            self.assertEqual(0o600, stat.S_IMODE(os.stat(state_path).st_mode))
            with open(state_path, "r", encoding="utf-8") as handle:
                state_text = handle.read()
            self.assertNotIn("never forward", state_text)
            self.assertEqual("clear", json.loads(state_text)["status"])

    def test_notifies_once_per_attention_and_recovery_transition(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = os.path.join(directory, "state.json")
            notifier, events = self._notifier(directory)

            first = monitor_inbox(FakeClient([_receipt(True, 2)]), state_path, notifier)
            unchanged = monitor_inbox(FakeClient([_receipt(True, 3)]), state_path, notifier)
            cleared = monitor_inbox(FakeClient([_receipt(False)]), state_path, notifier)

            self.assertEqual("initial_attention", first["transition"])
            self.assertTrue(first["notified"])
            self.assertEqual("unchanged", unchanged["transition"])
            self.assertFalse(unchanged["notified"])
            self.assertEqual("cleared", cleared["transition"])
            self.assertTrue(cleared["notified"])
            emitted = self._events(events)
            self.assertEqual(["initial_attention", "cleared"], [e["transition"] for e in emitted])
            self.assertTrue(all(e["untrusted_content_included"] is False for e in emitted))
            self.assertNotIn("never forward", json.dumps(emitted))

    def test_probe_failure_and_recovery_each_notify_once_without_error_text(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = os.path.join(directory, "state.json")
            notifier, events = self._notifier(directory)

            with self.assertRaisesRegex(RuntimeError, "sensitive server detail"):
                monitor_inbox(
                    FakeClient([RuntimeError("sensitive server detail")]), state_path, notifier)
            with self.assertRaises(RuntimeError):
                monitor_inbox(FakeClient([RuntimeError("another detail")]), state_path, notifier)
            result = monitor_inbox(FakeClient([_receipt(False)]), state_path, notifier)

            emitted = self._events(events)
            self.assertEqual(
                ["initial_failure", "recovered_clear"], [e["transition"] for e in emitted])
            self.assertNotIn("sensitive", json.dumps(emitted))
            self.assertNotIn("another detail", json.dumps(emitted))
            self.assertEqual("recovered_clear", result["transition"])

    def test_failed_notifier_does_not_advance_state_and_is_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = os.path.join(directory, "state.json")
            notifier, _ = self._notifier(directory, exit_status=9)

            with self.assertRaisesRegex(OSError, "exit status 9"):
                monitor_inbox(FakeClient([_receipt(True, 1)]), state_path, notifier)
            self.assertFalse(os.path.exists(state_path))

    def test_state_symlink_and_unsafe_notifier_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target_path = os.path.join(directory, "target.json")
            state_path = os.path.join(directory, "state.json")
            with open(target_path, "w", encoding="utf-8") as handle:
                handle.write('{"version":1,"status":"clear"}\n')
            os.symlink(target_path, state_path)
            with self.assertRaises(OSError):
                monitor_inbox(FakeClient([_receipt(False)]), state_path)

            os.unlink(state_path)
            notifier, _ = self._notifier(directory)
            os.chmod(notifier, 0o722)
            with self.assertRaisesRegex(ValueError, "writable by group"):
                monitor_inbox(FakeClient([_receipt(True, 1)]), state_path, notifier)

    def test_notifier_does_not_inherit_ainglish_or_colony_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = os.path.join(directory, "state.json")
            captured_path = os.path.join(directory, "captured.json")
            notifier_path = os.path.join(directory, "notify")
            with open(notifier_path, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/python3\n")
                handle.write("import json, os, sys\n")
                handle.write("sys.stdin.read()\n")
                handle.write("with open(%r, 'w') as output:\n" % captured_path)
                handle.write("    json.dump(dict(os.environ), output)\n")
            os.chmod(notifier_path, 0o700)

            with mock.patch.dict(os.environ, {
                "COLONY_API_KEY": "secret-colony-key",
                "AINGLISH_ID_TOKEN": "secret-id-token",
                "AINGLISH_TOTP_SECRET_FILE": "/private/seed",
            }):
                monitor_inbox(FakeClient([_receipt(True, 1)]), state_path, notifier_path)
            with open(captured_path, "r", encoding="utf-8") as handle:
                environment = json.load(handle)
            self.assertNotIn("COLONY_API_KEY", environment)
            self.assertNotIn("AINGLISH_ID_TOKEN", environment)
            self.assertNotIn("AINGLISH_TOTP_SECRET_FILE", environment)


if __name__ == "__main__":
    unittest.main()
