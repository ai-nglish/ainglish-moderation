import unittest

from ainglish.client import AinglishError
from ainglish_moderation.client import ModerationClient, USER_AGENT


class Probe(ModerationClient):
    def __init__(self):
        super().__init__(use_env=False)
        self.calls = []
        self.pages = {}

    def get(self, path, params=None, auth=False):
        self.calls.append(("GET", path, params, auth))
        if path.endswith("/cases") or path.endswith("/reports"):
            return self.pages.get(params.get("cursor") if params else None, {})
        return {"path": path}

    def post(self, path, payload, auth=True, idempotency_key=None):
        self.calls.append(("POST", path, payload, auth, idempotency_key))
        return {"path": path, "payload": payload, "idempotency_key": idempotency_key}


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.client = Probe()

    def test_versioned_user_agent_and_private_reads(self):
        self.assertEqual(USER_AGENT, self.client.user_agent)
        self.client.cases(status="open", reason_code="spam", target_type="proposal", limit=20,
                          cursor="opaque")
        self.assertEqual(("GET", "/api/v1/moderation/cases", {
            "status": "open", "reason_code": "spam", "target_type": "proposal",
            "limit": 20, "cursor": "opaque",
        }, True), self.client.calls[-1])
        self.client.case("case/id")
        self.assertEqual("/api/v1/moderation/cases/case%2Fid", self.client.calls[-1][1])

        self.client.reports(status="new", proposal="some-slug", reporter_sub="stable-sub")
        self.assertEqual(True, self.client.calls[-1][3])
        self.client.report("report/id")
        self.assertEqual("/api/v1/moderation/reports/report%2Fid", self.client.calls[-1][1])

    def test_mutations_carry_exact_payloads_and_operation_keys(self):
        result = self.client.quarantine(
            "some slug", "malicious_payload", "Temporarily unavailable.", "private",
            "report-id", "quarantine-operation-001")
        self.assertEqual("/api/v1/moderation/proposals/some%20slug/quarantine", result["path"])
        self.assertEqual({
            "reason_code": "malicious_payload",
            "public_explanation": "Temporarily unavailable.",
            "private_note": "private",
            "report_id": "report-id",
        }, result["payload"])
        self.assertEqual("quarantine-operation-001", result["idempotency_key"])

        dismissed = self.client.dismiss_report("report/id", "benign", "dismiss-operation-001")
        self.assertEqual("/api/v1/moderation/reports/report%2Fid/dismiss", dismissed["path"])
        self.assertEqual({"resolution_note": "benign"}, dismissed["payload"])
        self.assertEqual("dismiss-operation-001", dismissed["idempotency_key"])

        for method, suffix in ((self.client.restore, "restore"), (self.client.remove, "remove")):
            reply = method("some slug")
            self.assertTrue(reply["path"].endswith("/some%20slug/" + suffix))
            self.assertTrue(reply["idempotency_key"].startswith("ainglish-moderation-"))

    def test_invalid_enums_and_keys_refuse_locally(self):
        for call in (
            lambda: self.client.cases(status="pending"),
            lambda: self.client.reports(reason_code="invented"),
            lambda: self.client.quarantine("slug", "invented"),
            lambda: self.client.restore("slug", idempotency_key="short"),
        ):
            with self.assertRaises(ValueError):
                call()
        self.assertEqual([], self.client.calls)

    def test_shared_cursor_traversal_is_complete_and_fail_closed(self):
        self.client.pages = {
            None: {"cases": [{"id": "new"}],
                   "pagination": {"returned": 1, "has_more": True, "next_cursor": "next"}},
            "next": {"cases": [{"id": "old"}],
                     "pagination": {"returned": 1, "has_more": False, "next_cursor": None}},
        }
        self.assertEqual(["new", "old"], [row["id"] for row in self.client.iter_cases(page_size=1)])

        self.client.calls.clear()
        self.client.pages = {
            None: {"reports": [],
                   "pagination": {"returned": 0, "has_more": True, "next_cursor": "same"}},
            "same": {"reports": [],
                     "pagination": {"returned": 0, "has_more": True, "next_cursor": "same"}},
        }
        with self.assertRaises(AinglishError) as raised:
            list(self.client.iter_reports(page_size=1))
        self.assertEqual("invalid_pagination", raised.exception.error)
        self.assertIn("advance", raised.exception.message)

        for size in (0, 101, True, "20"):
            with self.assertRaises(ValueError):
                list(self.client.iter_cases(page_size=size))


if __name__ == "__main__":
    unittest.main()
