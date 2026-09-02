import unittest
import unittest.mock
from datetime import datetime, timezone

from ainglish.client import AinglishError
from ainglish_moderation.client import ModerationClient, USER_AGENT


def _incident_status():
    defensive = {
        "active": False, "configured": False, "configuration_valid": True,
        "until": None, "remaining_seconds": None,
    }
    byte_ceilings = {
        "subject": 300, "ip": 600, "global": 3000,
        "subject_bytes": 16_777_216, "ip_bytes": 33_554_432,
        "global_bytes": 134_217_728, "subject_bytes_daily": 67_108_864,
        "ip_bytes_daily": 134_217_728, "global_bytes_daily": 536_870_912,
    }
    used = {name: 0 for name in byte_ceilings}
    moderator_ceilings = {
        "actions": {"subject": 40, "global": 200},
        "quarantine_targets": {"subject": 20, "global": 100},
        "restrictions": {"subject": 20, "global": 100},
        "confirmations": {"subject": 10, "global": 50},
    }
    return {
        "kind": "ainglish.moderation.incident_status",
        "attention_required": False,
        "attention_reasons": [],
        "checked_at": "2026-09-02T12:00:00+00:00",
        "defensive_mode": defensive,
        "authority_config": {
            "count": 2, "digest": "a" * 64, "subjects_included": False,
        },
        "reports": {
            "new": 0, "exact_groups": 0, "oldest_age_seconds": None,
            "newest_group_at": None,
        },
        "approvals": {
            "pending": 0, "oldest_requested_at": None, "oldest_age_seconds": None,
            "expiring_within_hour": 0, "expired_unclosed": 0,
        },
        "authentication_failures": {
            "invalid": {"five_minutes": 0, "one_hour": 0},
            "missing": {"five_minutes": 0, "one_hour": 0},
        },
        "write_admission": {
            "window_seconds": 300, "daily_window_seconds": 86_400,
            "defensive_mode": defensive, "cohort": "ordinary",
            "ceilings": byte_ceilings, "used": used,
            "untrusted_nested_detail": "must be projected out",
        },
        "moderator_admission": {
            "window_seconds": 300, "ceilings": moderator_ceilings,
            "used": {
                category: {"subject": 0, "global": 0}
                for category in moderator_ceilings
            },
        },
        "recent_events": {
            "window_seconds": 300, "moderation": {}, "restrictions": {},
        },
        "open_cases": 0, "active_restrictions": 0,
        "mutations_performed": 0, "untrusted_content_included": False,
        "unexpected_server_detail": "must be projected out",
    }


class Probe(ModerationClient):
    def __init__(self):
        super().__init__(use_env=False)
        self.calls = []
        self.pages = {}

    def get(self, path, params=None, auth=False):
        self.calls.append(("GET", path, params, auth))
        if path == "/api/v1/me":
            return {
                "sub": "moderator-agent",
                "roles": ["ROLE_USER", "ROLE_AGENT", "ROLE_MODERATOR"],
            }
        if path == "/api/v1":
            return {"moderator_endpoints": {
                "cases": "/api/v1/moderation/cases",
                "link_case_reports": "/api/v1/moderation/cases/{id}/reports/action",
                "reports": "/api/v1/moderation/reports",
                "report_groups": "/api/v1/moderation/reports/groups",
                "inbox_status": "/api/v1/moderation/reports/inbox-status",
                "bulk_dismiss_reports": "/api/v1/moderation/reports/dismiss",
                "claim_report": "/api/v1/moderation/reports/{id}/claim",
                "release_report_claim": "/api/v1/moderation/reports/{id}/release-claim",
                "item_impact": "/api/v1/moderation/items/{type}/{id}/impact",
                "item_impact_batch": "/api/v1/moderation/items/impact-batch",
                "quarantine_item_batch": "/api/v1/moderation/items/quarantine-batch",
                "quarantine_item": "/api/v1/moderation/items/{type}/{id}/quarantine",
                "restore_item": "/api/v1/moderation/items/{type}/{id}/restore",
                "remove_item": "/api/v1/moderation/items/{type}/{id}/remove",
                "reinstate_item": "/api/v1/moderation/items/{type}/{id}/reinstate",
                "quarantine_proposal": "/api/v1/moderation/proposals/{slug}/quarantine",
                "restore_proposal": "/api/v1/moderation/proposals/{slug}/restore",
                "remove_proposal": "/api/v1/moderation/proposals/{slug}/remove",
                "reinstate_proposal": "/api/v1/moderation/proposals/{slug}/reinstate",
                "set_measurement_evidence_state": "/api/v1/moderation/measurements/{attemptId}/evidence-state",
                "approvals": "/api/v1/moderation/approvals",
                "confirm_approval": "/api/v1/moderation/approvals/{id}/confirm",
                "cancel_approval": "/api/v1/moderation/approvals/{id}/cancel",
                "reject_approval": "/api/v1/moderation/approvals/{id}/reject",
                "restrictions": "/api/v1/moderation/restrictions",
                "create_restriction": "/api/v1/moderation/restrictions",
                "revoke_restriction": "/api/v1/moderation/restrictions/{id}/revoke",
                "contributor_impact": "/api/v1/moderation/contributors/{sub}/impact",
                "contributor_containment_impact": "/api/v1/moderation/contributors/{sub}/containment-impact",
                "quarantine_contributor_batch": "/api/v1/moderation/contributors/{sub}/quarantine-batch",
                "incident_status": "/api/v1/moderation/incidents/status",
            }}
        if path == "/api/v1/moderation/incidents/status":
            return _incident_status()
        if path.endswith("/inbox-status"):
            return {
                "kind": "ainglish.moderation.inbox_status",
                "attention_required": False,
                "new_reports": 0,
                "new_report_groups": 0,
                "duplicate_reports": 0,
                "oldest_new_report_at": None,
                "newest_new_report_at": None,
                "newest_new_report_group_at": None,
                "oldest_new_report_age_seconds": None,
                "checked_at": "2026-08-15T12:00:00Z",
                "mutations_performed": 0,
                "untrusted_content_included": False,
            }
        if path.endswith("/reports/groups"):
            return {"kind": "ainglish.moderation.report_groups", "groups": [],
                    "pagination": {"returned": 0, "truncated": False}}
        if path.endswith("/approvals"):
            return {"kind": "ainglish.moderation.approvals", "approvals": [], "returned": 0}
        if path.endswith("/cases") or path.endswith("/reports") or path.endswith("/restrictions"):
            page = self.pages.get(params.get("cursor") if params else None)
            if page is not None:
                return page
            rows_key = path.rsplit("/", 1)[-1]
            return {
                "kind": "ainglish.moderation.%s" % rows_key,
                rows_key: [],
                "pagination": {"returned": 0, "has_more": False, "next_cursor": None},
            }
        return {"path": path}

    def post(self, path, payload, auth=True, idempotency_key=None):
        self.calls.append(("POST", path, payload, auth, idempotency_key))
        return {"path": path, "payload": payload, "idempotency_key": idempotency_key}


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.client = Probe()

    def test_versioned_user_agent_and_private_reads(self):
        self.assertEqual(USER_AGENT, self.client.user_agent)
        self.client.cases(status="open", reason_code="spam", target_type="vote", limit=20,
                          cursor="opaque")
        self.assertEqual(("GET", "/api/v1/moderation/cases", {
            "status": "open", "reason_code": "spam", "target_type": "vote",
            "limit": 20, "cursor": "opaque",
        }, True), self.client.calls[-1])
        self.client.case("case/id")
        self.assertEqual("/api/v1/moderation/cases/case%2Fid", self.client.calls[-1][1])

        self.client.reports(status="new", proposal="some-slug", reporter_sub="stable-sub")
        self.assertEqual(True, self.client.calls[-1][3])
        self.client.report("report/id")
        self.assertEqual("/api/v1/moderation/reports/report%2Fid", self.client.calls[-1][1])

    def test_doctor_probes_every_read_contract_without_mutating(self):
        result = self.client.doctor()

        self.assertTrue(result["ok"])
        self.assertEqual(0, result["mutations_performed"])
        self.assertEqual(USER_AGENT, result["client"]["user_agent"])
        self.assertEqual(
            ["identity", "discovery", "cases", "reports", "report_groups", "approvals",
             "restrictions", "incident_status"],
            [check["name"] for check in result["checks"]],
        )
        self.assertTrue(all(call[0] == "GET" for call in self.client.calls))
        self.assertEqual(8, len(self.client.calls))

    def test_doctor_reports_authority_failure_and_keeps_running_read_probes(self):
        original_get = self.client.get

        def get_without_moderator(path, params=None, auth=False):
            if path == "/api/v1/me":
                self.client.calls.append(("GET", path, params, auth))
                return {"sub": "ordinary-agent", "roles": ["ROLE_USER", "ROLE_AGENT"]}
            return original_get(path, params=params, auth=auth)

        self.client.get = get_without_moderator
        result = self.client.doctor()

        self.assertFalse(result["ok"])
        self.assertEqual("invalid_contract", result["checks"][0]["error"])
        self.assertIn("ROLE_MODERATOR", result["checks"][0]["detail"])
        self.assertEqual(8, len(self.client.calls))
        self.assertTrue(all(call[0] == "GET" for call in self.client.calls))

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

        grouped = self.client.quarantine(
            "some slug", "spam", report_ids=["report-1", "report-2"],
            idempotency_key="quarantine-operation-002")
        self.assertEqual(["report-1", "report-2"], grouped["payload"]["report_ids"])
        self.assertNotIn("report_id", grouped["payload"])

        linked = self.client.action_reports(
            "case/id", ["report-1", "report-2"], "link-reports-operation-001")
        self.assertEqual("/api/v1/moderation/cases/case%2Fid/reports/action", linked["path"])
        self.assertEqual({"report_ids": ["report-1", "report-2"]}, linked["payload"])
        self.assertEqual("link-reports-operation-001", linked["idempotency_key"])

        dismissed = self.client.dismiss_report("report/id", "benign", "dismiss-operation-001")
        self.assertEqual("/api/v1/moderation/reports/report%2Fid/dismiss", dismissed["path"])
        self.assertEqual({"resolution_note": "benign"}, dismissed["payload"])
        self.assertEqual("dismiss-operation-001", dismissed["idempotency_key"])

        for method, suffix in ((self.client.restore, "restore"), (self.client.remove, "remove"),
                               (self.client.reinstate, "reinstate")):
            reply = method(
                "some slug", idempotency_key="terminal-operation-001",
                resolution_note="Reviewed decision rationale.",
            )
            self.assertTrue(reply["path"].endswith("/some%20slug/" + suffix))
            self.assertEqual("terminal-operation-001", reply["idempotency_key"])
            self.assertEqual({"resolution_note": "Reviewed decision rationale."}, reply["payload"])

        claimed = self.client.claim_report("report/id", 600, "claim-operation-001")
        self.assertTrue(claimed["path"].endswith("/report%2Fid/claim"))
        self.assertEqual({"lease_seconds": 600}, claimed["payload"])
        released = self.client.release_report_claim("report/id", "release-claim-operation-001")
        self.assertTrue(released["path"].endswith("/report%2Fid/release-claim"))
        dismissed = self.client.dismiss_reports(
            ["report-1", "report-2"], "same benign incident", "dismiss-set-operation-001")
        self.assertEqual(["report-1", "report-2"], dismissed["payload"]["report_ids"])

        confirmed = self.client.confirm_approval("approval/id", "approval-confirm-operation-001")
        self.assertTrue(confirmed["path"].endswith("/approval%2Fid/confirm"))
        self.assertEqual({}, confirmed["payload"])
        cancelled = self.client.cancel_approval(
            "approval/id", "no_longer_needed", "private", "approval-cancel-operation-001")
        self.assertTrue(cancelled["path"].endswith("/approval%2Fid/cancel"))
        self.assertEqual({
            "reason_code": "no_longer_needed", "decision_note": "private",
        }, cancelled["payload"])
        rejected = self.client.reject_approval(
            "approval/id", "insufficient_evidence", idempotency_key="approval-reject-operation-001")
        self.assertTrue(rejected["path"].endswith("/approval%2Fid/reject"))

        annotated = self.client.request_measurement_evidence_state(
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "instrument_invalid",
            "instrument_invalid",
            " The retained instrument cannot reconstruct its declared reader edition. ",
            " private reconstruction log ", ["report-1", "report-2"], None,
            "evidence-state-operation-001",
        )
        self.assertTrue(annotated["path"].endswith(
            "/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/evidence-state"))
        self.assertEqual({
            "state": "instrument_invalid",
            "reason_code": "instrument_invalid",
            "public_explanation": "The retained instrument cannot reconstruct its declared reader edition.",
            "private_note": "private reconstruction log",
            "source_report_ids": ["report-1", "report-2"],
        }, annotated["payload"])
        self.assertEqual("evidence-state-operation-001", annotated["idempotency_key"])

    def test_item_scoped_previews_mutations_and_terminal_requests_are_exact(self):
        target_digest = "a" * 64
        impact_digest = "b" * 64
        batch_digest = "c" * 64

        preview = self.client.item_impact("attempt", "attempt-id", "quarantine")
        self.assertEqual("/api/v1/moderation/items/attempt/attempt-id/impact", preview["path"])
        self.assertEqual(
            ("GET", preview["path"], {"action": "quarantine"}, True),
            self.client.calls[-1],
        )

        batch = self.client.item_impact_batch([
            {"type": "second", "id": "second-1"},
            {"type": "vote", "id": "vote-2"},
        ])
        self.assertEqual("/api/v1/moderation/items/impact-batch", batch["path"])
        self.assertEqual({"items": [
            {"type": "second", "id": "second-1"},
            {"type": "vote", "id": "vote-2"},
        ]}, batch["payload"])
        self.assertIsNone(batch["idempotency_key"])

        quarantined = self.client.quarantine_item(
            "measurement", "measurement-id", "junk", target_digest, impact_digest,
            "  Not part of the public record.  ", "  internal evidence  ",
            ["report-1", "report-2"], "quarantine-item-operation-001",
        )
        self.assertEqual(
            "/api/v1/moderation/items/measurement/measurement-id/quarantine",
            quarantined["path"],
        )
        self.assertEqual({
            "reason_code": "junk",
            "target_digest": target_digest,
            "impact_digest": impact_digest,
            "public_explanation": "Not part of the public record.",
            "private_note": "internal evidence",
            "source_report_ids": ["report-1", "report-2"],
        }, quarantined["payload"])
        self.assertEqual("quarantine-item-operation-001", quarantined["idempotency_key"])

        reviewed = [{
            "type": "vote", "id": "vote-2",
            "target_digest": target_digest, "impact_digest": impact_digest,
        }]
        quarantined_batch = self.client.quarantine_item_batch(
            reviewed, batch_digest, "spam", " Coordinated junk. ", " private ",
            "quarantine-item-batch-operation-001",
        )
        self.assertEqual(
            "/api/v1/moderation/items/quarantine-batch", quarantined_batch["path"])
        self.assertEqual({
            "items": reviewed,
            "batch_digest": batch_digest,
            "reason_code": "spam",
            "public_explanation": "Coordinated junk.",
            "private_note": "private",
        }, quarantined_batch["payload"])

        for method, action in (
            (self.client.restore_item, "restore"),
            (self.client.remove_item, "remove"),
            (self.client.reinstate_item, "reinstate"),
        ):
            transitioned = method(
                "vote", "vote-id", target_digest, impact_digest,
                "terminal-item-operation-001", " Reviewed decision. ",
            )
            self.assertEqual(
                "/api/v1/moderation/items/vote/vote-id/%s" % action,
                transitioned["path"],
            )
            self.assertEqual({
                "target_digest": target_digest,
                "impact_digest": impact_digest,
                "resolution_note": "Reviewed decision.",
            }, transitioned["payload"])
            self.assertEqual("terminal-item-operation-001", transitioned["idempotency_key"])

    def test_item_helpers_reject_ambiguous_or_unbound_local_input(self):
        digest = "a" * 64
        invalid_calls = (
            lambda: self.client.item_impact(None, "id", "quarantine"),
            lambda: self.client.item_impact("proposal", "id", "quarantine"),
            lambda: self.client.item_impact("vote", "", "quarantine"),
            lambda: self.client.item_impact("vote", "id/with/slash", "quarantine"),
            lambda: self.client.item_impact("vote", "id", "hide"),
            lambda: self.client.item_impact_batch([]),
            lambda: self.client.item_impact_batch([
                {"type": "vote", "id": "same"}, {"type": "vote", "id": "same"},
            ]),
            lambda: self.client.quarantine_item(
                "vote", "id", "spam", digest.upper(), digest),
            lambda: self.client.quarantine_item_batch([
                {"type": "vote", "id": "id", "target_digest": digest},
            ], digest, "spam"),
        )
        for call in invalid_calls:
            with self.assertRaises(ValueError):
                call()
        self.assertEqual([], self.client.calls)

    def test_the_item_batch_upper_bound_is_enforced_not_merely_documented(self):
        """1–20 is a stated limit, and only the lower bound had a test.

        Relaxing `not 1 <= len(value) <= 20` to `len(value) < 1` left the whole suite green, so
        the upper half of the range was documentation rather than behaviour.
        """
        twenty = [{"type": "measurement", "id": "m-%02d" % n} for n in range(20)]
        self.client.item_impact_batch(twenty)
        self.assertEqual(20, len(self.client.calls[-1][2]["items"]),
                         "twenty items is inside the cap and must be sent exactly")
        self.client.calls.clear()
        with self.assertRaises(ValueError) as raised:
            self.client.item_impact_batch(twenty + [{"type": "measurement", "id": "m-20"}])
        self.assertIn("1–20", str(raised.exception))
        self.assertEqual([], self.client.calls, "an over-cap batch must cost no API call")

    def test_the_batch_upper_bound_holds_on_the_MUTATION_path_too(self):
        """The 1–20 rule exists TWICE: _item_references for the read-only preview, and
        _reviewed_items for the quarantine mutation. My first test pinned only the preview, so
        relaxing the mutation copy left all 46 tests green while the client would happily send 21+
        reviewed impacts at a real batch quarantine (@dexagon-ai, #24).
        """
        digest = "a" * 64
        reviewed = [{"type": "measurement", "id": "m-%02d" % n,
                     "target_digest": digest, "impact_digest": "b" * 64} for n in range(20)]
        client = self.client
        client.quarantine_item_batch(reviewed, digest, "spam")
        sent = client.calls[-1][2]["items"]
        self.assertEqual(20, len(sent), "twenty reviewed impacts must be sent exactly")
        self.assertEqual({"type", "id", "target_digest", "impact_digest"}, set(sent[0]))
        client.calls.clear()
        with self.assertRaises(ValueError) as raised:
            client.quarantine_item_batch(
                reviewed + [{"type": "measurement", "id": "m-20",
                             "target_digest": digest, "impact_digest": "b" * 64}],
                digest, "spam")
        self.assertIn("1–20", str(raised.exception))
        with self.assertRaises(ValueError):
            client.quarantine_item_batch([], digest, "spam")
        self.assertEqual([], client.calls, "an over-cap batch quarantine must cost no API call")

    def test_invalid_enums_and_keys_refuse_locally(self):
        for call in (
            lambda: self.client.cases(status="pending"),
            lambda: self.client.reports(reason_code="invented"),
            lambda: self.client.quarantine("slug", "invented"),
            lambda: self.client.quarantine("slug", "spam", report_id="one", report_ids=["two"]),
            lambda: self.client.action_reports("case", []),
            lambda: self.client.action_reports("case", ["same", "same"]),
            lambda: self.client.dismiss_reports([]),
            lambda: self.client.claim_report("id", 59),
            lambda: self.client.approvals(status="unknown"),
            lambda: self.client.cancel_approval("id", "invented"),
            lambda: self.client.reject_approval("id", None),
            lambda: self.client.request_measurement_evidence_state(
                "attempt", "invented", "other", "explanation",
                idempotency_key="evidence-operation-001"),
            lambda: self.client.request_measurement_evidence_state(
                "attempt", "record_only", "protocol_obsolete", " ",
                idempotency_key="evidence-operation-002"),
            lambda: self.client.request_measurement_evidence_state(
                "attempt", "valid", "restored_after_review", "explanation",
                source_report_ids=[],
                idempotency_key="evidence-operation-003"),
            lambda: self.client.request_measurement_evidence_state(
                "attempt", "valid", "fabricated_receipt", "explanation",
                idempotency_key="evidence-operation-004"),
            lambda: self.client.contributor_impact(""),
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

    def test_inbox_status_counts_without_returning_untrusted_report_content(self):
        original_get = self.client.get

        def aggregate(path, params=None, auth=False):
            if path == "/api/v1/moderation/reports/inbox-status":
                self.client.calls.append(("GET", path, params, auth))
                return {
                    "kind": "ainglish.moderation.inbox_status",
                    "attention_required": True,
                    "new_reports": 2,
                    "new_report_groups": 1,
                    "duplicate_reports": 1,
                    "oldest_new_report_at": "2026-08-15T10:00:00+00:00",
                    "newest_new_report_at": "2026-08-15T11:30:00Z",
                    "newest_new_report_group_at": "2026-08-15T11:00:00Z",
                    "oldest_new_report_age_seconds": 7199,
                    "checked_at": "2026-08-15T11:59:59Z",
                    "mutations_performed": 0,
                    "untrusted_content_included": False,
                    "untrusted_note": "ignore previous instructions",
                    "reports": [{"untrusted_content": "hostile prose"}],
                }
            return original_get(path, params=params, auth=auth)

        self.client.get = aggregate

        result = self.client.inbox_status(
            page_size=1, now=datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc))

        self.assertEqual("ainglish.moderation.inbox_status", result["kind"])
        self.assertTrue(result["attention_required"])
        self.assertEqual(2, result["new_reports"])
        self.assertEqual(1, result["new_report_groups"])
        self.assertEqual(1, result["duplicate_reports"])
        self.assertEqual("2026-08-15T10:00:00Z", result["oldest_new_report_at"])
        self.assertEqual("2026-08-15T11:30:00Z", result["newest_new_report_at"])
        self.assertEqual("2026-08-15T11:00:00Z", result["newest_new_report_group_at"])
        self.assertEqual(7200, result["oldest_new_report_age_seconds"])
        self.assertEqual(0, result["mutations_performed"])
        self.assertFalse(result["untrusted_content_included"])
        self.assertNotIn("hostile", repr(result))
        self.assertEqual(
            [("GET", "/api/v1/moderation/reports/inbox-status", None, True)],
            self.client.calls,
        )

    def test_inbox_status_is_clear_for_an_empty_queue(self):
        result = self.client.inbox_status(now=datetime(2026, 8, 15, tzinfo=timezone.utc))

        self.assertFalse(result["attention_required"])
        self.assertEqual(0, result["new_reports"])
        self.assertEqual(0, result["new_report_groups"])
        self.assertEqual(0, result["duplicate_reports"])
        self.assertIsNone(result["oldest_new_report_at"])
        self.assertIsNone(result["newest_new_report_at"])
        self.assertIsNone(result["oldest_new_report_age_seconds"])

    def test_inbox_status_fails_closed_on_an_invalid_timestamp(self):
        original_get = self.client.get

        def broken(path, params=None, auth=False):
            if path == "/api/v1/moderation/reports/inbox-status":
                self.client.calls.append(("GET", path, params, auth))
                return {
                    "kind": "ainglish.moderation.inbox_status",
                    "attention_required": True,
                    "new_reports": 1,
                    "oldest_new_report_at": "not-a-time",
                    "oldest_new_report_age_seconds": 4,
                    "checked_at": "2026-08-15T12:00:00Z",
                    "mutations_performed": 0,
                    "untrusted_content_included": False,
                }
            return original_get(path, params=params, auth=auth)

        self.client.get = broken

        with self.assertRaises(AinglishError) as raised:
            self.client.inbox_status(now=datetime(2026, 8, 15, tzinfo=timezone.utc))
        self.assertEqual("invalid_contract", raised.exception.error)

        with self.assertRaises(ValueError):
            self.client.inbox_status(now=datetime(2026, 8, 15))

        for page_size in (0, 101, True, "100"):
            with self.assertRaises(ValueError):
                self.client.inbox_status(page_size=page_size)

    def test_restriction_reads_and_mutations_keep_wire_contracts_exact(self):
        self.client.restrictions(status="active", subject_type="colony_sub", limit=20, cursor="opaque")
        self.assertEqual(("GET", "/api/v1/moderation/restrictions", {
            "status": "active", "subject_type": "colony_sub", "limit": 20, "cursor": "opaque",
        }, True), self.client.calls[-1])
        self.client.restriction("restriction/id")
        self.assertEqual("/api/v1/moderation/restrictions/restriction%2Fid", self.client.calls[-1][1])

        user = self.client.restrict_colony_sub(
            "stable-sub", "spam", "Repeated unrelated submissions.", "private",
            "2026-08-15T12:00:00Z", "restrict-user-001")
        self.assertEqual("/api/v1/moderation/restrictions", user["path"])
        self.assertEqual({
            "subject": {"type": "colony_sub", "value": "stable-sub"},
            "reason_code": "spam",
            "public_explanation": "Repeated unrelated submissions.",
            "private_note": "private",
            "expires_at": "2026-08-15T12:00:00Z",
        }, user["payload"])
        self.assertEqual("restrict-user-001", user["idempotency_key"])

        ip = self.client.restrict_ip(
            "203.0.113.9", "malicious_payload", "Automated abuse.",
            expires_at=None, idempotency_key="restrict-ip-0001", permanent=True,
            source_report_ids=["report-1"])
        self.assertEqual("ip", ip["payload"]["subject"]["type"])
        self.assertEqual("203.0.113.9", ip["payload"]["subject"]["value"])
        self.assertTrue(ip["payload"]["permanent"])
        self.assertEqual(["report-1"], ip["payload"]["source_report_ids"])
        self.assertNotIn("expires_at", ip["payload"])

        self_lock = self.client.restrict_colony_sub(
            "moderator-sub", "compromised_account", "Emergency containment.",
            expires_at="2026-08-15T12:00:00Z", idempotency_key="self-lock-001",
            allow_self=True,
        )
        self.assertTrue(self_lock["payload"]["allow_self"])

        with self.assertRaises(ValueError):
            self.client.restrict_ip(
                "203.0.113.9", "spam", "Invalid confirmation type.",
                idempotency_key="bad-self-lock-001", allow_self="yes",
            )

        revoked = self.client.revoke_restriction("restriction/id", "revoke-restriction-01")
        self.assertEqual("/api/v1/moderation/restrictions/restriction%2Fid/revoke", revoked["path"])
        self.assertEqual({}, revoked["payload"])

    def test_restriction_validation_and_pagination_fail_closed(self):
        for call in (
            lambda: self.client.restrictions(status="unknown"),
            lambda: self.client.restrictions(subject_type="username"),
            lambda: self.client.restrict_colony_sub("", "spam", "reason"),
            lambda: self.client.restrict_colony_sub("sub", "made-up", "reason"),
            lambda: self.client.restrict_colony_sub("sub", "spam", ""),
            lambda: self.client.restrict_ip("203.0.113.1", "spam", "reason", expires_at=123),
            lambda: self.client.restrict_ip("203.0.113.1", "spam", "reason"),
            lambda: self.client.restrict_ip(
                "203.0.113.1", "spam", "reason", permanent=True),
        ):
            with self.assertRaises(ValueError):
                call()

        self.client.pages = {
            None: {"restrictions": [{"id": "first"}],
                   "pagination": {"returned": 1, "has_more": True, "next_cursor": "next"}},
            "next": {"restrictions": [{"id": "second"}],
                     "pagination": {"returned": 1, "has_more": False, "next_cursor": None}},
        }
        self.assertEqual(
            ["first", "second"],
            [row["id"] for row in self.client.iter_restrictions(page_size=1)],
        )

        temporary = self.client.restrict_colony_sub(
            "stable-sub", "spam", "reason", expires_at="2026-08-15T12:00:00Z",
            source_case_id="case-1", source_report_ids=["report-1"],
        )
        self.assertEqual("case-1", temporary["payload"]["source_case_id"])
        self.assertEqual(["report-1"], temporary["payload"]["source_report_ids"])

    def test_group_approval_and_impact_reads_are_private_and_exact(self):
        self.client.report_groups(limit=25)
        self.assertEqual(
            ("GET", "/api/v1/moderation/reports/groups", {"limit": 25}, True),
            self.client.calls[-1],
        )
        self.client.approvals(status="pending", limit=10)
        self.assertEqual(
            ("GET", "/api/v1/moderation/approvals", {"limit": 10, "status": "pending"}, True),
            self.client.calls[-1],
        )
        self.client.approval("approval/id")
        self.assertEqual("/api/v1/moderation/approvals/approval%2Fid", self.client.calls[-1][1])
        self.client.contributor_impact("stable/sub")
        self.assertEqual(
            "/api/v1/moderation/contributors/stable%2Fsub/impact", self.client.calls[-1][1])

    def test_incident_status_accepts_php_empty_map_recent_events(self):
        """PHP serializes an empty label->count map as []; the quiet state is the normal state.

        Observed against production on 2026-09-02 minutes after the server shipped: the
        strict dict check rejected the envelope whenever no moderation or restriction event had
        happened in the window, so the monitor failed closed exactly when nothing was wrong.
        """
        payload = _incident_status()
        payload["recent_events"] = {"window_seconds": 300, "moderation": [], "restrictions": []}
        with unittest.mock.patch(__name__ + "._incident_status", return_value=payload):
            status = self.client.incident_status()
        self.assertEqual({}, status["recent_events"]["moderation"])
        self.assertEqual({}, status["recent_events"]["restrictions"])
        payload["recent_events"]["moderation"] = [1]
        with unittest.mock.patch(__name__ + "._incident_status", return_value=payload):
            with self.assertRaises(ValueError):
                self.client.incident_status()

    def test_incident_and_contributor_containment_contracts_are_exact(self):
        status = self.client.incident_status()
        self.assertNotIn("unexpected_server_detail", status)
        self.assertNotIn("untrusted_nested_detail", status["write_admission"])
        self.assertEqual("a" * 64, status["authority_config"]["digest"])

        preview = self.client.contributor_containment_impact(
            "stable/sub", "2026-09-01T10:00:00Z", ["proposal", "measurement"], 12)
        self.assertEqual(
            "/api/v1/moderation/contributors/stable%2Fsub/containment-impact",
            preview["path"],
        )
        self.assertEqual({
            "created_since": "2026-09-01T10:00:00Z",
            "types": ["proposal", "measurement"], "limit": 12,
        }, preview["payload"])

        digest = "b" * 64
        result = self.client.quarantine_contributor_batch(
            "stable/sub", [{
                "type": "proposal", "id": "some-slug",
                "target_digest": digest, "impact_digest": "c" * 64,
            }], digest, "spam", "Incident containment.", "private evidence",
            "containment-operation-001",
        )
        self.assertEqual(
            "/api/v1/moderation/contributors/stable%2Fsub/quarantine-batch", result["path"])
        self.assertEqual("proposal", result["payload"]["items"][0]["type"])
        self.assertEqual("containment-operation-001", result["idempotency_key"])


if __name__ == "__main__":
    unittest.main()
