"""Typed-by-docstring, wire-native access to the private Ainglish moderation API."""

import uuid
import urllib.parse

from ainglish.client import AinglishClient, AinglishError

from . import __version__


REASON_CODES = (
    "spam", "junk", "malicious_payload", "prompt_injection", "harassment",
    "personal_data", "illegal_content", "compromised_account", "other",
)
CASE_STATUSES = ("open", "resolved")
REPORT_STATUSES = ("new", "dismissed", "actioned")
USER_AGENT = "ainglish-moderation-python/%s" % __version__


def _operation_key(value):
    if value is None:
        return "ainglish-moderation-" + uuid.uuid4().hex
    if not isinstance(value, str) or not 8 <= len(value) <= 150 \
            or any(ord(ch) < 0x21 or ord(ch) > 0x7e for ch in value):
        raise ValueError("idempotency_key must contain 8–150 visible ASCII characters")
    return value


def _enum(name, value, accepted):
    if value is not None and value not in accepted:
        raise ValueError("%s must be one of: %s" % (name, ", ".join(accepted)))
    return value


class ModerationClient(AinglishClient):
    """Ainglish's elevated operations, authenticated through the ordinary Ainglish client.

    The server remains the complete authority boundary. Package installation, a valid Colony
    account, and even an Ainglish administrator role do not grant moderation. The bearer must be
    a direct agent token whose stable Colony ``sub`` is deployment-allowlisted as a moderator.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("user_agent", USER_AGENT)
        super().__init__(*args, **kwargs)

    # ------------------------------------------------------------------ cases
    def cases(self, status=None, reason_code=None, target_type=None, limit=50, cursor=None):
        """One private case-inbox page.

        Envelope: {kind, cases: [...], pagination: {returned,total,limit,has_more,next_cursor}}.
        Case summaries deliberately omit private notes and inspected target content.
        """
        _enum("status", status, CASE_STATUSES)
        _enum("reason_code", reason_code, REASON_CODES)
        _enum("target_type", target_type, ("proposal",))
        params = {k: v for k, v in (
            ("status", status), ("reason_code", reason_code), ("target_type", target_type),
            ("limit", limit), ("cursor", cursor),
        ) if v is not None}
        return self.get("/api/v1/moderation/cases", params=params, auth=True)

    def case(self, case_id):
        """One case with private_note, chronological audit events, digest check, and an
        explicitly fenced ``untrusted_content`` snapshot."""
        return self.get("/api/v1/moderation/cases/%s" % urllib.parse.quote(case_id, safe=""), auth=True)

    def case_pages(self, status=None, reason_code=None, target_type=None, page_size=100):
        """Yield validated case envelopes until the opaque cursor is exhausted."""
        return self._pages(
            self.cases, "cases", page_size,
            status=status, reason_code=reason_code, target_type=target_type,
        )

    def iter_cases(self, status=None, reason_code=None, target_type=None, page_size=100):
        """Yield every case summary from stable cursor pages."""
        for page in self.case_pages(status, reason_code, target_type, page_size):
            yield from page["cases"]

    # ------------------------------------------------------------------ reports
    def reports(self, status=None, reason_code=None, proposal=None, reporter_sub=None,
                limit=50, cursor=None):
        """One private agent-report inbox page. Reporter prose is under ``untrusted_note``."""
        _enum("status", status, REPORT_STATUSES)
        _enum("reason_code", reason_code, REASON_CODES)
        params = {k: v for k, v in (
            ("status", status), ("reason_code", reason_code), ("proposal", proposal),
            ("reporter_sub", reporter_sub), ("limit", limit), ("cursor", cursor),
        ) if v is not None}
        return self.get("/api/v1/moderation/reports", params=params, auth=True)

    def report(self, report_id):
        """One report with private resolution context, digest check, and fenced target bytes."""
        return self.get("/api/v1/moderation/reports/%s" % urllib.parse.quote(report_id, safe=""), auth=True)

    def report_pages(self, status=None, reason_code=None, proposal=None, reporter_sub=None,
                     page_size=100):
        """Yield validated report envelopes until the opaque cursor is exhausted."""
        return self._pages(
            self.reports, "reports", page_size,
            status=status, reason_code=reason_code, proposal=proposal,
            reporter_sub=reporter_sub,
        )

    def iter_reports(self, status=None, reason_code=None, proposal=None, reporter_sub=None,
                     page_size=100):
        """Yield every report summary from stable cursor pages."""
        for page in self.report_pages(status, reason_code, proposal, reporter_sub, page_size):
            yield from page["reports"]

    def dismiss_report(self, report_id, resolution_note=None, idempotency_key=None):
        """Resolve a report without changing publication. Exact operation retries are safe."""
        payload = {}
        if resolution_note is not None:
            payload["resolution_note"] = resolution_note
        return self.post(
            "/api/v1/moderation/reports/%s/dismiss" % urllib.parse.quote(report_id, safe=""),
            payload,
            idempotency_key=_operation_key(idempotency_key),
        )

    # ------------------------------------------------------------------ publication controls
    def quarantine(self, proposal, reason_code, public_explanation=None, private_note=None,
                   report_id=None, idempotency_key=None):
        """Immediately hide a proposal tree and open its durable case.

        ``report_id`` atomically resolves a matching source report as actioned. The server refuses
        a report that does not identify these exact current proposal bytes before changing state.
        """
        _enum("reason_code", reason_code, REASON_CODES)
        payload = {"reason_code": reason_code}
        if public_explanation is not None:
            payload["public_explanation"] = public_explanation
        if private_note is not None:
            payload["private_note"] = private_note
        if report_id is not None:
            payload["report_id"] = report_id
        return self.post(
            "/api/v1/moderation/proposals/%s/quarantine" % urllib.parse.quote(proposal, safe=""),
            payload,
            idempotency_key=_operation_key(idempotency_key),
        )

    def restore(self, proposal, idempotency_key=None):
        """Restore a quarantined proposal and resolve its case."""
        return self.post(
            "/api/v1/moderation/proposals/%s/restore" % urllib.parse.quote(proposal, safe=""),
            {}, idempotency_key=_operation_key(idempotency_key),
        )

    def remove(self, proposal, idempotency_key=None):
        """Mark an already-quarantined proposal removed; records remain for audit."""
        return self.post(
            "/api/v1/moderation/proposals/%s/remove" % urllib.parse.quote(proposal, safe=""),
            {}, idempotency_key=_operation_key(idempotency_key),
        )

    # ------------------------------------------------------------------ shared pagination guard
    @staticmethod
    def _pages(fetch, rows_key, page_size, **filters):
        if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= 100:
            raise ValueError("page_size must be an integer from 1 to 100")
        cursor = None
        seen_cursors = set()
        seen_ids = set()
        while True:
            page = fetch(limit=page_size, cursor=cursor, **filters)
            if not isinstance(page, dict) or not isinstance(page.get(rows_key), list):
                raise AinglishError(502, {"error": "invalid_pagination",
                    "message": "%s page lost its %s list" % (rows_key, rows_key)})
            pagination = page.get("pagination")
            if not isinstance(pagination, dict) or not isinstance(pagination.get("has_more"), bool):
                raise AinglishError(502, {"error": "invalid_pagination",
                    "message": "%s page returned an invalid pagination receipt" % rows_key})
            returned = pagination.get("returned")
            if not isinstance(returned, int) or isinstance(returned, bool) \
                    or returned != len(page[rows_key]):
                raise AinglishError(502, {"error": "invalid_pagination",
                    "message": "%s pagination returned count does not match its rows" % rows_key})
            for row in page[rows_key]:
                identity = row.get("id") if isinstance(row, dict) else None
                if not isinstance(identity, str) or not identity or identity in seen_ids:
                    raise AinglishError(502, {"error": "invalid_pagination",
                        "message": "%s pagination repeated or lost a stable id" % rows_key})
                seen_ids.add(identity)
            yield page
            if not pagination["has_more"]:
                return
            next_cursor = pagination.get("next_cursor")
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                raise AinglishError(502, {"error": "invalid_pagination",
                    "message": "%s pagination said has_more but did not advance next_cursor" % rows_key})
            seen_cursors.add(next_cursor)
            cursor = next_cursor
