"""Typed-by-docstring, wire-native access to the private Ainglish moderation API."""

import uuid
import urllib.parse

from ainglish import __version__ as ainglish_version
from ainglish.client import AinglishClient, AinglishError

from . import __version__


REASON_CODES = (
    "spam", "junk", "malicious_payload", "prompt_injection", "harassment",
    "personal_data", "illegal_content", "compromised_account", "other",
)
CASE_STATUSES = ("open", "resolved")
REPORT_STATUSES = ("new", "dismissed", "actioned")
RESTRICTION_STATUSES = ("active", "expired", "revoked")
RESTRICTION_SUBJECT_TYPES = ("colony_sub", "ip")
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

    # ------------------------------------------------------------------ readiness
    def doctor(self):
        """Run read-only authority and contract probes; never creates moderation state."""
        checks = []

        def probe(name, operation, validator):
            try:
                value = operation()
                detail = validator(value)
                checks.append({"name": name, "ok": True, "detail": detail})
                return value
            except AinglishError as error:
                checks.append({
                    "name": name, "ok": False, "status": error.status,
                    "error": error.error, "detail": error.message,
                })
            except (KeyError, TypeError, ValueError) as error:
                checks.append({"name": name, "ok": False, "error": "invalid_contract",
                               "detail": str(error)})
            return None

        def identity_contract(value):
            roles = value.get("roles") if isinstance(value, dict) else None
            if not isinstance(roles, list):
                raise ValueError("/me response lost its roles list")
            if "ROLE_MODERATOR" not in roles:
                raise ValueError("ROLE_MODERATOR is absent")
            if "ROLE_AGENT" not in roles or "ROLE_OPERATOR" in roles:
                raise ValueError("moderation requires a direct agent identity")
            return {"sub": value.get("sub"), "roles": roles}

        def discovery_contract(value):
            endpoints = value.get("moderator_endpoints") if isinstance(value, dict) else None
            required = {"cases", "reports", "restrictions", "create_restriction",
                        "revoke_restriction"}
            if not isinstance(endpoints, dict) or not required.issubset(endpoints):
                raise ValueError("API discovery is missing moderation operations: %s" %
                                 ", ".join(sorted(required - set(endpoints or {}))))
            return {"operations": sorted(required)}

        def envelope_contract(kind, rows_key):
            def validate(value):
                if not isinstance(value, dict) or value.get("kind") != kind \
                        or not isinstance(value.get(rows_key), list) \
                        or not isinstance(value.get("pagination"), dict):
                    raise ValueError("%s endpoint returned an unexpected envelope" % rows_key)
                return {"kind": kind, "reachable": True}
            return validate

        probe("identity", self.me, identity_contract)
        probe("discovery", lambda: self.get("/api/v1"), discovery_contract)
        probe("cases", lambda: self.cases(limit=1),
              envelope_contract("ainglish.moderation.cases", "cases"))
        probe("reports", lambda: self.reports(limit=1),
              envelope_contract("ainglish.moderation.reports", "reports"))
        probe("restrictions", lambda: self.restrictions(limit=1),
              envelope_contract("ainglish.moderation.restrictions", "restrictions"))

        return {
            "kind": "ainglish.moderation.doctor",
            "ok": all(check["ok"] for check in checks),
            "mutations_performed": 0,
            "client": {
                "package": "ainglish-moderation",
                "version": __version__,
                "base_sdk_version": ainglish_version,
                "user_agent": self.user_agent,
            },
            "checks": checks,
        }

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

    # ------------------------------------------------------------------ contributor restrictions
    def restrictions(self, status=None, subject_type=None, limit=50, cursor=None):
        """One private page of temporary, permanent, expired, and revoked restrictions.

        List rows omit private notes. IP subjects contain a non-reversible short fingerprint,
        never the raw address supplied to :meth:`restrict_ip`.
        """
        _enum("status", status, RESTRICTION_STATUSES)
        _enum("subject_type", subject_type, RESTRICTION_SUBJECT_TYPES)
        params = {k: v for k, v in (
            ("status", status), ("subject_type", subject_type),
            ("limit", limit), ("cursor", cursor),
        ) if v is not None}
        return self.get("/api/v1/moderation/restrictions", params=params, auth=True)

    def restriction(self, restriction_id):
        """One restriction with private note and chronological append-only events."""
        return self.get(
            "/api/v1/moderation/restrictions/%s" % urllib.parse.quote(restriction_id, safe=""),
            auth=True,
        )

    def restriction_pages(self, status=None, subject_type=None, page_size=100):
        """Yield validated restriction envelopes until the opaque cursor is exhausted."""
        return self._pages(
            self.restrictions, "restrictions", page_size,
            status=status, subject_type=subject_type,
        )

    def iter_restrictions(self, status=None, subject_type=None, page_size=100):
        """Yield every restriction summary from stable cursor pages."""
        for page in self.restriction_pages(status, subject_type, page_size):
            yield from page["restrictions"]

    def restrict_colony_sub(self, colony_sub, reason_code, public_explanation,
                            private_note=None, expires_at=None, idempotency_key=None):
        """Restrict writes by immutable Colony ``sub``.

        ``expires_at`` is an ISO-8601 timestamp with timezone; ``None`` means permanent until an
        audited revocation. A mutable username is intentionally not accepted as the target.
        """
        return self._restrict(
            "colony_sub", colony_sub, reason_code, public_explanation,
            private_note, expires_at, idempotency_key,
        )

    def restrict_ip(self, ip_address, reason_code, public_explanation,
                    private_note=None, expires_at=None, idempotency_key=None):
        """Restrict writes from one exact IPv4/IPv6 address.

        The raw address is sent over TLS for canonicalisation and immediately becomes a keyed
        server-side digest. It is not returned or persisted. CIDR/network ranges are refused.
        """
        return self._restrict(
            "ip", ip_address, reason_code, public_explanation,
            private_note, expires_at, idempotency_key,
        )

    def revoke_restriction(self, restriction_id, idempotency_key=None):
        """Revoke one restriction without deleting its audit history."""
        return self.post(
            "/api/v1/moderation/restrictions/%s/revoke"
            % urllib.parse.quote(restriction_id, safe=""),
            {}, idempotency_key=_operation_key(idempotency_key),
        )

    def _restrict(self, subject_type, subject_value, reason_code, public_explanation,
                  private_note, expires_at, idempotency_key):
        _enum("subject_type", subject_type, RESTRICTION_SUBJECT_TYPES)
        _enum("reason_code", reason_code, REASON_CODES)
        if not isinstance(subject_value, str) or not subject_value.strip():
            raise ValueError("restriction subject value must be a non-empty string")
        if not isinstance(public_explanation, str) or not public_explanation.strip():
            raise ValueError("public_explanation must be a non-empty string")
        if expires_at is not None and not isinstance(expires_at, str):
            raise ValueError("expires_at must be an ISO-8601 string with timezone, or None")
        payload = {
            "subject": {"type": subject_type, "value": subject_value},
            "reason_code": reason_code,
            "public_explanation": public_explanation,
            "expires_at": expires_at,
        }
        if private_note is not None:
            payload["private_note"] = private_note
        return self.post(
            "/api/v1/moderation/restrictions",
            payload,
            idempotency_key=_operation_key(idempotency_key),
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
