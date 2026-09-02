"""Typed-by-docstring, wire-native access to the private Ainglish moderation API."""

import uuid
import urllib.parse
from datetime import datetime, timezone

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
APPROVAL_STATUSES = ("pending", "confirmed", "cancelled", "rejected", "expired")
APPROVAL_DECISION_REASONS = (
    "no_longer_needed", "target_changed", "insufficient_evidence", "unsafe_request", "other",
)
MEASUREMENT_EVIDENCE_STATES = (
    "valid", "record_only", "instrument_invalid", "result_invalid",
)
MEASUREMENT_EVIDENCE_REASONS_BY_STATE = {
    "valid": ("restored_after_review",),
    "record_only": ("protocol_obsolete", "insufficient_retained_material", "other"),
    "instrument_invalid": (
        "instrument_invalid", "insufficient_retained_material", "other",
    ),
    "result_invalid": (
        "value_not_reproducible", "manifest_result_mismatch", "fabricated_receipt", "other",
    ),
}
ITEM_TYPES = ("second", "attempt", "measurement", "vote")
CONTRIBUTOR_TARGET_TYPES = ("proposal",) + ITEM_TYPES
ITEM_ACTIONS = ("quarantine", "restore", "remove", "reinstate")
CASE_TARGET_TYPES = ("proposal",) + ITEM_TYPES
INCIDENT_ATTENTION_REASONS = (
    "new_reports", "approval_backlog_age", "expired_approval_rows",
    "defensive_mode_active", "defensive_mode_configuration_invalid",
    "authentication_failure_surge", "admission_budget_pressure",
)
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


def _report_ids(value):
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= 20:
        raise ValueError("report_ids must be a non-empty list of at most 20 report id strings")
    result = []
    for report_id in value:
        if not isinstance(report_id, str) or not report_id.strip():
            raise ValueError("every report_ids item must be a non-empty string")
        report_id = report_id.strip()
        if report_id in result:
            raise ValueError("report_ids must not contain duplicates")
        result.append(report_id)
    return result


def _digest(name, value):
    if not isinstance(value, str) or len(value) != 64 \
            or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError("%s must be a lowercase SHA-256 digest" % name)
    return value


def _item_reference(item_type, item_id, accepted_types=ITEM_TYPES):
    if not isinstance(item_type, str):
        raise ValueError("item_type is required")
    _enum("item_type", item_type, accepted_types)
    item_id = item_id.strip() if isinstance(item_id, str) else ""
    if not item_id or len(item_id) > 191 \
            or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-"
                   for ch in item_id):
        raise ValueError("item_id must contain 1–191 ASCII letters, digits, or hyphens")
    return {"type": item_type, "id": item_id}


def _item_references(value):
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= 20:
        raise ValueError("items must be a list of 1–20 exact item references")
    result = []
    identities = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"type", "id"}:
            raise ValueError("each item must contain exactly type and id")
        reference = _item_reference(item["type"], item["id"])
        identity = (reference["type"], reference["id"])
        if identity in identities:
            raise ValueError("items must not contain duplicate references")
        identities.add(identity)
        result.append(reference)
    return result


def _reviewed_items(value, accepted_types=ITEM_TYPES):
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= 20:
        raise ValueError("items must be a list of 1–20 reviewed item impacts")
    result = []
    identities = set()
    expected = {"type", "id", "target_digest", "impact_digest"}
    for item in value:
        if not isinstance(item, dict) or set(item) != expected:
            raise ValueError(
                "each reviewed item must contain exactly type, id, target_digest and impact_digest")
        reference = _item_reference(item["type"], item["id"], accepted_types)
        identity = (reference["type"], reference["id"])
        if identity in identities:
            raise ValueError("items must not contain duplicate references")
        identities.add(identity)
        result.append({
            **reference,
            "target_digest": _digest("target_digest", item["target_digest"]),
            "impact_digest": _digest("impact_digest", item["impact_digest"]),
        })
    return result


def _optional_text(name, value, maximum):
    if value is None:
        return None
    if not isinstance(value, str) or len(value.strip()) > maximum:
        raise ValueError("%s must be a string of at most %d characters" % (name, maximum))
    return value.strip() or None


def _count(name, value):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("%s must be a non-negative integer" % name)
    return value


def _optional_timestamp(name, value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("%s must be a bounded ISO-8601 timestamp" % name)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("%s must be an ISO-8601 timestamp" % name) from error
    if parsed.tzinfo is None:
        raise ValueError("%s must include a timezone" % name)
    return value


def _defensive_receipt(value):
    if not isinstance(value, dict) \
            or not all(isinstance(value.get(name), bool) for name in (
                "active", "configured", "configuration_valid")):
        raise ValueError("incident status has an invalid defensive mode")
    remaining = value.get("remaining_seconds")
    if remaining is not None:
        remaining = _count("defensive_mode.remaining_seconds", remaining)
    return {
        "active": value["active"],
        "configured": value["configured"],
        "configuration_valid": value["configuration_valid"],
        "until": _optional_timestamp("defensive_mode.until", value.get("until")),
        "remaining_seconds": remaining,
    }


def _numeric_fields(name, value, fields):
    if not isinstance(value, dict):
        raise ValueError("%s must be an aggregate object" % name)
    return {field: _count("%s.%s" % (name, field), value.get(field)) for field in fields}


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
            required = {"cases", "link_case_reports", "reports", "report_groups",
                        "inbox_status", "bulk_dismiss_reports", "claim_report",
                        "release_report_claim", "quarantine_proposal", "restore_proposal",
                        "remove_proposal", "reinstate_proposal", "set_measurement_evidence_state",
                        "item_impact", "item_impact_batch", "quarantine_item_batch",
                        "quarantine_item", "restore_item", "remove_item", "reinstate_item",
                        "approvals",
                        "confirm_approval", "cancel_approval", "reject_approval",
                        "restrictions", "create_restriction",
                        "revoke_restriction", "contributor_impact",
                        "contributor_containment_impact", "quarantine_contributor_batch",
                        "incident_status"}
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

        def approval_contract(value):
            if not isinstance(value, dict) \
                    or value.get("kind") != "ainglish.moderation.approvals" \
                    or not isinstance(value.get("approvals"), list):
                raise ValueError("approvals endpoint returned an unexpected envelope")
            return {"kind": value["kind"], "reachable": True}

        probe("identity", self.me, identity_contract)
        probe("discovery", lambda: self.get("/api/v1"), discovery_contract)
        probe("cases", lambda: self.cases(limit=1),
              envelope_contract("ainglish.moderation.cases", "cases"))
        probe("reports", lambda: self.reports(limit=1),
              envelope_contract("ainglish.moderation.reports", "reports"))
        probe("report_groups", lambda: self.report_groups(limit=1),
              envelope_contract("ainglish.moderation.report_groups", "groups"))
        probe("approvals", lambda: self.approvals(limit=1), approval_contract)
        probe("restrictions", lambda: self.restrictions(limit=1),
              envelope_contract("ainglish.moderation.restrictions", "restrictions"))
        probe("incident_status", self.incident_status, lambda value: {
            "kind": value["kind"], "reachable": True,
        })

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
        _enum("target_type", target_type, CASE_TARGET_TYPES)
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
        """One private metadata-only inbox page; reporter prose is omitted by the server."""
        _enum("status", status, REPORT_STATUSES)
        _enum("reason_code", reason_code, REASON_CODES)
        params = {k: v for k, v in (
            ("status", status), ("reason_code", reason_code), ("proposal", proposal),
            ("reporter_sub", reporter_sub), ("limit", limit), ("cursor", cursor),
        ) if v is not None}
        return self.get("/api/v1/moderation/reports", params=params, auth=True)

    def report(self, report_id):
        """One explicit detail read with untrusted reporter prose and fenced target bytes."""
        return self.get("/api/v1/moderation/reports/%s" % urllib.parse.quote(report_id, safe=""), auth=True)

    def report_groups(self, limit=50):
        """Content-free oldest-first groups of new reports sharing exact target bytes/reason."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100")
        return self.get("/api/v1/moderation/reports/groups", params={"limit": limit}, auth=True)

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

    def inbox_status(self, page_size=100, now=None):
        """Return a content-free health receipt for unattended inbox monitoring.

        The server answers from one aggregate query and returns neither report rows nor
        reporter-supplied prose. ``page_size`` remains as a validated compatibility argument for
        callers of the original paginated implementation; it no longer controls any traversal.
        ``now`` exists for deterministic tests; normal callers should leave it unset.
        """
        if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= 100:
            raise ValueError("page_size must be an integer from 1 to 100")
        checked_at = now
        if checked_at is not None and (not isinstance(checked_at, datetime)
                                       or checked_at.tzinfo is None
                                       or checked_at.utcoffset() is None):
            raise ValueError("now must be a timezone-aware datetime")

        receipt = self.get("/api/v1/moderation/reports/inbox-status", auth=True)
        if not isinstance(receipt, dict) or receipt.get("kind") != "ainglish.moderation.inbox_status":
            raise AinglishError(502, {
                "error": "invalid_contract",
                "message": "moderation inbox status returned an unexpected envelope",
            })
        count = receipt.get("new_reports")
        groups_present = "new_report_groups" in receipt
        duplicates_present = "duplicate_reports" in receipt
        groups = receipt.get("new_report_groups", count)
        duplicates = receipt.get("duplicate_reports", count - groups if isinstance(count, int)
                                 and isinstance(groups, int) else None)
        attention = receipt.get("attention_required")
        oldest_raw = receipt.get("oldest_new_report_at")
        newest_present = "newest_new_report_at" in receipt
        newest_raw = receipt.get("newest_new_report_at")
        newest_group_present = "newest_new_report_group_at" in receipt
        newest_group_raw = receipt.get("newest_new_report_group_at", newest_raw)
        age = receipt.get("oldest_new_report_age_seconds")
        checked_raw = receipt.get("checked_at")
        if groups_present != duplicates_present or groups_present != newest_group_present \
                or not isinstance(count, int) or isinstance(count, bool) or count < 0 \
                or not isinstance(groups, int) or isinstance(groups, bool) or not 0 <= groups <= count \
                or not isinstance(duplicates, int) or isinstance(duplicates, bool) \
                or duplicates != count - groups \
                or not isinstance(attention, bool) or attention != (count > 0) \
                or receipt.get("mutations_performed") != 0 \
                or receipt.get("untrusted_content_included") is not False:
            raise AinglishError(502, {
                "error": "invalid_contract",
                "message": "moderation inbox status lost its content-free health contract",
            })

        def parse_timestamp(value, field):
            if not isinstance(value, str):
                raise AinglishError(502, {
                    "error": "invalid_contract",
                    "message": "moderation inbox status returned an invalid %s timestamp" % field,
                })
            try:
                parsed = datetime.fromisoformat(
                    value[:-1] + "+00:00" if value.endswith("Z") else value
                )
            except ValueError:
                parsed = None
            if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
                raise AinglishError(502, {
                    "error": "invalid_contract",
                    "message": "moderation inbox status returned an invalid %s timestamp" % field,
                })
            return parsed.astimezone(timezone.utc)

        server_checked_at = parse_timestamp(checked_raw, "checked_at")
        oldest = None if oldest_raw is None else parse_timestamp(oldest_raw, "oldest_new_report_at")
        newest = None if newest_raw is None else parse_timestamp(newest_raw, "newest_new_report_at")
        newest_group = None if newest_group_raw is None else parse_timestamp(
            newest_group_raw, "newest_new_report_group_at")
        if count == 0:
            if oldest is not None or newest is not None or newest_group is not None or age is not None \
                    or groups != 0 or duplicates != 0:
                raise AinglishError(502, {
                    "error": "invalid_contract",
                    "message": "an empty moderation inbox returned non-empty age metadata",
                })
        elif oldest is None or not isinstance(age, int) or isinstance(age, bool) or age < 0:
            raise AinglishError(502, {
                "error": "invalid_contract",
                "message": "a non-empty moderation inbox lost its oldest-report age metadata",
            })
        elif newest_present and newest is None:
            raise AinglishError(502, {
                "error": "invalid_contract",
                "message": "a non-empty moderation inbox lost its newest-report timestamp",
            })
        elif newest_group_present and (not newest_present or newest_group is None):
            raise AinglishError(502, {
                "error": "invalid_contract",
                "message": "a non-empty moderation inbox lost its newest-group timestamp",
            })
        elif newest is not None and (newest < oldest or newest > server_checked_at):
            raise AinglishError(502, {
                "error": "invalid_contract",
                "message": "moderation inbox timestamps are not chronologically consistent",
            })
        elif newest_group is not None and (newest_group < oldest or newest_group > newest):
            raise AinglishError(502, {
                "error": "invalid_contract",
                "message": "moderation inbox group timestamps are not chronologically consistent",
            })

        checked_at = server_checked_at if checked_at is None else checked_at.astimezone(timezone.utc)
        if oldest is not None and now is not None:
            age = max(0, int((checked_at - oldest).total_seconds()))

        # Construct a strict allowlist rather than returning the server object. If a future server
        # accidentally adds rows or prose, this content-free command still cannot print them.
        return {
            "kind": "ainglish.moderation.inbox_status",
            "attention_required": attention,
            "new_reports": count,
            "new_report_groups": groups,
            "duplicate_reports": duplicates,
            "oldest_new_report_at": oldest.isoformat().replace("+00:00", "Z") if oldest else None,
            "newest_new_report_at": newest.isoformat().replace("+00:00", "Z") if newest else None,
            "newest_new_report_group_at": (
                newest_group.isoformat().replace("+00:00", "Z") if newest_group else None),
            "oldest_new_report_age_seconds": age,
            "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
            "mutations_performed": 0,
            "untrusted_content_included": False,
        }

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

    def dismiss_reports(self, report_ids, resolution_note=None, idempotency_key=None):
        """Atomically dismiss an explicit set; one invalid/stale member changes none."""
        payload = {"report_ids": _report_ids(report_ids)}
        if resolution_note is not None:
            payload["resolution_note"] = resolution_note
        return self.post(
            "/api/v1/moderation/reports/dismiss", payload,
            idempotency_key=_operation_key(idempotency_key),
        )

    def claim_report(self, report_id, lease_seconds=900, idempotency_key=None):
        """Claim an advisory review lease; the report remains new and unresolved."""
        if not isinstance(lease_seconds, int) or isinstance(lease_seconds, bool) \
                or not 60 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be an integer from 60 to 3600")
        return self.post(
            "/api/v1/moderation/reports/%s/claim"
            % urllib.parse.quote(report_id, safe=""),
            {"lease_seconds": lease_seconds}, idempotency_key=_operation_key(idempotency_key),
        )

    def release_report_claim(self, report_id, idempotency_key=None):
        """Release an advisory review lease without resolving the report."""
        return self.post(
            "/api/v1/moderation/reports/%s/release-claim"
            % urllib.parse.quote(report_id, safe=""),
            {}, idempotency_key=_operation_key(idempotency_key),
        )

    # ------------------------------------------------------------------ publication controls
    def item_impact(self, item_type, item_id, action):
        """Read-only exact-item transition preview with target and graph-impact digests."""
        reference = _item_reference(item_type, item_id)
        if not isinstance(action, str):
            raise ValueError("action is required")
        _enum("action", action, ITEM_ACTIONS)
        return self.get(
            "/api/v1/moderation/items/%s/%s/impact" % (
                urllib.parse.quote(reference["type"], safe=""),
                urllib.parse.quote(reference["id"], safe=""),
            ),
            params={"action": action}, auth=True,
        )

    def item_impact_batch(self, items):
        """Read-only POST preview for 1–20 independent proposal graphs.

        This intentionally sends no idempotency key because it creates no case, approval, audit
        event, or publication change. The returned batch digest commits to the canonical item set
        and every per-item impact.
        """
        return self.post(
            "/api/v1/moderation/items/impact-batch",
            {"items": _item_references(items)},
        )

    def quarantine_item(self, item_type, item_id, reason_code, target_digest, impact_digest,
                        public_explanation=None, private_note=None, source_report_ids=None,
                        idempotency_key=None):
        """Immediately contain one reviewed item and recompute its proposal atomically.

        When ``source_report_ids`` is supplied, every exact matching report is actioned in the
        same server transaction; any stale or mismatched report refuses the whole operation.
        """
        reference = _item_reference(item_type, item_id)
        if not isinstance(reason_code, str):
            raise ValueError("reason_code is required")
        _enum("reason_code", reason_code, REASON_CODES)
        payload = {
            "reason_code": reason_code,
            "target_digest": _digest("target_digest", target_digest),
            "impact_digest": _digest("impact_digest", impact_digest),
        }
        public_explanation = _optional_text("public_explanation", public_explanation, 500)
        private_note = _optional_text("private_note", private_note, 20000)
        if public_explanation is not None:
            payload["public_explanation"] = public_explanation
        if private_note is not None:
            payload["private_note"] = private_note
        if source_report_ids is not None:
            payload["source_report_ids"] = _report_ids(source_report_ids)
        return self.post(
            "/api/v1/moderation/items/%s/%s/quarantine" % (
                urllib.parse.quote(reference["type"], safe=""),
                urllib.parse.quote(reference["id"], safe=""),
            ),
            payload, idempotency_key=_operation_key(idempotency_key),
        )

    def quarantine_item_batch(self, items, batch_digest, reason_code,
                              public_explanation=None, private_note=None,
                              idempotency_key=None):
        """Atomically contain 1–20 reviewed items on distinct proposals.

        ``items`` is the exact list of {type,id,target_digest,impact_digest} rows copied from the
        batch preview. Source reports are deliberately unsupported here; use
        :meth:`quarantine_item` when report resolution must commit with containment.
        """
        if not isinstance(reason_code, str):
            raise ValueError("reason_code is required")
        _enum("reason_code", reason_code, REASON_CODES)
        payload = {
            "items": _reviewed_items(items),
            "batch_digest": _digest("batch_digest", batch_digest),
            "reason_code": reason_code,
        }
        public_explanation = _optional_text("public_explanation", public_explanation, 500)
        private_note = _optional_text("private_note", private_note, 20000)
        if public_explanation is not None:
            payload["public_explanation"] = public_explanation
        if private_note is not None:
            payload["private_note"] = private_note
        return self.post(
            "/api/v1/moderation/items/quarantine-batch", payload,
            idempotency_key=_operation_key(idempotency_key),
        )

    def restore_item(self, item_type, item_id, target_digest, impact_digest,
                     idempotency_key=None, resolution_note=None):
        """Request independently confirmed restoration of one quarantined item."""
        return self._request_item_transition(
            "restore", item_type, item_id, target_digest, impact_digest,
            idempotency_key, resolution_note,
        )

    def remove_item(self, item_type, item_id, target_digest, impact_digest,
                    idempotency_key=None, resolution_note=None):
        """Request independently confirmed final removal of one quarantined item."""
        return self._request_item_transition(
            "remove", item_type, item_id, target_digest, impact_digest,
            idempotency_key, resolution_note,
        )

    def reinstate_item(self, item_type, item_id, target_digest, impact_digest,
                       idempotency_key=None, resolution_note=None):
        """Request that one removed item return to quarantine, never directly to visibility."""
        return self._request_item_transition(
            "reinstate", item_type, item_id, target_digest, impact_digest,
            idempotency_key, resolution_note,
        )

    def _request_item_transition(self, action, item_type, item_id, target_digest, impact_digest,
                                 idempotency_key, resolution_note):
        _enum("action", action, ("restore", "remove", "reinstate"))
        reference = _item_reference(item_type, item_id)
        payload = {
            "target_digest": _digest("target_digest", target_digest),
            "impact_digest": _digest("impact_digest", impact_digest),
        }
        resolution_note = _optional_text("resolution_note", resolution_note, 20000)
        if resolution_note is not None:
            payload["resolution_note"] = resolution_note
        return self.post(
            "/api/v1/moderation/items/%s/%s/%s" % (
                urllib.parse.quote(reference["type"], safe=""),
                urllib.parse.quote(reference["id"], safe=""), action,
            ),
            payload, idempotency_key=_operation_key(idempotency_key),
        )

    def quarantine(self, proposal, reason_code, public_explanation=None, private_note=None,
                   report_id=None, idempotency_key=None, report_ids=None):
        """Immediately hide a proposal tree and open its durable case.

        ``report_id`` is the backward-compatible single-report input. Prefer ``report_ids`` for
        an explicit set of up to 20 matching reports; the server validates all of them before
        changing publication and resolves them atomically. The two arguments are mutually
        exclusive.
        """
        _enum("reason_code", reason_code, REASON_CODES)
        payload = {"reason_code": reason_code}
        if public_explanation is not None:
            payload["public_explanation"] = public_explanation
        if private_note is not None:
            payload["private_note"] = private_note
        if report_id is not None and report_ids is not None:
            raise ValueError("use report_id or report_ids, not both")
        if report_id is not None:
            payload["report_id"] = report_id
        if report_ids is not None:
            payload["report_ids"] = _report_ids(report_ids)
        return self.post(
            "/api/v1/moderation/proposals/%s/quarantine" % urllib.parse.quote(proposal, safe=""),
            payload,
            idempotency_key=_operation_key(idempotency_key),
        )

    def action_reports(self, case_id, report_ids, idempotency_key=None):
        """Mark an explicit report set actioned by an existing proposal moderation case.

        This is for matching reports triaged after containment. Nothing is selected implicitly;
        the server validates every target and binds the sorted set to the operation key.
        """
        return self.post(
            "/api/v1/moderation/cases/%s/reports/action" % urllib.parse.quote(case_id, safe=""),
            {"report_ids": _report_ids(report_ids)},
            idempotency_key=_operation_key(idempotency_key),
        )

    def restore(self, proposal, idempotency_key=None, resolution_note=None):
        """Request restoration; publication changes only after distinct confirmation."""
        payload = {}
        if resolution_note is not None:
            payload["resolution_note"] = resolution_note
        return self.post(
            "/api/v1/moderation/proposals/%s/restore" % urllib.parse.quote(proposal, safe=""),
            payload, idempotency_key=_operation_key(idempotency_key),
        )

    def remove(self, proposal, idempotency_key=None, resolution_note=None):
        """Request final removal; publication changes only after distinct confirmation."""
        payload = {}
        if resolution_note is not None:
            payload["resolution_note"] = resolution_note
        return self.post(
            "/api/v1/moderation/proposals/%s/remove" % urllib.parse.quote(proposal, safe=""),
            payload, idempotency_key=_operation_key(idempotency_key),
        )

    def reinstate(self, proposal, idempotency_key=None, resolution_note=None):
        """Request removed content return to quarantine; this can never republish directly."""
        payload = {}
        if resolution_note is not None:
            payload["resolution_note"] = resolution_note
        return self.post(
            "/api/v1/moderation/proposals/%s/reinstate"
            % urllib.parse.quote(proposal, safe=""),
            payload, idempotency_key=_operation_key(idempotency_key),
        )

    def request_measurement_evidence_state(self, attempt_id, state, reason_code,
                                           public_explanation, private_note=None,
                                           source_report_ids=None, successor_attempt_id=None,
                                           idempotency_key=None):
        """Request an audit-preserving evidence annotation; a second moderator must confirm.

        Excluded rows remain public and citable. The server alone changes settlement counters and
        refuses a restoration that would double-count one principal's settlement voice.
        """
        if not isinstance(attempt_id, str) or not attempt_id.strip():
            raise ValueError("attempt_id must be a non-empty string")
        _enum("state", state, MEASUREMENT_EVIDENCE_STATES)
        if reason_code not in MEASUREMENT_EVIDENCE_REASONS_BY_STATE[state]:
            raise ValueError(
                "reason_code for %s must be one of: %s" % (
                    state, ", ".join(MEASUREMENT_EVIDENCE_REASONS_BY_STATE[state])))
        if not isinstance(public_explanation, str) \
                or not 1 <= len(public_explanation.strip()) <= 500:
            raise ValueError("public_explanation must contain 1–500 characters")
        payload = {
            "state": state,
            "reason_code": reason_code,
            "public_explanation": public_explanation.strip(),
        }
        if private_note is not None:
            if not isinstance(private_note, str) or len(private_note.strip()) > 20000:
                raise ValueError("private_note must be a string of at most 20000 characters")
            if private_note.strip():
                payload["private_note"] = private_note.strip()
        if source_report_ids is not None:
            payload["source_report_ids"] = _report_ids(source_report_ids)
        if successor_attempt_id is not None:
            if not isinstance(successor_attempt_id, str) \
                    or not 1 <= len(successor_attempt_id.strip()) <= 36:
                raise ValueError("successor_attempt_id must contain 1–36 characters")
            payload["successor_attempt_id"] = successor_attempt_id.strip().lower()
        return self.post(
            "/api/v1/moderation/measurements/%s/evidence-state"
            % urllib.parse.quote(attempt_id.strip().lower(), safe=""),
            payload, idempotency_key=_operation_key(idempotency_key),
        )

    # ------------------------------------------------------------------ terminal approvals
    def approvals(self, status=None, limit=50):
        """Recent content-minimised two-person requests; private payloads are omitted."""
        _enum("status", status, APPROVAL_STATUSES)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100")
        params = {"limit": limit}
        if status is not None:
            params["status"] = status
        return self.get("/api/v1/moderation/approvals", params=params, auth=True)

    def approval(self, approval_id):
        """One content-minimised two-person request; inspect its case/reports separately."""
        return self.get(
            "/api/v1/moderation/approvals/%s" % urllib.parse.quote(approval_id, safe=""),
            auth=True,
        )

    def confirm_approval(self, approval_id, idempotency_key=None):
        """Confirm as a moderator distinct from the requester and perform the action atomically."""
        return self.post(
            "/api/v1/moderation/approvals/%s/confirm"
            % urllib.parse.quote(approval_id, safe=""),
            {}, idempotency_key=_operation_key(idempotency_key),
        )

    def cancel_approval(self, approval_id, reason_code, decision_note=None, idempotency_key=None):
        """Cancel one's own pending request without performing its target action."""
        return self._close_approval(
            approval_id, "cancel", reason_code, decision_note, idempotency_key)

    def reject_approval(self, approval_id, reason_code, decision_note=None, idempotency_key=None):
        """Reject another moderator's pending request without performing its target action."""
        return self._close_approval(
            approval_id, "reject", reason_code, decision_note, idempotency_key)

    def _close_approval(self, approval_id, action, reason_code, decision_note, idempotency_key):
        if not isinstance(reason_code, str):
            raise ValueError("reason_code is required")
        _enum("reason_code", reason_code, APPROVAL_DECISION_REASONS)
        if decision_note is not None and (not isinstance(decision_note, str)
                                          or len(decision_note) > 20000):
            raise ValueError("decision_note must be a string of at most 20000 characters")
        payload = {"reason_code": reason_code}
        if decision_note is not None:
            payload["decision_note"] = decision_note
        return self.post(
            "/api/v1/moderation/approvals/%s/%s"
            % (urllib.parse.quote(approval_id, safe=""), action),
            payload, idempotency_key=_operation_key(idempotency_key),
        )

    def contributor_impact(self, colony_sub):
        """Bounded, prose-free inventory of rows attributable to one immutable Colony sub."""
        if not isinstance(colony_sub, str) or not colony_sub.strip() or len(colony_sub) > 191:
            raise ValueError("colony_sub must be a non-empty string of at most 191 characters")
        return self.get(
            "/api/v1/moderation/contributors/%s/impact"
            % urllib.parse.quote(colony_sub.strip(), safe=""), auth=True,
        )

    def contributor_containment_impact(self, colony_sub, created_since, types=None, limit=20):
        """Preview one bounded, digest-bound containment chunk without changing publication."""
        subject = self._contributor_subject(colony_sub)
        if not isinstance(created_since, str) or not created_since.strip():
            raise ValueError("created_since must be an ISO-8601 timestamp with timezone")
        try:
            parsed = datetime.fromisoformat(created_since.strip().replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("created_since must be an ISO-8601 timestamp with timezone") from error
        if parsed.tzinfo is None:
            raise ValueError("created_since must include a timezone")
        if types is None:
            selected_types = list(CONTRIBUTOR_TARGET_TYPES)
        else:
            if not isinstance(types, (list, tuple)) or not types:
                raise ValueError("types must be a non-empty list of contributor target types")
            selected_types = []
            for item_type in types:
                _enum("type", item_type, CONTRIBUTOR_TARGET_TYPES)
                if item_type in selected_types:
                    raise ValueError("types must not contain duplicates")
                selected_types.append(item_type)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 20:
            raise ValueError("limit must be an integer from 1 to 20")
        return self.post(
            "/api/v1/moderation/contributors/%s/containment-impact"
            % urllib.parse.quote(subject, safe=""),
            {"created_since": created_since.strip(), "types": selected_types, "limit": limit},
        )

    def quarantine_contributor_batch(self, colony_sub, items, batch_digest, reason_code,
                                     public_explanation=None, private_note=None,
                                     idempotency_key=None):
        """Contain one exact reviewed contributor chunk; the server rechecks every binding."""
        subject = self._contributor_subject(colony_sub)
        _enum("reason_code", reason_code, REASON_CODES)
        payload = {
            "items": _reviewed_items(items, CONTRIBUTOR_TARGET_TYPES),
            "batch_digest": _digest("batch_digest", batch_digest),
            "reason_code": reason_code,
        }
        for name, value, maximum in (
            ("public_explanation", public_explanation, 500),
            ("private_note", private_note, 20000),
        ):
            normalized = _optional_text(name, value, maximum)
            if normalized is not None:
                payload[name] = normalized
        return self.post(
            "/api/v1/moderation/contributors/%s/quarantine-batch"
            % urllib.parse.quote(subject, safe=""),
            payload, idempotency_key=_operation_key(idempotency_key),
        )

    def incident_status(self):
        """Return one projected, content-free operational snapshot with zero mutations."""
        value = self.get("/api/v1/moderation/incidents/status", auth=True)
        if not isinstance(value, dict) \
                or value.get("kind") != "ainglish.moderation.incident_status" \
                or not isinstance(value.get("attention_required"), bool) \
                or not isinstance(value.get("attention_reasons"), list) \
                or any(reason not in INCIDENT_ATTENTION_REASONS
                       for reason in value["attention_reasons"]) \
                or value.get("mutations_performed") != 0 \
                or value.get("untrusted_content_included") is not False:
            raise ValueError("incident status returned an unsafe or unexpected envelope")
        authority = value.get("authority_config")
        if not isinstance(authority, dict) or authority.get("subjects_included") is not False:
            raise ValueError("incident status unexpectedly included authority subjects")
        _digest("authority_config.digest", authority.get("digest"))
        report_fields = ("new", "exact_groups")
        approval_fields = ("pending", "expiring_within_hour", "expired_unclosed")
        byte_fields = (
            "subject", "ip", "global", "subject_bytes", "ip_bytes", "global_bytes",
            "subject_bytes_daily", "ip_bytes_daily", "global_bytes_daily",
        )
        write = value.get("write_admission")
        if not isinstance(write, dict) or write.get("cohort") not in (
                "ordinary", "new", "established", "moderator"):
            raise ValueError("incident status has an invalid write-admission cohort")
        write_used_fields = tuple(
            field for field in byte_fields if field in write.get("used", {}))
        if not {"subject", "global", "subject_bytes", "global_bytes",
                "subject_bytes_daily", "global_bytes_daily"}.issubset(write_used_fields):
            raise ValueError("incident status is missing write-admission usage")
        moderator = value.get("moderator_admission")
        if not isinstance(moderator, dict):
            raise ValueError("incident status has an invalid moderator-admission object")
        moderation_categories = (
            "actions", "quarantine_targets", "restrictions", "confirmations",
        )
        moderator_ceilings = {}
        moderator_used = {}
        for category in moderation_categories:
            moderator_ceilings[category] = _numeric_fields(
                "moderator_admission.ceilings.%s" % category,
                moderator.get("ceilings", {}).get(category), ("subject", "global"))
            moderator_used[category] = _numeric_fields(
                "moderator_admission.used.%s" % category,
                moderator.get("used", {}).get(category), ("subject", "global"))
        authentication = value.get("authentication_failures")
        if not isinstance(authentication, dict):
            raise ValueError("incident status has invalid authentication aggregates")
        recent = value.get("recent_events")
        if not isinstance(recent, dict):
            raise ValueError("incident status has invalid recent-event aggregates")

        def event_counts(kind):
            rows = recent.get(kind)
            if rows == []:
                rows = {}  # PHP serializes an empty label->count map as []; the quiet state is normal
            if not isinstance(rows, dict) or any(
                    not isinstance(action, str) or len(action) > 64
                    or not action.replace("_", "").isalnum()
                    for action in rows):
                raise ValueError("incident status has invalid recent-event labels")
            return {action: _count("recent_events.%s.%s" % (kind, action), count)
                    for action, count in rows.items()}

        reports = _numeric_fields("reports", value.get("reports"), report_fields)
        reports.update({
            "oldest_age_seconds": (
                None if value["reports"].get("oldest_age_seconds") is None
                else _count("reports.oldest_age_seconds",
                            value["reports"]["oldest_age_seconds"])),
            "newest_group_at": _optional_timestamp(
                "reports.newest_group_at", value["reports"].get("newest_group_at")),
        })
        approvals = _numeric_fields("approvals", value.get("approvals"), approval_fields)
        approvals.update({
            "oldest_requested_at": _optional_timestamp(
                "approvals.oldest_requested_at",
                value["approvals"].get("oldest_requested_at")),
            "oldest_age_seconds": (
                None if value["approvals"].get("oldest_age_seconds") is None
                else _count("approvals.oldest_age_seconds",
                            value["approvals"]["oldest_age_seconds"])),
        })
        return {
            "kind": value["kind"],
            "attention_required": value["attention_required"],
            "attention_reasons": sorted(set(value["attention_reasons"])),
            "checked_at": _optional_timestamp("checked_at", value.get("checked_at")),
            "defensive_mode": _defensive_receipt(value.get("defensive_mode")),
            "authority_config": {
                "count": _count("authority_config.count", authority.get("count")),
                "digest": authority["digest"], "subjects_included": False,
            },
            "reports": reports,
            "approvals": approvals,
            "authentication_failures": {
                kind: _numeric_fields(
                    "authentication_failures.%s" % kind, authentication.get(kind),
                    ("five_minutes", "one_hour"))
                for kind in ("invalid", "missing")
            },
            "write_admission": {
                "window_seconds": _count(
                    "write_admission.window_seconds", write.get("window_seconds")),
                "daily_window_seconds": _count(
                    "write_admission.daily_window_seconds", write.get("daily_window_seconds")),
                "defensive_mode": _defensive_receipt(write.get("defensive_mode")),
                "cohort": write["cohort"],
                "ceilings": _numeric_fields(
                    "write_admission.ceilings", write.get("ceilings"), byte_fields),
                "used": _numeric_fields(
                    "write_admission.used", write.get("used"), write_used_fields),
            },
            "moderator_admission": {
                "window_seconds": _count(
                    "moderator_admission.window_seconds", moderator.get("window_seconds")),
                "ceilings": moderator_ceilings, "used": moderator_used,
            },
            "recent_events": {
                "window_seconds": _count(
                    "recent_events.window_seconds", recent.get("window_seconds")),
                "moderation": event_counts("moderation"),
                "restrictions": event_counts("restrictions"),
            },
            "open_cases": _count("open_cases", value.get("open_cases")),
            "active_restrictions": _count(
                "active_restrictions", value.get("active_restrictions")),
            "mutations_performed": 0,
            "untrusted_content_included": False,
        }

    @staticmethod
    def _contributor_subject(colony_sub):
        if not isinstance(colony_sub, str) or not colony_sub.strip() or len(colony_sub) > 191:
            raise ValueError("colony_sub must be a non-empty string of at most 191 characters")
        return colony_sub.strip()

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
                            private_note=None, expires_at=None, idempotency_key=None,
                            allow_self=False, permanent=False, source_case_id=None,
                            source_report_ids=None):
        """Restrict writes by immutable Colony ``sub``.

        ``expires_at`` creates an immediate temporary restriction. ``permanent=True`` instead
        creates a two-person request and requires a source case and/or source reports. Temporary
        restrictions may also retain this private provenance when supplied.
        A mutable username is intentionally not accepted as the target.
        ``allow_self=True`` is an emergency confirmation: use it only after proving a second
        moderator/recovery path can revoke a restriction on this client's own subject.
        """
        return self._restrict(
            "colony_sub", colony_sub, reason_code, public_explanation,
            private_note, expires_at, idempotency_key, allow_self, permanent,
            source_case_id, source_report_ids,
        )

    def restrict_ip(self, ip_address, reason_code, public_explanation,
                    private_note=None, expires_at=None, idempotency_key=None,
                    allow_self=False, permanent=False, source_case_id=None,
                    source_report_ids=None):
        """Restrict writes from one exact IPv4/IPv6 address.

        The raw address is sent over TLS for canonicalisation and immediately becomes a keyed
        server-side digest. It is not returned or persisted. CIDR/network ranges are refused.
        ``allow_self=True`` is required if this is the current client address and should be used
        only after verifying an independent recovery path.
        """
        return self._restrict(
            "ip", ip_address, reason_code, public_explanation,
            private_note, expires_at, idempotency_key, allow_self, permanent,
            source_case_id, source_report_ids,
        )

    def revoke_restriction(self, restriction_id, idempotency_key=None):
        """Revoke one restriction without deleting its audit history."""
        return self.post(
            "/api/v1/moderation/restrictions/%s/revoke"
            % urllib.parse.quote(restriction_id, safe=""),
            {}, idempotency_key=_operation_key(idempotency_key),
        )

    def _restrict(self, subject_type, subject_value, reason_code, public_explanation,
                  private_note, expires_at, idempotency_key, allow_self, permanent,
                  source_case_id, source_report_ids):
        _enum("subject_type", subject_type, RESTRICTION_SUBJECT_TYPES)
        _enum("reason_code", reason_code, REASON_CODES)
        if not isinstance(subject_value, str) or not subject_value.strip():
            raise ValueError("restriction subject value must be a non-empty string")
        if not isinstance(public_explanation, str) or not public_explanation.strip():
            raise ValueError("public_explanation must be a non-empty string")
        if expires_at is not None and not isinstance(expires_at, str):
            raise ValueError("expires_at must be an ISO-8601 string with timezone, or None")
        if not isinstance(allow_self, bool):
            raise ValueError("allow_self must be a boolean")
        if not isinstance(permanent, bool):
            raise ValueError("permanent must be a boolean")
        if permanent and expires_at is not None:
            raise ValueError("choose expires_at for temporary containment or permanent=True, not both")
        if not permanent and expires_at is None:
            raise ValueError("expires_at is required unless permanent=True")
        if source_case_id is not None and (not isinstance(source_case_id, str)
                                           or not source_case_id.strip()):
            raise ValueError("source_case_id must be a non-empty string")
        sources = None if source_report_ids is None else _report_ids(source_report_ids)
        if permanent and source_case_id is None and sources is None:
            raise ValueError("permanent restrictions require source_case_id and/or source_report_ids")
        payload = {
            "subject": {"type": subject_type, "value": subject_value},
            "reason_code": reason_code,
            "public_explanation": public_explanation,
        }
        if permanent:
            payload["permanent"] = True
        else:
            payload["expires_at"] = expires_at
        if source_case_id is not None:
            payload["source_case_id"] = source_case_id.strip()
        if sources is not None:
            payload["source_report_ids"] = sources
        if private_note is not None:
            payload["private_note"] = private_note
        if allow_self:
            payload["allow_self"] = True
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
