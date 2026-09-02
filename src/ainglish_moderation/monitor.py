"""Local, content-free state tracking for the moderation inbox probe."""

import json
import os
import stat
import subprocess
import tempfile


_STATE_VERSION = 3
_INCIDENT_STATE_VERSION = 1
_AGE_THRESHOLDS = ((24 * 60 * 60, "24h"), (6 * 60 * 60, "6h"), (60 * 60, "1h"))
_NOTIFIER_ENV_NAMES = ("HOME", "LANG", "LC_ALL", "PATH", "TZ")
_INCIDENT_REASONS = {
    "new_reports", "approval_backlog_age", "expired_approval_rows",
    "defensive_mode_active", "defensive_mode_configuration_invalid",
    "authentication_failure_surge", "admission_budget_pressure",
}


def default_state_path():
    """Return the per-user monitor state path without creating it."""
    state_root = os.environ.get("XDG_STATE_HOME")
    if not state_root:
        state_root = os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(state_root, "ainglish-moderation", "inbox-monitor.json")


def default_incident_state_path():
    """Return the separate per-user incident-monitor state path without creating it."""
    state_root = os.environ.get("XDG_STATE_HOME")
    if not state_root:
        state_root = os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(state_root, "ainglish-moderation", "incident-monitor.json")


def _private_parent(path):
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    metadata = os.lstat(parent)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError("monitor state parent must be a real directory")
    if metadata.st_uid != os.getuid():
        raise ValueError("monitor state parent must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("monitor state parent must not be accessible by group or other users")
    return parent


def _load_state(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("monitor state must be a regular file")
        if metadata.st_uid != os.getuid():
            raise ValueError("monitor state must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("monitor state must be owner-only")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            state = json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if not isinstance(state, dict) or state.get("version") not in (1, 2, _STATE_VERSION):
        raise ValueError("monitor state has an unsupported format")
    if state.get("status") not in ("clear", "attention", "failure"):
        raise ValueError("monitor state has an invalid status")
    return state


def _write_state(path, state):
    parent = _private_parent(path)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=".%s." % os.path.basename(path), suffix=".tmp", dir=parent,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        directory_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def _validated_notifier(path):
    if not os.path.isabs(path):
        raise ValueError("notifier program must use an absolute path")
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("notifier program must be a real regular file")
    if metadata.st_uid not in (0, os.getuid()):
        raise ValueError("notifier program must be owned by root or the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError("notifier program must not be writable by group or other users")
    if not os.access(path, os.X_OK):
        raise ValueError("notifier program must be executable")
    return path


def _notify(path, event, timeout):
    program = _validated_notifier(path)
    payload = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    environment = {name: os.environ[name] for name in _NOTIFIER_ENV_NAMES if name in os.environ}
    try:
        result = subprocess.run(
            [program], input=payload, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=environment, check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise OSError("notifier program timed out") from error
    if result.returncode != 0:
        raise OSError("notifier program failed with exit status %d" % result.returncode)


def _transition(previous_status, status):
    if previous_status == status:
        return "unchanged"
    if previous_status is None:
        return "initial_%s" % status
    if previous_status == "failure":
        return "recovered_%s" % status
    if status == "failure":
        return "probe_failed"
    return "attention_required" if status == "attention" else "cleared"


def _age_level(age):
    if not isinstance(age, int) or isinstance(age, bool) or age < 0:
        return None
    for seconds, label in _AGE_THRESHOLDS:
        if age >= seconds:
            return label
    return "fresh"


def _age_rank(level):
    return {None: -1, "fresh": 0, "1h": 1, "6h": 2, "24h": 3}.get(level, -1)


def _attention_transition(previous, receipt):
    """Describe one aggregate queue change without turning every poll into a notification."""
    if previous is None or previous.get("status") != "attention":
        return None
    previous_count = previous.get("new_reports")
    count = receipt.get("new_reports")
    previous_groups = previous.get("new_report_groups", previous_count)
    groups = receipt.get("new_report_groups", count)
    previous_newest_group = previous.get(
        "newest_new_report_group_at", previous.get("newest_new_report_at"))
    newest_group = receipt.get(
        "newest_new_report_group_at", receipt.get("newest_new_report_at"))
    previous_level = previous.get("age_level")
    if previous_level is None:
        previous_level = _age_level(previous.get("oldest_new_report_age_seconds"))
    level = _age_level(receipt.get("oldest_new_report_age_seconds"))

    if (isinstance(previous_groups, int) and isinstance(groups, int)
            and groups > previous_groups) or (
            isinstance(newest_group, str) and isinstance(previous_newest_group, str)
            and newest_group > previous_newest_group):
        return "new_report_groups_arrived"
    if _age_rank(level) > _age_rank(previous_level):
        return "age_escalated_%s" % level
    if isinstance(previous_count, int) and isinstance(count, int) and count > previous_count:
        return "duplicate_reports_arrived"
    if isinstance(previous_count, int) and isinstance(count, int) and count < previous_count:
        return "inbox_count_decreased"
    return "unchanged"


def monitor_inbox(client, state_path, notifier_program=None, notifier_timeout=15.0):
    """Probe once, notify on state transitions, and retain only aggregate local state."""
    if notifier_timeout <= 0:
        raise ValueError("notifier timeout must be greater than zero")
    absolute_state_path = os.path.abspath(os.path.expanduser(state_path))
    _private_parent(absolute_state_path)
    previous = _load_state(absolute_state_path)
    previous_status = None if previous is None else previous["status"]
    try:
        receipt = client.inbox_status()
        attention = receipt.get("attention_required")
        if not isinstance(attention, bool):
            raise ValueError("inbox status has an invalid attention value")
    except Exception:
        transition = _transition(previous_status, "failure")
        event = {
            "kind": "ainglish.moderation.inbox_transition",
            "probe_ok": False,
            "attention_required": None,
            "transition": transition,
            "new_reports": None,
            "oldest_new_report_age_seconds": None,
            "untrusted_content_included": False,
        }
        if transition != "unchanged" and notifier_program:
            _notify(notifier_program, event, notifier_timeout)
        _write_state(absolute_state_path, {"version": _STATE_VERSION, "status": "failure"})
        raise

    status = "attention" if attention else "clear"
    transition = _transition(previous_status, status)
    if status == "attention" and previous_status == "attention":
        transition = _attention_transition(previous, receipt)
    changed = transition != "unchanged"
    notify = changed and transition not in (
        "initial_clear", "inbox_count_decreased", "duplicate_reports_arrived")
    event = {
        "kind": "ainglish.moderation.inbox_transition",
        "probe_ok": True,
        "attention_required": attention,
        "transition": transition,
        "new_reports": receipt.get("new_reports"),
        "new_report_groups": receipt.get("new_report_groups"),
        "duplicate_reports": receipt.get("duplicate_reports"),
        "oldest_new_report_age_seconds": receipt.get("oldest_new_report_age_seconds"),
        "newest_new_report_at": receipt.get("newest_new_report_at"),
        "newest_new_report_group_at": receipt.get("newest_new_report_group_at"),
        "untrusted_content_included": False,
    }
    notified = False
    if notify and notifier_program:
        _notify(notifier_program, event, notifier_timeout)
        notified = True

    _write_state(absolute_state_path, {
        "version": _STATE_VERSION,
        "status": status,
        "attention_required": attention,
        "new_reports": receipt.get("new_reports"),
        "new_report_groups": receipt.get("new_report_groups"),
        "duplicate_reports": receipt.get("duplicate_reports"),
        "oldest_new_report_age_seconds": receipt.get("oldest_new_report_age_seconds"),
        "newest_new_report_at": receipt.get("newest_new_report_at"),
        "newest_new_report_group_at": receipt.get("newest_new_report_group_at"),
        "age_level": _age_level(receipt.get("oldest_new_report_age_seconds")),
    })
    return {
        **event,
        "state_changed": changed,
        "notification_attempted": bool(notify and notifier_program),
        "notified": notified,
        "mutations_performed": 0,
    }


def _integer(value, name):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("incident status has an invalid %s count" % name)
    return value


def _incident_snapshot(receipt):
    """Project the server receipt to fixed aggregate fields safe for disk and notifications."""
    reasons = receipt.get("attention_reasons")
    if not isinstance(reasons, list) or any(reason not in _INCIDENT_REASONS for reason in reasons):
        raise ValueError("incident status has an unknown attention reason")
    defensive = receipt.get("defensive_mode")
    authority = receipt.get("authority_config")
    reports = receipt.get("reports")
    approvals = receipt.get("approvals")
    authentication = receipt.get("authentication_failures")
    recent = receipt.get("recent_events")
    if not all(isinstance(value, dict) for value in (
            defensive, authority, reports, approvals, authentication, recent)):
        raise ValueError("incident status is missing aggregate fields")
    if not isinstance(defensive.get("active"), bool) \
            or not isinstance(defensive.get("configuration_valid"), bool):
        raise ValueError("incident status has an invalid defensive mode")
    digest = authority.get("digest")
    if not isinstance(digest, str) or len(digest) != 64 \
            or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("incident status has an invalid authority digest")
    if authority.get("subjects_included") is not False:
        raise ValueError("incident status must not include moderator subjects")

    def auth_count(kind, window):
        values = authentication.get(kind)
        if not isinstance(values, dict):
            raise ValueError("incident status has invalid authentication aggregates")
        return _integer(values.get(window), "authentication failure")

    def event_total(kind):
        values = recent.get(kind)
        if not isinstance(values, dict) or any(
                not isinstance(name, str) or not isinstance(count, int)
                or isinstance(count, bool) or count < 0 for name, count in values.items()):
            raise ValueError("incident status has invalid recent event aggregates")
        return sum(values.values())

    oldest_age = approvals.get("oldest_age_seconds")
    if oldest_age is not None:
        oldest_age = _integer(oldest_age, "oldest approval age")
    newest_group = reports.get("newest_group_at")
    if newest_group is not None and not isinstance(newest_group, str):
        raise ValueError("incident status has an invalid newest report-group timestamp")
    until = defensive.get("until")
    if until is not None and not isinstance(until, str):
        raise ValueError("incident status has an invalid defensive-mode expiry")

    return {
        "status": "attention" if receipt["attention_required"] else "clear",
        "attention_reasons": sorted(set(reasons)),
        "defensive_active": defensive["active"],
        "defensive_configuration_valid": defensive["configuration_valid"],
        "defensive_until": until,
        "authority_count": _integer(authority.get("count"), "authority"),
        "authority_digest": digest,
        "report_groups": _integer(reports.get("exact_groups"), "report group"),
        "newest_report_group_at": newest_group,
        "pending_approvals": _integer(approvals.get("pending"), "pending approval"),
        "approval_age_level": _age_level(oldest_age),
        "expiring_approvals": _integer(
            approvals.get("expiring_within_hour"), "expiring approval"),
        "expired_approvals": _integer(approvals.get("expired_unclosed"), "expired approval"),
        "invalid_auth_five_minutes": auth_count("invalid", "five_minutes"),
        "missing_auth_five_minutes": auth_count("missing", "five_minutes"),
        "moderation_events_five_minutes": event_total("moderation"),
        "restriction_events_five_minutes": event_total("restrictions"),
        "open_cases": _integer(receipt.get("open_cases"), "open case"),
        "active_restrictions": _integer(
            receipt.get("active_restrictions"), "active restriction"),
    }


def _incident_changes(previous, current):
    changes = []
    if (previous.get("authority_count"), previous.get("authority_digest")) != (
            current["authority_count"], current["authority_digest"]):
        changes.append("authority_config_changed")
    if (previous.get("defensive_active"), previous.get("defensive_configuration_valid"),
            previous.get("defensive_until")) != (
            current["defensive_active"], current["defensive_configuration_valid"],
            current["defensive_until"]):
        changes.append("defensive_mode_changed")
    old_reasons = set(previous.get("attention_reasons", []))
    if set(current["attention_reasons"]) - old_reasons:
        changes.append("new_attention_reason")
    if _age_rank(current["approval_age_level"]) > _age_rank(
            previous.get("approval_age_level")):
        changes.append("approval_age_escalated")
    for key, label in (
        ("report_groups", "new_report_groups"),
        ("pending_approvals", "pending_approvals_increased"),
        ("expiring_approvals", "approvals_near_expiry"),
        ("expired_approvals", "expired_approvals_increased"),
        ("moderation_events_five_minutes", "new_moderation_events"),
        ("restriction_events_five_minutes", "new_restriction_events"),
        ("open_cases", "open_cases_increased"),
        ("active_restrictions", "active_restrictions_increased"),
    ):
        if current[key] > previous.get(key, current[key]):
            changes.append(label)
    if "authentication_failure_surge" in current["attention_reasons"] and any(
            current[key] > previous.get(key, current[key]) for key in (
                "invalid_auth_five_minutes", "missing_auth_five_minutes")):
        changes.append("authentication_failure_surge_increased")
    return changes


def monitor_incidents(client, state_path, notifier_program=None, notifier_timeout=15.0):
    """Probe operational aggregates once and notify only on meaningful content-free changes."""
    if notifier_timeout <= 0:
        raise ValueError("notifier timeout must be greater than zero")
    absolute_state_path = os.path.abspath(os.path.expanduser(state_path))
    _private_parent(absolute_state_path)
    previous = _load_state(absolute_state_path)
    previous_status = None if previous is None else previous["status"]
    try:
        receipt = client.incident_status()
        if not isinstance(receipt.get("attention_required"), bool):
            raise ValueError("incident status has an invalid attention value")
        current = _incident_snapshot(receipt)
    except Exception:
        transition = _transition(previous_status, "failure")
        event = {
            "kind": "ainglish.moderation.incident_transition",
            "probe_ok": False,
            "attention_required": None,
            "transition": transition,
            "changes": [],
            "untrusted_content_included": False,
        }
        if transition != "unchanged" and notifier_program:
            _notify(notifier_program, event, notifier_timeout)
        _write_state(absolute_state_path, {
            "version": _INCIDENT_STATE_VERSION, "status": "failure",
        })
        raise

    status = current["status"]
    transition = _transition(previous_status, status)
    changes = [] if previous is None else _incident_changes(previous, current)
    if transition == "unchanged" and changes:
        transition = "incident_changed"
    changed = transition != "unchanged"
    notify = changed and transition != "initial_clear"
    event = {
        "kind": "ainglish.moderation.incident_transition",
        "probe_ok": True,
        "attention_required": status == "attention",
        "transition": transition,
        "changes": changes,
        "attention_reasons": current["attention_reasons"],
        "defensive_mode_active": current["defensive_active"],
        "authority_config_digest": current["authority_digest"],
        "pending_approvals": current["pending_approvals"],
        "report_groups": current["report_groups"],
        "untrusted_content_included": False,
    }
    notified = False
    if notify and notifier_program:
        _notify(notifier_program, event, notifier_timeout)
        notified = True
    _write_state(absolute_state_path, {
        "version": _INCIDENT_STATE_VERSION,
        **current,
    })
    return {
        **event,
        "state_changed": changed,
        "notification_attempted": bool(notify and notifier_program),
        "notified": notified,
        "mutations_performed": 0,
    }
