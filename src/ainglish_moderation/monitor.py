"""Local, content-free state tracking for the moderation inbox probe."""

import json
import os
import stat
import subprocess
import tempfile


_STATE_VERSION = 3
_AGE_THRESHOLDS = ((24 * 60 * 60, "24h"), (6 * 60 * 60, "6h"), (60 * 60, "1h"))
_NOTIFIER_ENV_NAMES = ("HOME", "LANG", "LC_ALL", "PATH", "TZ")


def default_state_path():
    """Return the per-user monitor state path without creating it."""
    state_root = os.environ.get("XDG_STATE_HOME")
    if not state_root:
        state_root = os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(state_root, "ainglish-moderation", "inbox-monitor.json")


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
