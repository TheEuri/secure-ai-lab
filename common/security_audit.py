"""Structured, minimized security audit events stored in SQLite."""

from common.users import get_db


EVENT_TYPES = frozenset(
    {
        "auth.login.success",
        "auth.login.failure",
        "auth.logout",
        "auth.password.changed",
        "authz.admin.denied",
        "profile.bio.updated",
        "profile.avatar.updated",
        "admin.topic.deleted",
        "admin.reply.deleted",
    }
)
OUTCOMES = frozenset({"success", "failure", "denied"})
TARGET_TYPES = frozenset({"user", "admin", "topic", "reply"})
REQUEST_METHODS = frozenset({"GET", "POST"})
MAX_RECENT_EVENTS = 100


def _optional_integer(value, field_name):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer or None")
    return value


def record_security_event(
    event_type,
    outcome,
    actor_user_id=None,
    target_type=None,
    target_id=None,
    request_method=None,
    request_path=None,
):
    """Persist one allowlisted event without accepting request or content dumps."""

    if event_type not in EVENT_TYPES:
        raise ValueError("event_type is not allowlisted")
    if outcome not in OUTCOMES:
        raise ValueError("outcome is not allowlisted")

    actor_user_id = _optional_integer(actor_user_id, "actor_user_id")
    target_id = _optional_integer(target_id, "target_id")

    if target_type is not None and target_type not in TARGET_TYPES:
        raise ValueError("target_type is not allowlisted")
    if target_id is not None and target_type is None:
        raise ValueError("target_type is required when target_id is provided")

    if request_method is not None:
        request_method = request_method.upper()
        if request_method not in REQUEST_METHODS:
            raise ValueError("request_method is not allowlisted")

    if request_path is not None:
        if (
            not isinstance(request_path, str)
            or not request_path.startswith("/")
            or "?" in request_path
            or len(request_path) > 255
        ):
            raise ValueError("request_path must be a bounded path without a query string")

    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO security_events (
                event_type,
                actor_user_id,
                outcome,
                target_type,
                target_id,
                request_method,
                request_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                actor_user_id,
                outcome,
                target_type,
                target_id,
                request_method,
                request_path,
            ),
        )
        conn.commit()
        return cursor.lastrowid


def get_recent_security_events(limit=MAX_RECENT_EVENTS):
    """Return at most 100 newest structured events for the admin audit view."""

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    bounded_limit = min(max(limit, 1), MAX_RECENT_EVENTS)

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, event_type, actor_user_id, outcome, target_type,
                   target_id, request_method, request_path, created_at
            FROM security_events
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()
    return [dict(row) for row in rows]
