import hashlib
from functools import wraps
import secrets
import time

from flask import abort, current_app, request

from common.users import get_db


SESSION_COOKIE_NAME = "session_id"
SESSION_COOKIE_PATH = "/"
SESSION_LIFETIME_SECONDS = 3600
SESSION_TOKEN_BYTES = 32
CSRF_TOKEN_BYTES = 32


def _token_digest(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _session_lifetime_seconds() -> int:
    lifetime = int(
        current_app.config.get(
            "SESSION_LIFETIME_SECONDS",
            SESSION_LIFETIME_SECONDS,
        )
    )
    if lifetime <= 0:
        raise RuntimeError("SESSION_LIFETIME_SECONDS must be positive")
    return lifetime


def create_session(user_id: int) -> str:
    """Create a finite server-side session and return its opaque bearer token."""

    raw_token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    csrf_token = secrets.token_urlsafe(CSRF_TOKEN_BYTES)
    now = int(time.time())
    expires_at = now + _session_lifetime_seconds()
    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO auth_sessions (
                user_id, token_hash, created_at, expires_at, csrf_token
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, _token_digest(raw_token), now, expires_at, csrf_token),
        )
        conn.commit()
    finally:
        conn.close()
    return raw_token


def get_session_user(raw_token: str, *, now: int | None = None):
    """Resolve an active opaque token to the current database user row."""

    if not isinstance(raw_token, str) or not raw_token:
        return None
    current_time = int(time.time()) if now is None else int(now)
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT users.*
            FROM auth_sessions
            JOIN users ON users.id = auth_sessions.user_id
            WHERE auth_sessions.token_hash = ?
              AND auth_sessions.revoked_at IS NULL
              AND auth_sessions.expires_at > ?
              AND auth_sessions.csrf_token IS NOT NULL
              AND auth_sessions.csrf_token <> ''
            LIMIT 1
            """,
            (_token_digest(raw_token), current_time),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_current_user(strict=True):
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    user = get_session_user(raw_token) if raw_token else None
    if user is not None:
        return user
    return None if strict else {}


def get_current_csrf_token():
    """Return the active session's CSRF token, never the authentication token."""

    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not isinstance(raw_token, str) or not raw_token:
        return None
    current_time = int(time.time())
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT csrf_token
            FROM auth_sessions
            WHERE token_hash = ?
              AND revoked_at IS NULL
              AND expires_at > ?
              AND csrf_token IS NOT NULL
              AND csrf_token <> ''
            LIMIT 1
            """,
            (_token_digest(raw_token), current_time),
        ).fetchone()
        return row[0] if row and isinstance(row[0], str) else None
    finally:
        conn.close()


def validate_csrf_token(submitted):
    """Validate a submitted synchronizer token against the active session."""

    expected = get_current_csrf_token()
    if (
        not isinstance(submitted, str)
        or not submitted
        or not isinstance(expected, str)
        or not expected
    ):
        return False
    return secrets.compare_digest(submitted, expected)


def csrf_protect(view):
    """Require a valid form token for authenticated POST mutations."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method == "POST" and get_current_user() is not None:
            if not validate_csrf_token(request.form.get("csrf_token")):
                abort(403)
        return view(*args, **kwargs)

    return wrapped


def revoke_session(raw_token: str) -> bool:
    """Revoke one presented session without persisting or exposing its token."""

    if not isinstance(raw_token, str) or not raw_token:
        return False
    conn = get_db()
    try:
        cursor = conn.execute(
            """
            UPDATE auth_sessions
            SET revoked_at = ?
            WHERE token_hash = ? AND revoked_at IS NULL
            """,
            (int(time.time()), _token_digest(raw_token)),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def revoke_user_sessions(user_id: int) -> int:
    """Revoke every active session issued for one database user."""

    conn = get_db()
    try:
        cursor = conn.execute(
            """
            UPDATE auth_sessions
            SET revoked_at = ?
            WHERE user_id = ? AND revoked_at IS NULL
            """,
            (int(time.time()), user_id),
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def set_session_cookie(response, raw_token: str):
    response.set_cookie(
        SESSION_COOKIE_NAME,
        raw_token,
        max_age=_session_lifetime_seconds(),
        path=SESSION_COOKIE_PATH,
        httponly=True,
        secure=bool(current_app.config.get("SESSION_COOKIE_SECURE", False)),
        samesite="Lax",
    )
    return response


def delete_session_cookie(response):
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path=SESSION_COOKIE_PATH,
        httponly=True,
        secure=bool(current_app.config.get("SESSION_COOKIE_SECURE", False)),
        samesite="Lax",
    )
    return response
