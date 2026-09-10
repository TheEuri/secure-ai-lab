import sqlite3
from pathlib import Path
import hashlib
import hmac

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from flask import current_app, has_app_context

DB_PATH = Path(__file__).resolve().parents[1] / 'data' / 'secureboard.db'
PASSWORD_HASHER = PasswordHasher(type=Type.ID)


def _database_path():
    if has_app_context():
        configured = current_app.config.get('DATABASE')
        if configured:
            return Path(configured)
    return DB_PATH

def get_db():
    conn = sqlite3.connect(_database_path())
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    """Create a new encoded Argon2id password representation."""

    return PASSWORD_HASHER.hash(password)


def _legacy_sha256(password: str) -> str:
    """Reproduce the former format only for authenticated migration."""

    return hashlib.sha256(password.encode()).hexdigest()


def is_legacy_password_hash(stored_hash: str) -> bool:
    return (
        isinstance(stored_hash, str)
        and len(stored_hash) == 64
        and all(character in "0123456789abcdef" for character in stored_hash)
    )


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify an Argon2 hash or the exact historical SHA-256 format."""

    if not isinstance(stored_hash, str) or not isinstance(password, str):
        return False
    if is_legacy_password_hash(stored_hash):
        return hmac.compare_digest(stored_hash, _legacy_sha256(password))
    try:
        return PASSWORD_HASHER.verify(stored_hash, password)
    except (InvalidHashError, VerificationError):
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    """Report whether a verified representation should be replaced."""

    if is_legacy_password_hash(stored_hash):
        return True
    try:
        return PASSWORD_HASHER.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return False


def verify_and_rehash_password(
    user_id: int,
    stored_hash: str,
    password: str,
) -> bool:
    """Verify a login password and upgrade its stored hash when required."""

    if not verify_password(stored_hash, password):
        return False
    if not password_needs_rehash(stored_hash):
        return True

    replacement = hash_password(password)
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ? AND password = ?",
            (replacement, user_id, stored_hash),
        )
        conn.commit()
    return True

def _fetchone(query, params=()):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        row = cur.fetchone()
        return dict(row) if row else None

def _exists(query, params=()):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        return cur.fetchone() is not None

def get_user_by_username(username):
    return _fetchone("SELECT * FROM users WHERE username = ?", (username,))

def get_user_by_id(user_id):
    return _fetchone("SELECT * FROM users WHERE id = ?", (user_id,))

def username_exists(username):
    return _exists("SELECT 1 FROM users WHERE username = ?", (username,))

def email_exists(email):
    return _exists("SELECT 1 FROM users WHERE email = ?", (email,))
