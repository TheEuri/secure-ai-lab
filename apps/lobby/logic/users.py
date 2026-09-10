"""Bounded account-creation helpers for the public registration flow."""

import sqlite3

from common.users import get_db, hash_password


ACCOUNT_CREATED = 'created'
ACCOUNT_CREATION_ERROR = 'error'
DUPLICATE_USERNAME = 'duplicate_username'
DUPLICATE_EMAIL = 'duplicate_email'
DUPLICATE_USERNAME_AND_EMAIL = 'duplicate_username_and_email'


def _duplicate_result(conn, username: str, email: str) -> str:
    username_taken = conn.execute(
        'SELECT 1 FROM users WHERE username = ?',
        (username,),
    ).fetchone() is not None
    email_taken = conn.execute(
        'SELECT 1 FROM users WHERE email = ?',
        (email,),
    ).fetchone() is not None

    if username_taken and email_taken:
        return DUPLICATE_USERNAME_AND_EMAIL
    if username_taken:
        return DUPLICATE_USERNAME
    if email_taken:
        return DUPLICATE_EMAIL
    return ACCOUNT_CREATION_ERROR


def _rollback_safely(conn) -> None:
    try:
        conn.rollback()
    except sqlite3.DatabaseError:
        pass


def create_user(username: str, password: str, email: str) -> str:
    """Create one ordinary account and return a sanitized result status."""

    try:
        conn = get_db()
    except sqlite3.DatabaseError:
        return ACCOUNT_CREATION_ERROR

    try:
        try:
            conn.execute(
                """
                INSERT INTO users (username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, hash_password(password), 'user', email, ''),
            )
            conn.commit()
            return ACCOUNT_CREATED
        except sqlite3.IntegrityError:
            _rollback_safely(conn)
            try:
                return _duplicate_result(conn, username, email)
            except sqlite3.DatabaseError:
                return ACCOUNT_CREATION_ERROR
        except sqlite3.DatabaseError:
            _rollback_safely(conn)
            return ACCOUNT_CREATION_ERROR
    finally:
        try:
            conn.close()
        except sqlite3.DatabaseError:
            pass
