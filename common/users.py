import sqlite3
from pathlib import Path
import hashlib
from flask import current_app, has_app_context

DB_PATH = Path(__file__).resolve().parents[1] / 'data' / 'secureboard.db'


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
    return hashlib.sha256(password.encode()).hexdigest()

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
