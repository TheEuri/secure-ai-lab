"""Explicit SQLite schema and local setup commands.

The application deliberately keeps database setup out of import/startup.  This
module is the small boundary for creating a compatible product schema and for
provisioning local demo accounts/data through Flask's CLI.
"""

from pathlib import Path
import sqlite3

import click
from flask import current_app, has_app_context
from flask.cli import with_appcontext

from common.message_crypto import (
    MessageCryptoConfigurationError,
    encrypt_message,
    load_message_encryption_key,
)


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = BASE_DIR / "data" / "secureboard.db"


PRODUCT_SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    bio TEXT,
    avatar_sha256 TEXT NULL
);

CREATE TABLE chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    message_ciphertext BLOB NULL,
    message_nonce BLOB NULL,
    crypto_version INTEGER NULL,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(recipient_id) REFERENCES users(id)
);

CREATE TABLE board (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(author_id) REFERENCES users(id)
);

CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    board_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(board_id) REFERENCES board(id),
    FOREIGN KEY(author_id) REFERENCES users(id)
);
"""


SECURITY_EVENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor_user_id INTEGER NULL,
    outcome TEXT NOT NULL,
    target_type TEXT NULL,
    target_id INTEGER NULL,
    request_method TEXT NULL,
    request_path TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


AUTH_SESSIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER NULL,
    csrf_token TEXT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
"""


ADDITIVE_SCHEMA = SECURITY_EVENTS_SCHEMA + AUTH_SESSIONS_SCHEMA
SCHEMA = PRODUCT_SCHEMA + ADDITIVE_SCHEMA


PRODUCT_TABLES = frozenset({"users", "chat", "board", "comments"})
ADDITIVE_TABLES = frozenset({"security_events", "auth_sessions"})
REQUIRED_TABLES = PRODUCT_TABLES | ADDITIVE_TABLES

LEGACY_AUTH_SESSIONS_COLUMNS = (
    ("id", "INTEGER", 0, None, 1),
    ("user_id", "INTEGER", 1, None, 0),
    ("token_hash", "TEXT", 1, None, 0),
    ("created_at", "INTEGER", 1, None, 0),
    ("expires_at", "INTEGER", 1, None, 0),
    ("revoked_at", "INTEGER", 0, None, 0),
)

LEGACY_USERS_COLUMNS = (
    ("id", "INTEGER", 0, None, 1),
    ("username", "TEXT", 1, None, 0),
    ("password", "TEXT", 1, None, 0),
    ("role", "TEXT", 1, None, 0),
    ("email", "TEXT", 1, None, 0),
    ("bio", "TEXT", 0, None, 0),
)

LEGACY_CHAT_COLUMNS = (
    ("id", "INTEGER", 0, None, 1),
    ("sender_id", "INTEGER", 1, None, 0),
    ("recipient_id", "INTEGER", 1, None, 0),
    ("text", "TEXT", 1, None, 0),
    ("timestamp", "DATETIME", 0, "CURRENT_TIMESTAMP", 0),
)

EXPECTED_COLUMNS = {
    "users": (
        ("id", "INTEGER", 0, None, 1),
        ("username", "TEXT", 1, None, 0),
        ("password", "TEXT", 1, None, 0),
        ("role", "TEXT", 1, None, 0),
        ("email", "TEXT", 1, None, 0),
        ("bio", "TEXT", 0, None, 0),
        ("avatar_sha256", "TEXT", 0, None, 0),
    ),
    "chat": (
        ("id", "INTEGER", 0, None, 1),
        ("sender_id", "INTEGER", 1, None, 0),
        ("recipient_id", "INTEGER", 1, None, 0),
        ("text", "TEXT", 1, None, 0),
        ("timestamp", "DATETIME", 0, "CURRENT_TIMESTAMP", 0),
        ("message_ciphertext", "BLOB", 0, None, 0),
        ("message_nonce", "BLOB", 0, None, 0),
        ("crypto_version", "INTEGER", 0, None, 0),
    ),
    "board": (
        ("id", "INTEGER", 0, None, 1),
        ("author_id", "INTEGER", 1, None, 0),
        ("title", "TEXT", 1, None, 0),
        ("body", "TEXT", 1, None, 0),
        ("created_at", "DATETIME", 0, "CURRENT_TIMESTAMP", 0),
    ),
    "comments": (
        ("id", "INTEGER", 0, None, 1),
        ("board_id", "INTEGER", 1, None, 0),
        ("author_id", "INTEGER", 1, None, 0),
        ("body", "TEXT", 1, None, 0),
        ("created_at", "DATETIME", 0, "CURRENT_TIMESTAMP", 0),
    ),
    "security_events": (
        ("id", "INTEGER", 0, None, 1),
        ("event_type", "TEXT", 1, None, 0),
        ("actor_user_id", "INTEGER", 0, None, 0),
        ("outcome", "TEXT", 1, None, 0),
        ("target_type", "TEXT", 0, None, 0),
        ("target_id", "INTEGER", 0, None, 0),
        ("request_method", "TEXT", 0, None, 0),
        ("request_path", "TEXT", 0, None, 0),
        ("created_at", "TIMESTAMP", 0, "CURRENT_TIMESTAMP", 0),
    ),
    "auth_sessions": (
        ("id", "INTEGER", 0, None, 1),
        ("user_id", "INTEGER", 1, None, 0),
        ("token_hash", "TEXT", 1, None, 0),
        ("created_at", "INTEGER", 1, None, 0),
        ("expires_at", "INTEGER", 1, None, 0),
        ("revoked_at", "INTEGER", 0, None, 0),
        ("csrf_token", "TEXT", 0, None, 0),
    ),
}

EXPECTED_FOREIGN_KEYS = {
    "chat": {
        ("sender_id", "users", "id"),
        ("recipient_id", "users", "id"),
    },
    "board": {
        ("author_id", "users", "id"),
    },
    "comments": {
        ("board_id", "board", "id"),
        ("author_id", "users", "id"),
    },
    "auth_sessions": {
        ("user_id", "users", "id"),
    },
}


# These are intentionally neutral, fictional identities.  Passwords are
# supplied at setup time and are never stored in source or fixture constants.
SEED_USERS = (
    {
        "id": 2101,
        "username": "lume",
        "email": "lume@example.test",
        "role": "user",
        "bio": "Gosta de trocar ideias sobre projetos locais.",
    },
    {
        "id": 2102,
        "username": "nori",
        "email": "nori@example.test",
        "role": "user",
        "bio": "Coleciona perguntas e caminhos para aprender.",
    },
    {
        "id": 2103,
        "username": "tavi",
        "email": "tavi@example.test",
        "role": "user",
        "bio": "Prefere conversas tranquilas e anotações curtas.",
    },
)

SEED_BOARDS = (
    {
        "id": 3101,
        "author_id": 2101,
        "title": "Pequenas ideias para a semana",
        "body": "Quais hábitos simples ajudam a organizar uma semana movimentada?",
    },
    {
        "id": 3102,
        "author_id": 2102,
        "title": "Receitas com ingredientes locais",
        "body": "Vamos compartilhar combinações fáceis para um almoço leve e colorido.",
    },
)

SEED_COMMENTS = (
    {
        "id": 4101,
        "board_id": 3101,
        "author_id": 2102,
        "body": "Eu começo a semana escolhendo uma tarefa pequena e possível.",
    },
    {
        "id": 4102,
        "board_id": 3101,
        "author_id": 2103,
        "body": "Uma lista curta deixa espaço para ajustar os planos.",
    },
    {
        "id": 4103,
        "board_id": 3102,
        "author_id": 2101,
        "body": "Legumes assados e ervas frescas funcionam muito bem juntos.",
    },
)

SEED_CHATS = (
    {
        "id": 5101,
        "sender_id": 2101,
        "recipient_id": 2102,
        "text": "Oi, Nori! Você encontrou uma ideia boa para a semana?",
    },
    {
        "id": 5102,
        "sender_id": 2102,
        "recipient_id": 2101,
        "text": "Encontrei sim. Vou testar uma lista curta amanhã.",
    },
)


class DatabaseSetupError(RuntimeError):
    """Raised when setup would be unsafe or the product schema is incompatible."""


def _database_path(database_path=None):
    if database_path is not None:
        return Path(database_path)
    if has_app_context():
        configured = current_app.config.get("DATABASE")
        if configured:
            return Path(configured)
    return DEFAULT_DATABASE


def _user_schema_objects(conn):
    rows = conn.execute(
        """
        SELECT type, name
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
          AND type IN ('table', 'view', 'trigger')
        """
    ).fetchall()
    return {(row[0], row[1]) for row in rows}


def _validate_indexes(conn, actual_tables):
    unique_columns = set()
    for index_row in conn.execute("PRAGMA index_list(users)").fetchall():
        if not index_row[2]:
            continue
        index_name = str(index_row[1]).replace('"', '""')
        columns = conn.execute(f'PRAGMA index_info("{index_name}")').fetchall()
        if len(columns) == 1:
            unique_columns.add(columns[0][2])
    missing = {"username", "email"} - unique_columns
    if missing:
        raise DatabaseSetupError(
            "Incompatible database schema: users is missing unique "
            f"constraints for {', '.join(sorted(missing))}."
        )

    if "auth_sessions" in actual_tables:
        token_hash_is_unique = False
        for index_row in conn.execute("PRAGMA index_list(auth_sessions)").fetchall():
            if not index_row[2]:
                continue
            index_name = str(index_row[1]).replace('"', '""')
            columns = conn.execute(f'PRAGMA index_info("{index_name}")').fetchall()
            if len(columns) == 1 and columns[0][2] == "token_hash":
                token_hash_is_unique = True
                break
        if not token_hash_is_unique:
            raise DatabaseSetupError(
                "Incompatible database schema: auth_sessions is missing a unique "
                "constraint for token_hash."
            )


def _validate_schema(
    conn,
    *,
    allow_missing_additive_tables=False,
    allow_legacy_auth_sessions=False,
    allow_legacy_users=False,
    allow_legacy_chat=False,
):
    schema_objects = _user_schema_objects(conn)
    actual_tables = {name for kind, name in schema_objects if kind == "table"}
    unexpected_objects = sorted(
        f"{kind} {name}" for kind, name in schema_objects if kind != "table"
    )
    if unexpected_objects:
        raise DatabaseSetupError(
            "Incompatible database schema: unexpected objects: "
            + ", ".join(unexpected_objects)
            + "."
        )
    if allow_missing_additive_tables:
        missing = sorted(PRODUCT_TABLES - actual_tables)
        unexpected = sorted(actual_tables - REQUIRED_TABLES)
    else:
        missing = sorted(REQUIRED_TABLES - actual_tables)
        unexpected = sorted(actual_tables - REQUIRED_TABLES)
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing tables: {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected tables: {', '.join(unexpected)}")
        raise DatabaseSetupError("Incompatible database schema: " + "; ".join(details) + ".")

    for table, expected in EXPECTED_COLUMNS.items():
        if table not in actual_tables:
            continue
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        actual = tuple((row[1], row[2], row[3], row[4], row[5]) for row in rows)
        if actual != expected:
            if (
                table == "auth_sessions"
                and allow_legacy_auth_sessions
                and actual == LEGACY_AUTH_SESSIONS_COLUMNS
            ):
                continue
            if (
                table == "users"
                and allow_legacy_users
                and actual == LEGACY_USERS_COLUMNS
            ):
                continue
            if table == "chat" and allow_legacy_chat and actual == LEGACY_CHAT_COLUMNS:
                continue
            raise DatabaseSetupError(
                f"Incompatible database schema: columns for {table} do not match."
            )

    for table, expected in EXPECTED_FOREIGN_KEYS.items():
        if table not in actual_tables:
            continue
        rows = conn.execute(f"PRAGMA foreign_key_list({table})").fetchall()
        actual = {(row[3], row[2], row[4]) for row in rows}
        if actual != expected:
            raise DatabaseSetupError(
                f"Incompatible database schema: foreign keys for {table} do not match."
            )

    _validate_indexes(conn, actual_tables)

    autoincrement_tables = ["chat", "board", "comments"]
    if "security_events" in actual_tables:
        autoincrement_tables.append("security_events")
    if "auth_sessions" in actual_tables:
        autoincrement_tables.append("auth_sessions")
    for table in autoincrement_tables:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        if not row or "AUTOINCREMENT" not in (row[0] or "").upper():
            raise DatabaseSetupError(
                f"Incompatible database schema: {table} must use AUTOINCREMENT."
            )


def _upgrade_legacy_auth_sessions(conn):
    """Add only the known pre-CSRF session column without touching rows."""

    if not any(row[1] == "auth_sessions" for row in _user_schema_objects(conn)):
        return
    rows = conn.execute("PRAGMA table_info(auth_sessions)").fetchall()
    actual = tuple((row[1], row[2], row[3], row[4], row[5]) for row in rows)
    if actual == LEGACY_AUTH_SESSIONS_COLUMNS:
        conn.execute("ALTER TABLE auth_sessions ADD COLUMN csrf_token TEXT NULL")


def _upgrade_legacy_users(conn):
    """Add only the known pre-integrity nullable avatar digest column."""

    if not any(row[1] == "users" for row in _user_schema_objects(conn)):
        return
    rows = conn.execute("PRAGMA table_info(users)").fetchall()
    actual = tuple((row[1], row[2], row[3], row[4], row[5]) for row in rows)
    if actual == LEGACY_USERS_COLUMNS:
        conn.execute("ALTER TABLE users ADD COLUMN avatar_sha256 TEXT NULL")


def _upgrade_legacy_chat(conn):
    """Add only the known Phase-5K encrypted-message columns."""

    if not any(row[1] == "chat" for row in _user_schema_objects(conn)):
        return
    rows = conn.execute("PRAGMA table_info(chat)").fetchall()
    actual = tuple((row[1], row[2], row[3], row[4], row[5]) for row in rows)
    if actual == LEGACY_CHAT_COLUMNS:
        conn.execute("ALTER TABLE chat ADD COLUMN message_ciphertext BLOB NULL")
        conn.execute("ALTER TABLE chat ADD COLUMN message_nonce BLOB NULL")
        conn.execute("ALTER TABLE chat ADD COLUMN crypto_version INTEGER NULL")


def _compatible_database(database_path=None):
    path = _database_path(database_path)
    if not path.exists():
        raise DatabaseSetupError(
            f"Database is not initialized at {path}; run init-db first."
        )
    try:
        with sqlite3.connect(path) as conn:
            _validate_schema(conn)
    except sqlite3.DatabaseError as exc:
        raise DatabaseSetupError(f"Database cannot be read safely: {exc}.") from exc
    return path


def initialize_database(database_path=None):
    """Create or validate the exact product schema without deleting data."""

    path = _database_path(database_path)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with sqlite3.connect(path) as conn:
                conn.executescript(SCHEMA)
                _validate_schema(conn)
        except sqlite3.DatabaseError as exc:
            raise DatabaseSetupError(f"Database initialization failed: {exc}.") from exc
        return path

    try:
        with sqlite3.connect(path) as conn:
            # SQLite internal tables (for example sqlite_sequence) do not make a
            # database non-empty for setup purposes.  User objects do.
            if not _user_schema_objects(conn):
                conn.executescript(SCHEMA)
                _validate_schema(conn)
            else:
                _validate_schema(
                    conn,
                    allow_missing_additive_tables=True,
                    allow_legacy_auth_sessions=True,
                    allow_legacy_users=True,
                    allow_legacy_chat=True,
                )
                _upgrade_legacy_users(conn)
                _upgrade_legacy_auth_sessions(conn)
                _upgrade_legacy_chat(conn)
                conn.executescript(ADDITIVE_SCHEMA)
                _validate_schema(conn)
    except sqlite3.DatabaseError as exc:
        raise DatabaseSetupError(f"Database validation failed: {exc}.") from exc
    return path


def init_db(database_path=None):
    """Compatibility-friendly public name for the non-destructive initializer."""

    return initialize_database(database_path)


def create_admin_account(username, email, password, database_path=None):
    path = _compatible_database(database_path)
    from common.users import hash_password

    try:
        with sqlite3.connect(path) as conn:
            collision = conn.execute(
                "SELECT 1 FROM users WHERE username = ? OR email = ? LIMIT 1",
                (username, email),
            ).fetchone()
            if collision:
                raise DatabaseSetupError(
                    "An account with that username or email already exists; no changes made."
                )
            conn.execute(
                """
                INSERT INTO users (username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, hash_password(password), "admin", email, ""),
            )
            conn.commit()
    except sqlite3.IntegrityError as exc:
        raise DatabaseSetupError(
            "An account with that username or email already exists; no changes made."
        ) from exc
    except sqlite3.DatabaseError as exc:
        raise DatabaseSetupError(f"Administrator creation failed: {exc}.") from exc
    return path


def create_admin(username, email, password, database_path=None):
    return create_admin_account(username, email, password, database_path)


def _seed_state(conn):
    """Return new/complete, or reject partial and inconsistent seed state."""

    expected_count = (
        len(SEED_USERS) + len(SEED_BOARDS) + len(SEED_COMMENTS) + len(SEED_CHATS)
    )
    present_count = 0

    for user in SEED_USERS:
        row = conn.execute(
            "SELECT id, username, email, role FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
        identity_rows = conn.execute(
            "SELECT id, username, email FROM users WHERE username = ? OR email = ?",
            (user["username"], user["email"]),
        ).fetchall()

        if any(identity_row[0] != user["id"] for identity_row in identity_rows):
            raise DatabaseSetupError(
                "Demo data cannot be seeded safely: a user identifier collides."
            )
        if row is None:
            if identity_rows:
                raise DatabaseSetupError(
                    "Demo data cannot be seeded safely: a user identifier collides."
                )
            continue
        if tuple(row) != (
            user["id"],
            user["username"],
            user["email"],
            user["role"],
        ):
            raise DatabaseSetupError(
                "Demo data cannot be seeded safely: an existing user row is inconsistent."
            )
        present_count += 1

    for board in SEED_BOARDS:
        row = conn.execute(
            "SELECT id, author_id FROM board WHERE id = ?",
            (board["id"],),
        ).fetchone()
        if row is None:
            continue
        if tuple(row) != (board["id"], board["author_id"]):
            raise DatabaseSetupError(
                "Demo data cannot be seeded safely: a topic identifier collides."
            )
        present_count += 1

    for comment in SEED_COMMENTS:
        row = conn.execute(
            "SELECT id, board_id, author_id FROM comments WHERE id = ?",
            (comment["id"],),
        ).fetchone()
        if row is None:
            continue
        if tuple(row) != (
            comment["id"],
            comment["board_id"],
            comment["author_id"],
        ):
            raise DatabaseSetupError(
                "Demo data cannot be seeded safely: a reply identifier collides."
            )
        present_count += 1

    for chat in SEED_CHATS:
        row = conn.execute(
            "SELECT id, sender_id, recipient_id FROM chat WHERE id = ?",
            (chat["id"],),
        ).fetchone()
        if row is None:
            continue
        if tuple(row) != (chat["id"], chat["sender_id"], chat["recipient_id"]):
            raise DatabaseSetupError(
                "Demo data cannot be seeded safely: a message identifier collides."
            )
        present_count += 1

    if present_count == 0:
        return "new"
    if present_count == expected_count:
        return "complete"
    raise DatabaseSetupError(
        "Demo data is partially present; refusing to modify the existing database."
    )


def _seed_state_for_cli(database_path=None):
    path = _compatible_database(database_path)
    try:
        with sqlite3.connect(path) as conn:
            return path, _seed_state(conn)
    except sqlite3.DatabaseError as exc:
        raise DatabaseSetupError(f"Demo data inspection failed: {exc}.") from exc


def seed_demo_data(password, database_path=None):
    path = _compatible_database(database_path)
    from common.users import hash_password

    # Validate before the transaction so setup never partially inserts demo data.
    load_message_encryption_key()

    try:
        with sqlite3.connect(path) as conn:
            state = _seed_state(conn)
            if state == "complete":
                return False
            if state != "new":
                raise DatabaseSetupError(
                    "Demo data is partially present; refusing to modify the existing database."
                )

            with conn:
                conn.executemany(
                    """
                    INSERT INTO users (id, username, password, role, email, bio)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            user["id"],
                            user["username"],
                            hash_password(password),
                            user["role"],
                            user["email"],
                            user["bio"],
                        )
                        for user in SEED_USERS
                    ],
                )
                conn.executemany(
                    "INSERT INTO board (id, author_id, title, body) VALUES (?, ?, ?, ?)",
                    [
                        (board["id"], board["author_id"], board["title"], board["body"])
                        for board in SEED_BOARDS
                    ],
                )
                conn.executemany(
                    """
                    INSERT INTO comments (id, board_id, author_id, body)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (
                            comment["id"],
                            comment["board_id"],
                            comment["author_id"],
                            comment["body"],
                        )
                        for comment in SEED_COMMENTS
                    ],
                )
                for chat in SEED_CHATS:
                    conn.execute(
                        """
                        INSERT INTO chat (id, sender_id, recipient_id, text)
                        VALUES (?, ?, ?, '')
                        """,
                        (chat["id"], chat["sender_id"], chat["recipient_id"]),
                    )
                    ciphertext, nonce, version = encrypt_message(
                        chat["text"],
                        chat["id"],
                        chat["sender_id"],
                        chat["recipient_id"],
                    )
                    conn.execute(
                        """
                        UPDATE chat
                        SET message_ciphertext = ?, message_nonce = ?, crypto_version = ?
                        WHERE id = ?
                        """,
                        (ciphertext, nonce, version, chat["id"]),
                    )
            return True
    except sqlite3.IntegrityError as exc:
        raise DatabaseSetupError(
            "Demo data insertion conflicted with existing data; no changes made."
        ) from exc
    except sqlite3.DatabaseError as exc:
        raise DatabaseSetupError(f"Demo data insertion failed: {exc}.") from exc


def seed_demo(password, database_path=None):
    return seed_demo_data(password, database_path)


def encrypt_legacy_messages(database_path=None):
    """Encrypt every legacy chat row in one idempotent transaction."""

    path = _compatible_database(database_path)

    load_message_encryption_key()
    try:
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            with conn:
                partial = conn.execute(
                    """
                    SELECT 1 FROM chat
                    WHERE NOT (
                        (message_ciphertext IS NULL AND message_nonce IS NULL
                         AND crypto_version IS NULL)
                        OR
                        (message_ciphertext IS NOT NULL AND message_nonce IS NOT NULL
                         AND crypto_version IS NOT NULL AND text = '')
                    )
                    LIMIT 1
                    """
                ).fetchone()
                if partial:
                    raise DatabaseSetupError(
                        "Legacy message migration found incomplete encryption metadata."
                    )
                rows = conn.execute(
                    """
                    SELECT id, sender_id, recipient_id, text
                    FROM chat
                    WHERE message_ciphertext IS NULL
                      AND message_nonce IS NULL
                      AND crypto_version IS NULL
                    ORDER BY id
                    """
                ).fetchall()
                for row in rows:
                    ciphertext, nonce, version = encrypt_message(
                        row["text"], row["id"], row["sender_id"], row["recipient_id"]
                    )
                    conn.execute(
                        """
                        UPDATE chat
                        SET text = '', message_ciphertext = ?, message_nonce = ?,
                            crypto_version = ?
                        WHERE id = ?
                        """,
                        (ciphertext, nonce, version, row["id"]),
                    )
            return len(rows)
    except DatabaseSetupError:
        raise
    except sqlite3.DatabaseError as exc:
        raise DatabaseSetupError("Legacy message migration failed safely.") from exc


@click.command("init-db")
@with_appcontext
def _init_db_command():
    try:
        path = initialize_database()
    except DatabaseSetupError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Database ready at {path}.")

@click.command("create-admin")
@with_appcontext
def _create_admin_command():
    try:
        path = _compatible_database()
        username = click.prompt("Username")
        email = click.prompt("Email (fictional)")
        if not username or not email:
            raise DatabaseSetupError("Username and email must not be empty.")
        with sqlite3.connect(path) as conn:
            collision = conn.execute(
                "SELECT 1 FROM users WHERE username = ? OR email = ? LIMIT 1",
                (username, email),
            ).fetchone()
        if collision:
            raise DatabaseSetupError(
                "An account with that username or email already exists; no changes made."
            )
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
        create_admin_account(username, email, password, path)
    except DatabaseSetupError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("Administrator account created.")

@click.command("seed-demo")
@with_appcontext
def _seed_demo_command():
    try:
        path, state = _seed_state_for_cli()
        if state == "complete":
            click.echo("Demo data is already present; no changes made.")
            return
        load_message_encryption_key()
        password = click.prompt(
            "Demo password (used for all demo members)",
            hide_input=True,
            confirmation_prompt=True,
        )
        seed_demo_data(password, path)
    except (DatabaseSetupError, MessageCryptoConfigurationError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        "Demo data created for ordinary members. Use create-admin to provision an administrator."
    )


@click.command("encrypt-legacy-messages")
@with_appcontext
def _encrypt_legacy_messages_command():
    try:
        count = encrypt_legacy_messages()
    except (DatabaseSetupError, MessageCryptoConfigurationError) as exc:
        # Crypto configuration exceptions carry only a generic safe message.
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Encrypted {count} legacy private message(s).")

def register_cli_commands(app):
    """Register only the explicit local setup commands on a Flask app."""

    for command in (
        _init_db_command,
        _create_admin_command,
        _seed_demo_command,
        _encrypt_legacy_messages_command,
    ):
        if command.name not in app.cli.commands:
            app.cli.add_command(command)
