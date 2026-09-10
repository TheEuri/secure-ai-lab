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


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = BASE_DIR / "data" / "secureboard.db"


SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    bio TEXT
);

CREATE TABLE chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
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


REQUIRED_TABLES = frozenset({"users", "chat", "board", "comments"})

EXPECTED_COLUMNS = {
    "users": (
        ("id", "INTEGER", 0, None, 1),
        ("username", "TEXT", 1, None, 0),
        ("password", "TEXT", 1, None, 0),
        ("role", "TEXT", 1, None, 0),
        ("email", "TEXT", 1, None, 0),
        ("bio", "TEXT", 0, None, 0),
    ),
    "chat": (
        ("id", "INTEGER", 0, None, 1),
        ("sender_id", "INTEGER", 1, None, 0),
        ("recipient_id", "INTEGER", 1, None, 0),
        ("text", "TEXT", 1, None, 0),
        ("timestamp", "DATETIME", 0, "CURRENT_TIMESTAMP", 0),
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


def _validate_indexes(conn):
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


def _validate_schema(conn):
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
    if actual_tables != REQUIRED_TABLES:
        missing = sorted(REQUIRED_TABLES - actual_tables)
        unexpected = sorted(actual_tables - REQUIRED_TABLES)
        details = []
        if missing:
            details.append(f"missing tables: {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected tables: {', '.join(unexpected)}")
        if not details:
            details.append("table set does not match the product schema")
        raise DatabaseSetupError("Incompatible database schema: " + "; ".join(details) + ".")

    for table, expected in EXPECTED_COLUMNS.items():
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        actual = tuple((row[1], row[2], row[3], row[4], row[5]) for row in rows)
        if actual != expected:
            raise DatabaseSetupError(
                f"Incompatible database schema: columns for {table} do not match."
            )

    for table, expected in EXPECTED_FOREIGN_KEYS.items():
        rows = conn.execute(f"PRAGMA foreign_key_list({table})").fetchall()
        actual = {(row[3], row[2], row[4]) for row in rows}
        if actual != expected:
            raise DatabaseSetupError(
                f"Incompatible database schema: foreign keys for {table} do not match."
            )

    _validate_indexes(conn)

    for table in ("chat", "board", "comments"):
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        if not row or "AUTOINCREMENT" not in (row[0] or "").upper():
            raise DatabaseSetupError(
                f"Incompatible database schema: {table} must use AUTOINCREMENT."
            )


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

    try:
        with sqlite3.connect(path) as conn:
            state = _seed_state(conn)
            if state == "complete":
                return False
            if state != "new":
                raise DatabaseSetupError(
                    "Demo data is partially present; refusing to modify the existing database."
                )

            password_hash = hash_password(password)
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
                            password_hash,
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
                conn.executemany(
                    "INSERT INTO chat (id, sender_id, recipient_id, text) VALUES (?, ?, ?, ?)",
                    [
                        (chat["id"], chat["sender_id"], chat["recipient_id"], chat["text"])
                        for chat in SEED_CHATS
                    ],
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
        password = click.prompt(
            "Demo password (used for all demo members)",
            hide_input=True,
            confirmation_prompt=True,
        )
        seed_demo_data(password, path)
    except DatabaseSetupError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        "Demo data created for ordinary members. Use create-admin to provision an administrator."
    )

def register_cli_commands(app):
    """Register only the explicit local setup commands on a Flask app."""

    for command in (_init_db_command, _create_admin_command, _seed_demo_command):
        if command.name not in app.cli.commands:
            app.cli.add_command(command)
