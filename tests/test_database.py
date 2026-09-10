import gc
import secrets
import sqlite3
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from werkzeug.datastructures import FileStorage

from apps.user.logic.users import update_avatar_file
from common.database import (
    REQUIRED_TABLES,
    SEED_BOARDS,
    SEED_CHATS,
    SEED_COMMENTS,
    SEED_USERS,
)
from common.users import get_db, hash_password, verify_password
from run import app


class DatabaseSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "data" / "runtime.db"
        self.avatar_dir = root / "avatars"
        self.original_database = app.config.get("DATABASE")
        self.original_avatar_dir = app.config.get("AVATAR_DIR")
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=self.avatar_dir,
        )

    def tearDown(self):
        app.config["DATABASE"] = self.original_database
        app.config["AVATAR_DIR"] = self.original_avatar_dir
        gc.collect()
        self.temp_dir.cleanup()

    def _invoke(self, *args, input_text=""):
        return app.test_cli_runner().invoke(args=list(args), input=input_text)

    def _rows(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchall()

    def _password_input(self, password):
        return f"{password}\n{password}\n"

    def test_init_db_creates_required_tables_without_enabling_foreign_keys(self):
        result = self._invoke("init-db")
        self.assertEqual(result.exit_code, 0, result.output)
        with sqlite3.connect(self.db_path) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
                if not row[0].startswith("sqlite_")
            }
            self.assertEqual(tables, set(REQUIRED_TABLES))
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 0)

    def test_init_db_adds_security_events_without_resetting_existing_product_data(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        from common.database import PRODUCT_SCHEMA

        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(PRODUCT_SCHEMA)
            conn.execute(
                "INSERT INTO users (id, username, password, role, email, bio) VALUES (?, ?, ?, ?, ?, ?)",
                (91, "existing", "existing-hash", "user", "existing@example.test", "keep"),
            )
            conn.commit()

        result = self._invoke("init-db")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(
            self._rows("SELECT username, bio FROM users WHERE id = ?", (91,)),
            [("existing", "keep")],
        )
        self.assertEqual(
            self._rows(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
                ("security_events",),
            ),
            [("security_events",)],
        )

    def test_repeated_init_preserves_rows_and_configured_avatar_bytes(self):
        self.assertEqual(self._invoke("init-db").exit_code, 0)
        password = secrets.token_urlsafe(18)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO users (id, username, password, role, email, bio) VALUES (?, ?, ?, ?, ?, ?)",
                (88, "repeatable", hash_password(password), "user", "repeatable@example.test", "edited"),
            )
            conn.commit()

        avatar_bytes = b"avatar bytes remain unchanged"
        with app.app_context():
            filename = update_avatar_file(
                88,
                FileStorage(stream=BytesIO(avatar_bytes), filename="not-used.bin"),
            )
        avatar_path = self.avatar_dir / filename
        self.assertEqual(filename, "88.jpg")
        self.assertEqual(avatar_path.read_bytes(), avatar_bytes)

        second = self._invoke("init-db")
        self.assertEqual(second.exit_code, 0, second.output)
        self.assertEqual(
            self._rows("SELECT username, bio FROM users WHERE id = ?", (88,)),
            [("repeatable", "edited")],
        )
        self.assertEqual(avatar_path.read_bytes(), avatar_bytes)

    def test_incompatible_schema_fails_without_resetting_existing_rows(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, marker TEXT)")
            conn.execute("INSERT INTO users (id, marker) VALUES (?, ?)", (1, "keep"))
            conn.commit()

        result = self._invoke("init-db")
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Incompatible database schema", result.output)
        self.assertEqual(self._rows("SELECT id, marker FROM users"), [(1, "keep")])
        self.assertEqual(
            self._rows("SELECT name FROM sqlite_master WHERE type = 'table'"),
            [("users",)],
        )

    def test_create_admin_uses_shared_hash_and_rejects_collisions(self):
        self.assertEqual(self._invoke("init-db").exit_code, 0)
        suffix = secrets.token_hex(4)
        username = f"operator_{suffix}"
        email = f"operator_{suffix}@example.test"
        password = secrets.token_urlsafe(18)

        result = self._invoke(
            "create-admin",
            input_text=f"{username}\n{email}\n{self._password_input(password)}",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        row = self._rows(
            "SELECT username, password, role, email FROM users WHERE username = ?",
            (username,),
        )
        self.assertEqual(len(row), 1)
        self.assertEqual((row[0][0], row[0][2], row[0][3]), (username, "admin", email))
        self.assertTrue(row[0][1].startswith("$argon2id$"))
        self.assertTrue(verify_password(row[0][1], password))
        self.assertNotIn(password, result.output)
        self.assertNotIn(row[0][1], result.output)

        collision = self._invoke(
            "create-admin",
            input_text=(
                f"{username}\n{email}\n"
                f"{secrets.token_urlsafe(18)}\n{secrets.token_urlsafe(18)}\n"
            ),
        )
        self.assertNotEqual(collision.exit_code, 0)
        self.assertIn("already exists", collision.output)
        self.assertEqual(
            self._rows("SELECT COUNT(*) FROM users WHERE username = ?", (username,)),
            [(1,)],
        )

    def test_seed_demo_is_neutral_structural_and_uses_only_member_roles(self):
        self.assertEqual(self._invoke("init-db").exit_code, 0)
        password = secrets.token_urlsafe(18)
        result = self._invoke(
            "seed-demo",
            input_text=self._password_input(password),
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn(password, result.output)
        self.assertEqual(
            self._rows("SELECT COUNT(*) FROM users"),
            [(len(SEED_USERS),)],
        )
        self.assertEqual(
            self._rows("SELECT COUNT(*) FROM board"),
            [(len(SEED_BOARDS),)],
        )
        self.assertEqual(
            self._rows("SELECT COUNT(*) FROM comments"),
            [(len(SEED_COMMENTS),)],
        )
        self.assertEqual(
            self._rows("SELECT COUNT(*) FROM chat"),
            [(len(SEED_CHATS),)],
        )
        self.assertEqual(self._rows("SELECT DISTINCT role FROM users"), [("user",)])
        self.assertEqual(
            self._rows(
                "SELECT sender_id, recipient_id FROM chat ORDER BY id"
            ),
            [(2101, 2102), (2102, 2101)],
        )
        self.assertIn("hábitos", self._rows("SELECT body FROM board WHERE id = 3101")[0][0])

    def test_repeated_seed_is_noop_without_prompt_and_preserves_edits(self):
        self.assertEqual(self._invoke("init-db").exit_code, 0)
        first_password = secrets.token_urlsafe(18)
        self.assertEqual(
            self._invoke("seed-demo", input_text=self._password_input(first_password)).exit_code,
            0,
        )
        edited_title = "Título editado pelo operador"
        edited_message = "Mensagem revisada pelo operador"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE board SET title = ? WHERE id = 3101", (edited_title,))
            conn.execute("UPDATE chat SET text = ? WHERE id = 5101", (edited_message,))
            conn.execute("UPDATE users SET bio = ? WHERE id = 2101", ("Bio revisada",))
            conn.commit()

        repeated = self._invoke("seed-demo")
        self.assertEqual(repeated.exit_code, 0, repeated.output)
        self.assertNotIn("Demo password", repeated.output)
        self.assertIn("already present", repeated.output)
        self.assertEqual(self._rows("SELECT title FROM board WHERE id = 3101"), [(edited_title,)])
        self.assertEqual(self._rows("SELECT text FROM chat WHERE id = 5101"), [(edited_message,)])
        self.assertEqual(self._rows("SELECT bio FROM users WHERE id = 2101"), [("Bio revisada",)])

    def test_partial_seed_fails_before_mutation_or_prompt(self):
        self.assertEqual(self._invoke("init-db").exit_code, 0)
        user = SEED_USERS[0]
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO users (id, username, password, role, email, bio) VALUES (?, ?, ?, ?, ?, ?)",
                (user["id"], user["username"], hash_password(secrets.token_urlsafe(18)), user["role"], user["email"], user["bio"]),
            )
            conn.commit()

        result = self._invoke("seed-demo")
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("partially present", result.output)
        self.assertEqual(self._rows("SELECT COUNT(*) FROM users"), [(1,)])
        self.assertEqual(self._rows("SELECT COUNT(*) FROM board"), [(0,)])

    def test_configured_database_avatar_and_reset_route_contract(self):
        self.assertEqual(self._invoke("init-db").exit_code, 0)
        with app.app_context():
            with get_db() as conn:
                self.assertEqual(Path(conn.execute("PRAGMA database_list").fetchone()[2]), self.db_path)
                self.assertEqual(conn.row_factory, sqlite3.Row)

        with app.app_context():
            payload = b"configured avatar"
            filename = update_avatar_file(
                123,
                FileStorage(stream=BytesIO(payload), filename="ignored.png"),
            )
        self.assertEqual(filename, "123.jpg")
        self.assertEqual((self.avatar_dir / "123.jpg").read_bytes(), payload)
        self.assertFalse(any(rule.rule == "/resetdb" for rule in app.url_map.iter_rules()))

    def test_default_runtime_database_was_not_created(self):
        project_root = Path(__file__).resolve().parents[1]
        self.assertFalse((project_root / "data" / "secureboard.db").exists())


if __name__ == "__main__":
    unittest.main()
