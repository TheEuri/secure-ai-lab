import gc
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

from common.database import init_db
from common.users import get_user_by_username, hash_password, verify_password
from run import app


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "data" / "registration.db"
        self.original_database = app.config.get("DATABASE")
        self.original_testing = app.config.get("TESTING")
        app.config.update(TESTING=True, DATABASE=self.db_path)
        init_db(self.db_path)
        self.client = app.test_client()

    def tearDown(self):
        app.config["DATABASE"] = self.original_database
        app.config["TESTING"] = self.original_testing
        gc.collect()
        self.temp_dir.cleanup()

    def _post(self, username="", email="", password="", **extra):
        data = {
            "username": username,
            "email": email,
            "password": password,
        }
        data.update(extra)
        return self.client.post("/register", data=data)

    def _rows(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchall()

    def _insert_user(self, user_id, username, email, password, role="user", bio=""):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, username, hash_password(password), role, email, bio),
            )

    def test_valid_registration_inserts_one_ordinary_user_with_shared_hash(self):
        username = f"member_{secrets.token_hex(5)}"
        email = f"{username}@example.test"
        password = secrets.token_urlsafe(18)

        before = self._rows("SELECT COUNT(*) FROM users")
        response = self._post(username=username, email=email, password=password)
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Account created. You may now log in.", body)
        self.assertNotIn(password, body)
        self.assertEqual(self._rows("SELECT COUNT(*) FROM users"), [(before[0][0] + 1,)])
        row = self._rows(
            "SELECT username, password, role, email, bio FROM users WHERE username = ?",
            (username,),
        )
        self.assertEqual(len(row), 1)
        self.assertEqual((row[0][0], row[0][2], row[0][3], row[0][4]), (username, "user", email, ""))
        self.assertTrue(row[0][1].startswith("$argon2id$"))
        self.assertTrue(verify_password(row[0][1], password))
        self.assertNotIn(row[0][1], body)
        with app.app_context():
            self.assertEqual(get_user_by_username(username)["username"], username)

    def test_unicode_username_is_stored_and_findable(self):
        username = f"ação_{secrets.token_hex(4)}"
        email = f"unicode_{secrets.token_hex(4)}@example.test"
        response = self._post(
            username=f"  {username}  ",
            email=f" {email} ",
            password=secrets.token_urlsafe(18),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self._rows("SELECT username, email FROM users"),
            [(username, email)],
        )

    def test_missing_required_fields_are_rejected_without_database_write(self):
        cases = (
            {"username": "", "email": "person@example.test", "password": "pw"},
            {"username": "person", "email": "", "password": "pw"},
            {"username": "person", "email": "person@example.test", "password": ""},
            {"username": "   ", "email": "person@example.test", "password": "pw"},
            {"username": "person", "email": "   ", "password": "pw"},
        )

        for case in cases:
            with self.subTest(case=case):
                response = self.client.post("/register", data=case)
                self.assertEqual(response.status_code, 200)
                self.assertIn("Username, email, and password are required.", response.get_data(as_text=True))
                self.assertEqual(self._rows("SELECT COUNT(*) FROM users"), [(0,)])

    def test_duplicate_username_gets_distinct_feedback(self):
        username = f"same_name_{secrets.token_hex(4)}"
        self._insert_user(41, username, "original@example.test", "original", bio="keep")

        response = self._post(
            username=username,
            email=f"new_{secrets.token_hex(4)}@example.test",
            password=secrets.token_urlsafe(18),
        )

        self.assertIn("That username is already in use.", response.get_data(as_text=True))
        self.assertEqual(self._rows("SELECT COUNT(*) FROM users"), [(1,)])

    def test_duplicate_email_gets_distinct_feedback(self):
        email = f"same_{secrets.token_hex(4)}@example.test"
        self._insert_user(42, f"original_{secrets.token_hex(4)}", email, "original")

        response = self._post(
            username=f"new_{secrets.token_hex(4)}",
            email=email,
            password=secrets.token_urlsafe(18),
        )

        self.assertIn("That email is already in use.", response.get_data(as_text=True))
        self.assertEqual(self._rows("SELECT COUNT(*) FROM users"), [(1,)])

    def test_both_duplicates_get_distinct_feedback_and_preserve_complete_row(self):
        username = f"same_both_{secrets.token_hex(4)}"
        email = f"both_{secrets.token_hex(4)}@example.test"
        password = secrets.token_urlsafe(18)
        self._insert_user(43, username, email, password, role="admin", bio="unchanged")
        before = self._rows(
            "SELECT id, username, password, role, email, bio FROM users WHERE id = 43"
        )

        response = self._post(
            username=f" {username} ",
            email=f" {email} ",
            password=secrets.token_urlsafe(18),
        )

        self.assertIn("That username and email are already in use.", response.get_data(as_text=True))
        self.assertEqual(
            self._rows("SELECT id, username, password, role, email, bio FROM users WHERE id = 43"),
            before,
        )

    def test_client_supplied_role_is_ignored(self):
        username = f"role_{secrets.token_hex(4)}"
        email = f"{username}@example.test"
        response = self._post(
            username=username,
            email=email,
            password=secrets.token_urlsafe(18),
            role="admin",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self._rows("SELECT role FROM users WHERE username = ?", (username,)),
            [("user",)],
        )

    def test_registration_feedback_and_username_value_are_escaped(self):
        username = "<b>member</b>"
        response = self._post(
            username=username,
            email=f"escaped_{secrets.token_hex(4)}@example.test",
            password=secrets.token_urlsafe(18),
        )
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("&lt;b&gt;member&lt;/b&gt;", body)
        self.assertNotIn(username, body)

    def test_registration_has_no_pending_queue_or_queue_helpers(self):
        project_root = Path(__file__).resolve().parents[1]
        pending_filename = "pending_" + "users.json"
        self.assertFalse((project_root / "data" / pending_filename).exists())
        route_source = (project_root / "apps" / "lobby" / "routes.py").read_text()
        helper_source = (project_root / "apps" / "lobby" / "logic" / "users.py").read_text()
        for source in (route_source, helper_source):
            self.assertNotIn("pending_" + "users", source)
            self.assertNotIn("add_" + "pending", source)
            self.assertNotIn("load_" + "pending", source)
            self.assertNotIn("PENDING_" + "FILE", source)

    def test_registration_does_not_create_default_runtime_database(self):
        project_root = Path(__file__).resolve().parents[1]
        default_database = project_root / "data" / "secureboard.db"
        self.assertFalse(default_database.exists())

        self._post(
            username=f"runtime_{secrets.token_hex(4)}",
            email=f"runtime_{secrets.token_hex(4)}@example.test",
            password=secrets.token_urlsafe(18),
        )

        self.assertFalse(default_database.exists())


if __name__ == "__main__":
    unittest.main()
