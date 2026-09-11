import gc
import hashlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image

from common.database import LEGACY_USERS_COLUMNS, init_db
from common.file_integrity import (
    AvatarPersistenceError,
    MATCH,
    MISMATCH,
    MISSING,
    UNTRACKED,
    canonical_avatar_path,
    get_avatar_integrity,
    get_file_integrity_rows,
)
from common.session import create_session
from common.users import hash_password
from run import app


class FileIntegrityTests(unittest.TestCase):
    """SHA-256 avatar-integrity states and administrator read-only view."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "integrity.db"
        self.avatar_dir = root / "avatars"
        self.original_config = {
            "DATABASE": app.config.get("DATABASE"),
            "AVATAR_DIR": app.config.get("AVATAR_DIR"),
            "TESTING": app.config.get("TESTING"),
        }
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=self.avatar_dir,
        )
        init_db(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (101, "integrity_member", hash_password("member-runtime"), "user", "integrity-member@example.test", ""),
                    (102, "integrity_untracked", hash_password("untracked-runtime"), "user", "integrity-untracked@example.test", ""),
                    (201, "integrity_admin", hash_password("admin-runtime"), "admin", "integrity-admin@example.test", ""),
                ],
            )
            conn.commit()
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    @staticmethod
    def _image_bytes(color=(30, 110, 190), image_format="JPEG", size=(5, 4)):
        output = io.BytesIO()
        Image.new("RGB", size, color).save(output, format=image_format)
        return output.getvalue()

    def _login_as(self, user_id):
        with app.app_context():
            token = create_session(user_id)
        self.client.set_cookie("session_id", token)
        with sqlite3.connect(self.db_path) as conn:
            self.csrf_token = conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()[0]

    def _admin_client(self):
        with app.app_context():
            token = create_session(201)
        client = app.test_client()
        client.set_cookie("session_id", token)
        return client

    def _upload(self, client=None, user_id=101, color=(30, 110, 190), filename="avatar.jpg"):
        client = client or self.client
        if client is self.client and not hasattr(self, "csrf_token"):
            self._login_as(user_id)
        csrf = self.csrf_token if client is self.client else self._csrf_for_client(client)
        return client.post(
            "/profile/edit_avatar",
            data={
                "csrf_token": csrf,
                "avatar": (io.BytesIO(self._image_bytes(color)), filename),
            },
            content_type="multipart/form-data",
        )

    def _csrf_for_client(self, client):
        token = client.get_cookie("session_id").value
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()[0]

    def _db_digest(self, user_id=101):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT avatar_sha256 FROM users WHERE id = ?", (user_id,)
            ).fetchone()[0]

    def test_new_schema_contains_nullable_avatar_digest(self):
        with sqlite3.connect(self.db_path) as conn:
            columns = conn.execute("PRAGMA table_info(users)").fetchall()
        self.assertEqual(columns[-1][1:], ("avatar_sha256", "TEXT", 0, None, 0))

    def test_exact_legacy_users_schema_upgrades_without_touching_rows(self):
        legacy_path = Path(self.temp_dir.name) / "legacy-users.db"
        with sqlite3.connect(legacy_path) as conn:
            conn.executescript(
                """
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
            )
            conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                (301, "legacy_integrity", "legacy-hash", "user", "legacy-integrity@example.test", "preserve"),
            )
            conn.commit()
        init_db(legacy_path)
        with sqlite3.connect(legacy_path) as conn:
            actual = tuple((row[1], row[2], row[3], row[4], row[5]) for row in conn.execute("PRAGMA table_info(users)"))
            self.assertEqual(actual[:-1], LEGACY_USERS_COLUMNS)
            self.assertIsNone(conn.execute("SELECT avatar_sha256 FROM users WHERE id = 301").fetchone()[0])
            self.assertEqual(conn.execute("SELECT username, bio FROM users WHERE id = 301").fetchone(), ("legacy_integrity", "preserve"))

    def test_status_rules_cover_match_mismatch_untracked_and_missing(self):
        path = canonical_avatar_path(101, self.avatar_dir)
        self.assertEqual(get_avatar_integrity(101, None, self.avatar_dir)["status"], MISSING)
        path.parent.mkdir(parents=True)
        first = self._image_bytes((10, 20, 30))
        path.write_bytes(first)
        actual = hashlib.sha256(first).hexdigest()
        self.assertEqual(get_avatar_integrity(101, None, self.avatar_dir)["status"], UNTRACKED)
        self.assertEqual(get_avatar_integrity(101, actual, self.avatar_dir)["status"], MATCH)
        self.assertEqual(get_avatar_integrity(101, "0" * 64, self.avatar_dir)["status"], MISMATCH)

    def test_successful_upload_is_match_with_digest_over_exact_stored_bytes(self):
        self._login_as(101)
        response = self._upload(color=(80, 90, 100), filename="input.png")
        self.assertEqual(response.status_code, 302)
        stored = (self.avatar_dir / "101.jpg").read_bytes()
        expected = self._db_digest()
        self.assertEqual(expected, hashlib.sha256(stored).hexdigest())
        self.assertEqual(get_avatar_integrity(101, expected, self.avatar_dir)["status"], MATCH)

    def test_external_replacement_without_db_change_is_mismatch(self):
        self._login_as(101)
        self.assertEqual(self._upload(color=(80, 90, 100)).status_code, 302)
        expected = self._db_digest()
        path = canonical_avatar_path(101, self.avatar_dir)
        path.write_bytes(self._image_bytes((220, 20, 30)))
        self.assertEqual(self._db_digest(), expected)
        result = get_avatar_integrity(101, expected, self.avatar_dir)
        self.assertEqual(result["status"], MISMATCH)
        self.assertNotEqual(result["current_digest"], expected)

    def test_admin_rows_are_bounded_to_database_users_and_digest_values_truncated(self):
        path = canonical_avatar_path(101, self.avatar_dir)
        path.parent.mkdir(parents=True)
        content = self._image_bytes()
        path.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE users SET avatar_sha256 = ? WHERE id = 101", (expected,))
            conn.execute("UPDATE users SET avatar_sha256 = ? WHERE id = 102", ("f" * 64,))
            conn.commit()
        with app.app_context():
            rows = get_file_integrity_rows(avatar_dir=self.avatar_dir)
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(by_id[101]["status"], MATCH)
        self.assertEqual(by_id[102]["status"], MISSING)
        self.assertEqual(by_id[101]["expected_digest"], expected[:12] + "…")
        self.assertNotEqual(by_id[101]["expected_digest"], expected)
        self.assertEqual(set(by_id), {101, 102, 201})

    def test_admin_page_requires_database_authorization_and_is_get_only(self):
        anonymous = app.test_client().get("/admin/file-integrity")
        self.assertEqual(anonymous.status_code, 302)
        self.assertIn("/login", anonymous.headers["Location"])

        self._login_as(101)
        member = self.client.get("/admin/file-integrity")
        self.assertEqual(member.status_code, 403)

        admin = self._admin_client()
        page = admin.get("/admin/file-integrity")
        self.assertEqual(page.status_code, 200)
        body = page.get_data(as_text=True)
        self.assertIn("MISSING", body)
        self.assertIn("integrity_member", body)
        self.assertNotIn(str(self.avatar_dir), body)
        self.assertNotIn("password", body.lower())
        self.assertEqual(admin.post("/admin/file-integrity").status_code, 405)

    def test_admin_page_does_not_accept_arbitrary_paths_or_hashing_input(self):
        with self.assertRaises(ValueError):
            canonical_avatar_path("../../outside", self.avatar_dir)
        admin = self._admin_client()
        response = admin.get("/admin/file-integrity?path=../../outside&digest=sentinel")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("outside", response.get_data(as_text=True))
        self.assertNotIn("sentinel", response.get_data(as_text=True))

    def test_filesystem_replacement_then_digest_failure_is_surfaced_without_success_claim(self):
        with app.app_context():
            original = self._image_bytes((1, 2, 3))
            new = self._image_bytes((4, 5, 6))
            path = canonical_avatar_path(101, self.avatar_dir)
            path.parent.mkdir(parents=True)
            path.write_bytes(original)
            with patch("common.file_integrity.get_db", side_effect=sqlite3.OperationalError("db failure")):
                with self.assertRaises(AvatarPersistenceError):
                    from common.file_integrity import store_canonical_avatar

                    store_canonical_avatar(101, new, self.avatar_dir)
            self.assertEqual(path.read_bytes(), new)
            self.assertEqual(get_avatar_integrity(101, None, self.avatar_dir)["status"], UNTRACKED)

    def test_success_and_mismatch_demo_keeps_full_digest_out_of_admin_html(self):
        self._login_as(101)
        self.assertEqual(self._upload(color=(15, 25, 35)).status_code, 302)
        expected = self._db_digest()
        path = canonical_avatar_path(101, self.avatar_dir)
        path.write_bytes(self._image_bytes((200, 201, 202)))
        admin = self._admin_client()
        body = admin.get("/admin/file-integrity").get_data(as_text=True)
        self.assertIn("MISMATCH", body)
        self.assertNotIn(expected, body)
        self.assertNotIn(str(path), body)


if __name__ == "__main__":
    unittest.main()
