import base64
import gc
import hashlib
import json
import secrets
import sqlite3
import tempfile
import unittest
from http.cookies import SimpleCookie
from pathlib import Path

from common.database import init_db
from common.session import create_session, revoke_session
from common.users import hash_password
from run import app


class SessionSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "session-security.db"
        self.avatar_dir = root / "avatars"
        self.original_config = {
            "DATABASE": app.config.get("DATABASE"),
            "AVATAR_DIR": app.config.get("AVATAR_DIR"),
            "TESTING": app.config.get("TESTING"),
            "SESSION_LIFETIME_SECONDS": app.config.get("SESSION_LIFETIME_SECONDS"),
            "SESSION_COOKIE_SECURE": app.config.get("SESSION_COOKIE_SECURE"),
        }
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=self.avatar_dir,
            SESSION_LIFETIME_SECONDS=3600,
            SESSION_COOKIE_SECURE=False,
        )
        init_db(self.db_path)
        self.member_password = f"member-{secrets.token_urlsafe(18)}"
        self.admin_password = f"admin-{secrets.token_urlsafe(18)}"
        self.replacement_password = f"replacement-{secrets.token_urlsafe(18)}"
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        101,
                        "session_member",
                        hash_password(self.member_password),
                        "user",
                        "member@example.test",
                        "Member bio",
                    ),
                    (
                        201,
                        "session_admin",
                        hash_password(self.admin_password),
                        "admin",
                        "admin@example.test",
                        "Admin bio",
                    ),
                ],
            )
            conn.commit()
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    @staticmethod
    def _digest(raw_token):
        return hashlib.sha256(raw_token.encode()).hexdigest()

    @staticmethod
    def _cookie(response):
        cookies = SimpleCookie()
        for header in response.headers.getlist("Set-Cookie"):
            cookies.load(header)
        return cookies["session_id"]

    def _login(self, username="session_member", password=None, client=None):
        active_client = client or self.client
        return active_client.post(
            "/login",
            data={
                "username": username,
                "password": self.member_password if password is None else password,
            },
        )

    def _create_session(self, user_id=101):
        with app.app_context():
            return create_session(user_id)

    def _session_row(self, raw_token):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                """
                SELECT user_id, token_hash, created_at, expires_at, revoked_at
                FROM auth_sessions WHERE token_hash = ?
                """,
                (self._digest(raw_token),),
            ).fetchone()

    def _csrf_token(self, raw_token):
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (self._digest(raw_token),),
            ).fetchone()
        self.assertIsNotNone(row)
        return row[0]

    @staticmethod
    def _old_unsigned_token(user_id=101, username="session_member", role="user"):
        payload = {"u": username, "id": user_id, "r": role, "exp": 4102444800, "v": 1}
        return base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).decode()

    def test_login_creates_server_side_session(self):
        response = self._login()
        raw_token = self._cookie(response).value
        row = self._session_row(raw_token)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(row[0], 101)
        self.assertIsNone(row[4])

    def test_raw_session_token_is_not_stored_in_sqlite(self):
        raw_token = self._cookie(self._login()).value
        with sqlite3.connect(self.db_path) as conn:
            stored = str(conn.execute("SELECT * FROM auth_sessions").fetchall())
        self.assertNotIn(raw_token, stored)
        self.assertIn(self._digest(raw_token), stored)

    def test_stored_digest_resolves_correct_database_user(self):
        raw_token = self._create_session()
        self.client.set_cookie("session_id", raw_token)
        response = self.client.get("/profile")
        self.assertEqual(self._session_row(raw_token)[1], self._digest(raw_token))
        self.assertEqual(response.status_code, 200)
        self.assertIn("session_member", response.get_data(as_text=True))

    def test_cookie_is_httponly(self):
        self.assertTrue(self._cookie(self._login())["httponly"])

    def test_cookie_has_explicit_samesite_lax(self):
        self.assertEqual(self._cookie(self._login())["samesite"], "Lax")

    def test_cookie_and_server_session_have_consistent_finite_lifetime(self):
        response = self._login()
        cookie = self._cookie(response)
        row = self._session_row(cookie.value)
        self.assertEqual(cookie["max-age"], "3600")
        self.assertEqual(row[3] - row[2], 3600)

    def test_secure_configuration_emits_secure_cookie(self):
        app.config["SESSION_COOKIE_SECURE"] = True
        header = "\n".join(self._login().headers.getlist("Set-Cookie"))
        self.assertIn("; Secure", header)

    def test_plain_http_development_configuration_remains_usable(self):
        app.config["SESSION_COOKIE_SECURE"] = False
        response = self._login()
        header = "\n".join(response.headers.getlist("Set-Cookie"))
        self.assertNotIn("; Secure", header)
        self.assertEqual(self.client.get("/board").status_code, 200)

    def test_old_forged_base64_identity_is_rejected_at_authentication_boundary(self):
        self.client.set_cookie("session_id", self._old_unsigned_token())
        response = self.client.get("/profile")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_random_invalid_token_is_rejected(self):
        self.client.set_cookie("session_id", secrets.token_urlsafe(32))
        response = self.client.get("/board")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_expired_server_side_session_is_rejected(self):
        raw_token = self._create_session()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE auth_sessions SET expires_at = created_at - 1 WHERE token_hash = ?",
                (self._digest(raw_token),),
            )
            conn.commit()
        self.client.set_cookie("session_id", raw_token)
        self.assertEqual(self.client.get("/profile").headers["Location"], "/login")

    def test_revoked_session_is_rejected(self):
        raw_token = self._create_session()
        with app.app_context():
            self.assertTrue(revoke_session(raw_token))
        self.client.set_cookie("session_id", raw_token)
        self.assertEqual(self.client.get("/profile").headers["Location"], "/login")

    def test_logout_revokes_server_side_session(self):
        raw_token = self._cookie(self._login()).value
        response = self.client.post(
            "/logout", data={"csrf_token": self._csrf_token(raw_token)}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIsNotNone(self._session_row(raw_token)[4])

    def test_copied_pre_logout_token_fails_after_logout(self):
        raw_token = self._cookie(self._login()).value
        self.client.post(
            "/logout", data={"csrf_token": self._csrf_token(raw_token)}
        )
        replay = app.test_client()
        replay.set_cookie("session_id", raw_token)
        response = replay.get("/profile")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_password_change_invalidates_all_old_sessions(self):
        current_token = self._cookie(self._login()).value
        other_token = self._create_session()
        response = self.client.post(
            "/profile/edit_password",
            data={
                "password": self.replacement_password,
                "confirm": self.replacement_password,
                "csrf_token": self._csrf_token(current_token),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIsNotNone(self._session_row(current_token)[4])
        self.assertIsNotNone(self._session_row(other_token)[4])

    def test_copied_pre_password_change_token_fails_after_change(self):
        old_token = self._cookie(self._login()).value
        self.client.post(
            "/profile/edit_password",
            data={
                "password": self.replacement_password,
                "confirm": self.replacement_password,
                "csrf_token": self._csrf_token(old_token),
            },
        )
        replay = app.test_client()
        replay.set_cookie("session_id", old_token)
        response = replay.get("/profile")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_password_change_rotates_current_browser_to_fresh_session(self):
        old_token = self._cookie(self._login()).value
        response = self.client.post(
            "/profile/edit_password",
            data={
                "password": self.replacement_password,
                "confirm": self.replacement_password,
                "csrf_token": self._csrf_token(old_token),
            },
        )
        new_token = self._cookie(response).value
        self.assertNotEqual(new_token, old_token)
        self.assertIsNone(self._session_row(new_token)[4])
        self.assertEqual(self.client.get("/profile").status_code, 200)

    def test_admin_authorization_tracks_current_database_role(self):
        raw_token = self._create_session()
        self.client.set_cookie("session_id", raw_token)
        self.assertEqual(self.client.get("/admin").status_code, 403)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (101,))
            conn.commit()
        self.assertEqual(self.client.get("/admin").status_code, 200)

    def test_false_client_role_data_cannot_create_admin_access(self):
        forged = self._old_unsigned_token(role="admin")
        self.client.set_cookie("session_id", forged)
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_security_events_never_contain_raw_token_or_digest(self):
        raw_token = self._cookie(self._login()).value
        digest = self._digest(raw_token)
        self.client.post(
            "/logout", data={"csrf_token": self._csrf_token(raw_token)}
        )
        with sqlite3.connect(self.db_path) as conn:
            events = str(conn.execute("SELECT * FROM security_events").fetchall())
        self.assertNotIn(raw_token, events)
        self.assertNotIn(digest, events)


if __name__ == "__main__":
    unittest.main()
