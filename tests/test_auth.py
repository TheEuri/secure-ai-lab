import base64
import gc
import json
import secrets
import sqlite3
import tempfile
import unittest
from email.message import Message
from http.cookies import SimpleCookie
from pathlib import Path
from unittest.mock import patch

from common.database import init_db
from common.session import generate_token
from common.users import hash_password
from run import app


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "data" / "auth.db"
        self.original_database = app.config.get("DATABASE")
        self.original_testing = app.config.get("TESTING")
        app.config.update(TESTING=True, DATABASE=self.db_path)
        init_db(self.db_path)
        self.client = app.test_client()
        self.member = self._insert_user("member", "user", 101)
        self.admin = self._insert_user("admin", "admin", 102)

    def tearDown(self):
        app.config["DATABASE"] = self.original_database
        app.config["TESTING"] = self.original_testing
        gc.collect()
        self.temp_dir.cleanup()

    def _insert_user(self, label, role, user_id):
        suffix = secrets.token_hex(5)
        account = {
            "id": user_id,
            "username": f"{label}_{suffix}",
            "email": f"{label}_{suffix}@example.test",
            "password": secrets.token_urlsafe(18),
            "role": role,
        }
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    account["id"],
                    account["username"],
                    hash_password(account["password"]),
                    account["role"],
                    account["email"],
                    "",
                ),
            )
        return account

    @staticmethod
    def _cookie_headers(response):
        return response.headers.getlist("Set-Cookie")

    def _issued_session_cookie(self, response):
        cookies = SimpleCookie()
        for header in self._cookie_headers(response):
            cookies.load(header)
        self.assertIn("session_id", cookies)
        return cookies["session_id"]

    def _login(self, account, client=None):
        active_client = client or self.client
        return active_client.post(
            "/login",
            data={
                "username": account["username"],
                "password": account["password"],
            },
        )

    @staticmethod
    def _unsigned_token(payload):
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.b64encode(raw).decode()

    def test_valid_member_and_admin_login_issue_session_and_redirect_to_board(self):
        for account in (self.member, self.admin):
            with self.subTest(role=account["role"]):
                client = app.test_client()
                response = self._login(account, client)

                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["Location"], "/board")
                self.assertNotIn(account["password"], response.get_data(as_text=True))
                self.assertNotIn(
                    hash_password(account["password"]), response.get_data(as_text=True)
                )
                self.assertEqual(client.get("/board").status_code, 200)
                self.assertNotIn("pre_auth_token", "\n".join(self._cookie_headers(response)))

    def test_invalid_username_and_wrong_password_use_ordinary_feedback_and_no_cookie(self):
        unknown = {
            "username": f"missing_{secrets.token_hex(5)}",
            "password": secrets.token_urlsafe(18),
        }
        with patch("apps.lobby.routes.time.sleep") as sleep:
            response = self.client.post("/login", data=unknown)
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body.count("Invalid credentials."), 1)
        self.assertNotIn("<!--", body)
        self.assertEqual(self._cookie_headers(response), [])
        sleep.assert_called_once_with(0.05)

        wrong_password = secrets.token_urlsafe(18)
        with patch("apps.lobby.routes.time.sleep") as sleep:
            response = self.client.post(
                "/login",
                data={"username": self.member["username"], "password": wrong_password},
            )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body.count("Invalid credentials."), 1)
        self.assertNotIn("<!--", body)
        self.assertEqual(self._cookie_headers(response), [])
        sleep.assert_called_once_with(0.1)
        self.assertFalse(Path(__file__).resolve().parents[1].joinpath(
            "apps/lobby/data/pre_auth.json"
        ).exists())

    def test_registration_then_login_reaches_authenticated_board_flow(self):
        suffix = secrets.token_hex(5)
        account = {
            "username": f"registered_{suffix}",
            "email": f"registered_{suffix}@example.test",
            "password": secrets.token_urlsafe(18),
        }
        response = self.client.post("/register", data=account)
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Account created. You may now log in.", body)
        self.assertNotIn(account["password"], body)
        self.assertNotIn(hash_password(account["password"]), body)

        response = self._login(account)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/board")
        self.assertTrue(self._issued_session_cookie(response).value)
        self.assertEqual(self.client.get("/").headers["Location"], "/board")
        self.assertEqual(self.client.get("/board").status_code, 200)

    def test_issued_token_is_standard_base64_json_and_preserves_current_schema(self):
        response = self._login(self.member)
        session_cookie = self._issued_session_cookie(response)
        payload = json.loads(base64.b64decode(session_cookie.value, validate=True).decode())

        self.assertEqual(set(payload), {"u", "id", "r", "exp", "v"})
        self.assertEqual(payload["u"], self.member["username"])
        self.assertEqual(payload["id"], self.member["id"])
        self.assertEqual(payload["r"], self.member["role"])
        self.assertIsInstance(payload["exp"], int)
        self.assertEqual(payload["v"], 1)
        self.assertNotIn("signature", payload)
        self.assertNotIn("sig", payload)
        self.assertNotIn("mac", payload)

    def test_missing_expiration_remains_compatible_and_expired_tokens_are_rejected(self):
        missing_exp = self._unsigned_token(
            {"u": self.member["username"], "id": self.member["id"], "r": "user", "v": 1}
        )
        self.client.set_cookie("session_id", missing_exp)
        self.assertEqual(self.client.get("/board").status_code, 200)

        expired = generate_token(
            self.member["username"], self.member["role"], self.member["id"], ttl_seconds=-1
        )
        self.client.set_cookie("session_id", expired)
        response = self.client.get("/board")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_session_cookie_issuance_keeps_exact_existing_attributes(self):
        response = self._login(self.member)
        cookie = self._issued_session_cookie(response)
        header = "\n".join(self._cookie_headers(response)).lower()

        self.assertEqual(cookie["path"], "/")
        self.assertEqual(cookie["httponly"], "")
        self.assertEqual(cookie["secure"], "")
        self.assertEqual(cookie["samesite"], "")
        self.assertEqual(cookie["max-age"], "")
        self.assertEqual(cookie["expires"], "")
        for attribute in ("httponly", "secure", "samesite", "max-age", "expires"):
            self.assertNotIn(attribute, header)

    def test_database_role_is_authoritative_over_token_role_claim(self):
        normal_with_admin_claim = self._unsigned_token(
            {
                "u": self.member["username"],
                "id": self.member["id"],
                "r": "admin",
                "exp": 4102444800,
                "v": 1,
            }
        )
        self.client.set_cookie("session_id", normal_with_admin_claim)
        self.assertEqual(self.client.get("/admin").status_code, 403)

        admin_with_user_claim = self._unsigned_token(
            {
                "u": self.admin["username"],
                "id": self.admin["id"],
                "r": "user",
                "exp": 4102444800,
                "v": 1,
            }
        )
        self.client.set_cookie("session_id", admin_with_user_claim)
        self.assertEqual(self.client.get("/admin").status_code, 200)

    def test_logout_keeps_redirect_and_client_cookie_deletion_semantics(self):
        self.assertEqual(self._login(self.member).status_code, 302)
        response = self.client.get("/logout")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")
        cookies = SimpleCookie()
        for header in self._cookie_headers(response):
            cookies.load(header)
        self.assertIn("session_id", cookies)
        self.assertEqual(cookies["session_id"].value, "")
        self.assertEqual(cookies["session_id"]["path"], "/")
        self.assertEqual(cookies["session_id"]["max-age"], "0")
        self.assertEqual(self.client.get("/board").headers["Location"], "/login")

    def test_fake_auth_download_routes_and_resources_are_absent_but_attribution_is_retained(self):
        project_root = Path(__file__).resolve().parents[1]
        route_paths = {rule.rule for rule in app.url_map.iter_rules()}
        for route in (
            "/2fa",
            "/download/nicks.txt",
            "/download/rockyou.txt",
            "/download/readme.txt",
        ):
            with self.subTest(route=route):
                self.assertNotIn(route, route_paths)
                self.assertEqual(self.client.get(route).status_code, 404)

        for relative_path in (
            "apps/lobby/templates/2fa.html",
            "apps/lobby/logic/auth_state.py",
            "apps/lobby/logic/two_fa.py",
            "apps/lobby/data/pre_auth.json",
            "apps/lobby/data/2fa.json",
            "apps/lobby/data/download/nicks.txt",
            "apps/lobby/data/download/rockyou.txt",
        ):
            self.assertFalse((project_root / relative_path).exists(), relative_path)

        readme = project_root / "apps/lobby/data/download/readme.txt"
        self.assertFalse(readme.exists())

        notice = project_root / "NOTICE"
        self.assertTrue(notice.exists())
        self.assertIn("Corisco 2025", notice.read_text(encoding="utf-8"))

    def test_auth_cleanup_has_no_fake_symbols_or_download_links_and_uses_configured_database(self):
        project_root = Path(__file__).resolve().parents[1]
        route_source = (project_root / "apps/lobby/routes.py").read_text(encoding="utf-8")
        login_source = (project_root / "apps/lobby/templates/login.html").read_text(encoding="utf-8")
        register_source = (project_root / "apps/lobby/templates/register.html").read_text(encoding="utf-8")
        css_source = (project_root / "apps/lobby/static/css/style.css").read_text(encoding="utf-8")
        run_source = (project_root / "run.py").read_text(encoding="utf-8")

        for source in (route_source, login_source, register_source, css_source):
            self.assertNotIn("/download/", source)
        for symbol in (
            "pre_auth",
            "auth_state",
            "two_fa",
            "generate_or_get_global_2fa_code",
            "uuid4",
            "DOWNLOAD_DIR",
            "send_file",
            "id:0",
            "padding --------------",
            ".notebook-links",
            ".notebook-btn",
            ".code-input-group",
            ".btn-2fa",
        ):
            self.assertNotIn(symbol, route_source + login_source + register_source + css_source)
        self.assertNotIn("app.secret_key", run_source)

        default_database = project_root / "data" / "secureboard.db"
        self.assertFalse(default_database.exists())
        self.assertEqual(self.db_path, Path(app.config["DATABASE"]))
        response = self._login(self.member)
        self.assertEqual(response.status_code, 302)
        self.assertFalse(default_database.exists())
        self.assertNotIn(self.member["password"], response.get_data(as_text=True))
        self.assertNotIn(hash_password(self.member["password"]), response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
