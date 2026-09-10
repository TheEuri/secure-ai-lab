import base64
import gc
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from common.database import SCHEMA
from common.session import create_session
from run import app


class AdminDashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "admin-test.db"
        self.original_database = app.config.get("DATABASE")
        app.config["DATABASE"] = self.db_path
        self._seed_database()
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def tearDown(self):
        app.config["DATABASE"] = self.original_database
        gc.collect()
        self.temp_dir.cleanup()

    def _seed_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)
            conn.executemany(
                "INSERT INTO users (id, username, password, role, email, bio) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (1, "admin", "admin-password-hash", "admin", "admin@example.test", "admin bio"),
                    (2, "member", "member-password-hash", "user", "member@example.test", "member bio"),
                    (3, "author", "author-password-hash", "user", "author@example.test", "author bio"),
                ],
            )
            conn.executemany(
                "INSERT INTO board (id, author_id, title, body) VALUES (?, ?, ?, ?)",
                [
                    (1, 3, "Selected topic", "Public topic body"),
                    (2, 2, "Unrelated topic", "Unrelated public body"),
                ],
            )
            conn.executemany(
                "INSERT INTO comments (id, board_id, author_id, body) VALUES (?, ?, ?, ?)",
                [
                    (1, 1, 2, "Selected reply"),
                    (2, 1, 3, "Second selected-topic reply"),
                    (3, 2, 2, "Unrelated reply"),
                ],
            )
            conn.execute(
                "INSERT INTO chat (sender_id, recipient_id, text) VALUES (?, ?, ?)",
                (2, 3, "private message must not appear"),
            )

    def _login_as(self, user_id, username, role):
        with app.app_context():
            token = create_session(user_id)
        self.client.set_cookie("session_id", token)

    def _rows(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchall()

    def test_anonymous_requests_redirect_to_login(self):
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")
        response = self.client.post("/admin/replies/1/delete")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_normal_member_and_forged_role_claim_are_denied(self):
        self._login_as(2, "member", "user")
        self.assertEqual(self.client.get("/admin").status_code, 403)
        self.assertEqual(
            self.client.post(
                "/admin/replies/1/delete", headers={"Origin": "http://localhost"}
            ).status_code,
            403,
        )

        forged_payload = {"u": "member", "id": 2, "r": "admin", "exp": 4102444800, "v": 1}
        forged_token = base64.b64encode(json.dumps(forged_payload).encode()).decode()
        self.client.set_cookie("session_id", forged_token)
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_database_admin_can_view_limited_dashboard_data(self):
        self._login_as(1, "admin", "admin")
        response = self.client.get("/admin")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Selected topic", body)
        self.assertIn("Selected reply", body)
        self.assertNotIn("admin-password-hash", body)
        self.assertNotIn("member@example.test", body)
        self.assertNotIn("member bio", body)
        self.assertNotIn("private message must not appear", body)

    def test_selected_reply_delete_preserves_its_topic_and_unrelated_data(self):
        self._login_as(1, "admin", "admin")
        response = self.client.post(
            "/admin/replies/1/delete", headers={"Origin": "http://localhost"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/admin")
        self.assertEqual(self._rows("SELECT id FROM comments WHERE id = ?", (1,)), [])
        self.assertEqual(self._rows("SELECT id FROM board WHERE id = ?", (1,)), [(1,)])
        self.assertEqual(self._rows("SELECT id FROM comments WHERE id = ?", (3,)), [(3,)])
        self.assertEqual(self._rows("SELECT id FROM users WHERE id = ?", (2,)), [(2,)])
        self.assertEqual(self._rows("SELECT text FROM chat"), [("private message must not appear",)])

    def test_topic_delete_removes_its_replies_and_preserves_unrelated_rows(self):
        self._login_as(1, "admin", "admin")
        response = self.client.post(
            "/admin/topics/1/delete", headers={"Referer": "http://localhost/admin"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._rows("SELECT id FROM board WHERE id = ?", (1,)), [])
        self.assertEqual(self._rows("SELECT id FROM comments WHERE board_id = ?", (1,)), [])
        self.assertEqual(self._rows("SELECT id FROM board WHERE id = ?", (2,)), [(2,)])
        self.assertEqual(self._rows("SELECT id FROM comments WHERE id = ?", (3,)), [(3,)])
        self.assertEqual(self._rows("SELECT id FROM users WHERE id = ?", (3,)), [(3,)])
        self.assertEqual(self._rows("SELECT text FROM chat"), [("private message must not appear",)])

    def test_cross_origin_and_unverifiable_origin_evidence_are_rejected(self):
        self._login_as(1, "admin", "admin")
        self.assertEqual(
            self.client.post(
                "/admin/replies/1/delete", headers={"Origin": "https://attacker.example"}
            ).status_code,
            403,
        )
        self.assertEqual(self.client.post("/admin/replies/1/delete").status_code, 403)
        self.assertEqual(
            self.client.post(
                "/admin/replies/1/delete",
                headers={"Origin": "null", "Referer": "http://localhost/admin"},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/admin/replies/1/delete", headers={"Origin": "http://localhost:bad"}
            ).status_code,
            403,
        )
        self.assertEqual(self._rows("SELECT id FROM comments WHERE id = ?", (1,)), [(1,)])

    def test_legacy_root_routes_are_unreachable(self):
        self.assertEqual(self.client.get("/root").status_code, 404)
        self.assertEqual(self.client.get("/root/download_source").status_code, 404)


if __name__ == "__main__":
    unittest.main()
