import gc
import hashlib
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

from apps.board.logic.forum import get_board_by_id, search_boards
from common.database import init_db
from common.users import hash_password
from run import app


class ForumSqlInjectionRegressionTests(unittest.TestCase):
    """Verify forum selection remains data-only at the application boundary."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "data" / "forum-security.db"
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
        self.client = app.test_client()
        self.member = self._insert_user("member", 101)
        self._login(self.member)
        self.alpha_id = self._insert_topic(
            "Alpha fixture topic",
            "Alpha fixture body",
        )
        self.beta_id = self._insert_topic(
            "Beta fixture topic",
            "Beta fixture body",
        )
        self._insert_reply(self.alpha_id, "Alpha fixture reply")
        self._insert_reply(self.beta_id, "Beta fixture reply")

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    def _insert_user(self, label, user_id):
        suffix = secrets.token_hex(5)
        account = {
            "id": user_id,
            "username": f"{label}_{suffix}",
            "email": f"{label}_{suffix}@example.test",
            "password": secrets.token_urlsafe(18),
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
                    "user",
                    account["email"],
                    "",
                ),
            )
        return account

    def _login(self, account):
        response = self.client.post(
            "/login",
            data={
                "username": account["username"],
                "password": account["password"],
            },
        )
        self.assertEqual(response.status_code, 302)
        cookie = self.client.get_cookie("session_id")
        with sqlite3.connect(self.db_path) as conn:
            self.csrf_token = conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (hashlib.sha256(cookie.value.encode()).hexdigest(),),
            ).fetchone()[0]

    def _insert_topic(self, title, body):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO board (author_id, title, body) VALUES (?, ?, ?)",
                (self.member["id"], title, body),
            )
        return cursor.lastrowid

    def _insert_reply(self, topic_id, body):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO comments (board_id, author_id, body) VALUES (?, ?, ?)",
                (topic_id, self.member["id"], body),
            )

    def _rows(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchall()

    def _forum_state(self):
        return (
            self._rows(
                """
                SELECT id, author_id, title, body, created_at
                FROM board
                ORDER BY id
                """
            ),
            self._rows(
                """
                SELECT id, board_id, author_id, body, created_at
                FROM comments
                ORDER BY id
                """
            ),
        )

    def test_valid_topic_id_returns_expected_topic(self):
        response = self.client.get(f"/board/{self.alpha_id}")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("Alpha fixture topic", body)
        self.assertIn("Alpha fixture body", body)
        self.assertIn("Alpha fixture reply", body)
        self.assertNotIn("Beta fixture topic", body)

    def test_nonexistent_topic_keeps_404(self):
        response = self.client.get("/board/999999")

        self.assertEqual(response.status_code, 404)
        self.assertNotIn("Alpha fixture topic", response.get_data(as_text=True))
        self.assertNotIn("Beta fixture topic", response.get_data(as_text=True))

    def test_encoded_detail_boolean_expression_is_literal_and_not_found(self):
        response = self.client.get("/board/0%20OR%201%3D1")

        self.assertEqual(response.status_code, 404)
        body = response.get_data(as_text=True)
        self.assertNotIn("Alpha fixture topic", body)
        self.assertNotIn("Beta fixture topic", body)

    def test_detail_retest_leaves_board_and_comment_rows_unchanged(self):
        before = self._forum_state()

        response = self.client.get("/board/0%20OR%201%3D1")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(self._forum_state(), before)

    def test_ordinary_search_matches_expected_title_and_body(self):
        response = self.client.get(
            "/board/search",
            query_string={"q": "Alpha fixture"},
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("Alpha fixture topic", body)
        self.assertIn("Alpha fixture body", body)
        self.assertNotIn("Beta fixture topic", body)

    def test_ordinary_no_match_returns_no_fixture_topic(self):
        response = self.client.get(
            "/board/search",
            query_string={"q": f"no-match-{secrets.token_hex(6)}"},
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("Nenhuma discussão encontrada", body)
        self.assertNotIn("Alpha fixture topic", body)
        self.assertNotIn("Beta fixture topic", body)

    def test_encoded_search_boolean_comment_expression_is_literal_data(self):
        response = self.client.get(
            "/board/search?q=%27%20OR%201%3D1%20--%20"
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("Nenhuma discussão encontrada", body)
        self.assertNotIn("Alpha fixture topic", body)
        self.assertNotIn("Beta fixture topic", body)

    def test_search_retest_leaves_board_and_comment_rows_unchanged(self):
        before = self._forum_state()

        response = self.client.get(
            "/board/search?q=%27%20OR%201%3D1%20--%20"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._forum_state(), before)

    def test_direct_helpers_keep_normal_results_and_block_both_inputs(self):
        with app.app_context():
            detail = get_board_by_id(self.alpha_id)
            detail_attack = get_board_by_id("0 OR 1=1")
            search = search_boards("Alpha fixture")
            search_attack = search_boards("' OR 1=1 -- ")

        self.assertEqual(detail["title"], "Alpha fixture topic")
        self.assertIsNone(detail_attack)
        self.assertEqual(
            [row["title"] for row in search],
            ["Alpha fixture topic"],
        )
        self.assertEqual(search_attack, [])

    def test_topic_and_reply_creation_flows_remain_available(self):
        topic_response = self.client.post(
            "/board/new",
            data={
                "title": "Created fixture topic",
                "body": "Created fixture body",
                "csrf_token": self.csrf_token,
            },
        )

        self.assertEqual(topic_response.status_code, 302)
        self.assertEqual(topic_response.headers["Location"], "/board")
        topic_id = self._rows(
            "SELECT id FROM board WHERE title = ?",
            ("Created fixture topic",),
        )[0][0]

        reply_response = self.client.post(
            f"/board/{topic_id}/reply",
            data={"body": "Created fixture reply", "csrf_token": self.csrf_token},
        )

        self.assertEqual(reply_response.status_code, 302)
        self.assertEqual(reply_response.headers["Location"], f"/board/{topic_id}")
        self.assertEqual(
            self._rows(
                "SELECT body, board_id, author_id FROM comments WHERE board_id = ?",
                (topic_id,),
            ),
            [("Created fixture reply", topic_id, self.member["id"])],
        )


if __name__ == "__main__":
    unittest.main()
