import gc
import hashlib
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

from common.database import init_db
from common.users import hash_password
from run import app


class ForumFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "data" / "forum.db"
        self.original_database = app.config.get("DATABASE")
        self.original_testing = app.config.get("TESTING")
        app.config.update(TESTING=True, DATABASE=self.db_path)
        init_db(self.db_path)
        self.client = app.test_client()
        self.member = self._insert_user("member", 101)
        self.other_member = self._insert_user("author", 102)
        self._login(self.member)

    def tearDown(self):
        app.config["DATABASE"] = self.original_database
        app.config["TESTING"] = self.original_testing
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

    def _insert_topic(self, title="Uma discussão", body="Uma mensagem da comunidade"):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO board (author_id, title, body) VALUES (?, ?, ?)",
                (self.other_member["id"], title, body),
            )
            topic_id = cursor.lastrowid
        return topic_id

    def _insert_reply(self, topic_id, body="Uma resposta da comunidade"):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO comments (board_id, author_id, body) VALUES (?, ?, ?)",
                (topic_id, self.other_member["id"], body),
            )
            reply_id = cursor.lastrowid
        return reply_id

    def _rows(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchall()

    def test_authenticated_forum_feed_loads_with_active_discussion_navigation(self):
        response = self.client.get("/board")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("Discussões", body)
        self.assertIn('aria-current="page"', body)
        self.assertIn("Discussões recentes", body)

    def test_topic_list_renders_title_author_reply_count_and_profile_link(self):
        topic_id = self._insert_topic()
        self._insert_reply(topic_id)

        response = self.client.get("/board")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Uma discussão", body)
        self.assertIn(self.other_member["username"], body)
        self.assertIn("1 resposta", body)
        self.assertIn(f"/user/{self.other_member['username']}", body)

    def test_empty_feed_renders_coherent_empty_state(self):
        response = self.client.get("/board")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Nenhuma discussão encontrada", body)
        self.assertIn("Nova discussão", body)

    def test_search_uses_existing_q_contract_and_renders_matching_topic(self):
        self._insert_topic("Aprender Python", "Uma conversa sobre código")
        self._insert_topic("Caminhada no bairro", "Uma conversa sobre passeios")

        response = self.client.get("/board/search?q=Python")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Aprender Python", body)
        self.assertNotIn("Caminhada no bairro", body)
        self.assertIn('name="q"', body)
        self.assertIn('value="Python"', body)

    def test_no_match_search_renders_normal_empty_state(self):
        self._insert_topic("Aprender Python", "Uma conversa sobre código")

        response = self.client.get("/board/search?q=sem+resultado")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Nenhuma discussão encontrada", body)
        self.assertIn("Não encontramos discussões para sua busca.", body)
        self.assertIn("Limpar busca", body)

    def test_topic_creation_preserves_post_contract_and_topic_appears_in_feed(self):
        response = self.client.post(
            "/board/new",
            data={
                "title": "Nova ideia",
                "body": "Uma ideia para a comunidade",
                "csrf_token": self.csrf_token,
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/board")
        self.assertEqual(
            self._rows("SELECT title, body, author_id FROM board"),
            [("Nova ideia", "Uma ideia para a comunidade", self.member["id"])],
        )
        body = self.client.get("/board").get_data(as_text=True)
        self.assertIn("Nova ideia", body)
        self.assertIn("Uma ideia para a comunidade", body)

    def test_topic_detail_renders_original_topic_and_active_navigation(self):
        topic_id = self._insert_topic("Detalhe da discussão", "Corpo da discussão")

        response = self.client.get(f"/board/{topic_id}")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Detalhe da discussão", body)
        self.assertIn("Corpo da discussão", body)
        self.assertIn("Respostas ", body)
        self.assertIn("(0)", body)
        self.assertIn('aria-current="page"', body)
        self.assertIn("Voltar para discussões", body)

    def test_reply_creation_preserves_post_contract_and_renders_under_topic(self):
        topic_id = self._insert_topic()

        response = self.client.post(
            f"/board/{topic_id}/reply",
            data={"body": "Uma resposta publicada", "csrf_token": self.csrf_token},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], f"/board/{topic_id}")
        self.assertEqual(
            self._rows("SELECT body, board_id, author_id FROM comments"),
            [("Uma resposta publicada", topic_id, self.member["id"])],
        )
        body = self.client.get(f"/board/{topic_id}").get_data(as_text=True)
        self.assertIn("Uma resposta publicada", body)
        self.assertIn("Respostas ", body)
        self.assertIn("(1)", body)

    def test_topic_and_reply_content_remain_escaped(self):
        topic_id = self._insert_topic("<b>Título</b>", "<b>Corpo</b>")
        self._insert_reply(topic_id, "<i>Resposta</i>")

        feed_body = self.client.get("/board").get_data(as_text=True)
        detail_body = self.client.get(f"/board/{topic_id}").get_data(as_text=True)

        self.assertIn("&lt;b&gt;Título&lt;/b&gt;", feed_body)
        self.assertNotIn("<b>Título</b>", feed_body)
        self.assertIn("&lt;b&gt;Título&lt;/b&gt;", detail_body)
        self.assertIn("&lt;b&gt;Corpo&lt;/b&gt;", detail_body)
        self.assertIn("&lt;i&gt;Resposta&lt;/i&gt;", detail_body)
        self.assertNotIn("<i>Resposta</i>", detail_body)

    def test_new_topic_and_search_forms_have_visible_labels_and_active_state(self):
        new_response = self.client.get("/board/new")
        new_body = new_response.get_data(as_text=True)
        search_response = self.client.get("/board/search?q=ideia")
        search_body = search_response.get_data(as_text=True)

        self.assertEqual(new_response.status_code, 200)
        self.assertIn('<label for="title">Título</label>', new_body)
        self.assertIn('<label for="body">Mensagem</label>', new_body)
        self.assertIn('class="app-nav-link is-active"', new_body)
        self.assertIn("Publicar discussão", new_body)
        self.assertIn('<label for="search-query">Buscar discussões</label>', search_body)
        self.assertIn('class="app-nav-link is-active"', search_body)

    def test_forum_routes_redirect_anonymous_users_to_login(self):
        anonymous = app.test_client()
        requests = (
            ("GET", "/board"),
            ("GET", "/board/search?q=ideia"),
            ("GET", "/board/new"),
            ("GET", "/board/1"),
            ("POST", "/board/1/reply"),
        )

        for method, path in requests:
            with self.subTest(method=method, path=path):
                response = anonymous.open(
                    path,
                    method=method,
                    data={"body": "resposta"} if method == "POST" else None,
                )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["Location"], "/login")


if __name__ == "__main__":
    unittest.main()
