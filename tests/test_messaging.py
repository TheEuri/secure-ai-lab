import gc
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from common.database import SCHEMA
from common.session import create_session
from common.users import hash_password
from run import app


class MessagingTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "messaging.db"
        self.original_config = {
            "DATABASE": app.config.get("DATABASE"),
            "AVATAR_DIR": app.config.get("AVATAR_DIR"),
            "TESTING": app.config.get("TESTING"),
        }
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=root / "avatars",
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)
            conn.executemany(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (101, "alice", hash_password("alice-password"), "user", "alice@example.test", "Alice bio"),
                    (102, "bob", hash_password("bob-password"), "user", "bob@example.test", "Bob bio"),
                    (103, "carol", hash_password("carol-password"), "user", "carol@example.test", "Carol bio"),
                    (104, "dave", hash_password("dave-password"), "user", "dave@example.test", "Dave bio"),
                ],
            )
            conn.executemany(
                """
                INSERT INTO chat (id, sender_id, recipient_id, text, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (201, 101, 102, "Olá, Bob", "2026-01-02 10:00:00"),
                    (202, 102, 101, "Oi, Alice", "2026-01-02 10:01:00"),
                    (203, 103, 101, "Nota para Alice", "2026-01-02 11:00:00"),
                    (204, 102, 104, "Nota exclusiva para Dave", "2026-01-02 12:00:00"),
                ],
            )
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    def _login_as(self, user_id, username, claimed_role="user"):
        with app.app_context():
            token = create_session(user_id)
        self.client.set_cookie(
            "session_id",
            token,
        )

    def _chat_rows(self):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT sender_id, recipient_id, text FROM chat ORDER BY id"
            ).fetchall()

    def test_authenticated_load_has_product_messaging_shell_and_conversations(self):
        self._login_as(101, "alice")

        response = self.client.get("/direct")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        for label in ("Mensagens", "Conversas", "Nova conversa", "Enviar mensagem", "Para", "Mensagem", "Enviar"):
            self.assertIn(label, body)
        self.assertIn("bob", body)
        self.assertIn("carol", body)
        conversation_list = body.split('<nav class="conversation-list"', 1)[1].split("</nav>", 1)[0]
        self.assertNotIn("dave", conversation_list)
        self.assertIn('class="app-header"', body)
        self.assertNotIn("GLHF", body)
        self.assertNotIn("mirc", body.lower())

    def test_alice_bob_selection_renders_two_party_history_and_prefills_recipient(self):
        self._login_as(101, "alice")

        response = self.client.get("/direct?to_user=bob")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("conversation-item is-selected", body)
        self.assertIn('aria-current="page"', body)
        self.assertIn('value="bob"', body)
        for value in ("Olá, Bob", "Oi, Alice", "2026-01-02 10:00:00", "2026-01-02 10:01:00"):
            self.assertIn(value, body)
        self.assertNotIn("Nota para Alice", body)
        self.assertIn("message-entry--sent", body)
        self.assertIn("message-entry--received", body)

    def test_third_user_history_does_not_expand_beyond_selected_pair(self):
        self._login_as(103, "carol")

        response = self.client.get("/direct?to_user=bob")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Nenhuma mensagem nesta conversa", body)
        self.assertNotIn("Olá, Bob", body)
        self.assertNotIn("Oi, Alice", body)

    def test_valid_send_inserts_one_row_and_is_visible_to_both_participants(self):
        self._login_as(101, "alice")
        before = len(self._chat_rows())

        response = self.client.post(
            "/direct",
            data={"to_user": "bob", "message": "Mensagem comum de teste"},
        )
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Mensagem comum de teste", body)
        self.assertEqual(len(self._chat_rows()), before + 1)
        self.assertEqual(
            self._chat_rows()[-1],
            (101, 102, "Mensagem comum de teste"),
        )

        self._login_as(102, "bob")
        recipient_body = self.client.get("/direct?to_user=alice").get_data(as_text=True)
        self.assertIn("Mensagem comum de teste", recipient_body)

    def test_unknown_recipient_and_empty_message_keep_normal_feedback_and_storage(self):
        self._login_as(101, "alice")
        before = len(self._chat_rows())

        unknown = self.client.post(
            "/direct",
            data={"to_user": "missing-user", "message": "Mensagem comum"},
        )
        unknown_body = unknown.get_data(as_text=True)
        self.assertEqual(unknown.status_code, 200)
        self.assertIn("User <b>missing-user</b> does not exist.", unknown_body)
        self.assertEqual(len(self._chat_rows()), before)

        empty = self.client.post(
            "/direct",
            data={"to_user": "bob", "message": "   "},
        )
        empty_body = empty.get_data(as_text=True)
        self.assertEqual(empty.status_code, 200)
        self.assertIn("Message cannot be empty.", empty_body)
        self.assertEqual(len(self._chat_rows()), before)

    def test_profile_message_link_selects_recipient_and_keeps_b08_contract(self):
        project_root = Path(__file__).resolve().parents[1]
        profile_template = (
            project_root / "apps" / "user" / "templates" / "public_profile.html"
        ).read_text(encoding="utf-8")
        self.assertIn("url_for('direct.direct', to_user=user.username)", profile_template)
        self.assertIn(">Enviar mensagem</a>", profile_template)

        self._login_as(101, "alice")
        profile_body = self.client.get("/user/bob").get_data(as_text=True)
        self.assertIn('href="/direct?to_user=bob"', profile_body)

        selected_body = self.client.get("/direct?to_user=bob").get_data(as_text=True)
        self.assertIn('value="bob"', selected_body)
        self.assertIn('id="conversation-title">bob</h2>', selected_body)

    def test_direct_template_preserves_exact_two_safe_sinks_and_escaped_metadata(self):
        project_root = Path(__file__).resolve().parents[1]
        direct_source = (
            project_root / "apps" / "direct" / "templates" / "direct.html"
        ).read_text(encoding="utf-8")

        self.assertEqual(direct_source.count("{{ msg.text|safe }}"), 1)
        self.assertEqual(direct_source.count("{{ error|safe }}"), 1)
        self.assertEqual(len(re.findall(r"\|\s*(?:safe|raw)\b", direct_source)), 2)
        self.assertNotIn("msg.sender|safe", direct_source)
        self.assertNotIn("msg.timestamp|safe", direct_source)
        self.assertNotIn("|raw", direct_source)

    def test_message_storage_read_sink_and_search_contracts_remain_explicit(self):
        project_root = Path(__file__).resolve().parents[1]
        routes_source = (project_root / "apps" / "direct" / "routes.py").read_text(encoding="utf-8")
        chat_source = (project_root / "apps" / "direct" / "logic" / "chat.py").read_text(encoding="utf-8")
        direct_source = (project_root / "apps" / "direct" / "templates" / "direct.html").read_text(encoding="utf-8")

        self.assertIn("request.form.get('message', '').strip()", routes_source)
        self.assertIn("send_message(current[\"id\"], to_user, message)", routes_source)
        self.assertIn('INSERT INTO chat (sender_id, recipient_id, text) VALUES (?, ?, ?)', chat_source)
        self.assertIn("(sender_id, recipient[\"id\"], text)", chat_source)
        self.assertIn("c.text", chat_source)
        self.assertIn('"text": row["text"]', chat_source)
        self.assertIn("{{ msg.text|safe }}", direct_source)

        self.assertIn('new RegExp(keyword, "gi")', direct_source)
        self.assertIn("msg.innerHTML = msg.textContent", direct_source)
        self.assertIn("msg.innerHTML = msg.innerHTML.replace", direct_source)
        self.assertIn("return '<mark>' + match + '</mark>'", direct_source)
        self.assertNotIn("msg.innerHTML += keyword", direct_source)
        self.assertNotIn("/<.*?>/.test(keyword)", direct_source)
        self.assertNotIn("fonts.googleapis.com", direct_source)
        self.assertNotIn("fonts.googleapis.com", (project_root / "apps" / "direct" / "static" / "css" / "style.css").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
