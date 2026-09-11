import gc
import base64
import hashlib
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

from common.database import init_db
from common.session import create_session
from common.users import hash_password
from run import app


class StoredXssSecurityTests(unittest.TestCase):
    """Regression coverage for the two confirmed persistent XSS sinks."""

    BIO_MARKER = (
        '<script data-marker="p5f-bio">'
        'document.documentElement.dataset.p5fBio = "executed";'
        'document.title = "P5F BIO EXECUTED";'
        "</script>"
    )
    MESSAGE_MARKER = (
        '<script data-marker="p5f-message">'
        'document.documentElement.dataset.p5fMessage = "executed";'
        'document.title = "P5F MESSAGE EXECUTED";'
        "</script>"
    )

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "data" / "xss-security.db"
        self.avatar_dir = root / "avatars"
        self.original_config = {
            "DATABASE": app.config.get("DATABASE"),
            "AVATAR_DIR": app.config.get("AVATAR_DIR"),
            "TESTING": app.config.get("TESTING"),
            "MESSAGE_ENCRYPTION_KEY": app.config.get("MESSAGE_ENCRYPTION_KEY"),
        }
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=self.avatar_dir,
            MESSAGE_ENCRYPTION_KEY=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        )
        init_db(self.db_path)
        self.alice = self._insert_user(
            601,
            "p5f_alice",
            "Biografia comum da Alice · café",
        )
        self.bob = self._insert_user(
            602,
            "p5f_bob",
            "Biografia comum do Bob",
        )
        self.carol = self._insert_user(
            603,
            "p5f_carol",
            "Biografia comum da Carol",
        )
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    def _insert_user(self, user_id, username, bio):
        runtime_password = secrets.token_urlsafe(18)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    username,
                    hash_password(runtime_password),
                    "user",
                    f"{username}@example.test",
                    bio,
                ),
            )
        return {"id": user_id, "username": username, "bio": bio}

    def _login(self, user):
        with app.app_context():
            token = create_session(user["id"])
        self.client.set_cookie("session_id", token)
        with sqlite3.connect(self.db_path) as conn:
            self.csrf_token = conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()[0]

    def _row(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchone()

    @staticmethod
    def _profile_bio_fragment(body):
        return body.split('<div class="profile-bio">', 1)[1].split(
            "</div>", 1
        )[0]

    @staticmethod
    def _message_fragment(body):
        return body.split('<div class="message-text">', 1)[1].split(
            "</div>", 1
        )[0]

    def _assert_inertly_encoded(self, fragment, expected_visible_text):
        self.assertIn("&lt;script", fragment.lower())
        self.assertNotIn("<script", fragment.lower())
        self.assertIn(expected_visible_text, fragment)
        self.assertIn("&amp;", fragment)
        self.assertIn("&#34;", fragment)
        self.assertNotIn("&amp;lt;", fragment)
        self.assertNotIn("&amp;gt;", fragment)
        self.assertNotIn("&amp;amp;", fragment)

    def test_ordinary_biography_display_remains_available(self):
        self._login(self.alice)

        response = self.client.get(f"/user/{self.alice['username']}")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(self.alice["bio"], body)
        self.assertIn("profile-bio", body)

    def test_biography_markup_is_stored_raw_but_rendered_as_inert_text(self):
        self._login(self.alice)
        bio = f'{self.BIO_MARKER} Olá & "amigos" · café'

        update = self.client.post(
            "/profile/edit_bio", data={"bio": bio, "csrf_token": self.csrf_token}
        )
        self.assertEqual(update.status_code, 302)
        self.assertEqual(
            self._row("SELECT bio FROM users WHERE id = ?", (self.alice["id"],)),
            (bio,),
        )

        response = self.client.get(f"/user/{self.alice['username']}")
        fragment = self._profile_bio_fragment(response.get_data(as_text=True))

        self.assertEqual(response.status_code, 200)
        self._assert_inertly_encoded(fragment, "Olá")
        self.assertIn("café", fragment)
        self.assertNotIn("data-marker=\"p5f-bio\"", fragment)

    def test_foreign_user_biography_mutation_remains_blocked(self):
        self._login(self.alice)
        original_bio = self._row(
            "SELECT bio FROM users WHERE id = ?", (self.bob["id"],)
        )

        response = self.client.post(
            "/profile/edit_bio",
            data={
                "user_id": str(self.bob["id"]),
                "bio": "attempted cross-user mutation",
                "csrf_token": self.csrf_token,
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            self._row("SELECT bio FROM users WHERE id = ?", (self.bob["id"],)),
            original_bio,
        )

    def test_ordinary_private_message_remains_visible_to_both_participants(self):
        self._login(self.alice)
        message = "Olá, Bob — conversa comum"

        response = self.client.post(
            "/direct",
            data={
                "to_user": self.bob["username"],
                "message": message,
                "csrf_token": self.csrf_token,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(message, response.get_data(as_text=True))
        self.assertEqual(
            self._row("SELECT sender_id, recipient_id, text, crypto_version FROM chat ORDER BY id DESC LIMIT 1"),
            (self.alice["id"], self.bob["id"], "", 1),
        )

        self._login(self.bob)
        recipient = self.client.get(f"/direct?to_user={self.alice['username']}")
        self.assertEqual(recipient.status_code, 200)
        self.assertIn(message, recipient.get_data(as_text=True))

    def test_message_markup_is_encrypted_then_rendered_as_inert_text(self):
        self._login(self.alice)
        message = f'{self.MESSAGE_MARKER} Olá & "B" · café'

        send = self.client.post(
            "/direct",
            data={
                "to_user": self.bob["username"],
                "message": message,
                "csrf_token": self.csrf_token,
            },
        )
        self.assertEqual(send.status_code, 200)
        self.assertEqual(
            self._row("SELECT sender_id, recipient_id, text, crypto_version FROM chat ORDER BY id DESC LIMIT 1"),
            (self.alice["id"], self.bob["id"], "", 1),
        )

        self._login(self.bob)
        response = self.client.get(f"/direct?to_user={self.alice['username']}")
        fragment = self._message_fragment(response.get_data(as_text=True))

        self.assertEqual(response.status_code, 200)
        self._assert_inertly_encoded(fragment, "Olá")
        self.assertIn("café", fragment)
        self.assertNotIn("data-marker=\"p5f-message\"", fragment)

    def test_nonparticipant_cannot_read_another_pair_history(self):
        self._login(self.alice)
        message = f"{self.MESSAGE_MARKER} participant-only marker"
        self.assertEqual(
            self.client.post(
                "/direct",
                data={
                    "to_user": self.bob["username"],
                    "message": message,
                    "csrf_token": self.csrf_token,
                },
            ).status_code,
            200,
        )

        self._login(self.carol)
        response = self.client.get(f"/direct?to_user={self.bob['username']}")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Nenhuma mensagem nesta conversa", body)
        self.assertNotIn("participant-only marker", body)
        self.assertNotIn("&lt;script", body.lower())


if __name__ == "__main__":
    unittest.main()
