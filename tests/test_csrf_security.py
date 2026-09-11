import gc
import base64
import hashlib
import secrets
import sqlite3
import tempfile
import unittest
from http.cookies import SimpleCookie
from io import BytesIO
from pathlib import Path

from PIL import Image

from common.database import (
    PRODUCT_SCHEMA,
    SECURITY_EVENTS_SCHEMA,
    init_db,
)
from common.session import create_session, revoke_session
from common.users import hash_password, verify_password
from run import app


def _jpeg_bytes(color=(65, 130, 210)):
    output = BytesIO()
    Image.new("RGB", (3, 3), color).save(output, format="JPEG")
    return output.getvalue()


class CsrfSecurityTests(unittest.TestCase):
    """S1 synchronizer-token behavior and equivalent retest coverage."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "data" / "csrf.db"
        self.avatar_dir = root / "avatars"
        self.original_config = {
            "DATABASE": app.config.get("DATABASE"),
            "AVATAR_DIR": app.config.get("AVATAR_DIR"),
            "TESTING": app.config.get("TESTING"),
            "SESSION_LIFETIME_SECONDS": app.config.get("SESSION_LIFETIME_SECONDS"),
            "SESSION_COOKIE_SECURE": app.config.get("SESSION_COOKIE_SECURE"),
            "MESSAGE_ENCRYPTION_KEY": app.config.get("MESSAGE_ENCRYPTION_KEY"),
        }
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=self.avatar_dir,
            SESSION_LIFETIME_SECONDS=3600,
            SESSION_COOKIE_SECURE=False,
            MESSAGE_ENCRYPTION_KEY=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        )
        init_db(self.db_path)
        self.alice = self._account("csrf_alice", 101, "user")
        self.bob = self._account("csrf_bob", 102, "user")
        self.admin = self._account("csrf_admin", 201, "admin")
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        account["id"],
                        account["username"],
                        hash_password(account["password"]),
                        account["role"],
                        account["email"],
                        account["bio"],
                    )
                    for account in (self.alice, self.bob, self.admin)
                ],
            )
            conn.commit()
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    @staticmethod
    def _account(label, user_id, role):
        suffix = secrets.token_hex(5)
        return {
            "id": user_id,
            "username": f"{label}_{suffix}",
            "email": f"{label}_{suffix}@example.test",
            "password": secrets.token_urlsafe(18),
            "role": role,
            "bio": f"Original fictional bio for {label}.",
        }

    @staticmethod
    def _digest(raw_token):
        return hashlib.sha256(raw_token.encode()).hexdigest()

    @staticmethod
    def _cookie(response):
        cookies = SimpleCookie()
        for header in response.headers.getlist("Set-Cookie"):
            cookies.load(header)
        return cookies["session_id"]

    def _csrf_for(self, raw_token):
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (self._digest(raw_token),),
            ).fetchone()
        self.assertIsNotNone(row)
        return row[0]

    def _login(self, account, client=None):
        active_client = client or self.client
        response = active_client.post(
            "/login",
            data={
                "username": account["username"],
                "password": account["password"],
            },
        )
        self.assertEqual(response.status_code, 302)
        raw_token = self._cookie(response).value
        return raw_token, self._csrf_for(raw_token)

    def _new_session(self, user_id=101):
        with app.app_context():
            raw_token = create_session(user_id)
        return raw_token, self._csrf_for(raw_token)

    def _rows(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchall()

    def _events(self):
        return self._rows(
            """
            SELECT event_type, actor_user_id, outcome, target_type, target_id,
                   request_method, request_path
            FROM security_events ORDER BY id
            """
        )

    def _insert_topic(self, author_id=102, title="CSRF topic", body="Topic body"):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO board (author_id, title, body) VALUES (?, ?, ?)",
                (author_id, title, body),
            )
            conn.commit()
            return cursor.lastrowid

    def _insert_reply(self, board_id, author_id=102, body="Reply body"):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO comments (board_id, author_id, body) VALUES (?, ?, ?)",
                (board_id, author_id, body),
            )
            conn.commit()
            return cursor.lastrowid

    def test_sessions_bind_distinct_csrf_tokens_and_rotate_on_password_change(self):
        old_auth, old_csrf = self._login(self.alice)
        other_client = app.test_client()
        other_auth, other_csrf = self._login(self.alice, other_client)

        self.assertNotEqual(old_auth, old_csrf)
        self.assertNotEqual(other_auth, other_csrf)
        self.assertNotEqual(old_csrf, other_csrf)
        self.assertNotEqual(old_auth, other_auth)
        self.assertEqual(
            self._rows(
                "SELECT token_hash, csrf_token FROM auth_sessions ORDER BY id"
            ),
            [
                (self._digest(old_auth), old_csrf),
                (self._digest(other_auth), other_csrf),
            ],
        )

        response = self.client.post(
            "/profile/edit_password",
            data={
                "password": self.alice["password"] + "-rotated",
                "confirm": self.alice["password"] + "-rotated",
                "csrf_token": old_csrf,
            },
        )
        self.assertEqual(response.status_code, 302)
        replacement_auth = self._cookie(response).value
        replacement_csrf = self._csrf_for(replacement_auth)
        self.assertNotEqual(replacement_auth, old_auth)
        self.assertNotEqual(replacement_csrf, old_csrf)
        self.assertIsNotNone(
            self._rows(
                "SELECT revoked_at FROM auth_sessions WHERE token_hash = ?",
                (self._digest(old_auth),),
            )[0][0]
        )
        self.assertEqual(
            self._rows(
                "SELECT revoked_at FROM auth_sessions WHERE token_hash = ?",
                (self._digest(replacement_auth),),
            ),
            [(None,)],
        )
        self.assertEqual(self.client.get("/profile").status_code, 200)

    def test_revoked_expired_and_legacy_null_sessions_cannot_use_old_context(self):
        for state in ("revoked", "expired", "legacy-null"):
            with self.subTest(state=state):
                raw_token, csrf_token = self._new_session()
                if state == "revoked":
                    with app.app_context():
                        self.assertTrue(revoke_session(raw_token))
                elif state == "expired":
                    with sqlite3.connect(self.db_path) as conn:
                        conn.execute(
                            "UPDATE auth_sessions SET expires_at = 0 WHERE token_hash = ?",
                            (self._digest(raw_token),),
                        )
                        conn.commit()
                else:
                    with sqlite3.connect(self.db_path) as conn:
                        conn.execute(
                            "UPDATE auth_sessions SET csrf_token = NULL WHERE token_hash = ?",
                            (self._digest(raw_token),),
                        )
                        conn.commit()

                client = app.test_client()
                client.set_cookie("session_id", raw_token)
                before = self._rows("SELECT bio FROM users WHERE id = 101")
                response = client.post(
                    "/profile/edit_bio",
                    data={"bio": "must not persist", "csrf_token": csrf_token},
                )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["Location"], "/login")
                self.assertEqual(self._rows("SELECT bio FROM users WHERE id = 101"), before)

    def test_bio_requires_token_and_exact_same_site_alternate_origin_is_blocked(self):
        raw_token, csrf_token = self._login(self.alice)
        original_bio = self._rows("SELECT bio FROM users WHERE id = 101")[0][0]

        missing = self.client.post(
            "/profile/edit_bio", data={"bio": "missing token"}
        )
        wrong = self.client.post(
            "/profile/edit_bio",
            data={"bio": "wrong token", "csrf_token": "wrong-csrf-token"},
        )
        self.assertEqual(missing.status_code, 403)
        self.assertEqual(wrong.status_code, 403)
        self.assertEqual(self._rows("SELECT bio FROM users WHERE id = 101"), [(original_bio,)])
        self.assertEqual(
            [event for event in self._events() if event[0] == "profile.bio.updated"],
            [],
        )

        # Cookie presence is intentional: the request is same-site by scheme/host
        # and differs only by loopback port, so SameSite=Lax is not the control.
        cross_origin = self.client.post(
            "/profile/edit_bio",
            data={"bio": "cross-origin without synchronizer token"},
            headers={"Origin": "http://localhost:5001"},
        )
        self.assertEqual(cross_origin.status_code, 403)
        self.assertEqual(self._rows("SELECT bio FROM users WHERE id = 101"), [(original_bio,)])
        self.assertEqual(self.client.get("/profile").status_code, 200)

        legitimate = self.client.post(
            "/profile/edit_bio",
            data={"bio": "legitimate token update", "csrf_token": csrf_token},
        )
        self.assertEqual(legitimate.status_code, 302)
        self.assertEqual(
            self._rows("SELECT bio FROM users WHERE id = 101"),
            [("legitimate token update",)],
        )
        self.assertEqual(self._csrf_for(raw_token), csrf_token)
        self.assertEqual(
            [event for event in self._events() if event[0] == "profile.bio.updated"][-1][2],
            "success",
        )

    def test_avatar_requires_token_and_accepts_valid_own_upload(self):
        _, csrf_token = self._login(self.alice)
        missing = self.client.post(
            "/profile/edit_avatar",
            data={"avatar": (BytesIO(b"missing-token-bytes"), "avatar.txt")},
            content_type="multipart/form-data",
        )
        wrong = self.client.post(
            "/profile/edit_avatar",
            data={
                "csrf_token": "wrong-csrf-token",
                "avatar": (BytesIO(b"wrong-token-bytes"), "avatar.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(missing.status_code, 403)
        self.assertEqual(wrong.status_code, 403)
        self.assertFalse((self.avatar_dir / "101.jpg").exists())

        accepted_image = _jpeg_bytes()
        valid = self.client.post(
            "/profile/edit_avatar",
            data={
                "csrf_token": csrf_token,
                "avatar": (BytesIO(accepted_image), "avatar.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(valid.status_code, 302)
        stored = (self.avatar_dir / "101.jpg").read_bytes()
        with Image.open(BytesIO(stored)) as image:
            self.assertEqual(image.format, "JPEG")
            self.assertEqual(image.mode, "RGB")

    def test_password_requires_token_and_valid_token_keeps_normal_rotation(self):
        _, csrf_token = self._login(self.alice)
        original_hash = self._rows("SELECT password FROM users WHERE id = 101")[0][0]
        missing = self.client.post(
            "/profile/edit_password",
            data={"password": "missing-password", "confirm": "missing-password"},
        )
        wrong = self.client.post(
            "/profile/edit_password",
            data={
                "password": "wrong-password",
                "confirm": "wrong-password",
                "csrf_token": "wrong-csrf-token",
            },
        )
        self.assertEqual(missing.status_code, 403)
        self.assertEqual(wrong.status_code, 403)
        self.assertEqual(
            self._rows("SELECT password FROM users WHERE id = 101"),
            [(original_hash,)],
        )

        replacement = "valid-password-" + secrets.token_urlsafe(8)
        valid = self.client.post(
            "/profile/edit_password",
            data={"password": replacement, "confirm": replacement, "csrf_token": csrf_token},
        )
        self.assertEqual(valid.status_code, 302)
        changed_hash = self._rows("SELECT password FROM users WHERE id = 101")[0][0]
        self.assertNotEqual(changed_hash, original_hash)
        self.assertTrue(verify_password(changed_hash, replacement))

    def test_direct_topic_and_reply_mutations_require_tokens_and_get_remains_read_only(self):
        _, csrf_token = self._login(self.alice)
        before_messages = self._rows("SELECT sender_id, recipient_id, text FROM chat")
        missing_message = self.client.post(
            "/direct", data={"to_user": self.bob["username"], "message": "no token"}
        )
        wrong_message = self.client.post(
            "/direct",
            data={
                "to_user": self.bob["username"],
                "message": "wrong token",
                "csrf_token": "wrong-csrf-token",
            },
        )
        self.assertEqual(missing_message.status_code, 403)
        self.assertEqual(wrong_message.status_code, 403)
        self.assertEqual(
            self._rows("SELECT sender_id, recipient_id, text FROM chat"), before_messages
        )
        self.assertEqual(self.client.get("/direct").status_code, 200)
        sent = self.client.post(
            "/direct",
            data={
                "to_user": self.bob["username"],
                "message": "valid message",
                "csrf_token": csrf_token,
            },
        )
        self.assertEqual(sent.status_code, 200)
        self.assertEqual(self._rows("SELECT text FROM chat ORDER BY id")[-1], ("",))

        missing_topic = self.client.post(
            "/board/new", data={"title": "No token", "body": "No token"}
        )
        wrong_topic = self.client.post(
            "/board/new",
            data={"title": "Wrong token", "body": "Wrong token", "csrf_token": "wrong-csrf-token"},
        )
        self.assertEqual(missing_topic.status_code, 403)
        self.assertEqual(wrong_topic.status_code, 403)
        self.assertEqual(self._rows("SELECT title FROM board"), [])
        self.assertEqual(self.client.get("/board/new").status_code, 200)

        valid_topic = self.client.post(
            "/board/new",
            data={"title": "Valid topic", "body": "Valid body", "csrf_token": csrf_token},
        )
        self.assertEqual(valid_topic.status_code, 302)
        topic_id = self._rows("SELECT id FROM board WHERE title = ?", ("Valid topic",))[0][0]
        self.assertEqual(self.client.get(f"/board/{topic_id}").status_code, 200)

        missing_reply = self.client.post(
            f"/board/{topic_id}/reply", data={"body": "No token reply"}
        )
        wrong_reply = self.client.post(
            f"/board/{topic_id}/reply",
            data={"body": "Wrong token reply", "csrf_token": "wrong-csrf-token"},
        )
        self.assertEqual(missing_reply.status_code, 403)
        self.assertEqual(wrong_reply.status_code, 403)
        self.assertEqual(self._rows("SELECT body FROM comments"), [])
        valid_reply = self.client.post(
            f"/board/{topic_id}/reply",
            data={"body": "Valid reply", "csrf_token": csrf_token},
        )
        self.assertEqual(valid_reply.status_code, 302)
        self.assertEqual(self._rows("SELECT body FROM comments"), [("Valid reply",)])

    def test_admin_deletes_require_token_in_addition_to_same_origin_headers(self):
        admin_client = app.test_client()
        _, csrf_token = self._login(self.admin, admin_client)
        topic_id = self._insert_topic(title="Topic to delete")
        reply_id = self._insert_reply(topic_id, body="Reply to delete")
        second_topic_id = self._insert_topic(title="Second topic")
        second_reply_id = self._insert_reply(second_topic_id, body="Second reply")

        missing_topic = admin_client.post(
            f"/admin/topics/{topic_id}/delete", headers={"Origin": "http://localhost"}
        )
        wrong_topic = admin_client.post(
            f"/admin/topics/{topic_id}/delete",
            data={"csrf_token": "wrong-csrf-token"},
            headers={"Origin": "http://localhost"},
        )
        self.assertEqual(missing_topic.status_code, 403)
        self.assertEqual(wrong_topic.status_code, 403)
        self.assertEqual(self._rows("SELECT id FROM board WHERE id = ?", (topic_id,)), [(topic_id,)])

        missing_reply = admin_client.post(
            f"/admin/replies/{reply_id}/delete", headers={"Origin": "http://localhost"}
        )
        wrong_reply = admin_client.post(
            f"/admin/replies/{reply_id}/delete",
            data={"csrf_token": "wrong-csrf-token"},
            headers={"Origin": "http://localhost"},
        )
        self.assertEqual(missing_reply.status_code, 403)
        self.assertEqual(wrong_reply.status_code, 403)
        self.assertEqual(self._rows("SELECT id FROM comments WHERE id = ?", (reply_id,)), [(reply_id,)])

        deleted_topic = admin_client.post(
            f"/admin/topics/{topic_id}/delete",
            data={"csrf_token": csrf_token},
            headers={"Origin": "http://localhost"},
        )
        deleted_reply = admin_client.post(
            f"/admin/replies/{second_reply_id}/delete",
            data={"csrf_token": csrf_token},
            headers={"Referer": "http://localhost/admin"},
        )
        self.assertEqual(deleted_topic.status_code, 302)
        self.assertEqual(deleted_reply.status_code, 302)
        self.assertEqual(self._rows("SELECT id FROM board WHERE id = ?", (topic_id,)), [])
        self.assertEqual(self._rows("SELECT id FROM comments WHERE id = ?", (reply_id,)), [])
        self.assertEqual(self._rows("SELECT id FROM comments WHERE id = ?", (second_reply_id,)), [])

    def test_logout_is_csrf_protected_post_and_revokes_only_valid_request(self):
        raw_token, csrf_token = self._login(self.alice)
        digest = self._digest(raw_token)

        for data in ({}, {"csrf_token": "wrong-csrf-token"}):
            response = self.client.post("/logout", data=data)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(
                self._rows("SELECT revoked_at FROM auth_sessions WHERE token_hash = ?", (digest,)),
                [(None,)],
            )
            self.assertEqual(response.headers.getlist("Set-Cookie"), [])
            self.assertEqual(self.client.get("/profile").status_code, 200)

        get_logout = self.client.get("/logout")
        self.assertEqual(get_logout.status_code, 405)
        self.assertEqual(
            self._rows("SELECT revoked_at FROM auth_sessions WHERE token_hash = ?", (digest,)),
            [(None,)],
        )

        response = self.client.post("/logout", data={"csrf_token": csrf_token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")
        self.assertIsNotNone(
            self._rows("SELECT revoked_at FROM auth_sessions WHERE token_hash = ?", (digest,))[0][0]
        )
        replay = app.test_client()
        replay.set_cookie("session_id", raw_token)
        self.assertEqual(replay.get("/profile").status_code, 302)
        self.assertEqual(replay.get("/profile").headers["Location"], "/login")

    def test_all_legitimate_protected_forms_render_token_without_auth_token(self):
        raw_token, csrf_token = self._login(self.alice)
        bodies = [
            self.client.get("/profile").get_data(as_text=True),
            self.client.get("/direct").get_data(as_text=True),
            self.client.get("/board/new").get_data(as_text=True),
        ]
        topic_id = self._insert_topic()
        bodies.append(self.client.get(f"/board/{topic_id}").get_data(as_text=True))

        admin_client = app.test_client()
        admin_raw, admin_csrf = self._login(self.admin, admin_client)
        admin_topic = self._insert_topic(title="Admin form topic")
        self._insert_reply(admin_topic)
        bodies.append(admin_client.get("/admin").get_data(as_text=True))

        for body in bodies:
            self.assertIn('name="csrf_token"', body)
            self.assertTrue(csrf_token in body or admin_csrf in body)
            self.assertNotIn(raw_token, body)
            self.assertNotIn(admin_raw, body)
            self.assertNotIn(self._digest(raw_token), body)
            self.assertNotIn(self._digest(admin_raw), body)

    def test_csrf_values_do_not_appear_in_events_or_rejection_bodies(self):
        raw_token, csrf_token = self._login(self.alice)
        sentinel = "CSRF_REJECTION_SENTINEL_" + secrets.token_urlsafe(8)
        response = self.client.post(
            "/profile/edit_bio",
            data={"bio": "must not persist", "csrf_token": sentinel},
        )
        self.assertEqual(response.status_code, 403)
        body = response.get_data(as_text=True)
        self.assertNotIn(csrf_token, body)
        self.assertNotIn(raw_token, body)
        serialized_events = str(self._events())
        self.assertNotIn(csrf_token, serialized_events)
        self.assertNotIn(sentinel, serialized_events)
        self.assertNotIn(raw_token, serialized_events)
        self.assertNotIn(self._digest(raw_token), serialized_events)

    def test_legacy_auth_sessions_upgrade_adds_only_nullable_csrf_column(self):
        legacy_path = Path(self.temp_dir.name) / "data" / "legacy.db"
        legacy_raw = secrets.token_urlsafe(32)
        legacy_digest = self._digest(legacy_raw)
        with sqlite3.connect(legacy_path) as conn:
            conn.executescript(
                PRODUCT_SCHEMA
                + SECURITY_EVENTS_SCHEMA
                + """
                CREATE TABLE auth_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                """
            )
            conn.execute(
                "INSERT INTO users (id, username, password, role, email, bio) VALUES (?, ?, ?, ?, ?, ?)",
                (901, "legacy_user", "legacy-hash", "user", "legacy@example.test", "keep me"),
            )
            conn.execute(
                "INSERT INTO security_events (event_type, outcome) VALUES (?, ?)",
                ("auth.login.failure", "failure"),
            )
            conn.execute(
                """
                INSERT INTO auth_sessions (user_id, token_hash, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (901, legacy_digest, 1, 4102444800),
            )
            conn.commit()

        init_db(legacy_path)
        with sqlite3.connect(legacy_path) as conn:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(auth_sessions)")]
            self.assertEqual(
                columns,
                ["id", "user_id", "token_hash", "created_at", "expires_at", "revoked_at", "csrf_token"],
            )
            self.assertEqual(
                conn.execute("SELECT user_id, token_hash, csrf_token FROM auth_sessions").fetchone(),
                (901, legacy_digest, None),
            )
            self.assertEqual(
                conn.execute("SELECT username, bio FROM users WHERE id = 901").fetchone(),
                ("legacy_user", "keep me"),
            )
            self.assertEqual(
                conn.execute("SELECT event_type, outcome FROM security_events").fetchone(),
                ("auth.login.failure", "failure"),
            )


if __name__ == "__main__":
    unittest.main()
