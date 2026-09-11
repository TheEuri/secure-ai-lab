import gc
import hashlib
import secrets
import sqlite3
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from common.database import init_db
from common.security_audit import (
    MAX_RECENT_EVENTS,
    get_recent_security_events,
    record_security_event,
)
from common.session import create_session
from common.users import hash_password
from run import app


class SecurityLoggingTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "security-logging.db"
        self.avatar_dir = root / "avatars"
        self.original_database = app.config.get("DATABASE")
        self.original_avatar_dir = app.config.get("AVATAR_DIR")
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=self.avatar_dir,
        )
        init_db(self.db_path)

        self.member_password = f"member-{secrets.token_urlsafe(18)}"
        self.target_password = f"target-{secrets.token_urlsafe(18)}"
        self.admin_password = f"admin-{secrets.token_urlsafe(18)}"
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (101, "audit_member", hash_password(self.member_password), "user", "member@example.test", "Member bio"),
                    (102, "audit_target", hash_password(self.target_password), "user", "target@example.test", "Target bio"),
                    (201, "audit_admin", hash_password(self.admin_password), "admin", "admin@example.test", "Admin bio"),
                ],
            )
            conn.executemany(
                "INSERT INTO board (id, author_id, title, body) VALUES (?, ?, ?, ?)",
                [
                    (301, 101, "Audit topic one", "Public audit topic body"),
                    (302, 102, "Audit topic two", "Another public topic"),
                ],
            )
            conn.executemany(
                "INSERT INTO comments (id, board_id, author_id, body) VALUES (?, ?, ?, ?)",
                [
                    (401, 301, 102, "Audit reply one"),
                    (402, 302, 101, "Audit reply two"),
                ],
            )
            conn.execute(
                "INSERT INTO chat (sender_id, recipient_id, text) VALUES (?, ?, ?)",
                (101, 102, "PRIVATE_MESSAGE_SENTINEL_DO_NOT_LOG"),
            )
            conn.commit()
        self.client = app.test_client()

    def tearDown(self):
        app.config["DATABASE"] = self.original_database
        app.config["AVATAR_DIR"] = self.original_avatar_dir
        gc.collect()
        self.temp_dir.cleanup()

    def _set_identity(self, user_id, username, role):
        with app.app_context():
            token = create_session(user_id)
        self.client.set_cookie("session_id", token)
        self.csrf_token = self._csrf_for(token)

    def _csrf_for(self, raw_token):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (hashlib.sha256(raw_token.encode()).hexdigest(),),
            ).fetchone()[0]

    def _csrf_for_client(self, client):
        cookie = client.get_cookie("session_id")
        self.assertIsNotNone(cookie)
        return self._csrf_for(cookie.value)

    def _login(self, username, password):
        response = self.client.post(
            "/login",
            data={"username": username, "password": password},
        )
        if response.status_code == 302:
            self.csrf_token = self._csrf_for_client(self.client)
        return response

    def _events(self, event_type=None):
        query = """
            SELECT id, event_type, actor_user_id, outcome, target_type,
                   target_id, request_method, request_path, created_at
            FROM security_events
        """
        params = ()
        if event_type is not None:
            query += " WHERE event_type = ?"
            params = (event_type,)
        query += " ORDER BY id"
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(query, params).fetchall()]

    def _latest(self, event_type):
        rows = self._events(event_type)
        self.assertTrue(rows, f"missing event {event_type}")
        return rows[-1]

    def test_successful_login_records_structured_success(self):
        response = self._login("audit_member", self.member_password)
        self.assertEqual(response.status_code, 302)
        event = self._latest("auth.login.success")
        self.assertEqual(event["actor_user_id"], 101)
        self.assertEqual(event["outcome"], "success")
        self.assertEqual((event["target_type"], event["target_id"]), ("user", 101))
        self.assertEqual((event["request_method"], event["request_path"]), ("POST", "/login"))
        self.assertIsNotNone(event["created_at"])

    def test_failed_login_records_known_actor_and_keeps_unknown_actor_null(self):
        self._login("audit_member", "wrong-password")
        unknown_username = f"UNKNOWN_USERNAME_SENTINEL_{secrets.token_hex(4)}"
        self._login(unknown_username, "another-wrong-password")
        events = self._events("auth.login.failure")
        self.assertEqual([event["actor_user_id"] for event in events], [101, None])
        self.assertNotIn(unknown_username, str(events))

    def test_logout_records_event_for_resolved_user(self):
        self._set_identity(101, "audit_member", "user")
        response = self.client.post(
            "/logout", data={"csrf_token": self.csrf_token}
        )
        self.assertEqual(response.status_code, 302)
        event = self._latest("auth.logout")
        self.assertEqual((event["actor_user_id"], event["outcome"]), (101, "success"))
        self.assertEqual((event["request_method"], event["request_path"]), ("POST", "/logout"))

    def test_password_change_records_event_without_password(self):
        self._set_identity(101, "audit_member", "user")
        password = f"PASSWORD_CHANGE_SENTINEL_{secrets.token_urlsafe(12)}"
        response = self.client.post(
            "/profile/edit_password",
            data={
                "password": password,
                "confirm": password,
                "csrf_token": self.csrf_token,
            },
        )
        self.assertEqual(response.status_code, 302)
        event = self._latest("auth.password.changed")
        self.assertEqual((event["actor_user_id"], event["target_id"]), (101, 101))
        self.assertNotIn(password, str(event))
        self.assertNotIn(hash_password(password), str(event))

    def test_denied_member_admin_access_records_denial(self):
        self._set_identity(101, "audit_member", "admin")
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 403)
        event = self._latest("authz.admin.denied")
        self.assertEqual((event["actor_user_id"], event["outcome"]), (101, "denied"))
        self.assertEqual((event["target_type"], event["request_path"]), ("admin", "/admin"))

    def test_biography_update_records_only_authorized_target_metadata(self):
        self._set_identity(101, "audit_member", "user")
        biography = "BIOGRAPHY_CONTENT_SENTINEL_DO_NOT_LOG"
        response = self.client.post(
            "/profile/edit_bio",
            data={
                "user_id": "101",
                "bio": biography,
                "csrf_token": self.csrf_token,
            },
        )
        self.assertEqual(response.status_code, 302)
        event = self._latest("profile.bio.updated")
        self.assertEqual((event["actor_user_id"], event["target_id"]), (101, 101))
        self.assertNotIn(biography, str(event))

    def test_avatar_update_records_only_authorized_target_metadata(self):
        self._set_identity(101, "audit_member", "user")
        upload = b"UPLOADED_FILE_CONTENT_SENTINEL_DO_NOT_LOG"
        response = self.client.post(
            "/profile/edit_avatar",
            data={
                "user_id": "101",
                "csrf_token": self.csrf_token,
                "avatar": (BytesIO(upload), "sentinel.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        event = self._latest("profile.avatar.updated")
        self.assertEqual((event["actor_user_id"], event["target_id"]), (101, 101))
        self.assertNotIn(upload.decode(), str(event))

    def test_admin_topic_deletion_records_target_and_outcome(self):
        self._set_identity(201, "audit_admin", "admin")
        response = self.client.post(
            "/admin/topics/301/delete",
            data={"csrf_token": self.csrf_token},
            headers={"Origin": "http://localhost"},
        )
        self.assertEqual(response.status_code, 302)
        event = self._latest("admin.topic.deleted")
        self.assertEqual((event["actor_user_id"], event["target_type"], event["target_id"]), (201, "topic", 301))
        self.assertEqual(event["outcome"], "success")

    def test_admin_reply_deletion_records_target_and_outcome(self):
        self._set_identity(201, "audit_admin", "admin")
        response = self.client.post(
            "/admin/replies/401/delete",
            data={"csrf_token": self.csrf_token},
            headers={"Origin": "http://localhost"},
        )
        self.assertEqual(response.status_code, 302)
        event = self._latest("admin.reply.deleted")
        self.assertEqual((event["actor_user_id"], event["target_type"], event["target_id"]), (201, "reply", 401))
        self.assertEqual(event["outcome"], "success")

    def test_records_persist_across_new_sqlite_connections(self):
        with app.app_context():
            event_id = record_security_event(
                "auth.logout",
                "success",
                actor_user_id=101,
                target_type="user",
                target_id=101,
                request_method="GET",
                request_path="/logout",
            )
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT event_type, actor_user_id, outcome FROM security_events WHERE id = ?",
                (event_id,),
            ).fetchone()
        self.assertEqual(row, ("auth.logout", 101, "success"))

    def test_administrator_can_view_recent_events(self):
        with app.app_context():
            record_security_event("auth.login.failure", "failure", request_method="POST", request_path="/login")
        self._set_identity(201, "audit_admin", "admin")
        response = self.client.get("/admin/security-events")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("auth.login.failure", body)
        self.assertIn("POST /login", body)

    def test_ordinary_user_cannot_view_audit_page(self):
        self._set_identity(101, "audit_member", "user")
        response = self.client.get("/admin/security-events")
        self.assertEqual(response.status_code, 403)
        event = self._latest("authz.admin.denied")
        self.assertEqual(event["request_path"], "/admin/security-events")

    def test_recent_events_are_newest_first(self):
        with app.app_context():
            ids = [
                record_security_event("auth.login.failure", "failure", request_method="POST", request_path="/login")
                for _ in range(3)
            ]
            events = get_recent_security_events(limit=3)
        self.assertEqual([event["id"] for event in events], list(reversed(ids)))

    def test_recent_event_limit_and_taxonomy_are_enforced(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                "INSERT INTO security_events (event_type, outcome) VALUES (?, ?)",
                [("auth.login.failure", "failure")] * (MAX_RECENT_EVENTS + 5),
            )
            conn.commit()
        with app.app_context():
            self.assertEqual(len(get_recent_security_events(limit=1000)), MAX_RECENT_EVENTS)
            with self.assertRaises(ValueError):
                record_security_event("user.supplied.event", "success")
            with self.assertRaises(ValueError):
                record_security_event("auth.logout", "user-supplied-outcome")

    def test_sensitive_sentinels_are_not_persisted_in_security_rows(self):
        username = "RAW_USERNAME_SENTINEL_DO_NOT_LOG"
        password = "RAW_PASSWORD_SENTINEL_DO_NOT_LOG"
        biography = "RAW_BIOGRAPHY_SENTINEL_DO_NOT_LOG"
        upload = b"RAW_UPLOAD_SENTINEL_DO_NOT_LOG"
        self.client.set_cookie("session_id", "RAW_SESSION_TOKEN_SENTINEL_DO_NOT_LOG")
        self._login(username, password)
        self._set_identity(101, "audit_member", "user")
        self.client.post(
            "/profile/edit_bio",
            data={"bio": biography, "csrf_token": self.csrf_token},
        )
        self.client.post(
            "/profile/edit_avatar",
            data={
                "csrf_token": self.csrf_token,
                "avatar": (BytesIO(upload), "sentinel.txt"),
            },
            content_type="multipart/form-data",
        )
        stored = str(self._events())
        for sentinel in (username, password, hash_password(password), biography, upload.decode(), "RAW_SESSION_TOKEN_SENTINEL_DO_NOT_LOG"):
            self.assertNotIn(sentinel, stored)

    def test_sensitive_sentinels_are_not_rendered_in_admin_audit_view(self):
        biography = "RENDERED_BIOGRAPHY_SENTINEL_DO_NOT_LOG"
        upload = b"RENDERED_UPLOAD_SENTINEL_DO_NOT_LOG"
        self._set_identity(101, "audit_member", "user")
        self.client.post(
            "/profile/edit_bio",
            data={"bio": biography, "csrf_token": self.csrf_token},
        )
        self.client.post(
            "/profile/edit_avatar",
            data={
                "csrf_token": self.csrf_token,
                "avatar": (BytesIO(upload), "sentinel.txt"),
            },
            content_type="multipart/form-data",
        )
        self._set_identity(201, "audit_admin", "admin")
        body = self.client.get("/admin/security-events").get_data(as_text=True)
        for sentinel in (
            biography,
            upload.decode(),
            "PRIVATE_MESSAGE_SENTINEL_DO_NOT_LOG",
            "member@example.test",
            self.member_password,
            hash_password(self.member_password),
        ):
            self.assertNotIn(sentinel, body)

    def test_s5_equivalent_retest_records_persists_limits_and_protects_events(self):
        failed_password = "S5_RETEST_FAILED_PASSWORD_SENTINEL"
        changed_password = "S5_RETEST_CHANGED_PASSWORD_SENTINEL"
        biography = "S5_RETEST_BIOGRAPHY_SENTINEL"
        upload = b"S5_RETEST_UPLOAD_SENTINEL"

        self._login("audit_member", failed_password)
        self.assertEqual(self._login("audit_member", self.member_password).status_code, 302)
        self.client.post(
            "/profile/edit_password",
            data={
                "password": changed_password,
                "confirm": changed_password,
                "csrf_token": self.csrf_token,
            },
        )
        self.csrf_token = self._csrf_for_client(self.client)
        self.client.post(
            "/profile/edit_bio",
            data={"bio": biography, "csrf_token": self.csrf_token},
        )
        self.client.post(
            "/profile/edit_avatar",
            data={
                "csrf_token": self.csrf_token,
                "avatar": (BytesIO(upload), "retest.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(self.client.get("/admin").status_code, 403)

        admin_client = app.test_client()
        self.assertEqual(
            admin_client.post(
                "/login",
                data={"username": "audit_admin", "password": self.admin_password},
            ).status_code,
            302,
        )
        self.assertEqual(
            admin_client.post(
                "/admin/replies/402/delete",
                data={"csrf_token": self._csrf_for_client(admin_client)},
                headers={"Origin": "http://localhost"},
            ).status_code,
            302,
        )
        self.assertEqual(
            admin_client.post(
                "/admin/topics/301/delete",
                data={"csrf_token": self._csrf_for_client(admin_client)},
                headers={"Origin": "http://localhost"},
            ).status_code,
            302,
        )

        required_types = {
            "auth.login.success",
            "auth.login.failure",
            "auth.password.changed",
            "authz.admin.denied",
            "profile.bio.updated",
            "profile.avatar.updated",
            "admin.topic.deleted",
            "admin.reply.deleted",
        }
        with sqlite3.connect(self.db_path) as fresh_connection:
            rows = fresh_connection.execute(
                """
                SELECT event_type, actor_user_id, outcome, target_type, target_id,
                       request_method, request_path, created_at
                FROM security_events
                ORDER BY id
                """
            ).fetchall()
        self.assertTrue(required_types.issubset({row[0] for row in rows}))
        self.assertTrue(all(row[2] in {"success", "failure", "denied"} for row in rows))
        self.assertTrue(all(row[6] and row[7] for row in rows))

        admin_page = admin_client.get("/admin/security-events")
        self.assertEqual(admin_page.status_code, 200)
        admin_body = admin_page.get_data(as_text=True)
        for event_type in required_types:
            self.assertIn(event_type, admin_body)

        self.assertEqual(self.client.get("/admin/security-events").status_code, 403)
        serialized_rows = str(rows)
        for sentinel in (
            failed_password,
            changed_password,
            hash_password(changed_password),
            biography,
            upload.decode(),
        ):
            self.assertNotIn(sentinel, serialized_rows)
            self.assertNotIn(sentinel, admin_body)


if __name__ == "__main__":
    unittest.main()
