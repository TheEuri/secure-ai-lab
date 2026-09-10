import gc
import sqlite3
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from common.database import init_db
from common.session import create_session
from common.users import hash_password
from run import app


class ProfileAuthorizationTests(unittest.TestCase):
    """Focused V2 regression tests for self-service profile mutations."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "profile-authorization.db"
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
                    (501, "owner_a", hash_password("owner-a-password"), "user", "owner-a@example.test", "A original bio"),
                    (502, "owner_b", hash_password("owner-b-password"), "user", "owner-b@example.test", "B original bio"),
                    (503, "profile_admin", hash_password("admin-password"), "admin", "profile-admin@example.test", "Admin original bio"),
                ],
            )
            conn.commit()
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    def _login_as(self, user_id):
        with app.app_context():
            token = create_session(user_id)
        self.client.set_cookie("session_id", token)

    def _row(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchone()

    def _profile_events(self):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                """
                SELECT event_type, actor_user_id, target_id, outcome
                FROM security_events
                WHERE event_type IN ('profile.bio.updated', 'profile.avatar.updated')
                ORDER BY id
                """
            ).fetchall()

    def test_self_bio_and_avatar_updates_work_without_client_target(self):
        self._login_as(501)

        bio_response = self.client.post(
            "/profile/edit_bio",
            data={"bio": "A updated bio"},
        )
        self.assertEqual(bio_response.status_code, 302)
        self.assertEqual(
            self._row("SELECT bio FROM users WHERE id = 501"),
            ("A updated bio",),
        )

        avatar_bytes = b"profile-owner-a-avatar-bytes"
        avatar_response = self.client.post(
            "/profile/edit_avatar",
            data={"avatar": (BytesIO(avatar_bytes), "owner-a.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(avatar_response.status_code, 302)
        self.assertEqual((self.avatar_dir / "501.jpg").read_bytes(), avatar_bytes)
        self.assertEqual(
            self._row("SELECT bio FROM users WHERE id = 502"),
            ("B original bio",),
        )

    def test_client_selected_other_id_is_rejected_before_bio_or_avatar_mutation(self):
        self._login_as(501)
        original_avatar = b"B avatar before authorization retest"
        self.avatar_dir.mkdir(parents=True)
        (self.avatar_dir / "502.jpg").write_bytes(original_avatar)

        bio_response = self.client.post(
            "/profile/edit_bio",
            data={"user_id": "502", "bio": "unauthorized B bio"},
        )
        self.assertEqual(bio_response.status_code, 403)
        self.assertEqual(
            self._row("SELECT bio FROM users WHERE id = 502"),
            ("B original bio",),
        )

        avatar_bytes = b"unauthorized-b-avatar-bytes"
        avatar_response = self.client.post(
            "/profile/edit_avatar",
            data={"user_id": "502", "avatar": (BytesIO(avatar_bytes), "owner-b.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(avatar_response.status_code, 403)
        self.assertEqual((self.avatar_dir / "502.jpg").read_bytes(), original_avatar)
        self.assertEqual(self._profile_events(), [])

    def test_malformed_client_target_is_rejected_before_mutation(self):
        self._login_as(501)

        response = self.client.post(
            "/profile/edit_bio",
            data={"user_id": "not-a-database-id", "bio": "must not persist"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            self._row("SELECT bio FROM users WHERE id = 501"),
            ("A original bio",),
        )
        self.assertEqual(self._profile_events(), [])

    def test_unauthenticated_profile_mutations_are_rejected(self):
        bio_response = self.client.post(
            "/profile/edit_bio",
            data={"user_id": "502", "bio": "anonymous attempt"},
        )
        self.assertEqual(bio_response.status_code, 302)
        self.assertEqual(bio_response.headers["Location"], "/login")

        avatar_response = self.client.post(
            "/profile/edit_avatar",
            data={"user_id": "502", "avatar": (BytesIO(b"anonymous avatar"), "owner-b.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(avatar_response.status_code, 302)
        self.assertEqual(avatar_response.headers["Location"], "/login")
        self.assertEqual(
            self._row("SELECT bio FROM users WHERE id = 502"),
            ("B original bio",),
        )
        self.assertFalse((self.avatar_dir / "502.jpg").exists())

    def test_admin_cannot_target_another_user_through_self_service_routes(self):
        self._login_as(503)
        original_avatar = b"B avatar before admin authorization retest"
        self.avatar_dir.mkdir(parents=True)
        (self.avatar_dir / "502.jpg").write_bytes(original_avatar)

        bio_response = self.client.post(
            "/profile/edit_bio",
            data={"user_id": "502", "bio": "admin cross-user attempt"},
        )
        self.assertEqual(bio_response.status_code, 403)
        self.assertEqual(
            self._row("SELECT bio FROM users WHERE id = 502"),
            ("B original bio",),
        )

        avatar_response = self.client.post(
            "/profile/edit_avatar",
            data={"user_id": "502", "avatar": (BytesIO(b"admin cross-user avatar"), "owner-b.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(avatar_response.status_code, 403)
        self.assertEqual((self.avatar_dir / "502.jpg").read_bytes(), original_avatar)
        self.assertEqual(self._profile_events(), [])

    def test_normal_profile_rendering_keeps_own_forms_without_hidden_target(self):
        self._login_as(501)

        response = self.client.get("/profile")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("A original bio", body)
        self.assertIn('action="/profile/edit_bio"', body)
        self.assertIn('action="/profile/edit_avatar"', body)
        self.assertNotIn('name="user_id"', body)

    def test_success_audit_events_always_target_authenticated_user(self):
        self._login_as(501)
        bio_response = self.client.post(
            "/profile/edit_bio",
            data={"bio": "audited A bio"},
        )
        self.assertEqual(bio_response.status_code, 302)
        avatar_response = self.client.post(
            "/profile/edit_avatar",
            data={"user_id": "501", "avatar": (BytesIO(b"audited avatar"), "owner-a.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(avatar_response.status_code, 302)

        self.assertEqual(
            self._profile_events(),
            [
                ("profile.bio.updated", 501, 501, "success"),
                ("profile.avatar.updated", 501, 501, "success"),
            ],
        )

    def test_s3_non_image_bytes_remain_saved_unchanged_for_own_avatar(self):
        self._login_as(501)
        harmless_non_image = b"plain text accepted by the intentionally unresolved upload control"

        response = self.client.post(
            "/profile/edit_avatar",
            data={"avatar": (BytesIO(harmless_non_image), "harmless.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual((self.avatar_dir / "501.jpg").read_bytes(), harmless_non_image)

        served = self.client.get("/user/avatar/501")
        self.assertEqual(served.status_code, 200)
        self.assertEqual(served.data, harmless_non_image)
        served.close()


if __name__ == "__main__":
    unittest.main()
