import gc
import sqlite3
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from common.database import SCHEMA
from common.session import create_session
from common.users import hash_password, verify_password
from run import app


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "profile.db"
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
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)
            conn.executemany(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (101, "alice", hash_password("alice-password"), "user", "alice@example.test", "Alice bio"),
                    (102, "admin", hash_password("admin-password"), "admin", "admin@example.test", "Admin bio"),
                    (103, "bob", hash_password("bob-password"), "user", "bob@example.test", "Bob bio"),
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

    def _rows(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchall()

    def test_own_profile_has_edit_forms_and_hides_message_action(self):
        self._login_as(101, "alice")

        response = self.client.get("/profile")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Alice bio", body)
        self.assertIn('src="/user/avatar/101"', body)
        self.assertIn('action="/profile/edit_bio"', body)
        self.assertIn('name="user_id" value="101"', body)
        self.assertIn('action="/profile/edit_avatar"', body)
        self.assertIn('name="avatar"', body)
        self.assertIn('action="/profile/edit_password"', body)
        self.assertIn('name="password"', body)
        self.assertIn('name="confirm"', body)
        self.assertIn("Salvar biografia", body)
        self.assertIn("Enviar avatar", body)
        self.assertIn("Atualizar senha", body)
        self.assertNotIn(">Enviar mensagem<", body)

    def test_other_member_profile_is_minimal_and_links_to_direct_selection(self):
        self._login_as(101, "alice")

        response = self.client.get("/user/bob")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("bob", body)
        self.assertIn("Bob bio", body)
        self.assertIn('src="/user/avatar/103"', body)
        self.assertIn(
            '<a\n          class="profile-message-link"\n          href="/direct?to_user=bob"\n        >Enviar mensagem</a>',
            body,
        )
        for private_value in (
            "bob@example.test",
            hash_password("bob-password"),
            "admin",
        ):
            self.assertNotIn(private_value, body)
        self.assertNotIn(">103<", body)
        self.assertNotIn('name="password"', body)
        self.assertNotIn('name="user_id"', body)

    def test_id_profile_and_missing_profiles_keep_existing_interfaces(self):
        self._login_as(101, "alice")

        by_id = self.client.get("/user?id=102")
        self.assertEqual(by_id.status_code, 200)
        self.assertIn("admin", by_id.get_data(as_text=True))

        self.assertEqual(self.client.get("/user/missing-user").status_code, 404)
        self.assertEqual(self.client.get("/user?id=999").status_code, 404)

    def test_navbar_uses_viewer_role_not_profile_role(self):
        self._login_as(102, "admin", "user")
        admin_viewing_member = self.client.get("/user/bob")
        self.assertEqual(admin_viewing_member.status_code, 200)
        self.assertIn("Administração", admin_viewing_member.get_data(as_text=True))

        self._login_as(101, "alice", "admin")
        member_viewing_admin = self.client.get("/user/admin")
        self.assertEqual(member_viewing_admin.status_code, 200)
        self.assertNotIn("Administração", member_viewing_admin.get_data(as_text=True))

    def test_missing_avatar_redirects_to_local_default_svg(self):
        self._login_as(101, "alice")

        response = self.client.get("/user/avatar/101")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/user_static/img/default-avatar.svg")

        fallback = self.client.get("/user/avatar/101", follow_redirects=True)
        self.assertEqual(fallback.status_code, 200)
        self.assertIn("image/svg+xml", fallback.content_type)
        self.assertIn("Avatar padrão", fallback.get_data(as_text=True))
        fallback.close()

    def test_configured_avatar_is_served_and_upload_uses_deterministic_target(self):
        self._login_as(101, "alice")
        self.avatar_dir.mkdir(parents=True)
        existing = b"configured-avatar-bytes"
        (self.avatar_dir / "101.jpg").write_bytes(existing)

        served = self.client.get("/user/avatar/101")
        self.assertEqual(served.status_code, 200)
        self.assertEqual(served.data, existing)
        served.close()

        uploaded = b"uploaded-avatar-bytes"
        response = self.client.post(
            "/profile/edit_avatar",
            data={"avatar": (BytesIO(uploaded), "client-provided.png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/profile")
        self.assertEqual((self.avatar_dir / "101.jpg").read_bytes(), uploaded)
        uploaded_response = self.client.get("/user/avatar/101")
        self.assertEqual(uploaded_response.data, uploaded)
        uploaded_response.close()

        profile = self.client.get("/profile")
        self.assertIn('src="/user/avatar/101"', profile.get_data(as_text=True))

    def test_biography_and_password_updates_keep_normal_behavior(self):
        self._login_as(101, "alice")

        new_bio = "Bio atualizada para Alice"
        response = self.client.post(
            "/profile/edit_bio",
            data={"user_id": "101", "bio": new_bio},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._rows("SELECT bio FROM users WHERE id = 101"), [(new_bio,)])
        self.assertIn(new_bio, self.client.get("/profile").get_data(as_text=True))

        response = self.client.post(
            "/profile/edit_password",
            data={"password": "new-alice-password", "confirm": "new-alice-password"},
        )
        self.assertEqual(response.status_code, 302)
        stored_password = self._rows("SELECT password FROM users WHERE id = 101")[0][0]
        self.assertTrue(stored_password.startswith("$argon2id$"))
        self.assertTrue(verify_password(stored_password, "new-alice-password"))

    def test_profile_source_preserves_vulnerability_contracts(self):
        project_root = Path(__file__).resolve().parents[1]
        routes = (project_root / "apps" / "user" / "routes.py").read_text(encoding="utf-8")
        public_template = (
            project_root / "apps" / "user" / "templates" / "public_profile.html"
        ).read_text(encoding="utf-8")

        self.assertEqual(routes.count('request.form.get("user_id", type=int)'), 2)
        self.assertEqual(public_template.count("{{ user.bio|safe }}"), 1)
        self.assertNotIn("|raw", public_template)
        self.assertNotIn("fonts.googleapis.com", (project_root / "apps" / "user" / "static" / "css" / "style.css").read_text(encoding="utf-8"))
        self.assertNotIn("720px", (project_root / "apps" / "user" / "static" / "css" / "style.css").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
