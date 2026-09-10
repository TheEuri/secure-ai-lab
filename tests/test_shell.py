import gc
import sqlite3
import tempfile
import unittest
from pathlib import Path

from common.database import SCHEMA
from common.session import generate_token
from run import app


class SharedShellTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "shell-test.db"
        self.original_config = {
            "DATABASE": app.config.get("DATABASE"),
            "AVATAR_DIR": app.config.get("AVATAR_DIR"),
            "TESTING": app.config.get("TESTING"),
        }
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=Path(self.temp_dir.name) / "avatars",
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)
            conn.executemany(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (101, "member", "member-hash", "user", "member@example.test", "Member bio"),
                    (102, "admin", "admin-hash", "admin", "admin@example.test", "Admin bio"),
                ],
            )
            conn.execute(
                "INSERT INTO board (id, author_id, title, body) VALUES (?, ?, ?, ?)",
                (201, 101, "Discussão de teste", "Conteúdo de teste"),
            )
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    def _login_as(self, user_id, username, claimed_role):
        self.client.set_cookie(
            "session_id",
            generate_token(username, claimed_role, user_id),
        )

    def test_anonymous_login_and_404_use_public_navigation(self):
        login = self.client.get("/login")
        missing = self.client.get("/missing/%3Cscript%3Ealert(1)%3C%2Fscript%3E")

        self.assertEqual(login.status_code, 200)
        self.assertEqual(missing.status_code, 404)
        for body in (login.get_data(as_text=True), missing.get_data(as_text=True)):
            self.assertIn("SecureBoard AI", body)
            self.assertIn("Entrar", body)
            self.assertIn("Criar conta", body)
            for private_label in ("Discussões", "Mensagens", "Meu perfil", "Administração", "Sair"):
                self.assertNotIn(private_label, body)
        missing_body = missing.get_data(as_text=True)
        self.assertIn("Página não encontrada", missing_body)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", missing_body)
        self.assertNotIn("<script>alert(1)</script>", missing_body)

    def test_member_navigation_has_member_destinations_without_admin(self):
        self._login_as(101, "member", "user")
        response = self.client.get("/board")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        for label in ("Discussões", "Mensagens", "Meu perfil", "Sair"):
            self.assertIn(label, body)
        self.assertNotIn("Administração", body)

    def test_database_admin_navigation_is_visible(self):
        self._login_as(102, "admin", "admin")
        response = self.client.get("/board")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Administração", body)
        self.assertIn('href="/admin"', body)

    def test_navigation_role_comes_from_viewer_not_viewed_profile(self):
        self._login_as(102, "admin", "user")
        admin_viewing_member = self.client.get("/user/member")
        self.assertEqual(admin_viewing_member.status_code, 200)
        self.assertIn("Administração", admin_viewing_member.get_data(as_text=True))

        self._login_as(101, "member", "admin")
        member_viewing_admin = self.client.get("/user/admin")
        self.assertEqual(member_viewing_admin.status_code, 200)
        self.assertNotIn("Administração", member_viewing_admin.get_data(as_text=True))

    def test_brand_and_profile_links_use_existing_routes(self):
        self._login_as(101, "member", "user")
        body = self.client.get("/profile").get_data(as_text=True)

        self.assertIn('class="app-brand" href="/board"', body)
        self.assertIn('href="/profile"', body)
        self.assertNotRegex(body, r"/(?:resetdb|root|2fa|download)\b")

    def test_404_has_viewer_navigation(self):
        self._login_as(101, "member", "user")
        response = self.client.get("/does-not-exist")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 404)
        self.assertIn("Voltar ao início", body)
        self.assertIn("Meu perfil", body)
        self.assertIn('href="/board"', body)

    def test_all_templates_compile_without_rendering(self):
        project_root = Path(__file__).resolve().parents[1]
        template_paths = sorted(project_root.rglob("*.html"))
        self.assertTrue(template_paths)
        for template_path in template_paths:
            with self.subTest(template=template_path.relative_to(project_root)):
                source = template_path.read_text(encoding="utf-8")
                app.jinja_env.compile(
                    source,
                    name=str(template_path.relative_to(project_root)),
                    filename=str(template_path),
                )

    def test_global_shell_has_responsive_focus_and_no_remote_font_import(self):
        project_root = Path(__file__).resolve().parents[1]
        base = (project_root / "templates" / "base.html").read_text(encoding="utf-8")
        css_sources = [
            (project_root / "static" / "css" / name).read_text(encoding="utf-8")
            for name in ("app.css", "navbar.css", "404.css")
        ]
        self.assertIn('name="viewport"', base)
        self.assertIn(":focus-visible", "\n".join(css_sources))
        self.assertIn("@media", "\n".join(css_sources))
        self.assertNotIn("fonts.googleapis.com", base)
        self.assertNotIn("fonts.googleapis.com", "\n".join(css_sources))
        for template_name in ("base.html", "navbar.html", "404.html"):
            template = (project_root / "templates" / template_name).read_text(encoding="utf-8")
            self.assertNotRegex(template, r"\|\s*(?:safe|raw)\b")


if __name__ == "__main__":
    unittest.main()
