import gc
import secrets
import sqlite3
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from run import app


class SecureBoardIntegrationTests(unittest.TestCase):
    """Exercise the product as one normal-flow application on disposable state."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "data" / "integration.db"
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
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    @staticmethod
    def _account(label):
        suffix = secrets.token_hex(6)
        return {
            "username": f"{label}_{suffix}",
            "email": f"{label}_{suffix}@example.test",
            "password": secrets.token_urlsafe(24),
        }

    def _invoke(self, *args, input_text=""):
        return app.test_cli_runner().invoke(args=list(args), input=input_text)

    def _setup_product(self):
        admin = self._account("admin")
        demo_password = secrets.token_urlsafe(24)

        init_result = self._invoke("init-db")
        self.assertEqual(init_result.exit_code, 0)
        self.assertNotIn(admin["password"], init_result.output)

        admin_result = self._invoke(
            "create-admin",
            input_text=(
                f"{admin['username']}\n{admin['email']}\n"
                f"{admin['password']}\n{admin['password']}\n"
            ),
        )
        self.assertEqual(admin_result.exit_code, 0)
        self.assertNotIn(admin["password"], admin_result.output)

        seed_result = self._invoke(
            "seed-demo",
            input_text=f"{demo_password}\n{demo_password}\n",
        )
        self.assertEqual(seed_result.exit_code, 0)
        self.assertNotIn(demo_password, seed_result.output)

        repeated_init = self._invoke("init-db")
        repeated_seed = self._invoke("seed-demo")
        self.assertEqual(repeated_init.exit_code, 0)
        self.assertEqual(repeated_seed.exit_code, 0)
        self.assertIn("already present", repeated_seed.output)
        self.assertNotIn(demo_password, repeated_seed.output)

        with sqlite3.connect(self.db_path) as conn:
            table_names = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
                if not row[0].startswith("sqlite_")
            }
            self.assertEqual(
                table_names,
                {"users", "chat", "board", "comments", "security_events"},
            )
            self.assertEqual(
                conn.execute("SELECT role FROM users WHERE username = ?", (admin["username"],)).fetchone(),
                ("admin",),
            )
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                4,
            )
        return admin

    def _register(self, account, client=None):
        active_client = client or self.client
        response = active_client.post(
            "/register",
            data={
                "username": account["username"],
                "email": account["email"],
                "password": account["password"],
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Account created. You may now log in.", response.get_data(as_text=True))
        self.assertNotIn(account["password"], response.get_data(as_text=True))
        return response

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
        self.assertEqual(response.headers["Location"], "/board")
        self.assertIn("session_id=", "\n".join(response.headers.getlist("Set-Cookie")))
        return response

    def _user_id(self, account):
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (account["username"],)
            ).fetchone()
        self.assertIsNotNone(row)
        return row[0]

    def _rows(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchall()

    def test_setup_to_moderation_chain_keeps_state_and_scopes_users(self):
        admin = self._setup_product()
        accounts = [self._account(label) for label in ("member_a", "member_b", "member_c")]
        for account in accounts:
            self._register(account)

        self.assertEqual(
            self._rows(
                "SELECT role FROM users WHERE username IN (?, ?, ?) ORDER BY username",
                tuple(account["username"] for account in accounts),
            ),
            [("user",), ("user",), ("user",)],
        )

        member_a, member_b, member_c = accounts
        member_a_id = self._user_id(member_a)
        member_b_id = self._user_id(member_b)
        member_c_id = self._user_id(member_c)

        self._login(member_a)
        self.assertEqual(self.client.get("/").headers["Location"], "/board")

        own_profile = self.client.get("/profile")
        own_profile_body = own_profile.get_data(as_text=True)
        self.assertEqual(own_profile.status_code, 200)
        self.assertIn(member_a["username"], own_profile_body)
        self.assertIn('action="/profile/edit_bio"', own_profile_body)
        self.assertIn('action="/profile/edit_avatar"', own_profile_body)
        self.assertIn('action="/profile/edit_password"', own_profile_body)

        missing_avatar_response = self.client.get(f"/user/avatar/{member_a_id}")
        self.assertEqual(missing_avatar_response.status_code, 302)
        missing_avatar_response.close()
        avatar_bytes = b"ordinary avatar bytes"
        upload = self.client.post(
            "/profile/edit_avatar",
            data={"avatar": (BytesIO(avatar_bytes), "avatar.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(upload.status_code, 302)
        self.assertEqual((self.avatar_dir / f"{member_a_id}.jpg").read_bytes(), avatar_bytes)
        served_avatar_response = self.client.get(f"/user/avatar/{member_a_id}")
        self.assertEqual(served_avatar_response.data, avatar_bytes)
        served_avatar_response.close()

        bio = f"Bio normal {secrets.token_hex(4)}"
        self.assertEqual(
            self.client.post(
                "/profile/edit_bio",
                data={"user_id": str(member_a_id), "bio": bio},
            ).status_code,
            302,
        )
        self.assertIn(bio, self.client.get("/profile").get_data(as_text=True))

        changed_password = secrets.token_urlsafe(24)
        self.assertEqual(
            self.client.post(
                "/profile/edit_password",
                data={"password": changed_password, "confirm": changed_password},
            ).status_code,
            302,
        )
        changed_account = dict(member_a, password=changed_password)
        reauthenticated = app.test_client()
        self._login(changed_account, reauthenticated)
        self.assertEqual(reauthenticated.get("/profile").status_code, 200)

        other_profile = self.client.get(f"/user/{member_b['username']}")
        other_profile_body = other_profile.get_data(as_text=True)
        self.assertEqual(other_profile.status_code, 200)
        self.assertIn(f"/direct?to_user={member_b['username']}", other_profile_body)

        feed = self.client.get("/board")
        self.assertEqual(feed.status_code, 200)
        self.assertIn("Discussões recentes", feed.get_data(as_text=True))
        unmatched = f"semresultado_{secrets.token_hex(4)}"
        empty_search = self.client.get(f"/board/search?q={unmatched}")
        self.assertEqual(empty_search.status_code, 200)
        self.assertIn("Nenhuma discussão encontrada", empty_search.get_data(as_text=True))

        topic_title = f"Tema normal {secrets.token_hex(4)}"
        topic_body = "Uma discussão comum para a integração."
        created_topic = self.client.post(
            "/board/new",
            data={"title": topic_title, "body": topic_body},
        )
        self.assertEqual(created_topic.status_code, 302)
        topic_id = self._rows(
            "SELECT id FROM board WHERE title = ?", (topic_title,)
        )[0][0]
        topic_search = self.client.get(
            "/board/search", query_string={"q": topic_title}
        )
        self.assertEqual(topic_search.status_code, 200)
        self.assertIn(topic_title, topic_search.get_data(as_text=True))
        topic_page = self.client.get(f"/board/{topic_id}")
        topic_page_body = topic_page.get_data(as_text=True)
        self.assertEqual(topic_page.status_code, 200)
        self.assertIn(topic_title, topic_page_body)
        self.assertIn(f"/user/{member_a['username']}", topic_page_body)

        reply_body = "Uma resposta comum para a integração."
        created_reply = self.client.post(
            f"/board/{topic_id}/reply", data={"body": reply_body}
        )
        self.assertEqual(created_reply.status_code, 302)
        topic_page = self.client.get(f"/board/{topic_id}")
        self.assertIn(reply_body, topic_page.get_data(as_text=True))
        self.assertIn("(1)", topic_page.get_data(as_text=True))

        message_a_to_b = "Mensagem comum de A para B."
        sent = self.client.post(
            "/direct",
            data={"to_user": member_b["username"], "message": message_a_to_b},
        )
        self.assertEqual(sent.status_code, 200)
        self.assertIn(message_a_to_b, sent.get_data(as_text=True))

        client_b = app.test_client()
        self._login(member_b, client_b)
        message_b_to_a = "Resposta comum de B para A."
        self.assertEqual(
            client_b.post(
                "/direct",
                data={"to_user": member_a["username"], "message": message_b_to_a},
            ).status_code,
            200,
        )
        conversation = self.client.get(f"/direct?to_user={member_b['username']}")
        conversation_body = conversation.get_data(as_text=True)
        self.assertIn(message_a_to_b, conversation_body)
        self.assertIn(message_b_to_a, conversation_body)
        ab_messages_before_moderation = self._rows(
            """
            SELECT sender_id, recipient_id, text
            FROM chat
            WHERE (sender_id = ? AND recipient_id = ?)
               OR (sender_id = ? AND recipient_id = ?)
            ORDER BY id
            """,
            (member_a_id, member_b_id, member_b_id, member_a_id),
        )

        client_c = app.test_client()
        self._login(member_c, client_c)
        c_conversation = client_c.get(f"/direct?to_user={member_b['username']}")
        c_conversation_body = c_conversation.get_data(as_text=True)
        self.assertEqual(c_conversation.status_code, 200)
        self.assertIn("Nenhuma mensagem nesta conversa", c_conversation_body)
        self.assertNotIn(message_a_to_b, c_conversation_body)
        self.assertNotIn(message_b_to_a, c_conversation_body)
        self.assertNotIn(member_b["username"], c_conversation_body.split('<nav class="conversation-list"', 1)[1].split("</nav>", 1)[0])
        self.assertEqual(member_c_id, self._user_id(member_c))

        admin_client = app.test_client()
        self._login(admin, admin_client)
        admin_page = admin_client.get("/admin")
        admin_body = admin_page.get_data(as_text=True)
        self.assertEqual(admin_page.status_code, 200)
        self.assertIn(topic_title, admin_body)
        self.assertIn(reply_body, admin_body)
        self.assertNotIn(member_a["email"], admin_body)
        self.assertNotIn(bio, admin_body)
        self.assertNotIn(message_a_to_b, admin_body)
        self.assertEqual(self.client.get("/admin").status_code, 403)

        reply_id = self._rows(
            "SELECT id FROM comments WHERE board_id = ? AND body = ?",
            (topic_id, reply_body),
        )[0][0]
        cross_origin = admin_client.post(
            f"/admin/replies/{reply_id}/delete",
            headers={"Origin": "https://elsewhere.example"},
        )
        self.assertEqual(cross_origin.status_code, 403)
        same_origin = admin_client.post(
            f"/admin/replies/{reply_id}/delete",
            headers={"Origin": "http://localhost"},
        )
        self.assertEqual(same_origin.status_code, 302)
        self.assertEqual(self._rows("SELECT id FROM comments WHERE id = ?", (reply_id,)), [])
        self.assertEqual(self._rows("SELECT id FROM board WHERE id = ?", (topic_id,)), [(topic_id,)])

        remaining_reply_body = "Outra resposta comum para a integração."
        created_remaining_reply = self.client.post(
            f"/board/{topic_id}/reply", data={"body": remaining_reply_body}
        )
        self.assertEqual(created_remaining_reply.status_code, 302)
        remaining_reply_id = self._rows(
            "SELECT id FROM comments WHERE board_id = ? AND body = ?",
            (topic_id, remaining_reply_body),
        )[0][0]

        delete_topic = admin_client.post(
            f"/admin/topics/{topic_id}/delete",
            headers={"Origin": "http://localhost"},
        )
        self.assertEqual(delete_topic.status_code, 302)
        self.assertEqual(self._rows("SELECT id FROM board WHERE id = ?", (topic_id,)), [])
        self.assertEqual(self._rows("SELECT id FROM comments WHERE board_id = ?", (topic_id,)), [])
        self.assertEqual(
            self._rows("SELECT id FROM comments WHERE id = ?", (remaining_reply_id,)),
            [],
        )
        self.assertEqual(self._rows("SELECT id FROM board WHERE id = 3101"), [(3101,)])
        self.assertEqual(self._rows("SELECT id FROM users WHERE id = ?", (member_b_id,)), [(member_b_id,)])
        self.assertEqual(
            self._rows(
                """
                SELECT sender_id, recipient_id, text
                FROM chat
                WHERE (sender_id = ? AND recipient_id = ?)
                   OR (sender_id = ? AND recipient_id = ?)
                ORDER BY id
                """,
                (member_a_id, member_b_id, member_b_id, member_a_id),
            ),
            ab_messages_before_moderation,
        )
        self.assertEqual(
            self._rows("SELECT sender_id, recipient_id FROM chat WHERE sender_id = ? OR recipient_id = ?", (member_c_id, member_c_id)),
            [],
        )

        self.assertEqual(self._invoke("init-db").exit_code, 0)
        repeated_seed = self._invoke("seed-demo")
        self.assertEqual(repeated_seed.exit_code, 0)
        self.assertIn("already present", repeated_seed.output)
        self.assertEqual((self.avatar_dir / f"{member_a_id}.jpg").read_bytes(), avatar_bytes)

        logout = self.client.get("/logout")
        self.assertEqual(logout.status_code, 302)
        self.assertEqual(logout.headers["Location"], "/login")
        self.assertEqual(self.client.get("/board").headers["Location"], "/login")
        anonymous = self.client.get("/login").get_data(as_text=True)
        self.assertIn("Entrar", anonymous)
        self.assertIn("Criar conta", anonymous)
        self.assertNotIn("Administração", anonymous)

    def test_route_inventory_and_normal_errors_stay_product_scoped(self):
        admin = self._setup_product()
        member = self._account("member")
        self._register(member)

        routes = {rule.rule for rule in app.url_map.iter_rules()}
        expected = {
            "/",
            "/login",
            "/register",
            "/logout",
            "/user/<username>",
            "/user",
            "/profile",
            "/user/avatar/<int:user_id>",
            "/profile/edit_password",
            "/profile/edit_avatar",
            "/profile/edit_bio",
            "/board",
            "/board/<board_id>",
            "/board/new",
            "/board/<int:board_id>/reply",
            "/board/search",
            "/direct",
            "/admin",
            "/admin/topics/<int:topic_id>/delete",
            "/admin/replies/<int:reply_id>/delete",
            "/admin/security-events",
        }
        self.assertTrue(expected.issubset(routes))
        for obsolete in (
            "/resetdb",
            "/root",
            "/root/download_source",
            "/2fa",
            "/download/nicks.txt",
            "/download/rockyou.txt",
            "/download/readme.txt",
        ):
            self.assertNotIn(obsolete, routes)

        anonymous = app.test_client()
        self.assertEqual(anonymous.get("/").headers["Location"], "/login")
        self.assertEqual(anonymous.get("/board").headers["Location"], "/login")
        missing_path = f"/missing_{secrets.token_hex(4)}"
        missing = anonymous.get(missing_path)
        self.assertEqual(missing.status_code, 404)
        self.assertIn("Página não encontrada", missing.get_data(as_text=True))

        invalid = anonymous.post(
            "/login",
            data={
                "username": f"unknown_{secrets.token_hex(4)}",
                "password": secrets.token_urlsafe(24),
            },
        )
        self.assertEqual(invalid.status_code, 200)
        self.assertIn("Invalid credentials.", invalid.get_data(as_text=True))
        self.assertNotIn("session_id=", "\n".join(invalid.headers.getlist("Set-Cookie")))

        duplicate = anonymous.post(
            "/register",
            data={
                "username": member["username"],
                "email": member["email"],
                "password": secrets.token_urlsafe(24),
            },
        )
        self.assertEqual(duplicate.status_code, 200)
        self.assertIn("already in use", duplicate.get_data(as_text=True))

        self._login(member)
        missing_profile = self.client.get(f"/user/unknown_{secrets.token_hex(4)}")
        self.assertEqual(missing_profile.status_code, 404)
        missing_avatar = self.client.get("/user/avatar/999999")
        self.assertEqual(missing_avatar.status_code, 302)
        self.assertIn("default-avatar.svg", missing_avatar.headers["Location"])

        unknown_recipient = self.client.post(
            "/direct",
            data={
                "to_user": f"unknown_{secrets.token_hex(4)}",
                "message": "Mensagem normal",
            },
        )
        self.assertEqual(unknown_recipient.status_code, 200)
        self.assertIn("does not exist", unknown_recipient.get_data(as_text=True))
        empty_message = self.client.post(
            "/direct", data={"to_user": admin["username"], "message": "   "}
        )
        self.assertEqual(empty_message.status_code, 200)
        self.assertIn("Message cannot be empty.", empty_message.get_data(as_text=True))
        self.assertEqual(self.client.get("/admin").status_code, 403)


if __name__ == "__main__":
    unittest.main()
