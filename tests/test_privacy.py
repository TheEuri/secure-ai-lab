import base64
import gc
import hashlib
import hmac
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

from common.database import init_db
from common.privacy import (
    PSEUDONYMIZATION_MESSAGE_PREFIX,
    PrivacyConfigurationError,
    get_privacy_analysis,
    pseudonymize_user_id,
    transform_security_events,
)
from common.security_audit import record_security_event
from common.session import create_session
from common.users import hash_password
from run import app


def _runtime_key():
    """Create an explicit Base64URL key from 256 bits of test randomness."""

    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _expected_pseudonym(user_id, key):
    digest = hmac.new(
        base64.urlsafe_b64decode(key),
        PSEUDONYMIZATION_MESSAGE_PREFIX + str(user_id).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return "P-" + digest[:32]


class PrivacyPseudonymizationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "privacy-test.db"
        self.original_config = {
            "DATABASE": app.config.get("DATABASE"),
            "AVATAR_DIR": app.config.get("AVATAR_DIR"),
            "TESTING": app.config.get("TESTING"),
            "PSEUDONYMIZATION_KEY": app.config.get("PSEUDONYMIZATION_KEY"),
        }
        self.key = _runtime_key()
        self.other_key = _runtime_key()
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=Path(self.temp_dir.name) / "avatars",
            PSEUDONYMIZATION_KEY=self.key,
        )
        init_db(self.db_path)
        self.admin_password = "fictional-admin-password"
        self.member_password = "fictional-member-password"
        self.target_password = "fictional-target-password"
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        303,
                        "privacy_admin_demo",
                        hash_password(self.admin_password),
                        "admin",
                        "privacy-admin@example.test",
                        "Fictional administrator biography",
                    ),
                    (
                        101,
                        "privacy_actor_a_demo",
                        hash_password(self.member_password),
                        "user",
                        "actor-a@example.test",
                        "Fictional actor A biography",
                    ),
                    (
                        202,
                        "privacy_actor_b_demo",
                        hash_password(self.target_password),
                        "user",
                        "actor-b@example.test",
                        "Fictional actor B biography",
                    ),
                ],
            )
            conn.execute(
                "INSERT INTO chat (sender_id, recipient_id, text) VALUES (?, ?, ?)",
                (101, 202, "PRIVATE_MESSAGE_SENTINEL_FICTIONAL_ONLY"),
            )
            conn.commit()
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    def _events(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT id, event_type, actor_user_id, outcome, target_type,
                           target_id, request_method, request_path, created_at
                    FROM security_events
                    ORDER BY id
                    """
                ).fetchall()
            ]

    def _login_session(self, user_id):
        with app.app_context():
            token = create_session(user_id)
        self.client.set_cookie("session_id", token)
        return token

    def _admin_login(self):
        return self._login_session(303)

    def test_same_id_and_key_are_stable_and_match_exact_domain_separated_hmac(self):
        first = pseudonymize_user_id(101, self.key)
        second = pseudonymize_user_id(101, self.key)
        self.assertEqual(first, second)
        self.assertEqual(first, _expected_pseudonym(101, self.key))
        self.assertEqual(len(first), 34)
        self.assertTrue(first[2:].islower())

    def test_different_ids_and_keys_produce_different_pseudonyms(self):
        actor_a = pseudonymize_user_id(101, self.key)
        actor_b = pseudonymize_user_id(202, self.key)
        actor_a_with_other_key = pseudonymize_user_id(101, self.other_key)
        self.assertNotEqual(actor_a, actor_b)
        self.assertNotEqual(actor_a, actor_a_with_other_key)
        self.assertEqual(actor_a, _expected_pseudonym(101, self.key))
        self.assertEqual(actor_b, _expected_pseudonym(202, self.key))
        self.assertEqual(actor_a_with_other_key, _expected_pseudonym(101, self.other_key))
        for pseudonym in (actor_a, actor_b, actor_a_with_other_key):
            self.assertRegex(pseudonym, r"^P-[0-9a-f]{32}$")
        self.assertNotEqual(actor_a, "P-101")
        self.assertNotEqual(actor_b, "P-202")

    def test_invalid_user_ids_are_rejected(self):
        for invalid in (True, False, 0, -1, 1.0, "101", None):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                pseudonymize_user_id(invalid, self.key)

    def test_missing_malformed_and_weak_keys_are_rejected_without_echoing_values(self):
        invalid_keys = (
            None,
            "",
            "not a base64url key",
            "!" * 43,
            base64.urlsafe_b64encode(b"too-short").decode("ascii"),
            "A" * 41,
            "A" * 42 + "=",
            b"bytes-are-not-config-text",
        )
        for invalid_key in invalid_keys:
            with self.subTest(invalid_key=repr(invalid_key)):
                with self.assertRaises(PrivacyConfigurationError) as raised:
                    pseudonymize_user_id(101, invalid_key)
                self.assertNotIn(repr(invalid_key), str(raised.exception))

    def test_transformer_returns_only_five_safe_fields_and_unknown_actor_is_none(self):
        rows = [
            {
                "id": 9001,
                "created_at": "2026-09-11 10:00:00",
                "event_type": "auth.login.success",
                "actor_user_id": 101,
                "outcome": "success",
                "target_type": "user",
                "target_id": 202,
                "request_method": "POST",
                "request_path": "/login",
                "username": "SHOULD_NOT_COPY",
                "private_message": "SHOULD_NOT_COPY",
            },
            {
                "id": 9002,
                "created_at": "2026-09-11 09:00:00",
                "event_type": "auth.login.failure",
                "actor_user_id": None,
                "outcome": "failure",
                "target_type": None,
                "target_id": None,
                "request_method": "POST",
                "request_path": "/login",
            },
        ]
        projected = transform_security_events(rows, self.key)
        self.assertEqual([set(row) for row in projected], [
            {
                "created_at",
                "event_type",
                "outcome",
                "actor_pseudonym",
                "target_type",
            },
            {
                "created_at",
                "event_type",
                "outcome",
                "actor_pseudonym",
                "target_type",
            },
        ])
        self.assertEqual(projected[0]["actor_pseudonym"], pseudonymize_user_id(101, self.key))
        self.assertIsNone(projected[1]["actor_pseudonym"])
        self.assertNotIn("id", projected[0])
        self.assertNotIn("target_id", projected[0])
        self.assertNotIn("request_path", projected[0])

    def test_stable_actor_a_events_and_actor_b_are_distinct_in_analysis(self):
        with app.app_context():
            record_security_event(
                "auth.login.success",
                "success",
                actor_user_id=101,
                target_type="user",
                target_id=101,
                request_method="POST",
                request_path="/login",
            )
            record_security_event(
                "profile.bio.updated",
                "success",
                actor_user_id=101,
                target_type="user",
                target_id=101,
                request_method="POST",
                request_path="/profile/edit_bio",
            )
            record_security_event(
                "auth.login.failure",
                "failure",
                actor_user_id=202,
                target_type="user",
                target_id=202,
                request_method="POST",
                request_path="/login",
            )
            rows = get_privacy_analysis()
        actor_a_rows = [row for row in rows if row["actor_pseudonym"] == pseudonymize_user_id(101, self.key)]
        actor_b_rows = [row for row in rows if row["actor_pseudonym"] == pseudonymize_user_id(202, self.key)]
        self.assertEqual(len(actor_a_rows), 2)
        self.assertEqual(len({row["actor_pseudonym"] for row in actor_a_rows}), 1)
        self.assertEqual(len(actor_b_rows), 1)
        self.assertNotEqual(actor_a_rows[0]["actor_pseudonym"], actor_b_rows[0]["actor_pseudonym"])

    def test_admin_can_view_minimized_analysis_without_direct_identifiers_or_secrets(self):
        with app.app_context():
            record_security_event(
                "auth.login.success",
                "success",
                actor_user_id=101,
                target_type="user",
                target_id=202,
                request_method="POST",
                request_path="/login",
            )
            record_security_event(
                "admin.topic.deleted",
                "success",
                actor_user_id=202,
                target_type="topic",
                target_id=31337,
                request_method="POST",
                request_path="/admin/topics/31337/delete",
            )
        raw_token = self._admin_login()
        csrf = self._csrf_token(raw_token)
        with sqlite3.connect(self.db_path) as conn:
            stored_member_hash = conn.execute(
                "SELECT password FROM users WHERE id = ?", (101,)
            ).fetchone()[0]
        body = self.client.get("/admin/privacy-analysis").get_data(as_text=True)
        self.assertEqual(self.client.get("/admin/privacy-analysis").status_code, 200)
        self.assertIn("auth.login.success", body)
        self.assertIn("admin.topic.deleted", body)
        self.assertIn("success", body)
        self.assertIn("user", body)
        self.assertIn("topic", body)
        self.assertIn(pseudonymize_user_id(101, self.key), body)
        self.assertIn(pseudonymize_user_id(202, self.key), body)
        self.assertEqual(body.count("<th>"), 5)
        self.assertNotIn("privacy_actor_a_demo", body)
        self.assertNotIn("privacy_actor_b_demo", body)
        self.assertNotIn("actor-a@example.test", body)
        self.assertNotIn("actor-b@example.test", body)
        self.assertNotIn("Fictional actor A biography", body)
        self.assertNotIn("PRIVATE_MESSAGE_SENTINEL_FICTIONAL_ONLY", body)
        self.assertNotIn(self.member_password, body)
        self.assertNotIn(stored_member_hash, body)
        self.assertNotIn(raw_token, body)
        self.assertNotIn(hashlib.sha256(raw_token.encode()).hexdigest(), body)
        self.assertNotIn(csrf, body)
        self.assertNotIn(self.key, body)
        for raw_table_label in (
            ">#101<",
            ">101<",
            ">#202<",
            ">202<",
            ">#31337<",
            ">31337<",
        ):
            self.assertNotIn(raw_table_label, body)
        self.assertNotIn("/admin/topics/31337/delete", body)
        self.assertNotIn("POST /login", body)

    def test_privacy_analysis_access_control_matches_existing_admin_guard(self):
        anonymous = app.test_client().get("/admin/privacy-analysis")
        self.assertEqual(anonymous.status_code, 302)
        self.assertEqual(anonymous.headers["Location"], "/login")

        self._login_session(101)
        member = self.client.get("/admin/privacy-analysis")
        self.assertEqual(member.status_code, 403)

        self.client = app.test_client()
        self._admin_login()
        self.assertEqual(self.client.get("/admin/privacy-analysis").status_code, 200)

    def test_missing_or_invalid_config_fails_closed_with_safe_503(self):
        self._admin_login()
        app.config["PSEUDONYMIZATION_KEY"] = None
        missing = self.client.get("/admin/privacy-analysis")
        self.assertEqual(missing.status_code, 503)
        self.assertIn("indisponível", missing.get_data(as_text=True))
        self.assertNotIn("None", missing.get_data(as_text=True))

        invalid_value = "not-a-valid-key"
        app.config["PSEUDONYMIZATION_KEY"] = invalid_value
        invalid = self.client.get("/admin/privacy-analysis")
        self.assertEqual(invalid.status_code, 503)
        invalid_body = invalid.get_data(as_text=True)
        self.assertNotIn(invalid_value, invalid_body)

    def test_analysis_is_bounded_to_100_newest_rows_and_operational_rows_remain_unchanged(self):
        with sqlite3.connect(self.db_path) as conn:
            for index in range(105):
                conn.execute(
                    """
                    INSERT INTO security_events (
                        event_type, actor_user_id, outcome, target_type,
                        target_id, request_method, request_path, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "auth.login.failure",
                        101,
                        "failure",
                        "user",
                        202,
                        "POST",
                        "/login",
                        f"2026-09-11 00:{index // 60:02d}:{index % 60:02d}",
                    ),
                )
            conn.commit()
        before = self._events()
        self.assertEqual(len(before), 105)
        with app.app_context():
            rows = get_privacy_analysis()
        self.assertEqual(len(rows), 100)
        self.assertEqual(rows[0]["created_at"], before[-1]["created_at"])
        self.assertEqual(rows[-1]["created_at"], before[-100]["created_at"])
        self.assertNotIn(before[-101]["created_at"], [row["created_at"] for row in rows])

        self._admin_login()
        response = self.client.get("/admin/privacy-analysis")
        self.assertEqual(response.status_code, 200)
        after = self._events()
        self.assertEqual(after, before)
        self.assertEqual(after[-1]["actor_user_id"], 101)

    def _csrf_token(self, raw_token):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (hashlib.sha256(raw_token.encode()).hexdigest(),),
            ).fetchone()[0]


if __name__ == "__main__":
    unittest.main()
