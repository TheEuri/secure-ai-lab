import gc
import hashlib
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

from argon2 import PasswordHasher, Type

from common.database import (
    SEED_USERS,
    create_admin_account,
    init_db,
    seed_demo_data,
)
from common.session import generate_token
from common.users import (
    PASSWORD_HASHER,
    hash_password,
    is_legacy_password_hash,
    password_needs_rehash,
    verify_password,
)
from run import app


class PasswordSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "password-security.db"
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
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    @staticmethod
    def _runtime_password(label):
        return f"{label}-{secrets.token_urlsafe(18)}"

    @staticmethod
    def _legacy_hash(password):
        """Construct only the exact historical compatibility fixture."""

        return hashlib.sha256(password.encode()).hexdigest()

    def _insert_account(self, user_id, username, password_hash, role="user"):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    username,
                    password_hash,
                    role,
                    f"{username}@example.test",
                    "",
                ),
            )
            conn.commit()

    def _stored_hash(self, username):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT password FROM users WHERE username = ?",
                (username,),
            ).fetchone()[0]

    def _login(self, username, password, client=None):
        active_client = client or self.client
        return active_client.post(
            "/login",
            data={"username": username, "password": password},
        )

    def test_hash_password_creates_standard_argon2id_representation(self):
        password = self._runtime_password("hash")
        stored_hash = hash_password(password)
        self.assertTrue(stored_hash.startswith("$argon2id$"))
        self.assertNotEqual(stored_hash, password)
        self.assertNotEqual(stored_hash, self._legacy_hash(password))
        self.assertFalse(is_legacy_password_hash(stored_hash))

    def test_correct_password_verifies(self):
        password = self._runtime_password("correct")
        self.assertTrue(verify_password(hash_password(password), password))

    def test_incorrect_password_fails(self):
        password = self._runtime_password("correct")
        self.assertFalse(
            verify_password(hash_password(password), self._runtime_password("wrong"))
        )

    def test_same_password_produces_distinct_representations(self):
        password = self._runtime_password("shared")
        first = hash_password(password)
        second = hash_password(password)
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("$argon2id$") and second.startswith("$argon2id$"))

    def test_distinct_representations_both_verify(self):
        password = self._runtime_password("shared")
        representations = [hash_password(password), hash_password(password)]
        self.assertTrue(all(verify_password(value, password) for value in representations))

    def test_registration_stores_argon2(self):
        username = f"registered_{secrets.token_hex(4)}"
        password = self._runtime_password("registration")
        response = self.client.post(
            "/register",
            data={
                "username": username,
                "email": f"{username}@example.test",
                "password": password,
            },
        )
        stored_hash = self._stored_hash(username)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(stored_hash.startswith("$argon2id$"))
        self.assertTrue(verify_password(stored_hash, password))

    def test_create_admin_stores_argon2(self):
        username = f"administrator_{secrets.token_hex(4)}"
        password = self._runtime_password("administrator")
        create_admin_account(
            username,
            f"{username}@example.test",
            password,
            self.db_path,
        )
        stored_hash = self._stored_hash(username)
        self.assertTrue(stored_hash.startswith("$argon2id$"))
        self.assertTrue(verify_password(stored_hash, password))

    def test_seed_demo_stores_distinct_argon2_hashes(self):
        password = self._runtime_password("demo")
        self.assertTrue(seed_demo_data(password, self.db_path))
        with sqlite3.connect(self.db_path) as conn:
            hashes = [
                row[0]
                for row in conn.execute(
                    "SELECT password FROM users ORDER BY id"
                ).fetchall()
            ]
        self.assertEqual(len(hashes), len(SEED_USERS))
        self.assertEqual(len(set(hashes)), len(SEED_USERS))
        self.assertTrue(all(value.startswith("$argon2id$") for value in hashes))
        self.assertTrue(all(verify_password(value, password) for value in hashes))

    def test_password_change_stores_argon2_and_keeps_audit_event(self):
        old_password = self._runtime_password("old")
        new_password = self._runtime_password("new")
        self._insert_account(101, "member", hash_password(old_password))
        self.client.set_cookie("session_id", generate_token("member", "user", 101))
        response = self.client.post(
            "/profile/edit_password",
            data={"password": new_password, "confirm": new_password},
        )
        stored_hash = self._stored_hash("member")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(stored_hash.startswith("$argon2id$"))
        self.assertTrue(verify_password(stored_hash, new_password))
        with sqlite3.connect(self.db_path) as conn:
            event = conn.execute(
                "SELECT event_type, actor_user_id, outcome FROM security_events"
            ).fetchone()
        self.assertEqual(event, ("auth.password.changed", 101, "success"))

    def test_login_works_with_existing_argon2_account(self):
        password = self._runtime_password("login")
        self._insert_account(101, "argon_member", hash_password(password))
        response = self._login("argon_member", password)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/board")

    def test_legacy_account_authenticates_with_correct_password(self):
        password = self._runtime_password("legacy")
        self._insert_account(101, "legacy_member", self._legacy_hash(password))
        self.assertEqual(self._login("legacy_member", password).status_code, 302)

    def test_successful_legacy_login_upgrades_to_argon2(self):
        password = self._runtime_password("legacy-upgrade")
        legacy_hash = self._legacy_hash(password)
        self._insert_account(101, "legacy_member", legacy_hash)
        self.assertTrue(is_legacy_password_hash(legacy_hash))
        self.assertTrue(password_needs_rehash(legacy_hash))
        self.assertEqual(self._login("legacy_member", password).status_code, 302)
        upgraded = self._stored_hash("legacy_member")
        self.assertNotEqual(upgraded, legacy_hash)
        self.assertTrue(upgraded.startswith("$argon2id$"))
        self.assertTrue(verify_password(upgraded, password))

    def test_failed_legacy_login_does_not_mutate_hash(self):
        password = self._runtime_password("legacy")
        legacy_hash = self._legacy_hash(password)
        self._insert_account(101, "legacy_member", legacy_hash)
        response = self._login("legacy_member", self._runtime_password("wrong"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._stored_hash("legacy_member"), legacy_hash)

    def test_migrated_account_authenticates_again_normally(self):
        password = self._runtime_password("legacy-repeat")
        self._insert_account(101, "legacy_member", self._legacy_hash(password))
        self.assertEqual(self._login("legacy_member", password).status_code, 302)
        migrated = self._stored_hash("legacy_member")
        second_client = app.test_client()
        self.assertEqual(
            self._login("legacy_member", password, second_client).status_code,
            302,
        )
        self.assertEqual(self._stored_hash("legacy_member"), migrated)

    def test_valid_outdated_argon2_hash_is_rehashed_after_login(self):
        password = self._runtime_password("argon-rehash")
        old_hasher = PasswordHasher(
            time_cost=1,
            memory_cost=8192,
            parallelism=1,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        outdated = old_hasher.hash(password)
        self.assertTrue(PASSWORD_HASHER.check_needs_rehash(outdated))
        self._insert_account(101, "outdated_member", outdated)
        self.assertEqual(self._login("outdated_member", password).status_code, 302)
        upgraded = self._stored_hash("outdated_member")
        self.assertNotEqual(upgraded, outdated)
        self.assertFalse(PASSWORD_HASHER.check_needs_rehash(upgraded))

    def test_passwords_and_hashes_are_absent_from_security_events(self):
        password = self._runtime_password("audit")
        stored_hash = hash_password(password)
        wrong_password = self._runtime_password("audit-wrong")
        self._insert_account(101, "audit_member", stored_hash)
        self._login("audit_member", wrong_password)
        self._login("audit_member", password)
        with sqlite3.connect(self.db_path) as conn:
            serialized_events = str(conn.execute("SELECT * FROM security_events").fetchall())
        for forbidden in (password, wrong_password, stored_hash):
            self.assertNotIn(forbidden, serialized_events)

    def test_registration_login_and_password_change_remain_functional(self):
        username = f"flow_{secrets.token_hex(4)}"
        original_password = self._runtime_password("flow-original")
        replacement_password = self._runtime_password("flow-replacement")
        self.assertEqual(
            self.client.post(
                "/register",
                data={
                    "username": username,
                    "email": f"{username}@example.test",
                    "password": original_password,
                },
            ).status_code,
            200,
        )
        self.assertEqual(self._login(username, original_password).status_code, 302)
        user_id = None
        with sqlite3.connect(self.db_path) as conn:
            user_id = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()[0]
        self.client.set_cookie(
            "session_id",
            generate_token(username, "user", user_id),
        )
        self.assertEqual(
            self.client.post(
                "/profile/edit_password",
                data={
                    "password": replacement_password,
                    "confirm": replacement_password,
                },
            ).status_code,
            302,
        )
        second_client = app.test_client()
        self.assertEqual(
            self._login(username, replacement_password, second_client).status_code,
            302,
        )


if __name__ == "__main__":
    unittest.main()
