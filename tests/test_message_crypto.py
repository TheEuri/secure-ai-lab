import base64
import gc
import hashlib
import secrets
import sqlite3
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from common.database import PRODUCT_SCHEMA, encrypt_legacy_messages, init_db
from common.message_crypto import (
    MESSAGE_AAD_PREFIX,
    MESSAGE_CRYPTO_VERSION,
    MessageCryptoConfigurationError,
    MessageDecryptionError,
    decrypt_message,
    encrypt_message,
    load_message_encryption_key,
)
from common.security_audit import record_security_event
from common.session import create_session
from common.users import hash_password
from run import app


def _key():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


class MessageCryptoTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "message-crypto.db"
        self.key = _key()
        self.original_config = {
            "DATABASE": app.config.get("DATABASE"),
            "AVATAR_DIR": app.config.get("AVATAR_DIR"),
            "TESTING": app.config.get("TESTING"),
            "MESSAGE_ENCRYPTION_KEY": app.config.get("MESSAGE_ENCRYPTION_KEY"),
            "PSEUDONYMIZATION_KEY": app.config.get("PSEUDONYMIZATION_KEY"),
        }
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=root / "avatars",
            MESSAGE_ENCRYPTION_KEY=self.key,
            PSEUDONYMIZATION_KEY=_key(),
        )
        init_db(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (101, "cipher_alice", hash_password("alice-runtime"), "user", "alice@example.test", "A"),
                    (102, "cipher_bob", hash_password("bob-runtime"), "user", "bob@example.test", "B"),
                    (103, "cipher_carol", hash_password("carol-runtime"), "user", "carol@example.test", "C"),
                    (201, "cipher_admin", hash_password("admin-runtime"), "admin", "admin@example.test", "Admin"),
                ],
            )
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    def _login(self, user_id, client=None):
        active = client or self.client
        with app.app_context():
            token = create_session(user_id)
        active.set_cookie("session_id", token)
        with sqlite3.connect(self.db_path) as conn:
            csrf = conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()[0]
        return token, csrf

    def _send(self, message, recipient="cipher_bob", client=None, user_id=101):
        active = client or self.client
        _, csrf = self._login(user_id, active)
        return active.post(
            "/direct",
            data={"to_user": recipient, "message": message, "csrf_token": csrf},
        )

    def _row(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query, params).fetchone()

    def test_key_validation_accepts_exact_32_bytes_and_rejects_missing_malformed_or_wrong_length(self):
        self.assertEqual(len(load_message_encryption_key(self.key)), 32)
        self.assertEqual(
            load_message_encryption_key(self.key.rstrip("=")),
            load_message_encryption_key(self.key),
        )
        for invalid in (None, "", "not base64!", _key()[:-3], base64.urlsafe_b64encode(b"short").decode()):
            with self.subTest(invalid=repr(invalid)), self.assertRaises(MessageCryptoConfigurationError) as raised:
                load_message_encryption_key(invalid)
            self.assertNotIn(repr(invalid), str(raised.exception))

    def test_aesgcm_unicode_roundtrip_random_nonce_and_ciphertext(self):
        text = 'Olá <seguro> & "privado" — café'
        first = encrypt_message(text, 1, 101, 102, self.key)
        second = encrypt_message(text, 1, 101, 102, self.key)
        self.assertEqual((first[2], second[2]), (MESSAGE_CRYPTO_VERSION,) * 2)
        self.assertEqual((len(first[1]), len(second[1])), (12, 12))
        self.assertNotEqual(first[:2], second[:2])
        self.assertNotIn(text.encode(), first[0])
        self.assertEqual(decrypt_message(*first, 1, 101, 102, self.key), text)
        self.assertTrue(MESSAGE_AAD_PREFIX.startswith(b"secureboard:message:v1:"))

    def test_ciphertext_nonce_wrong_key_and_changed_aad_fail_authentication(self):
        encrypted = encrypt_message("authenticated", 7, 101, 102, self.key)
        ciphertext, nonce, version = encrypted
        corrupt_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        corrupt_nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
        cases = (
            (corrupt_ciphertext, nonce, version, 7, 101, 102, self.key),
            (ciphertext, corrupt_nonce, version, 7, 101, 102, self.key),
            (ciphertext, nonce, version, 7, 101, 102, _key()),
            (ciphertext, nonce, version, 8, 101, 102, self.key),
            (ciphertext, nonce, version, 7, 102, 101, self.key),
        )
        for case in cases:
            with self.subTest(case=case[3:6]), self.assertRaises(MessageDecryptionError):
                decrypt_message(*case)

    def test_new_message_is_encrypted_at_rest_and_both_participants_can_read(self):
        text = "P5K fictional rendezvous · confirmado"
        response = self._send(text)
        self.assertEqual(response.status_code, 200)
        self.assertIn(text, response.get_data(as_text=True))
        row = self._row(
            """
            SELECT id, sender_id, recipient_id, text, message_ciphertext,
                   message_nonce, crypto_version
            FROM chat ORDER BY id DESC LIMIT 1
            """
        )
        self.assertEqual(row[1:4], (101, 102, ""))
        self.assertIsInstance(row[4], bytes)
        self.assertEqual(len(row[5]), 12)
        self.assertEqual(row[6], 1)
        self.assertNotIn(text.encode(), row[4])
        self.assertNotIn(text, repr(row))

        bob = app.test_client()
        self._login(102, bob)
        recipient = bob.get("/direct?to_user=cipher_alice")
        self.assertEqual(recipient.status_code, 200)
        self.assertIn(text, recipient.get_data(as_text=True))

        carol = app.test_client()
        self._login(103, carol)
        outsider = carol.get("/direct?to_user=cipher_bob")
        self.assertEqual(outsider.status_code, 200)
        self.assertNotIn(text, outsider.get_data(as_text=True))

    def test_missing_key_rolls_back_send_and_returns_generic_unavailable(self):
        app.config["MESSAGE_ENCRYPTION_KEY"] = None
        before = self._row("SELECT COUNT(*) FROM chat")[0]
        response = self._send("MISSING_KEY_SENTINEL")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self._row("SELECT COUNT(*) FROM chat")[0], before)
        body = response.get_data(as_text=True)
        self.assertIn("temporarily unavailable", body)
        self.assertNotIn("MESSAGE_ENCRYPTION_KEY", body)
        self.assertNotIn("MISSING_KEY_SENTINEL", body)

    def test_tamper_and_record_copy_fail_closed_without_plaintext_fallback(self):
        first_text = "TAMPERED_CONTENT_MUST_NOT_RENDER"
        second_text = "SECOND_MESSAGE_MUST_NOT_FALL_BACK"
        self.assertEqual(self._send(first_text).status_code, 200)
        self.assertEqual(self._send(second_text).status_code, 200)
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, message_ciphertext, message_nonce FROM chat ORDER BY id"
            ).fetchall()
            first, second = rows[-2], rows[-1]
            conn.execute(
                "UPDATE chat SET message_ciphertext = ?, message_nonce = ? WHERE id = ?",
                (first[1], first[2], second[0]),
            )
        response = self.client.get("/direct?to_user=cipher_bob")
        self.assertEqual(response.status_code, 503)
        body = response.get_data(as_text=True)
        self.assertNotIn(first_text, body)
        self.assertNotIn(second_text, body)
        self.assertNotIn("ciphertext", body.lower())

    def test_one_byte_stored_ciphertext_tamper_returns_generic_failure(self):
        text = "ONE_BYTE_TAMPER_MUST_NOT_RENDER"
        self.assertEqual(self._send(text).status_code, 200)
        with sqlite3.connect(self.db_path) as conn:
            message_id, ciphertext = conn.execute(
                "SELECT id, message_ciphertext FROM chat ORDER BY id DESC LIMIT 1"
            ).fetchone()
            tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
            conn.execute(
                "UPDATE chat SET message_ciphertext = ? WHERE id = ?",
                (tampered, message_id),
            )
        response = self.client.get("/direct?to_user=cipher_bob")
        self.assertEqual(response.status_code, 503)
        body = response.get_data(as_text=True)
        self.assertIn("temporarily unavailable", body)
        self.assertNotIn(text, body)
        self.assertNotIn("InvalidTag", body)

    def test_legacy_migration_preserves_metadata_clears_plaintext_and_is_idempotent(self):
        text = "LEGACY_FICTIONAL_CONTENT"
        timestamp = "2026-09-11 12:34:56"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO chat (id, sender_id, recipient_id, text, timestamp) VALUES (?, ?, ?, ?, ?)",
                (7001, 101, 102, text, timestamp),
            )
        before = self._row("SELECT id, sender_id, recipient_id, text, timestamp FROM chat WHERE id=7001")
        with app.app_context():
            self.assertEqual(encrypt_legacy_messages(self.db_path), 1)
            self.assertEqual(encrypt_legacy_messages(self.db_path), 0)
        after = self._row(
            "SELECT id, sender_id, recipient_id, text, timestamp, message_ciphertext, message_nonce, crypto_version FROM chat WHERE id=7001"
        )
        self.assertEqual(after[:3], before[:3])
        self.assertEqual(after[4], before[4])
        self.assertEqual(after[3], "")
        self.assertEqual(len(after[6]), 12)
        self.assertEqual(after[7], 1)
        self.assertNotIn(text.encode(), after[5])
        self._login(102)
        rendered = self.client.get("/direct?to_user=cipher_alice")
        self.assertEqual(rendered.status_code, 200)
        self.assertIn(text, rendered.get_data(as_text=True))

    def test_migration_cli_requires_key_and_never_prints_content_or_key(self):
        text = "CLI_LEGACY_SECRET_SENTINEL"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO chat (sender_id, recipient_id, text) VALUES (?, ?, ?)",
                (101, 102, text),
            )
        configured_key = self.key
        app.config["MESSAGE_ENCRYPTION_KEY"] = None
        missing = app.test_cli_runner().invoke(args=["encrypt-legacy-messages"])
        self.assertNotEqual(missing.exit_code, 0)
        self.assertEqual(self._row("SELECT text FROM chat ORDER BY id DESC LIMIT 1"), (text,))
        self.assertNotIn(text, missing.output)
        self.assertNotIn(configured_key, missing.output)

        app.config["MESSAGE_ENCRYPTION_KEY"] = configured_key
        first = app.test_cli_runner().invoke(args=["encrypt-legacy-messages"])
        second = app.test_cli_runner().invoke(args=["encrypt-legacy-messages"])
        self.assertEqual(first.exit_code, 0, first.output)
        self.assertIn("Encrypted 1", first.output)
        self.assertIn("Encrypted 0", second.output)
        for output in (first.output, second.output):
            self.assertNotIn(text, output)
            self.assertNotIn(configured_key, output)

    def test_migration_failure_rolls_back_every_legacy_row(self):
        legacy_rows = (
            (7101, 101, 102, "first legacy"),
            (7102, 102, 101, "second legacy"),
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                "INSERT INTO chat (id, sender_id, recipient_id, text) VALUES (?, ?, ?, ?)",
                legacy_rows,
            )
        first_encrypted = encrypt_message("first legacy", 7101, 101, 102, self.key)
        with app.app_context(), mock.patch(
            "common.database.encrypt_message",
            side_effect=[first_encrypted, RuntimeError("controlled failure")],
        ):
            with self.assertRaises(RuntimeError):
                encrypt_legacy_messages(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            after = conn.execute(
                "SELECT id, sender_id, recipient_id, text, message_ciphertext, message_nonce, crypto_version FROM chat ORDER BY id"
            ).fetchall()
        self.assertEqual([row[:4] for row in after], list(legacy_rows))
        self.assertTrue(all(row[4:] == (None, None, None) for row in after))

    def test_legacy_chat_schema_upgrades_additively_without_changing_existing_data(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.db"
        legacy_schema = PRODUCT_SCHEMA.replace(
            "    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,\n"
            "    message_ciphertext BLOB NULL,\n"
            "    message_nonce BLOB NULL,\n"
            "    crypto_version INTEGER NULL,\n",
            "    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,\n",
        )
        with sqlite3.connect(legacy_path) as conn:
            conn.executescript(legacy_schema)
            conn.execute(
                "INSERT INTO users (id, username, password, role, email, bio) VALUES (1, 'legacy', 'hash', 'user', 'legacy@example.test', 'keep')"
            )
            conn.execute("INSERT INTO chat (id, sender_id, recipient_id, text) VALUES (5, 1, 1, 'keep-message')")
        init_db(legacy_path)
        with sqlite3.connect(legacy_path) as conn:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(chat)")]
            row = conn.execute("SELECT id, sender_id, recipient_id, text FROM chat").fetchone()
            bio = conn.execute("SELECT bio FROM users WHERE id=1").fetchone()
        self.assertEqual(columns[-3:], ["message_ciphertext", "message_nonce", "crypto_version"])
        self.assertEqual(row, (5, 1, 1, "keep-message"))
        self.assertEqual(bio, ("keep",))

    def test_csrf_xss_logging_and_privacy_boundaries_remain_intact(self):
        marker = '<script data-p5k="inert">P5K_CONTENT_SENTINEL</script>'
        _, csrf = self._login(101)
        missing = self.client.post("/direct", data={"to_user": "cipher_bob", "message": marker})
        self.assertEqual(missing.status_code, 403)
        sent = self.client.post(
            "/direct",
            data={"to_user": "cipher_bob", "message": marker, "csrf_token": csrf},
        )
        self.assertEqual(sent.status_code, 200)
        body = sent.get_data(as_text=True)
        self.assertIn("&lt;script", body)
        self.assertNotIn('<script data-p5k="inert">', body)
        with app.app_context():
            record_security_event("auth.logout", "success", actor_user_id=101)
        with sqlite3.connect(self.db_path) as conn:
            events = repr(conn.execute("SELECT * FROM security_events").fetchall())
        self.assertNotIn(marker, events)
        self.assertNotIn(self.key, events)


if __name__ == "__main__":
    unittest.main()
