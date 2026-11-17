import base64
import secrets
import unittest

from cryptolab.keys import KeyRing, UnknownKeyError, derive_key


def b64(key):
    return base64.urlsafe_b64encode(key).decode().rstrip("=")


class KeyRingTests(unittest.TestCase):
    def test_master_keys_must_be_32_bytes(self):
        for size in (31, 33):
            with self.assertRaises(ValueError):
                KeyRing({1: b"x" * size}, active_id=1)

    def test_derive_key_is_deterministic(self):
        master = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        self.assertEqual(derive_key(master, salt, "enc"), derive_key(master, salt, "enc"))
        self.assertEqual(len(derive_key(master, salt, "enc")), 32)

    def test_derive_key_changes_with_salt_and_purpose(self):
        master = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        enc = derive_key(master, salt, "enc")
        self.assertNotEqual(enc, derive_key(master, secrets.token_bytes(16), "enc"))
        self.assertNotEqual(enc, derive_key(master, salt, "mac"))

    def test_unknown_purpose_is_rejected(self):
        with self.assertRaises(ValueError):
            derive_key(secrets.token_bytes(32), b"", "anything")

    def test_rotate_keeps_old_key_and_activates_new(self):
        ring = KeyRing.generate()
        old_id = ring.active_id
        old_key = ring.master(old_id)
        new_id = ring.rotate()
        self.assertEqual(new_id, old_id + 1)
        self.assertEqual(ring.active_id, new_id)
        self.assertEqual(ring.master(old_id), old_key)
        self.assertNotEqual(ring.master(new_id), old_key)

    def test_unknown_key_id(self):
        with self.assertRaises(UnknownKeyError):
            KeyRing.generate().master(99)

    def test_from_env_round_trip(self):
        k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
        ring = KeyRing.from_env(f"1:{b64(k1)},2:{b64(k2)}")
        self.assertEqual(ring.active_id, 2)
        self.assertEqual(ring.master(1), k1)
        self.assertEqual(KeyRing.from_env(ring.to_env()).master(2), k2)

    def test_from_env_rejects_garbage(self):
        for value in ("", "abc", "1:short", "x:" + b64(secrets.token_bytes(32))):
            with self.assertRaises(ValueError):
                KeyRing.from_env(value)


if __name__ == "__main__":
    unittest.main()
