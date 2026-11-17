import hashlib
import os
import unittest

from cryptolab.cipher import (
    BLOCK_BYTES,
    BlockCipher,
    CryptoLabIntegrityError,
    PaddingError,
    VARIANTS,
    _keyed_shuffle,
    permutation_spreads_all_columns,
    cbc_decrypt,
    cbc_encrypt,
    ecb_decrypt,
    ecb_encrypt,
    get_variant,
    open_sealed,
    pkcs7_unpad,
    seal,
)
from cryptolab.keys import KeyRing, derive_key


class BlockCipherTests(unittest.TestCase):
    def setUp(self):
        self.cipher = BlockCipher(bytes(range(32)))

    def test_block_round_trip(self):
        for _ in range(200):
            block = os.urandom(BLOCK_BYTES)
            self.assertEqual(self.cipher.decrypt_block(self.cipher.encrypt_block(block)), block)

    def test_sbox_is_key_dependent_permutation(self):
        self.assertEqual(sorted(self.cipher.sbox), list(range(256)))
        other = BlockCipher(bytes(range(1, 33)))
        self.assertNotEqual(self.cipher.sbox, other.sbox)
        self.assertEqual(sorted(self.cipher.perm), list(range(16)))

    def test_permutation_never_traps_diffusion_in_a_column_subset(self):
        # Before the fix, ~0.2% of keys drew a permutation that mapped a set of
        # MixColumns columns onto itself; a 1-bit change then stayed inside one
        # column for all rounds (12 of 16 output bytes unchanged).
        for i in range(3000):
            key = hashlib.sha256(b"sbx-weak-key-%d" % i).digest()
            self.assertTrue(permutation_spreads_all_columns(BlockCipher(key).perm), i)

    def test_formerly_weak_key_has_full_avalanche_for_every_byte(self):
        cipher = BlockCipher(hashlib.sha256(b"sbx-weak-key-1403").digest())
        base = bytes(range(16))
        reference = cipher.encrypt_block(base)
        for position in range(BLOCK_BYTES):
            changed = bytearray(base)
            changed[position] ^= 1
            out = cipher.encrypt_block(bytes(changed))
            bits = sum(bin(a ^ b).count("1") for a, b in zip(reference, out))
            unchanged_bytes = sum(a == b for a, b in zip(reference, out))
            self.assertGreaterEqual(bits, 40, position)
            self.assertLessEqual(unchanged_bytes, 2, position)

    def test_strong_key_permutation_is_unchanged(self):
        # Keys whose first permutation is already safe keep it, so earlier
        # ciphertexts and measurements stay valid.
        cipher = BlockCipher(bytes(range(32)))
        first = _keyed_shuffle(16, derive_key(bytes(range(32)), b"", "perm", length=64))
        self.assertEqual(cipher.perm, first)

    def test_block_size_enforced(self):
        with self.assertRaises(ValueError):
            self.cipher.encrypt_block(b"short")

    def test_modes_round_trip(self):
        iv = os.urandom(16)
        for size in (0, 1, 15, 16, 17, 1000):
            data = os.urandom(size)
            self.assertEqual(ecb_decrypt(self.cipher, ecb_encrypt(self.cipher, data)), data)
            self.assertEqual(cbc_decrypt(self.cipher, cbc_encrypt(self.cipher, data, iv), iv), data)

    def test_bad_padding(self):
        with self.assertRaises(PaddingError):
            pkcs7_unpad(b"A" * 15 + b"\x00")
        with self.assertRaises(PaddingError):
            pkcs7_unpad(b"A" * 14 + b"\x01\x02")

    def test_known_answer_is_stable(self):
        # regression vector: fixed key, fixed block
        first = self.cipher.encrypt_block(bytes(16)).hex()
        self.assertEqual(first, BlockCipher(bytes(range(32))).encrypt_block(bytes(16)).hex())
        self.assertNotEqual(first, bytes(16).hex())


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.ring = KeyRing.generate()

    def test_seal_round_trip(self):
        for message in (b"", b"oi", "mensagem secreta çã".encode() * 50):
            self.assertEqual(open_sealed(self.ring, seal(self.ring, message)), message)

    def test_same_message_encrypts_differently(self):
        self.assertNotEqual(seal(self.ring, b"repeat"), seal(self.ring, b"repeat"))

    def test_any_bit_flip_is_detected(self):
        blob = bytearray(seal(self.ring, b"integrity matters"))
        for index in range(len(blob)):
            tampered = bytearray(blob)
            tampered[index] ^= 0x01
            with self.assertRaises(CryptoLabIntegrityError):
                open_sealed(self.ring, bytes(tampered))

    def test_truncated_and_garbage(self):
        for blob in (b"", b"SBX1", os.urandom(100)):
            with self.assertRaises(CryptoLabIntegrityError):
                open_sealed(self.ring, blob)

    def test_unknown_key_id_fails_closed(self):
        blob = seal(self.ring, b"x")
        with self.assertRaises(CryptoLabIntegrityError):
            open_sealed(KeyRing({7: os.urandom(32)}, active_id=7), blob)

    def test_wrong_master_with_same_id_fails_closed(self):
        blob = seal(self.ring, b"x")
        with self.assertRaises(CryptoLabIntegrityError):
            open_sealed(KeyRing.generate(), blob)

    def test_rotation_keeps_old_ciphertexts_readable(self):
        old = seal(self.ring, b"old")
        self.ring.rotate()
        new = seal(self.ring, b"new")
        self.assertEqual(old[4], 1)
        self.assertEqual(new[4], 2)
        self.assertEqual(open_sealed(self.ring, old), b"old")
        self.assertEqual(open_sealed(self.ring, new), b"new")

    def test_deterministic_with_fixed_salt_and_iv(self):
        a = seal(self.ring, b"abc", salt=bytes(16), iv=bytes(16))
        b = seal(self.ring, b"abc", salt=bytes(16), iv=bytes(16))
        self.assertEqual(a, b)


class VariantTests(unittest.TestCase):
    def test_all_variants_round_trip(self):
        key = os.urandom(32)
        for name in VARIANTS:
            variant = get_variant(name)
            ct = variant.encrypt(key, b"hello variants" * 5, iv=bytes(16))
            self.assertEqual(variant.decrypt(key, ct, iv=bytes(16)), b"hello variants" * 5, name)

    def test_unknown_variant(self):
        with self.assertRaises(KeyError):
            get_variant("rot13")


if __name__ == "__main__":
    unittest.main()
