import os
import unittest

from cryptolab.cipher import CryptoLabIntegrityError
from cryptolab.files import FILE_SUFFIX, open_file, seal_file
from cryptolab.keys import KeyRing


class FileEncryptionTests(unittest.TestCase):
    def test_round_trip_keeps_name_and_bytes(self):
        ring = KeyRing.generate()
        data = os.urandom(5000)
        blob = seal_file(ring, "relatório.pdf", data)
        self.assertEqual(open_file(ring, blob), ("relatório.pdf", data))
        self.assertEqual(FILE_SUFFIX, ".sbx")

    def test_ciphertext_hides_content_and_name(self):
        ring = KeyRing.generate()
        blob = seal_file(ring, "senhas.txt", b"conteudo secreto " * 20)
        self.assertNotIn(b"senhas", blob)
        self.assertNotIn(b"conteudo secreto", blob)

    def test_same_file_twice_gives_different_ciphertexts(self):
        ring = KeyRing.generate()
        self.assertNotEqual(seal_file(ring, "a.txt", b"x"), seal_file(ring, "a.txt", b"x"))

    def test_path_components_are_stripped(self):
        ring = KeyRing.generate()
        name, _ = open_file(ring, seal_file(ring, "../../etc/passwd", b"x"))
        self.assertEqual(name, "passwd")

    def test_any_flipped_byte_is_rejected(self):
        ring = KeyRing.generate()
        blob = bytearray(seal_file(ring, "a.bin", os.urandom(100)))
        blob[len(blob) // 2] ^= 1
        with self.assertRaises(CryptoLabIntegrityError):
            open_file(ring, bytes(blob))

    def test_other_master_key_cannot_open(self):
        blob = seal_file(KeyRing.generate(), "a.bin", b"data")
        with self.assertRaises(CryptoLabIntegrityError):
            open_file(KeyRing.generate(), blob)


if __name__ == "__main__":
    unittest.main()
