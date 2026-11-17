import io
import os
import unittest

from PIL import Image

from cryptolab.cipher import CryptoLabIntegrityError
from cryptolab.keys import KeyRing
from cryptolab.stego import (
    NoPayloadError,
    PayloadTooLargeError,
    capacity_bytes,
    embed,
    extract,
    hide_secret,
    flip_payload_bit,
    lsb_chi_square,
    read_salt,
    stego_key_for,
    psnr,
    reveal_secret,
)


def cover(size=(64, 64)):
    # smooth gradient: realistic cover with structure in its LSBs
    img = Image.new("RGB", size)
    img.putdata([((x * 4) % 256, (y * 4) % 256, ((x + y) * 2) % 256)
                 for y in range(size[1]) for x in range(size[0])])
    return img


class StegoTests(unittest.TestCase):
    def test_capacity(self):
        self.assertEqual(capacity_bytes(cover((10, 10))), (10 * 10 * 3) // 8 - 8)

    def test_round_trip_sequential_and_keyed(self):
        payload = os.urandom(200)
        self.assertEqual(extract(embed(cover(), payload, stego_key=None), stego_key=None), payload)
        key = os.urandom(32)
        self.assertEqual(extract(embed(cover(), payload, stego_key=key), stego_key=key), payload)

    def test_payload_too_large(self):
        with self.assertRaises(PayloadTooLargeError):
            embed(cover((8, 8)), os.urandom(100), stego_key=None)

    def test_clean_image_has_no_payload(self):
        with self.assertRaises(NoPayloadError):
            extract(cover(), stego_key=None)

    def test_wrong_stego_key(self):
        stego = embed(cover(), b"hidden", stego_key=os.urandom(32))
        with self.assertRaises(NoPayloadError):
            extract(stego, stego_key=os.urandom(32))

    def test_psnr_high_for_small_payload(self):
        original = cover()
        self.assertGreater(psnr(original, embed(original, os.urandom(64), stego_key=None)), 50)
        self.assertEqual(psnr(original, original.copy()), float("inf"))

    def test_hide_and_reveal_secret_through_png(self):
        ring = KeyRing.generate()
        stego = hide_secret(ring, cover(), "segredo de laboratório".encode())
        buf = io.BytesIO()
        stego.save(buf, format="PNG")
        buf.seek(0)
        self.assertEqual(reveal_secret(ring, Image.open(buf)), "segredo de laboratório".encode())

    def test_tampered_stego_fails_closed(self):
        ring = KeyRing.generate()
        stego = hide_secret(ring, cover(), b"x" * 100)
        pixels = stego.load()
        failures = 0
        for x in range(stego.width):
            tampered = stego.copy()
            p = tampered.load()
            r, g, b = pixels[x, 3]
            p[x, 3] = (r ^ 1, g ^ 1, b ^ 1)
            try:
                if reveal_secret(ring, tampered) != b"x" * 100:
                    self.fail("tampering produced wrong plaintext")
            except (CryptoLabIntegrityError, NoPayloadError):
                failures += 1
        self.assertGreater(failures, 0)

    def test_flipping_any_payload_bit_is_detected(self):
        ring = KeyRing.generate()
        stego = hide_secret(ring, cover((128, 128)), b"y" * 50)
        for bit in (70, 200, 500):
            tampered = flip_payload_bit(stego, stego_key_for(ring, stego), bit)
            with self.assertRaises((CryptoLabIntegrityError, NoPayloadError)):
                reveal_secret(ring, tampered)

    def test_each_image_gets_its_own_stego_key(self):
        """Feedback P1: no single symmetric key shared by every operation."""
        ring = KeyRing.generate()
        a = hide_secret(ring, cover(), b"mesmo segredo")
        b = hide_secret(ring, cover(), b"mesmo segredo")
        self.assertNotEqual(read_salt(a), read_salt(b))
        self.assertNotEqual(stego_key_for(ring, a), stego_key_for(ring, b))
        with self.assertRaises(NoPayloadError):
            extract(b, stego_key=stego_key_for(ring, a), reserved=128)

    def test_tampered_salt_fails_closed(self):
        ring = KeyRing.generate()
        stego = hide_secret(ring, cover(), b"segredo")
        p = stego.load()
        r, g, bl = p[0, 0]
        p[0, 0] = (r ^ 1, g, bl)
        with self.assertRaises((NoPayloadError, CryptoLabIntegrityError)):
            reveal_secret(ring, stego)

    def test_reveal_after_key_rotation(self):
        ring = KeyRing.generate()
        stego = hide_secret(ring, cover(), b"antigo")
        ring.rotate()
        self.assertEqual(reveal_secret(ring, stego), b"antigo")

    def test_non_rgb_input_is_normalised(self):
        ring = KeyRing.generate()
        stego = hide_secret(ring, cover().convert("RGBA"), b"rgba")
        self.assertEqual(reveal_secret(ring, stego), b"rgba")

    def test_chi_square_detects_full_sequential_embedding(self):
        original = cover((128, 128))
        full = embed(original, os.urandom(capacity_bytes(original)), stego_key=None)
        self.assertLess(lsb_chi_square(original, 0.5), 0.05)
        self.assertGreater(lsb_chi_square(full, 0.5), 0.5)


if __name__ == "__main__":
    unittest.main()
