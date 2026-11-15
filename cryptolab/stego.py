"""LSB steganography carrying SBX-sealed payloads inside PNG images.

Steganography hides *that* a message exists; it does not protect *what* the
message says.  Therefore the payload is always sealed (encrypted and
authenticated) before it is embedded, and the order of the modified bits is
a secret permutation derived from the key.  Without the key an analyst can
neither locate the bits nor read them, and any change to the carrier makes
the HMAC check fail.

Each image gets its own order key: a random public salt is written in the
first ``SALT_SLOTS`` LSBs and the order key is HKDF(master, salt, "stego").
Two images never share the same bit positions, even with the same master.
"""

import hashlib
import math
import secrets

import numpy as np
from PIL import Image
from scipy.stats import chi2

from cryptolab.cipher import open_sealed, seal
from cryptolab.keys import KeyRing, derive_key

STEGO_MAGIC = b"STG1"
HEADER_BYTES = 8  # magic(4) + payload length(4)
SALT_BYTES = 16
SALT_SLOTS = SALT_BYTES * 8  # first LSBs hold the public per-image salt


class PayloadTooLargeError(ValueError):
    pass


class NoPayloadError(ValueError):
    pass


def _rgb_array(image: Image.Image) -> np.ndarray:
    return np.array(image.convert("RGB"), dtype=np.uint8)


def capacity_bytes(image: Image.Image, reserved: int = 0) -> int:
    width, height = image.size
    return max(0, (width * height * 3 - reserved) // 8 - HEADER_BYTES)


def _slot_order(n_slots: int, stego_key, reserved: int = 0) -> np.ndarray:
    if stego_key is None:
        return np.arange(reserved, n_slots)
    seed = int.from_bytes(hashlib.sha256(b"cryptolab:stego-order:" + stego_key).digest(), "big")
    return reserved + np.random.default_rng(seed).permutation(max(0, n_slots - reserved))


def embed(cover: Image.Image, payload: bytes, *, stego_key, reserved: int = 0) -> Image.Image:
    pixels = _rgb_array(cover)
    flat = pixels.reshape(-1).copy()
    capacity = capacity_bytes(cover, reserved)
    if len(payload) > capacity:
        raise PayloadTooLargeError(
            f"payload has {len(payload)} bytes; image carries at most {capacity}"
        )
    data = STEGO_MAGIC + len(payload).to_bytes(4, "big") + payload
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    slots = _slot_order(flat.size, stego_key, reserved)[: bits.size]
    flat[slots] = (flat[slots] & 0xFE) | bits
    return Image.fromarray(flat.reshape(pixels.shape), "RGB")


def extract(image: Image.Image, *, stego_key, reserved: int = 0) -> bytes:
    flat = _rgb_array(image).reshape(-1)
    if flat.size < reserved + HEADER_BYTES * 8:
        raise NoPayloadError("image too small")
    order = _slot_order(flat.size, stego_key, reserved)
    header = np.packbits(flat[order[: HEADER_BYTES * 8]] & 1).tobytes()
    if header[:4] != STEGO_MAGIC:
        raise NoPayloadError("no payload found")
    length = int.from_bytes(header[4:8], "big")
    if length > capacity_bytes(image, reserved):
        raise NoPayloadError("corrupted payload header")
    start = HEADER_BYTES * 8
    return np.packbits(flat[order[start:start + length * 8]] & 1).tobytes()


def _write_salt(image: Image.Image, salt: bytes) -> Image.Image:
    pixels = _rgb_array(image)
    flat = pixels.reshape(-1).copy()
    bits = np.unpackbits(np.frombuffer(salt, dtype=np.uint8))
    flat[:SALT_SLOTS] = (flat[:SALT_SLOTS] & 0xFE) | bits
    return Image.fromarray(flat.reshape(pixels.shape), "RGB")


def read_salt(image: Image.Image) -> bytes:
    """Public per-image salt stored in the first ``SALT_SLOTS`` LSBs."""

    flat = _rgb_array(image).reshape(-1)
    if flat.size < SALT_SLOTS:
        raise NoPayloadError("image too small")
    return np.packbits(flat[:SALT_SLOTS] & 1).tobytes()


def flip_payload_bit(image: Image.Image, stego_key, bit_index: int,
                     reserved: int = SALT_SLOTS) -> Image.Image:
    """Return a copy with the carrier LSB of the given embedded bit inverted.

    Used to simulate a targeted forgery on an image produced by
    ``hide_secret``: the attacker changes a bit that really carries the
    hidden message (header bits are 0..63).
    """

    pixels = _rgb_array(image)
    flat = pixels.reshape(-1).copy()
    slot = _slot_order(flat.size, stego_key, reserved)[bit_index]
    flat[slot] ^= 1
    return Image.fromarray(flat.reshape(pixels.shape), "RGB")


def psnr(a: Image.Image, b: Image.Image) -> float:
    x, y = _rgb_array(a).astype(np.float64), _rgb_array(b).astype(np.float64)
    mse = float(np.mean((x - y) ** 2))
    return float("inf") if mse == 0 else 10 * math.log10(255 ** 2 / mse)


def lsb_chi_square(image: Image.Image, fraction: float = 1.0) -> float:
    """Westfeld-Pfitzmann pairs-of-values test.

    Returns the probability that the analysed portion carries embedded
    random bits (high value = suspicious, close to 0 = natural image).
    """

    flat = _rgb_array(image).reshape(-1)
    sample = flat[: max(2, int(flat.size * fraction))]
    hist = np.bincount(sample, minlength=256).astype(np.float64)
    even, odd = hist[0::2], hist[1::2]
    expected = (even + odd) / 2
    mask = expected > 4
    if mask.sum() < 2:
        return 0.0
    stat = float(np.sum((even[mask] - expected[mask]) ** 2 / expected[mask]))
    return float(1 - chi2.cdf(stat, int(mask.sum()) - 1))


def stego_key_for(ring: KeyRing, image: Image.Image, key_id: int = None) -> bytes:
    """Order key of one image: HKDF(master, per-image salt, "stego")."""

    master = ring.master(ring.active_id if key_id is None else key_id)
    return derive_key(master, read_salt(image), "stego")


def hide_secret(ring: KeyRing, cover: Image.Image, plaintext: bytes) -> Image.Image:
    salt = secrets.token_bytes(SALT_BYTES)
    key = derive_key(ring.master(ring.active_id), salt, "stego")
    carrier = embed(cover, seal(ring, plaintext), stego_key=key, reserved=SALT_SLOTS)
    return _write_salt(carrier, salt)


def reveal_secret(ring: KeyRing, image: Image.Image) -> bytes:
    """Try the active and older master keys (supports key rotation)."""

    last_error = NoPayloadError("no payload found")
    for key_id in reversed(ring.key_ids):
        key = stego_key_for(ring, image, key_id)
        try:
            blob = extract(image, stego_key=key, reserved=SALT_SLOTS)
        except NoPayloadError as exc:
            last_error = exc
            continue
        return open_sealed(ring, blob)
    raise last_error
