"""Key management for CryptoLab.

A master key never encrypts data directly.  Every operation derives a
short-lived working key with HKDF-SHA256 from ``(master key, random salt,
purpose)``.  Consequences:

* the effective key changes on every message (dynamic keys);
* encryption and authentication use different keys (domain separation);
* a ``key_id`` travels with each ciphertext, so master keys can be rotated
  while old ciphertexts stay readable.
"""

import base64
import binascii
import re
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MASTER_KEY_BYTES = 32
INFO_PREFIX = b"cryptolab:v1:"
PURPOSES = frozenset({"enc", "mac", "round", "sbox", "perm", "stego"})
_B64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


class UnknownKeyError(KeyError):
    """Raised when a ciphertext references a key id that is not in the ring."""


def derive_key(master: bytes, salt: bytes, purpose: str, length: int = 32) -> bytes:
    """HKDF-SHA256 derivation bound to one purpose."""

    if purpose not in PURPOSES:
        raise ValueError("unknown key purpose")
    if not isinstance(master, bytes) or len(master) < 16:
        raise ValueError("master key too short")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt or None,
        info=INFO_PREFIX + purpose.encode("ascii"),
    ).derive(master)


def _decode_b64url(value: str) -> bytes:
    if not _B64URL.fullmatch(value):
        raise ValueError("invalid key encoding")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid key encoding") from exc


class KeyRing:
    """Set of versioned master keys with one active key for new data."""

    def __init__(self, keys: dict, active_id: int):
        if not keys:
            raise ValueError("key ring is empty")
        for key_id, key in keys.items():
            if not isinstance(key_id, int) or not 0 < key_id < 256:
                raise ValueError("key id must be an integer in 1..255")
            if not isinstance(key, bytes) or len(key) != MASTER_KEY_BYTES:
                raise ValueError("master keys must have exactly 32 bytes")
        if active_id not in keys:
            raise ValueError("active key id is not in the ring")
        self._keys = dict(keys)
        self.active_id = active_id

    @classmethod
    def generate(cls) -> "KeyRing":
        return cls({1: secrets.token_bytes(MASTER_KEY_BYTES)}, active_id=1)

    @classmethod
    def from_env(cls, value: str) -> "KeyRing":
        """Parse ``"1:<b64url>,2:<b64url>"``; the highest id is active."""

        if not isinstance(value, str) or not value.strip():
            raise ValueError("empty key ring")
        keys = {}
        for item in value.split(","):
            key_id, sep, encoded = item.strip().partition(":")
            if not sep or not key_id.isdigit():
                raise ValueError("invalid key ring entry")
            keys[int(key_id)] = _decode_b64url(encoded)
        return cls(keys, active_id=max(keys))

    def to_env(self) -> str:
        return ",".join(
            f"{key_id}:{base64.urlsafe_b64encode(key).decode().rstrip('=')}"
            for key_id, key in sorted(self._keys.items())
        )

    def master(self, key_id: int) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise UnknownKeyError(key_id) from None

    @property
    def key_ids(self):
        return sorted(self._keys)

    def rotate(self) -> int:
        """Add a fresh master key and make it active; old keys remain for reads."""

        new_id = max(self._keys) + 1
        if new_id > 255:
            raise ValueError("key id space exhausted")
        self._keys[new_id] = secrets.token_bytes(MASTER_KEY_BYTES)
        self.active_id = new_id
        return new_id

    def __repr__(self):  # never print key material
        return f"KeyRing(key_ids={self.key_ids}, active_id={self.active_id})"
