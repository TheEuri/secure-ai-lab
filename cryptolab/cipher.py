"""SBX-128: an experimental substitution-permutation block cipher.

This is a teaching cipher written to be attacked and measured, not a
replacement for AES.  The production path of SecureBoard keeps using
AES-256-GCM; ``aes-256-gcm`` is included here as the reference variant.

Structure (block = 16 bytes, default 10 rounds)::

    for r in 1..R:
        state ^= round_key[r-1]        # XOR with key material
        state  = SBOX[state]           # key-dependent substitution (confusion)
        state  = PERM(state)           # key-dependent byte permutation
        if r < R: MixColumns(state)    # GF(2^8) linear mixing (diffusion)
    state ^= round_key[R]              # final whitening

Round keys, S-box and permutation are all derived from the working key with
HKDF, and the working key itself is derived per message from a master key
and a random salt (see ``cryptolab.keys``).  Messages are processed in CBC
mode with PKCS#7 padding and authenticated with HMAC-SHA256
(encrypt-then-MAC).
"""

import hmac
import hashlib
import secrets
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptolab.keys import KeyRing, UnknownKeyError, derive_key

BLOCK_BYTES = 16
ROUNDS = 10
MAGIC = b"SBX1"
SALT_BYTES = 16
IV_BYTES = 16
TAG_BYTES = 32
HEADER_BYTES = len(MAGIC) + 1 + SALT_BYTES + IV_BYTES


class CryptoLabIntegrityError(Exception):
    """Ciphertext could not be authenticated; nothing is returned."""

    def __init__(self):
        super().__init__("ciphertext failed authentication")


class PaddingError(ValueError):
    pass


# --- GF(2^8) arithmetic (AES polynomial x^8+x^4+x^3+x+1) -------------------

def _gmul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else (a << 1)
        b >>= 1
    return result


_MUL = {n: bytes(_gmul(x, n) for x in range(256)) for n in (2, 3, 9, 11, 13, 14)}


def _mix_columns(s: list) -> None:
    m2, m3 = _MUL[2], _MUL[3]
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
        s[c] = m2[a0] ^ m3[a1] ^ a2 ^ a3
        s[c + 1] = a0 ^ m2[a1] ^ m3[a2] ^ a3
        s[c + 2] = a0 ^ a1 ^ m2[a2] ^ m3[a3]
        s[c + 3] = m3[a0] ^ a1 ^ a2 ^ m2[a3]


def _inv_mix_columns(s: list) -> None:
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
        s[c] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
        s[c + 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
        s[c + 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
        s[c + 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]


def _keyed_shuffle(n: int, stream: bytes) -> list:
    """Fisher-Yates shuffle of range(n) driven by a key-derived byte stream.

    Uses 16-bit draws with rejection sampling so every permutation is
    (statistically) equally likely.
    """

    items = list(range(n))
    pos = 0
    for i in range(n - 1, 0, -1):
        bound = i + 1
        limit = 65536 - (65536 % bound)
        while True:
            if pos + 2 > len(stream):
                raise RuntimeError("key stream exhausted")
            draw = int.from_bytes(stream[pos:pos + 2], "big")
            pos += 2
            if draw < limit:
                break
        j = draw % bound
        items[i], items[j] = items[j], items[i]
    return items


class BlockCipher:
    """SBX-128 block primitive bound to one 256-bit working key."""

    def __init__(self, key: bytes, rounds: int = ROUNDS):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("SBX working key must have 32 bytes")
        if not 1 <= rounds <= 32:
            raise ValueError("rounds must be in 1..32")
        self.rounds = rounds
        material = derive_key(key, b"", "round", length=BLOCK_BYTES * (rounds + 1))
        self.round_keys = [
            material[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES] for i in range(rounds + 1)
        ]
        self.sbox = _keyed_shuffle(256, derive_key(key, b"", "sbox", length=2048))
        self.inv_sbox = [0] * 256
        for i, v in enumerate(self.sbox):
            self.inv_sbox[v] = i
        self.perm = _keyed_shuffle(16, derive_key(key, b"", "perm", length=64))
        self.inv_perm = [0] * 16
        for i, v in enumerate(self.perm):
            self.inv_perm[v] = i

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_BYTES:
            raise ValueError("block must have 16 bytes")
        s = list(block)
        sbox, perm, last = self.sbox, self.perm, self.rounds
        for r in range(1, last + 1):
            rk = self.round_keys[r - 1]
            s = [sbox[s[i] ^ rk[i]] for i in range(16)]
            s = [s[perm[i]] for i in range(16)]
            if r < last:
                _mix_columns(s)
        rk = self.round_keys[last]
        return bytes(s[i] ^ rk[i] for i in range(16))

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_BYTES:
            raise ValueError("block must have 16 bytes")
        rk = self.round_keys[self.rounds]
        s = [block[i] ^ rk[i] for i in range(16)]
        inv_sbox, inv_perm = self.inv_sbox, self.inv_perm
        for r in range(self.rounds, 0, -1):
            if r < self.rounds:
                _inv_mix_columns(s)
            s = [s[inv_perm[i]] for i in range(16)]
            rk = self.round_keys[r - 1]
            s = [inv_sbox[s[i]] ^ rk[i] for i in range(16)]
        return bytes(s)


# --- padding and modes -----------------------------------------------------

def pkcs7_pad(data: bytes) -> bytes:
    n = BLOCK_BYTES - len(data) % BLOCK_BYTES
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_BYTES:
        raise PaddingError("invalid padded length")
    n = data[-1]
    if not 1 <= n <= BLOCK_BYTES or data[-n:] != bytes([n]) * n:
        raise PaddingError("invalid padding")
    return data[:-n]


def ecb_encrypt(cipher: BlockCipher, data: bytes) -> bytes:
    padded = pkcs7_pad(data)
    return b"".join(cipher.encrypt_block(padded[i:i + 16]) for i in range(0, len(padded), 16))


def ecb_decrypt(cipher: BlockCipher, data: bytes) -> bytes:
    if len(data) % BLOCK_BYTES:
        raise PaddingError("invalid ciphertext length")
    return pkcs7_unpad(b"".join(cipher.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16)))


def cbc_encrypt(cipher: BlockCipher, data: bytes, iv: bytes) -> bytes:
    if len(iv) != IV_BYTES:
        raise ValueError("IV must have 16 bytes")
    padded = pkcs7_pad(data)
    out, prev = [], iv
    for i in range(0, len(padded), 16):
        prev = cipher.encrypt_block(bytes(a ^ b for a, b in zip(padded[i:i + 16], prev)))
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(cipher: BlockCipher, data: bytes, iv: bytes) -> bytes:
    if len(iv) != IV_BYTES or not data or len(data) % BLOCK_BYTES:
        raise PaddingError("invalid ciphertext length")
    out, prev = [], iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out.append(bytes(a ^ b for a, b in zip(cipher.decrypt_block(block), prev)))
        prev = block
    return pkcs7_unpad(b"".join(out))


# --- authenticated envelope ------------------------------------------------

def seal(ring: KeyRing, plaintext: bytes, *, salt: bytes = None, iv: bytes = None) -> bytes:
    """Encrypt-then-MAC with per-message keys derived from the active master.

    Layout: MAGIC(4) | key_id(1) | salt(16) | iv(16) | ciphertext | tag(32)
    """

    salt = secrets.token_bytes(SALT_BYTES) if salt is None else salt
    iv = secrets.token_bytes(IV_BYTES) if iv is None else iv
    if len(salt) != SALT_BYTES or len(iv) != IV_BYTES:
        raise ValueError("salt and IV must have 16 bytes")
    key_id = ring.active_id
    master = ring.master(key_id)
    k_enc = derive_key(master, salt, "enc")
    k_mac = derive_key(master, salt, "mac")
    body = MAGIC + bytes([key_id]) + salt + iv + cbc_encrypt(BlockCipher(k_enc), plaintext, iv)
    return body + hmac.new(k_mac, body, hashlib.sha256).digest()


def open_sealed(ring: KeyRing, blob: bytes) -> bytes:
    """Verify the tag in constant time, then decrypt; fail closed."""

    try:
        if (
            not isinstance(blob, bytes)
            or len(blob) < HEADER_BYTES + BLOCK_BYTES + TAG_BYTES
            or blob[:4] != MAGIC
        ):
            raise CryptoLabIntegrityError()
        key_id = blob[4]
        salt = blob[5:5 + SALT_BYTES]
        iv = blob[5 + SALT_BYTES:HEADER_BYTES]
        body, tag = blob[:-TAG_BYTES], blob[-TAG_BYTES:]
        master = ring.master(key_id)
        expected = hmac.new(derive_key(master, salt, "mac"), body, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, tag):
            raise CryptoLabIntegrityError()
        return cbc_decrypt(BlockCipher(derive_key(master, salt, "enc")), body[HEADER_BYTES:], iv)
    except CryptoLabIntegrityError:
        raise
    except (UnknownKeyError, PaddingError, ValueError) as exc:
        raise CryptoLabIntegrityError() from exc


# --- variants used by the attack laboratory --------------------------------

@dataclass(frozen=True)
class Variant:
    name: str
    description: str
    key_bits: int
    encrypt: Callable
    decrypt: Callable


def _xor_repeating(key, data, iv=None):
    k = key[:4]
    return bytes(b ^ k[i % 4] for i, b in enumerate(data))


def _sbx_ecb(rounds):
    def enc(key, data, iv=None):
        return ecb_encrypt(BlockCipher(key, rounds), data)

    def dec(key, data, iv=None):
        return ecb_decrypt(BlockCipher(key, rounds), data)

    return enc, dec


def _sbx_full_encrypt(key, data, iv=None):
    """Full SBX system; returns ciphertext||tag (header is public metadata)."""

    ring = KeyRing({1: key}, active_id=1)
    nonce = iv if iv is not None else secrets.token_bytes(IV_BYTES)
    blob = seal(ring, data, salt=nonce, iv=nonce)
    return nonce + blob[HEADER_BYTES:] if iv is None else blob[HEADER_BYTES:]


def _sbx_full_decrypt(key, data, iv=None):
    ring = KeyRing({1: key}, active_id=1)
    if iv is None:
        iv, data = data[:IV_BYTES], data[IV_BYTES:]
    return open_sealed(ring, MAGIC + b"\x01" + iv + iv + data)


def _aes_encrypt(key, data, iv=None):
    nonce = iv[:12] if iv is not None else secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return ct if iv is not None else nonce + ct


def _aes_decrypt(key, data, iv=None):
    if iv is None:
        iv, data = data[:12], data[12:]
    try:
        return AESGCM(key).decrypt(iv[:12], data, None)
    except InvalidTag as exc:
        raise CryptoLabIntegrityError() from exc


_e1, _d1 = _sbx_ecb(1)
_e10, _d10 = _sbx_ecb(ROUNDS)

VARIANTS = {
    "xor-repeating": Variant(
        "xor-repeating", "XOR com chave de 4 bytes repetida (didática)", 32,
        _xor_repeating, _xor_repeating),
    "sbx-1r-ecb": Variant(
        "sbx-1r-ecb", "SBX com 1 rodada em modo ECB (enfraquecida)", 256, _e1, _d1),
    "sbx-10r-ecb": Variant(
        "sbx-10r-ecb", "SBX com 10 rodadas em modo ECB", 256, _e10, _d10),
    "sbx-10r-cbc": Variant(
        "sbx-10r-cbc", "SBX completa: chave dinâmica, CBC e HMAC-SHA256", 256,
        _sbx_full_encrypt, _sbx_full_decrypt),
    "aes-256-gcm": Variant(
        "aes-256-gcm", "AES-256-GCM (referência de mercado)", 256, _aes_encrypt, _aes_decrypt),
}


def get_variant(name: str) -> Variant:
    return VARIANTS[name]
