"""File encryption with the SBX-128 envelope (input type "arquivos").

The original file name travels *inside* the sealed payload, so neither the
content nor the name leaks.  Every file gets its own salt and therefore its
own derived keys; any changed byte is rejected by the HMAC before decryption.

Payload layout (before sealing): name_len(2) | name (UTF-8) | content
"""

from pathlib import PurePosixPath, PureWindowsPath

from cryptolab.cipher import CryptoLabIntegrityError, open_sealed, seal
from cryptolab.keys import KeyRing

FILE_SUFFIX = ".sbx"
MAX_NAME_BYTES = 255


def safe_name(filename: str) -> str:
    name = PureWindowsPath(PurePosixPath(filename or "").name).name.strip()
    name = name or "arquivo"
    while len(name.encode("utf-8")) > MAX_NAME_BYTES:
        name = name[:-1]
    return name


def seal_file(ring: KeyRing, filename: str, data: bytes) -> bytes:
    name = safe_name(filename).encode("utf-8")
    return seal(ring, len(name).to_bytes(2, "big") + name + data)


def open_file(ring: KeyRing, blob: bytes) -> tuple:
    payload = open_sealed(ring, blob)
    size = int.from_bytes(payload[:2], "big")
    if len(payload) < 2 + size:
        raise CryptoLabIntegrityError()
    try:
        name = payload[2:2 + size].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CryptoLabIntegrityError() from exc
    return safe_name(name), payload[2 + size:]
