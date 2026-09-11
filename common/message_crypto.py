"""Authenticated encryption for private-message content at rest."""

import base64
import binascii
import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app, has_app_context


MESSAGE_ENCRYPTION_KEY_CONFIG = "MESSAGE_ENCRYPTION_KEY"
MESSAGE_CRYPTO_VERSION = 1
MESSAGE_NONCE_BYTES = 12
MESSAGE_AAD_PREFIX = b"secureboard:message:v1:"

_KEY_UNSET = object()
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_BASE64URL_UNPADDED_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class MessageCryptoConfigurationError(RuntimeError):
    """Raised when the dedicated AES-256 key is unavailable or invalid."""

    def __init__(self):
        super().__init__("Private-message encryption is not configured.")


class MessageDecryptionError(RuntimeError):
    """Raised when encrypted message content cannot be authenticated safely."""

    def __init__(self):
        super().__init__("Private-message content could not be authenticated.")


def _configuration_error():
    return MessageCryptoConfigurationError()


def _decode_key(value):
    """Strictly decode exactly 256 bits of padded or unpadded Base64URL."""

    if not isinstance(value, str) or not value:
        raise _configuration_error()
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise _configuration_error() from exc

    if "=" in value:
        if not _BASE64URL_RE.fullmatch(value) or len(value) % 4:
            raise _configuration_error()
        unpadded = value.rstrip("=")
        padding = value[len(unpadded) :]
        if not unpadded or len(padding) > 2:
            raise _configuration_error()
        padded = value
    else:
        if not _BASE64URL_UNPADDED_RE.fullmatch(value) or len(value) % 4 == 1:
            raise _configuration_error()
        unpadded = value
        padded = value + ("=" * ((4 - len(value) % 4) % 4))

    try:
        decoded = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _configuration_error() from exc

    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != unpadded or len(decoded) != 32:
        raise _configuration_error()
    return decoded


def load_message_encryption_key(value=_KEY_UNSET):
    """Load the independent external AES-256 key without a fallback."""

    if value is _KEY_UNSET:
        if not has_app_context():
            raise _configuration_error()
        value = current_app.config.get(MESSAGE_ENCRYPTION_KEY_CONFIG)
    return _decode_key(value)


def _positive_id(value, field_name):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def message_aad(message_id, sender_id, recipient_id):
    """Return the canonical domain-separated message-record AAD."""

    values = (
        _positive_id(message_id, "message_id"),
        _positive_id(sender_id, "sender_id"),
        _positive_id(recipient_id, "recipient_id"),
    )
    return MESSAGE_AAD_PREFIX + ":".join(str(value) for value in values).encode("ascii")


def encrypt_message(text, message_id, sender_id, recipient_id, key=_KEY_UNSET):
    """Encrypt one UTF-8 message with a fresh conventional GCM nonce."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    key_bytes = load_message_encryption_key(key)
    nonce = secrets.token_bytes(MESSAGE_NONCE_BYTES)
    ciphertext = AESGCM(key_bytes).encrypt(
        nonce,
        text.encode("utf-8"),
        message_aad(message_id, sender_id, recipient_id),
    )
    return ciphertext, nonce, MESSAGE_CRYPTO_VERSION


def decrypt_message(
    ciphertext,
    nonce,
    crypto_version,
    message_id,
    sender_id,
    recipient_id,
    key=_KEY_UNSET,
):
    """Authenticate and decrypt one encrypted message, failing closed."""

    try:
        if crypto_version != MESSAGE_CRYPTO_VERSION:
            raise MessageDecryptionError()
        if not isinstance(ciphertext, bytes) or not ciphertext:
            raise MessageDecryptionError()
        if not isinstance(nonce, bytes) or len(nonce) != MESSAGE_NONCE_BYTES:
            raise MessageDecryptionError()
        plaintext = AESGCM(load_message_encryption_key(key)).decrypt(
            nonce,
            ciphertext,
            message_aad(message_id, sender_id, recipient_id),
        )
        return plaintext.decode("utf-8")
    except MessageCryptoConfigurationError:
        raise
    except (InvalidTag, UnicodeDecodeError, ValueError, TypeError) as exc:
        raise MessageDecryptionError() from exc


__all__ = [
    "MESSAGE_AAD_PREFIX",
    "MESSAGE_CRYPTO_VERSION",
    "MESSAGE_ENCRYPTION_KEY_CONFIG",
    "MESSAGE_NONCE_BYTES",
    "MessageCryptoConfigurationError",
    "MessageDecryptionError",
    "decrypt_message",
    "encrypt_message",
    "load_message_encryption_key",
    "message_aad",
]
