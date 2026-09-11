"""Privacy-preserving views over the existing security-event metadata.

The operational audit table deliberately keeps server-side identifiers for
authorization and incident response.  This module is the presentation
boundary for the smaller administrator analysis view: it validates a
configured Base64URL key, derives domain-separated HMAC pseudonyms, and
returns only the fields that analysis needs.
"""

import base64
import binascii
import hashlib
import hmac
from itertools import islice
import re
from collections.abc import Mapping

from flask import current_app, has_app_context

from common.security_audit import MAX_RECENT_EVENTS, get_recent_security_events


PSEUDONYMIZATION_KEY_CONFIG = "PSEUDONYMIZATION_KEY"
PSEUDONYMIZATION_MESSAGE_PREFIX = b"secureboard:user:v1:"
PRIVACY_ANALYSIS_FIELDS = (
    "created_at",
    "event_type",
    "outcome",
    "actor_pseudonym",
    "target_type",
)

_KEY_UNSET = object()
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_BASE64URL_UNPADDED_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class PrivacyConfigurationError(RuntimeError):
    """Raised when pseudonymization cannot safely be configured.

    The message is intentionally generic.  In particular, it never includes
    the configured value, decoded key bytes, or any derived secret.
    """

    def __init__(self):
        super().__init__(
            "Privacy analysis is unavailable because pseudonymization is not configured."
        )


def _invalid_key():
    """Create the one safe configuration exception used by this module."""

    return PrivacyConfigurationError()


def _decode_pseudonymization_key(value):
    """Strictly decode a padded or unpadded Base64URL key.

    Base64URL is accepted only as ASCII text with optional trailing padding.
    Canonical re-encoding also rejects non-zero padding bits that permissive
    decoders otherwise accept.  The key is required to provide at least 256
    bits of HMAC key material.
    """

    if not isinstance(value, str) or not value:
        raise _invalid_key()
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise _invalid_key() from exc

    has_padding = "=" in value
    if has_padding:
        if not _BASE64URL_RE.fullmatch(value) or len(value) % 4:
            raise _invalid_key()
        unpadded = value.rstrip("=")
        padding = value[len(unpadded) :]
        if len(padding) > 2 or not unpadded:
            raise _invalid_key()
        padded_value = value
    else:
        if not _BASE64URL_UNPADDED_RE.fullmatch(value) or len(value) % 4 == 1:
            raise _invalid_key()
        unpadded = value
        padded_value = value + ("=" * ((4 - len(value) % 4) % 4))

    try:
        decoded = base64.b64decode(
            padded_value.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise _invalid_key() from exc

    canonical_unpadded = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical_unpadded != unpadded or len(decoded) < 32:
        raise _invalid_key()
    return decoded


def _configured_key(value=_KEY_UNSET):
    """Resolve and validate the configured key without exposing its value."""

    if value is _KEY_UNSET:
        if not has_app_context():
            raise _invalid_key()
        value = current_app.config.get(PSEUDONYMIZATION_KEY_CONFIG)
    return _decode_pseudonymization_key(value)


def _canonical_user_id(user_id):
    """Return the required canonical ASCII decimal representation."""

    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("user_id must be a positive integer")
    return str(int(user_id)).encode("ascii")


def _pseudonym_from_key_bytes(user_id, key_bytes):
    canonical_id = _canonical_user_id(user_id)
    message = PSEUDONYMIZATION_MESSAGE_PREFIX + canonical_id
    digest = hmac.new(key_bytes, message, hashlib.sha256).hexdigest()
    return "P-" + digest[:32]


def pseudonymize_user_id(user_id, key=_KEY_UNSET):
    """Return a stable, domain-separated pseudonym for one user ID.

    ``key`` is normally omitted so the Flask ``PSEUDONYMIZATION_KEY``
    configuration is used.  Tests and controlled demonstrations may provide
    an explicit Base64URL key; it follows the same strict validation path.
    """

    return _pseudonym_from_key_bytes(user_id, _configured_key(key))


def user_pseudonym(user_id, key=_KEY_UNSET):
    """Readable alias for :func:`pseudonymize_user_id`."""

    return pseudonymize_user_id(user_id, key=key)


def _event_value(event, field_name):
    """Read a field from a dict-like event without copying other fields."""

    if isinstance(event, Mapping):
        return event.get(field_name)
    try:
        return event[field_name]
    except (KeyError, IndexError, TypeError):
        return None


def _project_security_events(events, key_bytes):
    """Project already-fetched rows using validated key bytes."""

    if events is None:
        limited_events = ()
    else:
        try:
            limited_events = islice(events, MAX_RECENT_EVENTS)
        except TypeError as exc:
            raise ValueError("events must be an iterable") from exc

    projected = []
    for event in limited_events:
        actor_id = _event_value(event, "actor_user_id")
        if actor_id is None:
            actor_pseudonym = None
        else:
            try:
                actor_pseudonym = _pseudonym_from_key_bytes(actor_id, key_bytes)
            except ValueError:
                # A malformed/legacy actor reference is not a known actor for
                # this view.  Do not expose or stringify it as an identity.
                actor_pseudonym = None

        projected.append(
            {
                "created_at": _event_value(event, "created_at"),
                "event_type": _event_value(event, "event_type"),
                "outcome": _event_value(event, "outcome"),
                "actor_pseudonym": actor_pseudonym,
                "target_type": _event_value(event, "target_type"),
            }
        )
    return projected


def transform_security_events(events, key=_KEY_UNSET):
    """Project events onto the five-field privacy analysis contract.

    The input is intentionally capped even when a caller supplies more rows.
    Rows are expected to already be newest-first as returned by
    ``get_recent_security_events``; this function never queries or exposes
    other event columns.
    """

    return _project_security_events(events, _configured_key(key))


def get_privacy_analysis_events():
    """Read and minimize the bounded recent security-event analysis view."""

    key_bytes = _configured_key()
    events = get_recent_security_events(limit=MAX_RECENT_EVENTS)
    return _project_security_events(events, key_bytes)


def get_privacy_analysis():
    """Primary route-facing name for the minimized analysis view."""

    return get_privacy_analysis_events()


__all__ = [
    "PRIVACY_ANALYSIS_FIELDS",
    "PSEUDONYMIZATION_KEY_CONFIG",
    "PSEUDONYMIZATION_MESSAGE_PREFIX",
    "PrivacyConfigurationError",
    "get_privacy_analysis",
    "get_privacy_analysis_events",
    "pseudonymize_user_id",
    "transform_security_events",
    "user_pseudonym",
]
