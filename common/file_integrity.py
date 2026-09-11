"""Safe avatar validation, canonical storage, and integrity verification.

The avatar pipeline deliberately keeps the filesystem target server-controlled:
callers provide a database user id, never a path.  Validation and normalization
complete in memory before an atomic replacement, and the digest is calculated
from the exact canonical bytes written to disk.
"""

from __future__ import annotations

from hashlib import sha256
import io
import os
from pathlib import Path
import tempfile
import warnings

from flask import current_app, has_app_context
from PIL import Image

from common.users import get_db


MAX_AVATAR_BYTES = 2 * 1024 * 1024
MAX_AVATAR_DIMENSION = 4096
MAX_AVATAR_PIXELS = 8_000_000
_INTEGRITY_HASH_CHUNK_SIZE = 64 * 1024

MATCH = "MATCH"
MISMATCH = "MISMATCH"
UNTRACKED = "UNTRACKED"
MISSING = "MISSING"
INTEGRITY_STATUSES = frozenset({MATCH, MISMATCH, UNTRACKED, MISSING})

DEFAULT_AVATAR_DIR = Path(__file__).resolve().parents[1] / "static" / "img" / "avatars"
MAX_INTEGRITY_USERS = 1000


class AvatarValidationError(ValueError):
    """Raised when uploaded bytes are not an acceptable avatar image."""

    def __init__(self, message="The avatar is invalid.", *, status_code=400):
        super().__init__(message)
        self.status_code = status_code


class AvatarPersistenceError(RuntimeError):
    """Raised when canonical avatar storage or digest persistence fails."""


def _avatar_dir(avatar_dir=None):
    if avatar_dir is not None:
        return Path(avatar_dir)
    if has_app_context() and current_app.config.get("AVATAR_DIR"):
        return Path(current_app.config["AVATAR_DIR"])
    return DEFAULT_AVATAR_DIR


def _validated_user_id(user_id):
    if isinstance(user_id, bool) or not isinstance(user_id, int):
        raise ValueError("user_id must be an integer")
    return user_id


def canonical_avatar_path(user_id, avatar_dir=None):
    """Resolve only the canonical JPEG path for an existing user id value."""

    user_id = _validated_user_id(user_id)
    return _avatar_dir(avatar_dir) / f"{user_id}.jpg"


def _read_limited(file_storage):
    stream = getattr(file_storage, "stream", file_storage)
    try:
        raw = stream.read(MAX_AVATAR_BYTES + 1)
    except Exception as exc:  # malformed/failed input is a safe validation error
        raise AvatarValidationError() from exc
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise AvatarValidationError()
    raw = bytes(raw)
    if len(raw) > MAX_AVATAR_BYTES:
        raise AvatarValidationError(
            "The avatar is too large.",
            status_code=413,
        )
    if not raw:
        raise AvatarValidationError()
    return raw


def _check_dimensions(width, height):
    if (
        not isinstance(width, int)
        or not isinstance(height, int)
        or width <= 0
        or height <= 0
        or width > MAX_AVATAR_DIMENSION
        or height > MAX_AVATAR_DIMENSION
        or width * height > MAX_AVATAR_PIXELS
    ):
        raise AvatarValidationError()


def _rgb_with_white_background(image):
    # Converting through RGBA honors palette/LA transparency.  The new image
    # has no source metadata, so JPEG output cannot carry the original EXIF.
    has_alpha = "A" in image.getbands() or "transparency" in image.info
    if has_alpha:
        rgba = image.convert("RGBA")
        background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        return Image.alpha_composite(background, rgba).convert("RGB")
    return image.convert("RGB")


def normalize_avatar(file_storage):
    """Validate and return canonical JPEG bytes without touching the filesystem."""

    raw = _read_limited(file_storage)
    input_stream = io.BytesIO(raw)

    try:
        # Treat Pillow's decompression-bomb warning as a validation failure,
        # while retaining Pillow's own protections and not changing its limits.
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(input_stream) as probe:
                if probe.format not in {"JPEG", "PNG"}:
                    raise AvatarValidationError()
                _check_dimensions(*probe.size)
                probe.verify()

            # verify() invalidates the first decoder; reopen and load to force
            # actual pixel decoding before canonical bytes are produced.
            with Image.open(io.BytesIO(raw)) as decoded:
                if decoded.format not in {"JPEG", "PNG"}:
                    raise AvatarValidationError()
                _check_dimensions(*decoded.size)
                decoded.load()
                rgb = _rgb_with_white_background(decoded)
                output = io.BytesIO()
                rgb.save(output, format="JPEG", quality=90, optimize=False)
                canonical = output.getvalue()
    except AvatarValidationError:
        raise
    except Exception as exc:
        # Pillow may report malformed/truncated/decompression failures through
        # several exception types; all are deliberately a generic safe 400.
        raise AvatarValidationError() from exc

    if not canonical:
        raise AvatarValidationError()
    return canonical


def _persist_avatar_digest(user_id, digest):
    try:
        with get_db() as conn:
            cursor = conn.execute(
                "UPDATE users SET avatar_sha256 = ? WHERE id = ?",
                (digest, user_id),
            )
            if cursor.rowcount != 1:
                raise AvatarPersistenceError()
            conn.commit()
    except AvatarPersistenceError:
        raise
    except Exception as exc:
        raise AvatarPersistenceError() from exc


def store_canonical_avatar(user_id, canonical_bytes, avatar_dir=None):
    """Atomically replace a canonical avatar, then persist its SHA-256 digest."""

    user_id = _validated_user_id(user_id)
    path = canonical_avatar_path(user_id, avatar_dir)
    digest = sha256(canonical_bytes).hexdigest()
    temporary_path = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{user_id}.",
            suffix=".avatar.tmp",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(canonical_bytes)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    except (OSError, ValueError, TypeError) as exc:
        raise AvatarPersistenceError() from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass

    # A database failure after replacement is intentionally surfaced.  The
    # file/database pair can then be detected as MISMATCH/UNTRACKED; silently
    # claiming success would conceal the cross-resource consistency limit.
    _persist_avatar_digest(user_id, digest)
    return path.name, digest


def update_avatar(user_id, file_storage, avatar_dir=None):
    """Validate, normalize, atomically store, and digest an uploaded avatar."""

    canonical = normalize_avatar(file_storage)
    return store_canonical_avatar(user_id, canonical, avatar_dir)


def _read_expected_digest(expected_digest):
    return expected_digest if isinstance(expected_digest, str) else None


def _sha256_file(path):
    """Hash a server-derived file incrementally without loading it in memory."""

    digest = sha256()
    try:
        with path.open("rb") as stored_file:
            while True:
                chunk = stored_file.read(_INTEGRITY_HASH_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def get_avatar_integrity(user_id, expected_digest=None, avatar_dir=None):
    """Return one of MATCH, MISMATCH, UNTRACKED, or MISSING for a user avatar."""

    path = canonical_avatar_path(user_id, avatar_dir)
    if not path.is_file():
        return {
            "status": MISSING,
            "expected_digest": _read_expected_digest(expected_digest),
            "current_digest": None,
        }
    expected = _read_expected_digest(expected_digest)
    if not expected:
        current = _sha256_file(path)
        return {
            "status": UNTRACKED,
            "expected_digest": expected,
            "current_digest": current,
        }
    current = _sha256_file(path)
    if current is None:
        return {
            "status": MISMATCH,
            "expected_digest": expected,
            "current_digest": None,
        }
    return {
        "status": MATCH if current == expected else MISMATCH,
        "expected_digest": expected,
        "current_digest": current,
    }


def _truncated_digest(value):
    if not isinstance(value, str) or not value:
        return "—"
    return f"{value[:12]}…"


def get_file_integrity_rows(limit=MAX_INTEGRITY_USERS, avatar_dir=None):
    """Return bounded, display-safe integrity rows for existing database users."""

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")
    bounded_limit = min(limit, MAX_INTEGRITY_USERS)
    with get_db() as conn:
        users = conn.execute(
            """
            SELECT id, username, avatar_sha256
            FROM users
            ORDER BY id ASC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()

    rows = []
    for user in users:
        result = get_avatar_integrity(
            user["id"],
            user["avatar_sha256"],
            avatar_dir,
        )
        rows.append(
            {
                "id": user["id"],
                "username": user["username"],
                "status": result["status"],
                "expected_digest": _truncated_digest(result["expected_digest"]),
                "current_digest": _truncated_digest(result["current_digest"]),
            }
        )
    return rows
