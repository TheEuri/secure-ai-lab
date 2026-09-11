import gc
import hashlib
import io
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

from PIL import Image
from PIL.PngImagePlugin import PngInfo

from common.database import init_db
from common.file_integrity import (
    MAX_AVATAR_BYTES,
    MAX_AVATAR_DIMENSION,
    MAX_AVATAR_PIXELS,
)
from common.session import create_session
from common.users import hash_password
from run import app


class _ReadTrackingStream(io.BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.requested_sizes = []

    def read(self, size=-1):
        self.requested_sizes.append(size)
        return super().read(size)


class UploadSecurityTests(unittest.TestCase):
    """S3 avatar validation and canonical-storage regression coverage."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "upload-security.db"
        self.avatar_dir = root / "avatars"
        self.original_config = {
            "DATABASE": app.config.get("DATABASE"),
            "AVATAR_DIR": app.config.get("AVATAR_DIR"),
            "TESTING": app.config.get("TESTING"),
        }
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=self.avatar_dir,
        )
        init_db(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (101, "upload_alice", hash_password(secrets.token_urlsafe(16)), "user", "upload-alice@example.test", ""),
                    (102, "upload_bob", hash_password(secrets.token_urlsafe(16)), "user", "upload-bob@example.test", ""),
                    (201, "upload_admin", hash_password(secrets.token_urlsafe(16)), "admin", "upload-admin@example.test", ""),
                ],
            )
            conn.commit()
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    @staticmethod
    def _image_bytes(
        image_format="JPEG",
        size=(6, 5),
        mode="RGB",
        color=(40, 110, 200),
        metadata=False,
        trailing=b"",
    ):
        output = io.BytesIO()
        image = Image.new(mode, size, color)
        if image_format == "PNG" and metadata:
            info = PngInfo()
            info.add_text("controlled", "P5H_METADATA_SENTINEL")
            image.save(output, format=image_format, pnginfo=info)
        else:
            image.save(output, format=image_format)
        return output.getvalue() + trailing

    def _login_as(self, user_id):
        with app.app_context():
            token = create_session(user_id)
        self.client.set_cookie("session_id", token)
        with sqlite3.connect(self.db_path) as conn:
            self.csrf_token = conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()[0]

    def _upload(self, payload, filename="avatar.jpg", content_type=None, user_id=None, csrf=None):
        self._login_as(user_id or 101) if csrf is None and not hasattr(self, "csrf_token") else None
        form = {"csrf_token": csrf or self.csrf_token}
        if user_id is not None:
            form["user_id"] = str(user_id)
        form["avatar"] = (io.BytesIO(payload), filename, content_type) if content_type else (io.BytesIO(payload), filename)
        return self.client.post(
            "/profile/edit_avatar",
            data=form,
            content_type="multipart/form-data",
        )

    def _events(self):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT event_type, outcome, actor_user_id, target_id FROM security_events ORDER BY id"
            ).fetchall()

    def _digest(self, user_id=101):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT avatar_sha256 FROM users WHERE id = ?", (user_id,)
            ).fetchone()[0]

    def test_constants_define_the_contract_limits(self):
        self.assertEqual(MAX_AVATAR_BYTES, 2 * 1024 * 1024)
        self.assertEqual(MAX_AVATAR_DIMENSION, 4096)
        self.assertEqual(MAX_AVATAR_PIXELS, 8_000_000)

    def test_valid_jpeg_is_accepted_as_canonical_rgb_jpeg(self):
        self._login_as(101)
        original = self._image_bytes("JPEG")
        response = self._upload(original, "client-name.not-jpeg", "application/octet-stream")
        self.assertEqual(response.status_code, 302)
        stored = (self.avatar_dir / "101.jpg").read_bytes()
        self.assertNotEqual(stored, original)
        with Image.open(io.BytesIO(stored)) as image:
            self.assertEqual(image.format, "JPEG")
            self.assertEqual(image.mode, "RGB")
            image.load()
        self.assertEqual(self._digest(), hashlib.sha256(stored).hexdigest())

    def test_valid_png_transparency_is_composited_onto_white(self):
        self._login_as(101)
        image = Image.new("RGBA", (8, 8), (255, 0, 0, 0))
        image.putpixel((0, 0), (255, 0, 0, 255))
        payload = io.BytesIO()
        image.save(payload, format="PNG")
        response = self._upload(payload.getvalue(), "avatar.png", "image/png")
        self.assertEqual(response.status_code, 302)
        with Image.open(self.avatar_dir / "101.jpg") as stored:
            stored.load()
            self.assertEqual(stored.mode, "RGB")
            self.assertGreaterEqual(stored.getpixel((7, 7))[0], 245)
            self.assertGreaterEqual(stored.getpixel((7, 7))[1], 245)
            self.assertGreaterEqual(stored.getpixel((7, 7))[2], 245)

    def test_filename_extension_and_declared_mime_do_not_control_acceptance(self):
        self._login_as(101)
        payload = self._image_bytes("PNG")
        response = self._upload(payload, "../../outside/pretend.txt", "application/pdf")
        self.assertEqual(response.status_code, 302)
        self.assertTrue((self.avatar_dir / "101.jpg").is_file())
        self.assertFalse((self.avatar_dir / "pretend.txt").exists())
        self.assertFalse((self.avatar_dir.parent / "outside").exists())

    def test_declared_image_mime_with_non_image_bytes_is_rejected(self):
        self._login_as(101)
        sentinel = b"P5H_NON_IMAGE_DECLARED_BYTES"
        for declared_mime, filename in (
            ("image/jpeg", "looks-like.jpg"),
            ("image/png", "looks-like.png"),
        ):
            with self.subTest(declared_mime=declared_mime):
                response = self._upload(sentinel, filename, declared_mime)
                self.assertEqual(response.status_code, 400)
                self.assertFalse((self.avatar_dir / "101.jpg").exists())
                self.assertEqual(self._digest(), None)
                self.assertEqual(self._events(), [])
                body = response.get_data(as_text=True)
                self.assertNotIn(filename, body)
                self.assertNotIn(str(self.avatar_dir), body)
                self.assertNotIn("Traceback", body)

    def test_malformed_or_truncated_image_is_rejected_without_mutation(self):
        self._login_as(101)
        payload = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01"
        response = self._upload(payload, "broken.jpg", "image/jpeg")
        self.assertEqual(response.status_code, 400)
        self.assertFalse((self.avatar_dir / "101.jpg").exists())
        self.assertEqual(self._events(), [])

    def test_unsupported_actual_image_format_is_rejected(self):
        self._login_as(101)
        payload = self._image_bytes("GIF")
        response = self._upload(payload, "allowed-by-name.jpg", "image/jpeg")
        self.assertEqual(response.status_code, 400)
        self.assertFalse((self.avatar_dir / "101.jpg").exists())
        self.assertEqual(self._events(), [])

    def test_encoded_payload_limit_is_enforced_by_reading_at_most_limit_plus_one(self):
        self._login_as(101)
        payload = b"X" * (MAX_AVATAR_BYTES + 1)
        response = self._upload(payload, "large.jpg", "image/jpeg")
        self.assertEqual(response.status_code, 413)
        self.assertFalse((self.avatar_dir / "101.jpg").exists())
        self.assertEqual(self._events(), [])

    def test_validation_reads_a_stream_once_with_the_encoded_limit(self):
        from werkzeug.datastructures import FileStorage
        from common.file_integrity import normalize_avatar

        payload = self._image_bytes("JPEG")
        stream = _ReadTrackingStream(payload)
        normalize_avatar(FileStorage(stream=stream, filename="ignored.bin"))
        self.assertEqual(stream.requested_sizes, [MAX_AVATAR_BYTES + 1])

    def test_dimension_limit_is_checked_before_decode_and_storage(self):
        self._login_as(101)
        payload = self._image_bytes("PNG", size=(MAX_AVATAR_DIMENSION + 1, 1))
        response = self._upload(payload, "small-file.png", "image/png")
        self.assertEqual(response.status_code, 400)
        self.assertFalse((self.avatar_dir / "101.jpg").exists())
        self.assertEqual(self._events(), [])

    def test_pixel_limit_is_checked_before_decode_and_storage(self):
        self._login_as(101)
        payload = self._image_bytes("PNG", size=(3000, 3000))
        response = self._upload(payload, "pixel-bomb.png", "image/png")
        self.assertEqual(response.status_code, 400)
        self.assertFalse((self.avatar_dir / "101.jpg").exists())
        self.assertEqual(self._events(), [])

    def test_rejected_replacement_preserves_previous_bytes_digest_and_events(self):
        self._login_as(101)
        valid = self._upload(self._image_bytes("JPEG", color=(10, 20, 30)), "first.jpg")
        self.assertEqual(valid.status_code, 302)
        before_bytes = (self.avatar_dir / "101.jpg").read_bytes()
        before_digest = self._digest()
        before_events = self._events()

        rejected = self._upload(b"P5H_REJECTED_REPLACEMENT", "new.jpg", "image/jpeg")
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual((self.avatar_dir / "101.jpg").read_bytes(), before_bytes)
        self.assertEqual(self._digest(), before_digest)
        self.assertEqual(self._events(), before_events)

    def test_canonical_output_discards_metadata_and_trailing_bytes(self):
        self._login_as(101)
        payload = self._image_bytes(
            "PNG",
            metadata=True,
            trailing=b"P5H_TRAILING_BYTES_SENTINEL",
        )
        response = self._upload(payload, "metadata.png", "image/png")
        self.assertEqual(response.status_code, 302)
        stored = (self.avatar_dir / "101.jpg").read_bytes()
        self.assertNotIn(b"P5H_METADATA_SENTINEL", stored)
        self.assertNotIn(b"P5H_TRAILING_BYTES_SENTINEL", stored)
        with Image.open(io.BytesIO(stored)) as image:
            self.assertEqual(image.format, "JPEG")
            self.assertEqual(image.mode, "RGB")
            image.verify()
        self.assertEqual(self._digest(), hashlib.sha256(stored).hexdigest())
        self.assertEqual(sorted(path.name for path in self.avatar_dir.iterdir()), ["101.jpg"])

    def test_cross_user_target_is_rejected_before_file_validation_or_mutation(self):
        self._login_as(101)
        response = self._upload(
            b"P5H_NOT_AN_IMAGE",
            "owner-b.jpg",
            "image/jpeg",
            user_id=102,
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse((self.avatar_dir / "101.jpg").exists())
        self.assertFalse((self.avatar_dir / "102.jpg").exists())
        self.assertEqual(self._events(), [])

    def test_csrf_failure_blocks_valid_avatar_before_storage(self):
        self._login_as(101)
        response = self._upload(
            self._image_bytes("JPEG"),
            "valid.jpg",
            "image/jpeg",
            csrf="wrong-csrf-token",
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse((self.avatar_dir / "101.jpg").exists())
        self.assertEqual(self._events(), [])

    def test_successful_upload_emits_only_existing_profile_success_event(self):
        self._login_as(101)
        response = self._upload(self._image_bytes("PNG"), "event.png", "image/png")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self._events(),
            [("profile.avatar.updated", "success", 101, 101)],
        )


if __name__ == "__main__":
    unittest.main()
