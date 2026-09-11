import gc
import ipaddress
import re
import secrets
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
from datetime import timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from werkzeug.serving import make_server

from common.database import init_db
from common.session import create_session
from common.transport import (
    CONTENT_SECURITY_POLICY,
    TLS_MINIMUM_VERSION,
    TransportConfigurationError,
    create_ssl_context,
    generate_development_certificate,
    ssl_context_from_config,
)
from common.users import hash_password
from run import app, run_server


class TransportSecurityTests(unittest.TestCase):
    """Transport, header, CSP, and HTTPS-bound cookie regression coverage."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "transport-security.db"
        self.avatar_dir = root / "avatars"
        self.cert_path = root / "requested" / "lab-cert.pem"
        self.key_path = root / "requested" / "lab-key.pem"
        self.password = f"transport-{secrets.token_urlsafe(18)}"
        self.original_config = {
            key: app.config.get(key)
            for key in (
                "DATABASE",
                "AVATAR_DIR",
                "TESTING",
                "TRANSPORT_MODE",
                "TLS_CERT_FILE",
                "TLS_KEY_FILE",
                "PORT",
                "HOST",
                "SESSION_COOKIE_SECURE",
            )
        }
        app.config.update(
            TESTING=True,
            DATABASE=self.db_path,
            AVATAR_DIR=self.avatar_dir,
            TRANSPORT_MODE="http",
            TLS_CERT_FILE=None,
            TLS_KEY_FILE=None,
            PORT=1337,
            HOST="127.0.0.1",
            SESSION_COOKIE_SECURE=False,
        )
        init_db(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (id, username, password, role, email, bio)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    901,
                    "transport_member",
                    hash_password(self.password),
                    "user",
                    "transport@example.test",
                    "Transport test member",
                ),
            )
            conn.commit()
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    @staticmethod
    def _cookie(response):
        cookies = SimpleCookie()
        for header in response.headers.getlist("Set-Cookie"):
            cookies.load(header)
        return cookies["session_id"]

    def _generate_tls(self):
        return generate_development_certificate(self.cert_path, self.key_path)

    def test_http_development_mode_has_no_context_or_hsts_and_cookie_is_usable(self):
        self.assertIsNone(ssl_context_from_config(app.config))

        login = self.client.post(
            "/login",
            base_url="http://localhost",
            data={"username": "transport_member", "password": self.password},
        )

        self.assertEqual(login.status_code, 302)
        self.assertNotIn("Strict-Transport-Security", login.headers)
        self.assertNotIn("; Secure", "\n".join(login.headers.getlist("Set-Cookie")))
        self.assertTrue(self.client.get("/board", base_url="http://localhost").status_code == 200)

    def test_https_mode_requires_both_certificate_and_key_without_http_fallback(self):
        app.config.update(TRANSPORT_MODE="https", TLS_CERT_FILE=None, TLS_KEY_FILE=None)
        with self.assertRaises(TransportConfigurationError):
            ssl_context_from_config(app.config)
        with patch.object(app, "run") as server_run:
            with self.assertRaises(TransportConfigurationError):
                run_server(port=1337)
            server_run.assert_not_called()

        self._generate_tls()
        app.config.update(TLS_CERT_FILE=self.cert_path, TLS_KEY_FILE=None)
        with self.assertRaises(TransportConfigurationError):
            ssl_context_from_config(app.config)

        malformed_cert_path = self.cert_path.with_name("malformed-cert.pem")
        malformed_cert_path.write_text("not a PEM certificate", encoding="ascii")
        app.config.update(TLS_CERT_FILE=malformed_cert_path, TLS_KEY_FILE=self.key_path)
        with patch.object(app, "run") as server_run:
            with self.assertRaises(TransportConfigurationError):
                run_server(port=1337)
            server_run.assert_not_called()

        mismatched_key_path = self.key_path.with_name("mismatched-key.pem")
        mismatched_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        mismatched_key_path.write_bytes(
            mismatched_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        app.config.update(TLS_CERT_FILE=self.cert_path, TLS_KEY_FILE=mismatched_key_path)
        with patch.object(app, "run") as server_run:
            with self.assertRaises(TransportConfigurationError):
                run_server(port=1337)
            server_run.assert_not_called()

        app.config.update(TLS_CERT_FILE=self.cert_path, TLS_KEY_FILE=self.key_path)
        self.assertIsNotNone(ssl_context_from_config(app.config))

    def test_development_certificate_is_finite_self_signed_and_not_silently_overwritten(self):
        runner = app.test_cli_runner()
        first = runner.invoke(
            args=[
                "generate-dev-tls",
                "--cert",
                str(self.cert_path),
                "--key",
                str(self.key_path),
            ]
        )
        self.assertEqual(first.exit_code, 0, first.output)
        self.assertTrue(self.cert_path.is_file())
        self.assertTrue(self.key_path.is_file())
        self.assertNotIn("BEGIN PRIVATE KEY", first.output)
        self.assertNotIn(self.key_path.read_text(encoding="utf-8"), first.output)

        original_certificate = self.cert_path.read_bytes()
        original_key = self.key_path.read_bytes()
        second = runner.invoke(
            args=[
                "generate-dev-tls",
                "--cert-path",
                str(self.cert_path),
                "--key-path",
                str(self.key_path),
            ]
        )
        self.assertNotEqual(second.exit_code, 0)
        self.assertEqual(self.cert_path.read_bytes(), original_certificate)
        self.assertEqual(self.key_path.read_bytes(), original_key)

        certificate = x509.load_pem_x509_certificate(original_certificate)
        self.assertEqual(certificate.subject, certificate.issuer)
        self.assertEqual(certificate.signature_hash_algorithm.name, "sha256")
        self.assertLess(certificate.not_valid_before_utc, certificate.not_valid_after_utc)
        self.assertLess(
            certificate.not_valid_after_utc - certificate.not_valid_before_utc,
            timedelta(days=31),
        )
        sans = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        self.assertIn(x509.DNSName("localhost"), sans)
        self.assertIn(x509.IPAddress(ipaddress.ip_address("127.0.0.1")), sans)
        self.assertIn(x509.IPAddress(ipaddress.ip_address("::1")), sans)
        public_key = certificate.public_key()
        self.assertIsInstance(public_key, rsa.RSAPublicKey)
        self.assertGreaterEqual(public_key.key_size, 2048)
        loaded_key = serialization.load_pem_private_key(original_key, password=None)
        self.assertEqual(loaded_key.public_key().public_numbers(), public_key.public_numbers())

    def test_tls_context_uses_tls12_minimum_and_matching_certificate_chain(self):
        self._generate_tls()
        context = create_ssl_context(self.cert_path, self.key_path)
        self.assertEqual(context.minimum_version, TLS_MINIMUM_VERSION)
        self.assertIn(
            context.maximum_version,
            {
                ssl.TLSVersion.MAXIMUM_SUPPORTED,
                ssl.TLSVersion.TLSv1_2,
                ssl.TLSVersion.TLSv1_3,
            },
        )

    def test_https_mode_forces_secure_cookie_and_exact_headers(self):
        self._generate_tls()
        app.config.update(
            TRANSPORT_MODE="https",
            TLS_CERT_FILE=self.cert_path,
            TLS_KEY_FILE=self.key_path,
            SESSION_COOKIE_SECURE=False,
        )
        response = self.client.post(
            "/login",
            base_url="https://localhost",
            data={"username": "transport_member", "password": self.password},
        )
        cookie = self._cookie(response)
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")
        self.assertEqual(cookie["path"], "/")
        self.assertEqual(cookie["max-age"], "3600")
        self.assertEqual(response.headers["Strict-Transport-Security"], "max-age=31536000")
        self.assertEqual(response.headers["Content-Security-Policy"], CONTENT_SECURITY_POLICY)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(
            response.headers["Referrer-Policy"], "strict-origin-when-cross-origin"
        )

    def test_headers_cover_redirect_error_http_and_https_responses(self):
        for scheme, has_hsts in (("http", False), ("https", True)):
            response = self.client.get("/missing", base_url=f"{scheme}://localhost")
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.headers["Content-Security-Policy"], CONTENT_SECURITY_POLICY)
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            self.assertEqual(
                response.headers["Referrer-Policy"], "strict-origin-when-cross-origin"
            )
            self.assertEqual("Strict-Transport-Security" in response.headers, has_hsts)

            redirect = self.client.get("/board", base_url=f"{scheme}://localhost")
            self.assertEqual(redirect.status_code, 302)
            self.assertEqual("Strict-Transport-Security" in redirect.headers, has_hsts)

    def test_csp_and_templates_have_no_inline_scripts_handlers_or_external_origins(self):
        self.assertNotIn("unsafe-inline", CONTENT_SECURITY_POLICY)
        self.assertNotIn("unsafe-eval", CONTENT_SECURITY_POLICY)
        self.assertNotRegex(CONTENT_SECURITY_POLICY, r"https?://|//[^; ]+")

        project_root = Path(__file__).resolve().parents[1]
        template_paths = list((project_root / "templates").rglob("*.html")) + list(
            (project_root / "apps").rglob("*.html")
        )
        inline_script = re.compile(r"<script(?![^>]*\bsrc\s*=)[^>]*>", re.IGNORECASE)
        inline_handler = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
        for template_path in template_paths:
            source = template_path.read_text(encoding="utf-8")
            self.assertIsNone(inline_script.search(source), template_path)
            self.assertIsNone(inline_handler.search(source), template_path)

        login = self.client.get("/login")
        body = login.get_data(as_text=True)
        self.assertIn('/static/js/bootstrap.bundle.min.js', body)
        self.assertIn('/static/js/app.js', body)
        app_js = self.client.get("/static/js/app.js")
        app_css = self.client.get("/static/css/app.css")
        self.assertEqual(app_js.status_code, 200)
        self.assertEqual(app_css.status_code, 200)
        app_js.close()
        app_css.close()

    def test_real_loopback_tls_listener_negotiates_tls_and_sets_secure_cookie(self):
        self._generate_tls()
        app.config.update(
            TRANSPORT_MODE="https",
            TLS_CERT_FILE=self.cert_path,
            TLS_KEY_FILE=self.key_path,
            SESSION_COOKIE_SECURE=False,
        )
        server = make_server(
            "127.0.0.1",
            0,
            app,
            ssl_context=ssl_context_from_config(app.config),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", server.server_port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.02)
            else:
                self.fail("TLS listener did not start")

            client_context = ssl.create_default_context(cafile=str(self.cert_path))
            client_context.minimum_version = ssl.TLSVersion.TLSv1_2

            def tls_request(request_bytes):
                raw_socket = socket.create_connection(
                    ("127.0.0.1", server.server_port), timeout=5
                )
                with client_context.wrap_socket(
                    raw_socket, server_hostname="localhost"
                ) as tls_socket:
                    negotiated = tls_socket.version()
                    tls_socket.sendall(request_bytes)
                    chunks = []
                    while True:
                        chunk = tls_socket.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                return negotiated, b"".join(chunks)

            negotiated_version, login_page = tls_request(
                b"GET /login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            self.assertIn(negotiated_version, {"TLSv1.2", "TLSv1.3"})
            login_headers, login_page_body = login_page.split(b"\r\n\r\n", 1)
            self.assertIn(b" 200 ", login_headers.split(b"\r\n", 1)[0])
            self.assertIn(b"Strict-Transport-Security: max-age=31536000", login_headers)
            self.assertIn(
                ("Content-Security-Policy: " + CONTENT_SECURITY_POLICY).encode(),
                login_headers,
            )
            self.assertIn(b"X-Content-Type-Options: nosniff", login_headers)
            self.assertIn(b"X-Frame-Options: DENY", login_headers)
            self.assertIn(
                b"Referrer-Policy: strict-origin-when-cross-origin", login_headers
            )
            self.assertIn(b"/static/js/app.js", login_page_body)

            body = urlencode(
                {"username": "transport_member", "password": self.password}
            ).encode()
            negotiated_version, login_response = tls_request(
                b"POST /login HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
            self.assertIn(negotiated_version, {"TLSv1.2", "TLSv1.3"})
            login_response_headers = login_response.split(b"\r\n\r\n", 1)[0]
            cookie_header = b"\r\n".join(
                line
                for line in login_response_headers.split(b"\r\n")
                if line.lower().startswith(b"set-cookie:")
            )
            self.assertIn(b"; Secure", cookie_header)
            self.assertIn(b"HttpOnly", cookie_header)
            self.assertIn(b"SameSite=Lax", cookie_header)
            self.assertIn(b"Path=/", cookie_header)
            self.assertIn(b"Max-Age=3600", cookie_header)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
