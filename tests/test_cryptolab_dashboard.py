import gc
import hashlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from common.database import init_db
from common.session import create_session
from common.users import hash_password
from cryptolab.events import EventStore
from cryptolab.experiments import run_all
from cryptolab.keys import KeyRing
from run import app

ADMIN_ROUTES = (
    ("GET", "/admin/cryptolab"),
    ("GET", "/admin/cryptolab/stego"),
    ("POST", "/admin/cryptolab/run"),
    ("POST", "/admin/cryptolab/stego/hide"),
    ("POST", "/admin/cryptolab/stego/reveal"),
)


def _png(size=(80, 80)):
    img = Image.new("RGB", size)
    img.putdata([((x * 3) % 256, (y * 3) % 256, 90) for y in range(size[1]) for x in range(size[0])])
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class CryptoLabDashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "lab.db"
        self.lab_dir = root / "cryptolab"
        self.original_config = {k: app.config.get(k) for k in (
            "DATABASE", "TESTING", "CRYPTOLAB_DIR", "CRYPTOLAB_MASTER_KEYS")}
        app.config.update(TESTING=True, DATABASE=self.db_path, CRYPTOLAB_DIR=self.lab_dir,
                          CRYPTOLAB_MASTER_KEYS=KeyRing.generate().to_env())
        init_db(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                "INSERT INTO users (id, username, password, role, email, bio) VALUES (?, ?, ?, ?, ?, ?)",
                [(101, "lab_member", hash_password("member-pw"), "user", "m@example.test", ""),
                 (201, "lab_admin", hash_password("admin-pw"), "admin", "a@example.test", "")])
            conn.commit()
        self.client = app.test_client()
        self.csrf_token = None

    def tearDown(self):
        app.config.update(self.original_config)
        gc.collect()
        self.temp_dir.cleanup()

    def _login_as(self, user_id):
        with app.app_context():
            token = create_session(user_id)
        self.client.set_cookie("session_id", token)
        with sqlite3.connect(self.db_path) as conn:
            self.csrf_token = conn.execute(
                "SELECT csrf_token FROM auth_sessions WHERE token_hash = ?",
                (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()[0]

    def _request(self, method, path, **kwargs):
        return self.client.open(path, method=method, **kwargs)

    def test_anonymous_is_redirected_to_login(self):
        for method, path in ADMIN_ROUTES:
            response = self._request(method, path)
            self.assertIn(response.status_code, (302, 403), path)
            if response.status_code == 302:
                self.assertIn("/login", response.headers["Location"])

    def test_member_is_denied(self):
        self._login_as(101)
        for method, path in ADMIN_ROUTES:
            data = {"csrf_token": self.csrf_token} if method == "POST" else None
            self.assertEqual(self._request(method, path, data=data).status_code, 403, path)
        with sqlite3.connect(self.db_path) as conn:
            denied = conn.execute(
                "SELECT count(*) FROM security_events WHERE event_type = 'authz.admin.denied'").fetchone()[0]
        self.assertGreater(denied, 0)

    def test_admin_empty_state(self):
        self._login_as(201)
        response = self.client.get("/admin/cryptolab")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Nenhum experimento executado", response.get_data(as_text=True))

    def test_admin_dashboard_with_results(self):
        store = EventStore(self.lab_dir / "events.duckdb")
        run_all(store, self.lab_dir, quick=True)
        store.close()
        self._login_as(201)
        body = self.client.get("/admin/cryptolab").get_data(as_text=True)
        self.assertIn("Efeito avalanche", body)
        self.assertIn("<svg", body)
        self.assertNotIn("style=", body)  # CSP: no inline styles
        image = self.client.get("/admin/cryptolab/img/ecb_original.png")
        self.assertEqual(image.status_code, 200)
        self.assertEqual(image.mimetype, "image/png")

    def test_image_outside_whitelist(self):
        store = EventStore(self.lab_dir / "events.duckdb")
        run_all(store, self.lab_dir, quick=True)
        store.close()
        self._login_as(201)
        for name in ("results.json", "events.duckdb", "..%2Flab.db", "nope.png"):
            self.assertEqual(self.client.get(f"/admin/cryptolab/img/{name}").status_code, 404, name)

    def test_post_without_csrf_is_rejected(self):
        self._login_as(201)
        for path in ("/admin/cryptolab/run", "/admin/cryptolab/stego/hide"):
            self.assertEqual(self.client.post(path, data={}).status_code, 403, path)

    def test_stego_round_trip_through_http(self):
        self._login_as(201)
        hide = self.client.post("/admin/cryptolab/stego/hide", data={
            "csrf_token": self.csrf_token, "secret": "senha do cofre: 4815",
            "cover": (io.BytesIO(_png()), "cover.png")}, content_type="multipart/form-data")
        self.assertEqual(hide.status_code, 200, hide.data[:300])
        self.assertEqual(hide.mimetype, "image/png")
        reveal = self.client.post("/admin/cryptolab/stego/reveal", data={
            "csrf_token": self.csrf_token,
            "image": (io.BytesIO(hide.data), "stego.png")}, content_type="multipart/form-data")
        self.assertEqual(reveal.status_code, 200)
        self.assertIn("senha do cofre: 4815", reveal.get_data(as_text=True))
        store = EventStore(self.lab_dir / "events.duckdb")
        types = {r[0] for r in store.query("SELECT event_type FROM events")}
        store.close()
        self.assertTrue({"stego.embed", "stego.extract", "crypto.decrypt.success"} <= types)

    def test_reveal_clean_image_reports_error_and_logs_failure(self):
        self._login_as(201)
        response = self.client.post("/admin/cryptolab/stego/reveal", data={
            "csrf_token": self.csrf_token,
            "image": (io.BytesIO(_png()), "clean.png")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Nenhuma mensagem", response.get_data(as_text=True))

    def test_secret_too_large_for_cover(self):
        self._login_as(201)
        response = self.client.post("/admin/cryptolab/stego/hide", data={
            "csrf_token": self.csrf_token, "secret": "x" * 1900,
            "cover": (io.BytesIO(_png((20, 20))), "tiny.png")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertIn("capacidade", response.get_data(as_text=True))

    def test_not_an_image(self):
        self._login_as(201)
        response = self.client.post("/admin/cryptolab/stego/hide", data={
            "csrf_token": self.csrf_token, "secret": "x",
            "cover": (io.BytesIO(b"not an image"), "x.png")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)

    def test_missing_keyring_fails_closed(self):
        app.config["CRYPTOLAB_MASTER_KEYS"] = None
        self._login_as(201)
        response = self.client.post("/admin/cryptolab/stego/hide", data={
            "csrf_token": self.csrf_token, "secret": "x",
            "cover": (io.BytesIO(_png()), "c.png")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 503)

    def test_run_endpoint_generates_results(self):
        self._login_as(201)
        response = self.client.post("/admin/cryptolab/run", data={"csrf_token": self.csrf_token})
        self.assertEqual(response.status_code, 302)
        self.assertTrue((self.lab_dir / "results.json").exists())

    # Another process (e.g. `flask cryptolab-all`) holds the DuckDB write lock.
    def _hold_lock(self):
        import subprocess, sys, time
        self.lab_dir.mkdir(parents=True, exist_ok=True)
        db = self.lab_dir / "events.duckdb"
        proc = subprocess.Popen([sys.executable, "-c",
            "import duckdb,sys,time; c=duckdb.connect(sys.argv[1]); print('locked', flush=True); time.sleep(30)",
            str(db)], stdout=subprocess.PIPE, text=True)
        self.assertEqual(proc.stdout.readline().strip(), "locked")
        self.addCleanup(proc.kill)
        return proc

    def test_dashboard_renders_notice_when_store_locked(self):
        store = EventStore(self.lab_dir / "events.duckdb")
        run_all(store, self.lab_dir, quick=True)
        store.close()
        self._hold_lock()
        self._login_as(201)
        response = self.client.get("/admin/cryptolab")
        self.assertEqual(response.status_code, 200)
        self.assertIn("em uso por outro processo", response.get_data(as_text=True))

    def test_stego_still_works_when_store_locked(self):
        self._hold_lock()
        self._login_as(201)
        hide = self.client.post("/admin/cryptolab/stego/hide", data={
            "csrf_token": self.csrf_token, "secret": "lock-safe",
            "cover": (io.BytesIO(_png()), "c.png")}, content_type="multipart/form-data")
        self.assertEqual(hide.status_code, 200)
        reveal = self.client.post("/admin/cryptolab/stego/reveal", data={
            "csrf_token": self.csrf_token,
            "image": (io.BytesIO(hide.data), "s.png")}, content_type="multipart/form-data")
        self.assertEqual(reveal.status_code, 200)
        self.assertIn("lock-safe", reveal.get_data(as_text=True))


class CryptoLabCliTests(unittest.TestCase):
    def test_cli_simulate_detect_and_experiments(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = app.config.get("CRYPTOLAB_DIR")
            app.config["CRYPTOLAB_DIR"] = Path(tmp)
            try:
                runner = app.test_cli_runner()
                result = runner.invoke(args=["cryptolab-all", "--events", "20000", "--quick"])
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertTrue((Path(tmp) / "results.json").exists())
                self.assertTrue((Path(tmp) / "detection.json").exists())
                self.assertTrue((Path(tmp) / "parquet" / "events.parquet").exists())
                genkey = runner.invoke(args=["cryptolab-genkey"])
                self.assertEqual(genkey.exit_code, 0)
                KeyRing.from_env(genkey.output.strip().split("=", 1)[1])
            finally:
                app.config["CRYPTOLAB_DIR"] = original


if __name__ == "__main__":
    unittest.main()

