import sqlite3
import tempfile
import unittest
from pathlib import Path

import duckdb

from cryptolab.events import ANOMALY_LABELS, EventStore
from cryptolab.simulate import simulate


class EventStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = EventStore(":memory:")
        cls.result = simulate(cls.store, n_events=20_000, seed=7)

    def test_count_matches_requested(self):
        self.assertEqual(self.store.count(), 20_000)
        self.assertEqual(self.result["n_events"], 20_000)

    def test_all_anomaly_labels_present(self):
        labels = {row[0] for row in self.store.query("SELECT DISTINCT label FROM events")}
        self.assertTrue(set(ANOMALY_LABELS) <= labels, labels)
        self.assertIn("normal", labels)

    def test_summary_shape(self):
        summary = self.store.summary()
        for key in ("total", "by_type", "by_outcome", "per_hour", "top_failing_actors"):
            self.assertIn(key, summary)
        self.assertEqual(summary["total"], 20_000)
        self.assertTrue(summary["by_type"])

    def test_record_and_query(self):
        store = EventStore(":memory:")
        store.record("crypto.encrypt", actor="u1", outcome="success", bytes=42)
        rows = store.query("SELECT event_type, actor, bytes FROM events")
        self.assertEqual(rows, [("crypto.encrypt", "u1", 42)])

    def test_insert_many_runs_under_the_store_lock(self):
        store = EventStore(":memory:")
        self.assertTrue(store._lock.acquire(blocking=False))
        store._lock.release()
        held = []
        original = store._lock

        class SpyLock:
            def __enter__(self):
                held.append(True)
                return original.__enter__()

            def __exit__(self, *exc):
                return original.__exit__(*exc)

        store._lock = SpyLock()
        store.insert_many("INSERT INTO anomalies VALUES (?, ?, ?, ?, ?, ?)",
                          [("2026-11-15 10:00:00", "u1", 0.7, "rules", "auth_fail", None)])
        self.assertEqual(held, [True])
        self.assertEqual(store.query("SELECT count(*) FROM anomalies")[0][0], 1)

    def test_record_rejects_unknown_type(self):
        with self.assertRaises(ValueError):
            EventStore(":memory:").record("rm -rf", actor="x", outcome="success")

    def test_export_parquet_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.store.export_parquet(Path(tmp))
            n = duckdb.connect().execute(
                "SELECT count(*) FROM read_parquet(?)", [str(path)]).fetchone()[0]
            self.assertEqual(n, 20_000)

    def test_persistent_file_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "events.duckdb"
            store = EventStore(db)
            store.record("auth.login.failure", actor="a", outcome="failure")
            store.close()
            self.assertEqual(EventStore(db).count(), 1)

    def test_ingest_secureboard_security_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sb.db"
            conn = sqlite3.connect(path)
            conn.execute(
                "CREATE TABLE security_events (id INTEGER PRIMARY KEY, created_at TEXT, "
                "event_type TEXT, actor_user_id INTEGER, outcome TEXT, target_type TEXT, "
                "target_id INTEGER, request_method TEXT, request_path TEXT)")
            conn.executemany(
                "INSERT INTO security_events (created_at, event_type, actor_user_id, outcome, "
                "target_type, target_id, request_method, request_path) VALUES (?,?,?,?,?,?,?,?)",
                [("2026-11-10 10:00:00", "auth.login.failure", None, "failure", "user", None, "POST", "/login"),
                 ("2026-11-10 10:00:05", "auth.login.success", 1, "success", "user", 1, "POST", "/login"),
                 ("2026-11-10 10:01:00", "authz.admin.denied", 2, "denied", "admin", None, "GET", "/admin")])
            conn.commit()
            conn.close()
            store = EventStore(":memory:")
            self.assertEqual(store.ingest_secureboard(path), 3)
            types = sorted(r[0] for r in store.query("SELECT event_type FROM events"))
            self.assertIn("auth.login.failure", types)
            actors = {r[0] for r in store.query("SELECT actor FROM events")}
            self.assertNotIn("1", actors)  # pseudonymised, not raw ids
            consistent = EventStore(":memory:")
            consistent.ingest_secureboard(path, pseudonymize=lambda uid: f"sb:P-{uid}")
            actors = {r[0] for r in consistent.query("SELECT actor FROM events")}
            self.assertEqual(actors, {"sb:anonymous", "sb:P-1", "sb:P-2"})


if __name__ == "__main__":
    unittest.main()
