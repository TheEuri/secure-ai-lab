"""Columnar event store (DuckDB) for CryptoLab telemetry.

Why DuckDB: the workload is append-mostly telemetry followed by analytical
scans (group-by per actor and time window over millions of rows).  A
columnar, vectorised engine answers those scans in milliseconds on one
machine and exports to Parquet, the interchange format used by Spark,
Athena or BigQuery if the data outgrows a single node.  SQLite (row store)
remains the transactional database of the web application.
"""

import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

import duckdb

EVENT_TYPES = (
    "auth.login.success",
    "auth.login.failure",
    "crypto.encrypt",
    "crypto.decrypt.success",
    "crypto.decrypt.failure",
    "file.read",
    "file.modified",
    "stego.embed",
    "stego.extract",
    "anomaly.detected",
)
ANOMALY_LABELS = ("bruteforce", "decrypt_storm", "file_tamper", "atypical_access", "event_flood")
_EVENT_TYPE_RE = re.compile(r"^[a-z]+(\.[a-z_]+){1,3}$")
COLUMNS = ("ts", "event_type", "actor", "source_ip", "resource", "outcome",
           "bytes", "latency_ms", "label")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    ts TIMESTAMP NOT NULL,
    event_type VARCHAR NOT NULL,
    actor VARCHAR NOT NULL,
    source_ip VARCHAR,
    resource VARCHAR,
    outcome VARCHAR NOT NULL,
    bytes BIGINT,
    latency_ms DOUBLE,
    label VARCHAR
);
CREATE TABLE IF NOT EXISTS anomalies (
    window_start TIMESTAMP NOT NULL,
    actor VARCHAR NOT NULL,
    score DOUBLE NOT NULL,
    detector VARCHAR NOT NULL,
    reasons VARCHAR,
    label VARCHAR
);
"""


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class EventStore:
    def __init__(self, path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(self.path)
        self.conn.execute(SCHEMA)
        self._lock = threading.Lock()

    def close(self):
        self.conn.close()

    # -- writes ---------------------------------------------------------
    def record(self, event_type, *, actor, outcome, source_ip="127.0.0.1", resource="",
               bytes=0, latency_ms=0.0, label=None, ts=None):
        if not isinstance(event_type, str) or not _EVENT_TYPE_RE.fullmatch(event_type):
            raise ValueError("invalid event type")
        with self._lock:
            self.conn.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [ts or _now(), event_type, str(actor), source_ip, resource, outcome,
                 int(bytes), float(latency_ms), label],
            )

    def bulk_insert_arrays(self, cols: dict):
        missing = set(COLUMNS) - set(cols)
        if missing:
            raise ValueError(f"missing columns: {sorted(missing)}")
        batch = {name: cols[name] for name in COLUMNS}  # noqa: F841 (scanned by DuckDB)
        with self._lock:
            self.conn.execute(f"INSERT INTO events SELECT {', '.join(COLUMNS)} FROM batch")

    def insert_many(self, sql, rows):
        with self._lock:
            self.conn.executemany(sql, rows)

    def ingest_secureboard(self, sqlite_path, pseudonym_key: bytes = None, pseudonymize=None) -> int:
        """Import SecureBoard's real audit trail with pseudonymised actors.

        ``pseudonymize(user_id)`` should be the same function the web app uses
        (keyed HMAC from ``PSEUDONYMIZATION_KEY``), so one person keeps one
        pseudonym across imported and live events.  Without it a throw-away
        key is used: actors stay consistent only within this import.
        """

        key = pseudonym_key or secrets.token_bytes(32)
        conn = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT created_at, event_type, actor_user_id, outcome, request_path "
                "FROM security_events ORDER BY id").fetchall()
        finally:
            conn.close()
        count = 0
        for created_at, event_type, actor_id, outcome, path in rows:
            if not _EVENT_TYPE_RE.fullmatch(event_type or ""):
                continue
            if actor_id is None:
                actor = "sb:anonymous"
            elif pseudonymize is not None:
                actor = pseudonymize(actor_id)
            else:
                actor = "sb:" + hmac.new(key, str(actor_id).encode(), hashlib.sha256).hexdigest()[:12]
            ts = datetime.fromisoformat(str(created_at)) if created_at else _now()
            self.record(event_type, actor=actor, outcome=outcome or "unknown",
                        resource=path or "", ts=ts)
            count += 1
        return count

    # -- reads ----------------------------------------------------------
    def count(self) -> int:
        return self.conn.execute("SELECT count(*) FROM events").fetchone()[0]

    def query(self, sql, params=()):
        with self._lock:
            return self.conn.execute(sql, list(params)).fetchall()

    def summary(self) -> dict:
        q = self.query
        return {
            "total": self.count(),
            "by_type": q("SELECT event_type, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC"),
            "by_outcome": q("SELECT outcome, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC"),
            "per_hour": q(
                "SELECT date_trunc('hour', ts) AS h, count(*), "
                "count(*) FILTER (WHERE outcome = 'failure'), "
                "count(*) FILTER (WHERE label IS NOT NULL AND label <> 'normal') "
                "FROM events GROUP BY 1 ORDER BY 1"),
            "top_failing_actors": q(
                "SELECT actor, count(*) FROM events WHERE outcome = 'failure' "
                "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"),
            "anomalies": q("SELECT count(*) FROM anomalies")[0][0],
        }

    def export_parquet(self, out_dir) -> Path:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        target = out_dir / "events.parquet"
        with self._lock:
            self.conn.execute(
                f"COPY events TO '{target.as_posix()}' (FORMAT PARQUET, COMPRESSION ZSTD)")
        return target
