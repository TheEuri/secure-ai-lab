"""Glue between the Flask app configuration and the cryptolab package."""

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import duckdb
from flask import current_app

from common.privacy import PrivacyConfigurationError, user_pseudonym
from cryptolab.anomaly import detect
from cryptolab.events import EventStore
from cryptolab.integrity import (DEFAULT_FILES, BaselineTamperedError, check_integrity,
                                 create_baseline, load_baseline, record_results, save_baseline)
from cryptolab.experiments import run_all
from cryptolab.keys import KeyRing
from cryptolab.simulate import simulate

EVENTS_DB = "events.duckdb"
DETECTION_FILE = "detection.json"
INTEGRITY_BASELINE = "integrity_baseline.json"
INTEGRITY_STATUS = "integrity_status.json"


class KeyRingUnavailable(RuntimeError):
    pass


class StoreBusy(RuntimeError):
    """The DuckDB file is locked by another process (e.g. a running CLI job)."""


def lab_dir() -> Path:
    return Path(current_app.config["CRYPTOLAB_DIR"])


@contextmanager
def open_store(directory: Path = None):
    """Open the DuckDB store only for the duration of one request/command.

    DuckDB allows a single writer process; short-lived connections let the
    CLI and the web server take turns on the same file.
    """

    try:
        store = EventStore((directory or lab_dir()) / EVENTS_DB)
    except duckdb.IOException as exc:
        raise StoreBusy() from exc
    try:
        yield store
    finally:
        store.close()


def record_events(events) -> bool:
    """Best-effort telemetry: never let a locked store break the user action."""

    try:
        with open_store() as store:
            for event_type, fields in events:
                store.record(event_type, **fields)
        return True
    except StoreBusy:
        current_app.logger.warning("cryptolab event store busy; %d events dropped", len(events))
        return False


def get_keyring() -> KeyRing:
    value = current_app.config.get("CRYPTOLAB_MASTER_KEYS")
    if not value:
        raise KeyRingUnavailable()
    try:
        return KeyRing.from_env(value)
    except ValueError as exc:
        raise KeyRingUnavailable() from exc


def actor_for(user) -> str:
    try:
        return "sb:" + user_pseudonym(user["id"])
    except (PrivacyConfigurationError, KeyError, TypeError):
        return "sb:admin"


def load_json(name):
    path = lab_dir() / name
    return json.loads(path.read_text()) if path.exists() else None


def run_pipeline(store: EventStore, directory: Path, *, events: int = 0, quick: bool = False,
                 seed: int = 42) -> dict:
    """simulate (optional) → attacks/experiments → anomaly detection → parquet."""

    sim = simulate(store, n_events=events, seed=seed) if events else None
    results = run_all(store, directory, quick=quick)
    if sim:
        results["simulation"] = sim
        (directory / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=1))
    report = detect(store, seed=seed)
    (directory / DETECTION_FILE).write_text(json.dumps(report.as_dict(), ensure_ascii=False,
                                                       indent=1, default=str))
    store.export_parquet(directory / "parquet")
    return {"results": results, "detection": report.as_dict()}


def run_integrity_check(ring: KeyRing, actor: str, source_ip: str, *, reset: bool = False) -> dict:
    """Check monitored files against the HMAC-signed SHA-256 baseline.

    The first run creates the baseline (trust on first use).  A baseline
    whose HMAC does not verify is treated as an attack: every file is
    reported and nothing is re-baselined automatically.
    """

    root = Path(current_app.config.get("CRYPTOLAB_INTEGRITY_ROOT") or current_app.root_path)
    paths = current_app.config.get("CRYPTOLAB_INTEGRITY_FILES") or DEFAULT_FILES
    directory = lab_dir()
    directory.mkdir(parents=True, exist_ok=True)
    baseline_path = directory / INTEGRITY_BASELINE
    created = reset or not baseline_path.exists()
    if created:
        save_baseline(ring, create_baseline(root, paths), baseline_path)
    try:
        baseline = load_baseline(ring, baseline_path)
        results = check_integrity(root, baseline)
        tampered = False
    except BaselineTamperedError:
        tampered = True
        results = [{"path": INTEGRITY_BASELINE, "status": "mismatch", "expected": None, "actual": None}]
    try:
        with open_store() as store:
            record_results(store, results, actor=actor, source_ip=source_ip)
    except StoreBusy:
        current_app.logger.warning("cryptolab event store busy; integrity events dropped")
    status = {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "baseline_created": created, "baseline_tampered": tampered, "results": results}
    (directory / INTEGRITY_STATUS).write_text(json.dumps(status, ensure_ascii=False, indent=1))
    return status
