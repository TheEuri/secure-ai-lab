"""Glue between the Flask app configuration and the cryptolab package."""

import json
from contextlib import contextmanager
from pathlib import Path

from flask import current_app

from common.privacy import PrivacyConfigurationError, user_pseudonym
from cryptolab.anomaly import detect
from cryptolab.events import EventStore
from cryptolab.experiments import run_all
from cryptolab.keys import KeyRing
from cryptolab.simulate import simulate

EVENTS_DB = "events.duckdb"
DETECTION_FILE = "detection.json"


class KeyRingUnavailable(RuntimeError):
    pass


def lab_dir() -> Path:
    return Path(current_app.config["CRYPTOLAB_DIR"])


@contextmanager
def open_store(directory: Path = None):
    """Open the DuckDB store only for the duration of one request/command.

    DuckDB allows a single writer process; short-lived connections let the
    CLI and the web server take turns on the same file.
    """

    store = EventStore((directory or lab_dir()) / EVENTS_DB)
    try:
        yield store
    finally:
        store.close()


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
