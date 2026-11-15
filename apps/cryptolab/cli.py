import json
import shutil
from pathlib import Path

import click
from flask import current_app
from flask.cli import with_appcontext

from apps.cryptolab.service import (DETECTION_FILE, KeyRingUnavailable, actor_pseudonymizer,
                                    get_keyring, lab_dir, open_store, run_integrity_check,
                                    run_pipeline)
from cryptolab.anomaly import detect
from cryptolab.experiments import run_all
from cryptolab.keys import KeyRing
from cryptolab.simulate import simulate


@click.command("cryptolab-genkey")
def genkey_command():
    """Print a new CryptoLab key ring line for the .env file."""
    click.echo("CRYPTOLAB_MASTER_KEYS=" + KeyRing.generate().to_env())


@click.command("cryptolab-simulate")
@click.option("--events", default=1_000_000, show_default=True)
@click.option("--seed", default=42, show_default=True)
@with_appcontext
def simulate_command(events, seed):
    """Generate labelled synthetic telemetry into the event store."""
    lab_dir().mkdir(parents=True, exist_ok=True)
    with open_store() as store:
        click.echo(json.dumps(simulate(store, n_events=events, seed=seed)))


@click.command("cryptolab-ingest")
@with_appcontext
def ingest_command():
    """Import SecureBoard security_events (pseudonymised) into the event store."""
    lab_dir().mkdir(parents=True, exist_ok=True)
    with open_store() as store:
        count = store.ingest_secureboard(current_app.config["DATABASE"],
                                         pseudonymize=actor_pseudonymizer())
        click.echo(f"ingested={count}")


@click.command("cryptolab-detect")
@with_appcontext
def detect_command():
    """Run anomaly detection over the event store."""
    with open_store() as store:
        report = detect(store).as_dict()
    (lab_dir() / DETECTION_FILE).write_text(json.dumps(report, ensure_ascii=False, indent=1, default=str))
    click.echo(json.dumps(report["metrics"]))


@click.command("cryptolab-experiments")
@click.option("--quick", is_flag=True)
@with_appcontext
def experiments_command(quick):
    """Run brute-force, differential and statistical attacks."""
    lab_dir().mkdir(parents=True, exist_ok=True)
    with open_store() as store:
        results = run_all(store, lab_dir(), quick=quick)
    click.echo(json.dumps(results["conclusions"]["avalanche"]))


@click.command("cryptolab-all")
@click.option("--events", default=1_000_000, show_default=True)
@click.option("--quick", is_flag=True)
@click.option("--keep", is_flag=True, help="Keep existing events instead of starting fresh.")
@with_appcontext
def all_command(events, quick, keep):
    """Full pipeline: simulate → attacks → detection → parquet export."""
    directory = lab_dir()
    if not keep and directory.exists():
        for name in ("events.duckdb", "events.duckdb.wal"):
            (directory / name).unlink(missing_ok=True)
        shutil.rmtree(directory / "parquet", ignore_errors=True)
    directory.mkdir(parents=True, exist_ok=True)
    with open_store() as store:
        if current_app.config.get("DATABASE") and Path(current_app.config["DATABASE"]).exists():
            try:
                store.ingest_secureboard(current_app.config["DATABASE"],
                                         pseudonymize=actor_pseudonymizer())
            except Exception:  # noqa: BLE001 - real audit trail is optional for the lab
                click.echo("warning: SecureBoard events not ingested")
        out = run_pipeline(store, directory, events=events, quick=quick)
    click.echo(json.dumps({"simulation": out["results"].get("simulation"),
                           "detection": out["detection"]["metrics"]}, default=str))


@click.command("cryptolab-integrity")
@click.option("--reset", is_flag=True, help="Re-sign the baseline after a legitimate change.")
@with_appcontext
def integrity_command(reset):
    """Check critical files against the HMAC-signed SHA-256 baseline."""
    try:
        ring = get_keyring()
    except KeyRingUnavailable as exc:
        raise click.ClickException("CRYPTOLAB_MASTER_KEYS não configurada") from exc
    status = run_integrity_check(ring, "cli:operator", "127.0.0.1", reset=reset)
    for r in status["results"]:
        click.echo(f"{r['path']}: {r['status']}")
    if any(r["status"] != "match" for r in status["results"]):
        raise SystemExit(1)


def register_cryptolab_cli(app):
    for command in (genkey_command, simulate_command, ingest_command, detect_command,
                    experiments_command, all_command, integrity_command):
        if command.name not in app.cli.commands:
            app.cli.add_command(command)
