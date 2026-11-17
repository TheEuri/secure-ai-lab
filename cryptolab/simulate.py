"""Synthetic, labelled security telemetry for the Big Data / AI experiments.

Normal behaviour: ~200 users working mostly in business hours from a stable
IP, encrypting/decrypting messages and reading their own documents.  Five
anomaly families are injected as short episodes and carry a ground-truth
``label`` so detectors can be scored (precision/recall), something real
logs cannot provide.
"""

import time

import numpy as np

from cryptolab.events import ANOMALY_LABELS, EventStore

START = np.datetime64("2026-11-02T00:00:00", "us")
US_PER_MIN = 60_000_000
STABLE_RESOURCES = ("config/keyring.json", "static/app.js", "templates/base.html")

NORMAL_TYPES = np.array([
    "auth.login.success", "auth.login.failure", "crypto.encrypt",
    "crypto.decrypt.success", "crypto.decrypt.failure", "file.read",
    "file.modified", "stego.embed", "stego.extract"])
NORMAL_P = np.array([0.10, 0.01, 0.25, 0.30, 0.005, 0.25, 0.02, 0.03, 0.035])
NORMAL_P = NORMAL_P / NORMAL_P.sum()
FAILURE_TYPES = {"auth.login.failure", "crypto.decrypt.failure"}

# (min, max) events per episode
EPISODE_SIZE = {
    "bruteforce": (60, 200),
    "decrypt_storm": (30, 100),
    "file_tamper": (1, 3),
    "atypical_access": (20, 60),
    "event_flood": (300, 800),
}


def _ip(rng, n, prefix="10.0"):
    return np.char.add(f"{prefix}.", np.char.add(
        rng.integers(0, 255, n).astype(str), np.char.add(".", rng.integers(1, 255, n).astype(str))))


def _episode(rng, label, actor, start_us, size):
    """Return dict of arrays for one anomaly episode inside a 5-minute burst."""

    offsets = np.sort(rng.integers(0, 5 * US_PER_MIN, size))
    ts = START + (start_us + offsets).astype("timedelta64[us]")
    actor_arr = np.full(size, actor)
    resource = np.full(size, "", dtype=object)
    outcome = np.full(size, "success", dtype=object)
    if label == "bruteforce":
        types = np.full(size, "auth.login.failure")
        outcome[:] = "failure"
        ips = np.full(size, _ip(rng, 1, "203.0")[0])
        resource[:] = "/login"
    elif label == "decrypt_storm":
        types = np.full(size, "crypto.decrypt.failure")
        outcome[:] = "failure"
        ips = np.full(size, _ip(rng, 1, "198.51")[0])
        resource[:] = "/direct"
    elif label == "file_tamper":
        types = np.full(size, "file.modified")
        ips = np.full(size, _ip(rng, 1, "192.0")[0])
        resource[:] = rng.choice(STABLE_RESOURCES)
    elif label == "atypical_access":
        types = np.full(size, "file.read")
        ips = _ip(rng, size, "100.64")[rng.integers(0, 5, size)] if size else np.array([])
        resource[:] = np.char.add("doc-u", rng.integers(0, 200, size).astype(str)).astype(object)
    else:  # event_flood
        types = rng.choice(["crypto.encrypt", "stego.embed", "crypto.decrypt.success"], size)
        ips = np.full(size, _ip(rng, 1, "10.9")[0])
        resource[:] = "/api"
    return {"ts": ts, "event_type": types.astype(object), "actor": actor_arr.astype(object),
            "source_ip": np.asarray(ips).astype(object), "resource": resource,
            "outcome": outcome, "label": np.full(size, label, dtype=object)}


def simulate(store: EventStore, n_events: int = 1_000_000, *, seed: int = 42,
             days: int = 7, n_actors: int = 200, anomaly_share: float = 0.02) -> dict:
    rng = np.random.default_rng(seed)
    span_us = days * 24 * 60 * US_PER_MIN
    actors = np.array([f"u{i:03d}" for i in range(n_actors)])
    home_ip = _ip(rng, n_actors)

    # --- anomaly episodes ------------------------------------------------
    chunks, counts = [], {}
    budget = int(n_events * anomaly_share)
    per_label = budget // len(ANOMALY_LABELS)
    for label in ANOMALY_LABELS:
        lo, hi = EPISODE_SIZE[label]
        used, episodes = 0, 0
        max_episodes = max(3, n_events // 50_000) if label == "file_tamper" else 10**9
        while ((used < per_label or episodes < 3) and episodes < max_episodes
               and used + lo <= max(per_label, 3 * hi)):
            size = int(rng.integers(lo, hi + 1))
            actor = actors[rng.integers(0, n_actors)]
            if label in ("file_tamper", "atypical_access"):
                day = int(rng.integers(0, days))
                start = (day * 24 + int(rng.integers(1, 5))) * 60 * US_PER_MIN  # 01h-05h
            else:
                start = int(rng.integers(0, span_us - 5 * US_PER_MIN))
            chunks.append(_episode(rng, label, actor, start, size))
            used += size
            episodes += 1
        counts[label] = {"events": used, "episodes": episodes}
    n_anom = sum(c["events"] for c in counts.values())
    n_normal = n_events - n_anom
    if n_normal <= 0:
        raise ValueError("n_events too small for the anomaly budget")

    # --- normal behaviour ------------------------------------------------
    idx = rng.integers(0, n_actors, n_normal)
    day = rng.integers(0, days, n_normal)
    business = rng.random(n_normal) < 0.92
    hour = np.where(business, rng.normal(13.5, 2.6, n_normal).clip(8, 19.9),
                    rng.uniform(0, 24, n_normal))
    offs = ((day * 24 + hour) * 60 * US_PER_MIN).astype(np.int64)
    types = rng.choice(NORMAL_TYPES, n_normal, p=NORMAL_P)
    outcome = np.where(np.isin(types, list(FAILURE_TYPES)), "failure", "success")
    resource = np.char.add(np.char.add("doc-", actors[idx]),
                           np.char.add("-", rng.integers(0, 5, n_normal).astype(str)))
    reads_stable = (types == "file.read") & (rng.random(n_normal) < 0.1)
    resource = np.where(reads_stable, rng.choice(STABLE_RESOURCES, n_normal), resource)
    chunks.append({
        "ts": START + offs.astype("timedelta64[us]"),
        "event_type": types.astype(object), "actor": actors[idx].astype(object),
        "source_ip": home_ip[idx].astype(object), "resource": resource.astype(object),
        "outcome": outcome.astype(object), "label": np.full(n_normal, "normal", dtype=object)})

    cols = {k: np.concatenate([c[k] for c in chunks]) for k in chunks[0]}
    n = len(cols["ts"])
    cols["bytes"] = rng.lognormal(7, 1.2, n).astype(np.int64)
    cols["latency_ms"] = np.round(rng.gamma(2.0, 1.5, n), 3)
    order = np.argsort(cols["ts"], kind="stable")
    cols = {k: v[order] for k, v in cols.items()}

    started = time.perf_counter()
    store.bulk_insert_arrays(cols)
    ingest_s = time.perf_counter() - started
    return {"n_events": n, "anomalies": counts, "normal_events": int(n_normal),
            "ingest_seconds": round(ingest_s, 3),
            "events_per_second": int(n / ingest_s) if ingest_s else None}
