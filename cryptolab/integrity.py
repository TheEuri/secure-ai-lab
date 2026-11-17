"""File integrity monitoring with SHA-256 (real "file.modified" events).

A baseline maps each monitored file to its SHA-256 digest.  The baseline is
signed with HMAC-SHA256 under a key derived from the master key (purpose
"integrity"): an attacker who changes a file cannot simply re-baseline it.
Each check is written to the event store, so unexpected changes feed the
same anomaly pipeline as the synthetic telemetry.
"""

import hashlib
import hmac
import json
from pathlib import Path

from cryptolab.keys import KeyRing, derive_key

DEFAULT_FILES = (
    "run.py",
    "requirements.txt",
    "cryptolab/cipher.py",
    "cryptolab/keys.py",
    "apps/cryptolab/routes.py",
    "templates/base.html",
)


class BaselineTamperedError(Exception):
    """The stored baseline does not carry a valid HMAC."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_baseline(root, paths) -> dict:
    root = Path(root)
    return {rel: sha256_file(root / rel) for rel in paths if (root / rel).is_file()}


def check_integrity(root, baseline: dict) -> list:
    root = Path(root)
    results = []
    for rel, expected in sorted(baseline.items()):
        path = root / rel
        actual = sha256_file(path) if path.is_file() else None
        status = "missing" if actual is None else ("match" if hmac.compare_digest(actual, expected)
                                                   else "mismatch")
        results.append({"path": rel, "status": status, "expected": expected, "actual": actual})
    return results


def _mac(ring: KeyRing, key_id: int, files: dict) -> str:
    key = derive_key(ring.master(key_id), b"", "integrity")
    body = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def save_baseline(ring: KeyRing, files: dict, target) -> None:
    doc = {"key_id": ring.active_id, "files": files, "mac": _mac(ring, ring.active_id, files)}
    Path(target).write_text(json.dumps(doc, indent=1, sort_keys=True))


def load_baseline(ring: KeyRing, target) -> dict:
    try:
        doc = json.loads(Path(target).read_text())
        files, key_id = doc["files"], int(doc["key_id"])
        expected = _mac(ring, key_id, files)
    except (ValueError, KeyError, TypeError) as exc:
        raise BaselineTamperedError() from exc
    if not hmac.compare_digest(expected, str(doc.get("mac", ""))):
        raise BaselineTamperedError()
    return files


def record_results(store, results, *, actor: str, source_ip: str = "127.0.0.1", ts=None) -> None:
    for r in results:
        if r["status"] == "match":
            store.record("file.read", actor=actor, outcome="success", source_ip=source_ip,
                         resource=r["path"], ts=ts)
        else:
            store.record("file.modified", actor=actor, outcome="mismatch", source_ip=source_ip,
                         resource=r["path"], ts=ts)
