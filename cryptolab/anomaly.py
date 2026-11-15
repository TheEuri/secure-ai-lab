"""Behavioural anomaly detection over the CryptoLab event store.

Unit of analysis: one actor in one 5-minute window.  DuckDB aggregates the
raw events into a feature vector per window; an Isolation Forest (an
unsupervised model: it needs no attack examples to train) scores how easy
each window is to isolate from the rest.  A transparent rule baseline runs
beside it, and the hybrid detector is their union.  Synthetic events carry
ground-truth labels, so every detector is scored with precision/recall.
"""

from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from cryptolab.events import ANOMALY_LABELS, EventStore
from cryptolab.simulate import STABLE_RESOURCES

WINDOW = "5 minutes"
FEATURES = ("n_events", "auth_fail", "decrypt_fail", "file_modified",
            "distinct_ips", "distinct_resources", "off_hours_ratio", "bytes_sum")
DEFAULT_CONTAMINATION = 0.002

_STABLE_SQL = ", ".join(f"'{r}'" for r in STABLE_RESOURCES)
FEATURE_SQL = f"""
SELECT actor,
       time_bucket(INTERVAL '{WINDOW}', ts) AS window_start,
       count(*) AS n_events,
       count(*) FILTER (WHERE event_type = 'auth.login.failure') AS auth_fail,
       count(*) FILTER (WHERE event_type = 'crypto.decrypt.failure') AS decrypt_fail,
       count(*) FILTER (WHERE event_type = 'file.modified'
                       AND (resource IN ({_STABLE_SQL}) OR outcome = 'mismatch')) AS file_modified,
       count(DISTINCT source_ip) AS distinct_ips,
       count(DISTINCT resource) AS distinct_resources,
       avg(CASE WHEN hour(ts) < 7 OR hour(ts) >= 21 THEN 1.0 ELSE 0.0 END) AS off_hours_ratio,
       coalesce(sum(bytes), 0) AS bytes_sum,
       CASE WHEN count(label) = 0 THEN NULL
            ELSE coalesce(max(label) FILTER (WHERE label <> 'normal'), 'normal') END AS label
FROM events
WHERE event_type <> 'anomaly.detected'
GROUP BY 1, 2
ORDER BY 2, 1
"""


@dataclass
class DetectionReport:
    n_windows: int = 0
    n_flagged: int = 0
    metrics: dict = field(default_factory=dict)
    per_label_recall: dict = field(default_factory=dict)
    flagged_by: dict = field(default_factory=dict)
    top: list = field(default_factory=list)

    def as_dict(self):
        return {"n_windows": self.n_windows, "n_flagged": self.n_flagged,
                "metrics": self.metrics, "per_label_recall": self.per_label_recall,
                "flagged_by": self.flagged_by, "top": self.top}


def build_feature_windows(store: EventStore):
    rows = store.query(FEATURE_SQL)
    keys = [(r[0], r[1]) for r in rows]
    X = np.array([r[2:2 + len(FEATURES)] for r in rows], dtype=np.float64).reshape(-1, len(FEATURES))
    labels = [r[-1] for r in rows]
    return keys, X, labels


def rule_flags(X: np.ndarray) -> np.ndarray:
    f = {name: X[:, i] for i, name in enumerate(FEATURES)}
    flood_threshold = max(50.0, float(np.percentile(f["n_events"], 99.9))) if len(X) else 50.0
    return (
        (f["auth_fail"] >= 10)
        | (f["decrypt_fail"] >= 5)
        | (f["file_modified"] >= 1)
        | ((f["off_hours_ratio"] > 0.8) & ((f["distinct_ips"] >= 3) | (f["distinct_resources"] >= 10)))
        | (f["n_events"] > flood_threshold)
    )


def _score(flags, labels):
    tp = fp = fn = 0
    per_label = {label: [0, 0] for label in ANOMALY_LABELS}
    for flagged, label in zip(flags, labels):
        if label is None:
            continue
        positive = label != "normal"
        if positive:
            per_label.setdefault(label, [0, 0])
            per_label[label][1] += 1
            per_label[label][0] += int(flagged)
        tp += int(flagged and positive)
        fp += int(flagged and not positive)
        fn += int(positive and not flagged)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    metrics = {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
               "tp": tp, "fp": fp, "fn": fn}
    recall_by_label = {k: round(v[0] / v[1], 4) if v[1] else None for k, v in per_label.items()}
    return metrics, recall_by_label


def detect(store: EventStore, *, contamination: float = DEFAULT_CONTAMINATION,
           seed: int = 42) -> DetectionReport:
    keys, X, labels = build_feature_windows(store)
    report = DetectionReport(n_windows=len(keys))
    store.query("DELETE FROM anomalies")
    if len(keys) < 10:
        return report

    Z = StandardScaler().fit_transform(np.log1p(X))
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(Z)
    scores = -model.score_samples(Z)  # higher = more anomalous
    if_flags = model.predict(Z) == -1
    rules = rule_flags(X)
    hybrid = if_flags | rules

    for name, flags in (("isolation_forest", if_flags), ("rules", rules), ("hybrid", hybrid)):
        metrics, by_label = _score(flags, labels)
        report.metrics[name] = metrics
        report.per_label_recall[name] = by_label
        report.flagged_by[name] = int(flags.sum())
    report.n_flagged = int(hybrid.sum())

    def reasons(i):
        names = [FEATURES[j] for j in np.argsort(-Z[i]) if Z[i, j] > 3]
        return ",".join(names) or "combinação atípica"

    anomaly_rows, event_rows = [], []
    for i in np.flatnonzero(hybrid):
        actor, window_start = keys[i]
        why = reasons(i)
        for detector, flags in (("isolation_forest", if_flags), ("rules", rules)):
            if flags[i]:
                anomaly_rows.append((window_start, actor, float(scores[i]), detector, why, labels[i]))
        event_rows.append((window_start, actor, labels[i]))
    if anomaly_rows:
        store.conn.executemany("INSERT INTO anomalies VALUES (?, ?, ?, ?, ?, ?)", anomaly_rows)
    if event_rows:
        store.conn.executemany(
            "INSERT INTO events VALUES (?, 'anomaly.detected', ?, NULL, 'detector', 'alert', 0, 0, ?)",
            event_rows)

    top_idx = np.argsort(-scores)[:20]
    report.top = [{"actor": keys[i][0], "window_start": str(keys[i][1]),
                   "score": round(float(scores[i]), 4), "label": labels[i],
                   "reasons": reasons(i), "rules": bool(rules[i])} for i in top_idx]
    return report
