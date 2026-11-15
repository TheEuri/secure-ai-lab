import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from cryptolab.anomaly import FEATURES, build_feature_windows
from cryptolab.events import EventStore
from cryptolab.integrity import (BaselineTamperedError, check_integrity, create_baseline,
                                 load_baseline, record_results, save_baseline)
from cryptolab.keys import KeyRing


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "app.py").write_text("print('ok')\n")
        (self.root / "conf").mkdir()
        (self.root / "conf" / "keys.json").write_text("{}")
        self.paths = ("app.py", "conf/keys.json")
        self.ring = KeyRing.generate()

    def tearDown(self):
        self.tmp.cleanup()

    def test_untouched_files_match(self):
        baseline = create_baseline(self.root, self.paths)
        statuses = {r["path"]: r["status"] for r in check_integrity(self.root, baseline)}
        self.assertEqual(statuses, {"app.py": "match", "conf/keys.json": "match"})

    def test_changed_and_deleted_files_are_reported(self):
        baseline = create_baseline(self.root, self.paths)
        (self.root / "app.py").write_text("print('backdoor')\n")
        (self.root / "conf" / "keys.json").unlink()
        statuses = {r["path"]: r["status"] for r in check_integrity(self.root, baseline)}
        self.assertEqual(statuses, {"app.py": "mismatch", "conf/keys.json": "missing"})

    def test_baseline_is_hmac_signed(self):
        target = self.root / "baseline.json"
        save_baseline(self.ring, create_baseline(self.root, self.paths), target)
        self.assertEqual(load_baseline(self.ring, target)["app.py"],
                         create_baseline(self.root, self.paths)["app.py"])
        doc = json.loads(target.read_text())
        doc["files"]["app.py"] = "0" * 64  # attacker "re-baselines" a modified file
        target.write_text(json.dumps(doc))
        with self.assertRaises(BaselineTamperedError):
            load_baseline(self.ring, target)

    def test_baseline_from_other_key_is_rejected(self):
        target = self.root / "baseline.json"
        save_baseline(KeyRing.generate(), create_baseline(self.root, self.paths), target)
        with self.assertRaises(BaselineTamperedError):
            load_baseline(self.ring, target)

    def test_mismatch_feeds_anomaly_features(self):
        baseline = create_baseline(self.root, self.paths)
        (self.root / "app.py").write_text("changed")
        store = EventStore(":memory:")
        record_results(store, check_integrity(self.root, baseline), actor="sb:admin",
                       ts=datetime(2026, 11, 15, 3, 0))
        kinds = dict(store.query("SELECT outcome, count(*) FROM events GROUP BY 1"))
        self.assertEqual(kinds, {"success": 1, "mismatch": 1})
        _, X, _ = build_feature_windows(store)
        self.assertEqual(X[:, FEATURES.index("file_modified")].sum(), 1)


if __name__ == "__main__":
    unittest.main()
