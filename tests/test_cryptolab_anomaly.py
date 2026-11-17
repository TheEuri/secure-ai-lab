import unittest

from cryptolab.anomaly import FEATURES, RULES, build_feature_windows, detect
from cryptolab.events import EventStore
from cryptolab.simulate import simulate


class AnomalyDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = EventStore(":memory:")
        simulate(cls.store, n_events=60_000, seed=11)
        cls.report = detect(cls.store, seed=11)

    def test_feature_windows(self):
        keys, X, labels = build_feature_windows(self.store)
        self.assertEqual(X.shape, (len(keys), len(FEATURES)))
        self.assertEqual(len(labels), len(keys))
        self.assertIn("normal", labels)
        self.assertIn("bruteforce", labels)

    def test_isolation_forest_catches_volumetric_attacks(self):
        recall = self.report.per_label_recall["isolation_forest"]
        self.assertGreaterEqual(recall["bruteforce"], 0.7)
        self.assertGreaterEqual(recall["event_flood"], 0.7)

    def test_some_detector_is_precise(self):
        best = max(m["precision"] for m in self.report.metrics.values())
        self.assertGreaterEqual(best, 0.5)

    def test_hybrid_detector_reported(self):
        self.assertIn("hybrid", self.report.metrics)
        self.assertGreaterEqual(self.report.metrics["hybrid"]["recall"],
                                self.report.metrics["isolation_forest"]["recall"])

    def test_anomalies_persisted_and_logged(self):
        n = self.store.query("SELECT count(*) FROM anomalies")[0][0]
        self.assertGreater(n, 0)
        logged = self.store.query(
            "SELECT count(*) FROM events WHERE event_type = 'anomaly.detected'")[0][0]
        self.assertGreater(logged, 0)

    def test_reasons_explain_bruteforce(self):
        reasons = [r for (r,) in self.store.query(
            "SELECT reasons FROM anomalies WHERE label = 'bruteforce' AND detector = 'isolation_forest'")]
        self.assertTrue(reasons)
        self.assertTrue(any("auth_fail" in r for r in reasons))

    def test_top_alerts_say_which_detector_fired_and_why(self):
        self.assertTrue(self.report.top)
        for alert in self.report.top:
            self.assertIsInstance(alert["isolation_forest"], bool)
            self.assertIsInstance(alert["rules_fired"], list)
            self.assertEqual(alert["rules"], bool(alert["rules_fired"]))
            self.assertEqual(set(alert["features"]), set(FEATURES))
            self.assertTrue(set(alert["rules_fired"]) <= set(RULES))
        brute = [a for a in self.report.top if a["label"] == "bruteforce" and a["rules"]]
        self.assertTrue(brute)
        self.assertIn("login_bruteforce", brute[0]["rules_fired"])

    def test_rule_only_alerts_are_reported(self):
        rule_only = self.report.as_dict()["rule_only"]
        self.assertTrue(rule_only)
        for alert in rule_only:
            self.assertFalse(alert["isolation_forest"])
            self.assertTrue(alert["rules_fired"])
        self.assertIn("file_tamper", {a["label"] for a in rule_only})

    def test_empty_store(self):
        report = detect(EventStore(":memory:"))
        self.assertEqual(report.n_windows, 0)
        self.assertEqual(report.n_flagged, 0)


if __name__ == "__main__":
    unittest.main()
