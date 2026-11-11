import json
import random
import tempfile
import unittest
from pathlib import Path

from cryptolab.attacks import (
    SAMPLE_TEXT_PT,
    avalanche,
    brute_force,
    ecb_image_leak,
    frequency_attack_xor,
    sac_matrix,
    statistics,
)
from cryptolab.cipher import get_variant
from cryptolab.events import EventStore
from cryptolab.experiments import run_all


class AvalancheTests(unittest.TestCase):
    def test_full_sbx_has_avalanche(self):
        for flip in ("plaintext", "key"):
            mean = avalanche("sbx-10r-cbc", samples=80, flip=flip)["mean"]
            self.assertTrue(0.45 <= mean <= 0.55, (flip, mean))

    def test_one_round_ecb_has_no_plaintext_avalanche(self):
        self.assertLess(avalanche("sbx-1r-ecb", samples=80)["mean"], 0.15)

    def test_xor_has_no_avalanche(self):
        self.assertLess(avalanche("xor-repeating", samples=80)["mean"], 0.02)

    def test_histogram_shape(self):
        result = avalanche("sbx-10r-ecb", samples=20)
        self.assertEqual(sum(result["histogram"]), 20)
        for key in ("mean", "std", "min", "max", "bits_compared"):
            self.assertIn(key, result)


class SacTests(unittest.TestCase):
    def test_sac_matrix_shape_and_quality(self):
        ten = sac_matrix(rounds=10, samples=24)
        one = sac_matrix(rounds=1, samples=24)
        self.assertEqual(len(ten["matrix"]), 128)
        self.assertEqual(len(ten["matrix"][0]), 128)
        self.assertLess(ten["mean_abs_deviation"], one["mean_abs_deviation"])


class StatisticalTests(unittest.TestCase):
    def setUp(self):
        self.text = (SAMPLE_TEXT_PT * 40).encode()

    def test_full_sbx_output_looks_uniform(self):
        stats = statistics("sbx-10r-cbc", self.text, seed=3)
        self.assertGreater(stats["chi2_p_value"], 0.001)
        self.assertGreater(stats["entropy_bits_per_byte"], 7.9)

    def test_xor_output_keeps_language_statistics(self):
        stats = statistics("xor-repeating", self.text, seed=3)
        self.assertLess(stats["chi2_p_value"], 1e-6)
        self.assertLess(stats["entropy_bits_per_byte"], 6.5)

    def test_ecb_repeats_blocks_cbc_does_not(self):
        pattern = b"0123456789ABCDEF" * 200
        self.assertGreater(statistics("sbx-10r-ecb", pattern, seed=3)["repeated_blocks"], 100)
        self.assertEqual(statistics("sbx-10r-cbc", pattern, seed=3)["repeated_blocks"], 0)

    def test_frequency_attack_breaks_repeating_xor(self):
        key = random.Random(5).randbytes(32)
        ct = get_variant("xor-repeating").encrypt(key, SAMPLE_TEXT_PT.encode())
        result = frequency_attack_xor(ct)
        self.assertTrue(result["success"])
        self.assertEqual(result["recovered_key"], key[:4].hex())
        self.assertEqual(result["key_length"], 4)

    def test_frequency_attack_fails_on_sbx(self):
        key = random.Random(5).randbytes(32)
        ct = get_variant("sbx-10r-cbc").encrypt(key, SAMPLE_TEXT_PT.encode(), iv=bytes(16))
        self.assertFalse(frequency_attack_xor(ct)["success"])


class BruteForceTests(unittest.TestCase):
    def test_recovers_reduced_key(self):
        for name in ("xor-repeating", "sbx-10r-cbc"):
            result = brute_force(name, unknown_bits=6, seed=2)
            self.assertTrue(result["found"], name)
            self.assertGreater(result["keys_per_second"], 0)
            self.assertEqual(result["full_space_log2"], get_variant(name).key_bits)

    def test_full_keyspace_is_infeasible_for_256_bits(self):
        result = brute_force("sbx-10r-cbc", unknown_bits=4, seed=2)
        self.assertGreater(result["years_full_space_at_1e12"], 1e50)


class EcbImageTests(unittest.TestCase):
    def test_images_have_same_size(self):
        images = ecb_image_leak(["sbx-10r-ecb", "sbx-10r-cbc"])
        self.assertEqual(set(images), {"original", "sbx-10r-ecb", "sbx-10r-cbc"})
        sizes = {img.size for img in images.values()}
        self.assertEqual(len(sizes), 1)


class RunAllTests(unittest.TestCase):
    def test_run_all_quick(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(":memory:")
            results = run_all(store, Path(tmp), quick=True)
            saved = json.loads((Path(tmp) / "results.json").read_text())
            for key in ("brute_force", "avalanche", "sac", "statistics",
                        "frequency_attack", "stego", "conclusions"):
                self.assertIn(key, saved)
            self.assertEqual(saved["conclusions"], results["conclusions"])
            self.assertTrue((Path(tmp) / "ecb_sbx-10r-ecb.png").exists())
            self.assertTrue(saved["stego"]["tamper_detected"])
            self.assertTrue(saved["stego"]["recovered"])
            self.assertGreater(store.count(), 0)


if __name__ == "__main__":
    unittest.main()


class CiphertextOnlyAvalancheTests(unittest.TestCase):
    """The HMAC/GCM tag flips ~50% regardless of the cipher; measure the body too."""

    def test_body_avalanche_separates_rounds_under_full_envelope(self):
        full = avalanche("sbx-10r-cbc", samples=60)
        self.assertTrue(0.45 <= full["body_mean"] <= 0.55, full["body_mean"])
        self.assertEqual(full["body_bits"], 128)

    def test_gcm_body_has_no_plaintext_diffusion(self):
        self.assertLess(avalanche("aes-256-gcm", samples=60)["body_mean"], 0.02)

    def test_body_equals_total_when_no_tag(self):
        r = avalanche("sbx-10r-ecb", samples=20)
        self.assertEqual(r["body_mean"], r["mean"])
