import unittest

from apps.cryptolab.charts import compact_number, hbar_chart


class ChartTests(unittest.TestCase):
    def test_compact_number(self):
        self.assertEqual(compact_number(296435), "296k")
        self.assertEqual(compact_number(1_250_000), "1.2M")
        self.assertEqual(compact_number(42), "42")
        self.assertEqual(compact_number(0.5), "0.5")

    def test_hbar_chart_has_one_row_per_label_and_escapes(self):
        svg = str(hbar_chart([3, 1], ["<a>", "b"]))
        self.assertEqual(svg.count("<rect"), 2)
        self.assertIn("&lt;a&gt;", svg)
        self.assertNotIn("style=", svg)
