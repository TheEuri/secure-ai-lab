import unittest

from apps.cryptolab.charts import bar_chart, compact_number, hbar_chart, histogram, log_hbar_chart, years_text


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

    def test_bar_chart_draws_reference_line_value_labels_and_axis_title(self):
        svg = str(bar_chart([[0.5, 0.01]], ["a", "b"], y_max=1, percent=True,
                            reference=(0.5, "ideal 50%"), y_title="bits que mudam"))
        self.assertIn('class="ref"', svg)
        self.assertIn("ideal 50%", svg)
        self.assertIn(">50.0%<", svg)
        self.assertIn(">1.0%<", svg)
        self.assertIn("bits que mudam", svg)

    def test_histogram_marks_the_ideal_point_and_names_axes(self):
        svg = str(histogram([0, 1, 5, 1, 0], marker=(2, "ideal"), x_title="bits alterados"))
        self.assertIn('class="ref"', svg)
        self.assertIn("ideal", svg)
        self.assertIn("bits alterados", svg)

    def test_log_hbar_chart_uses_powers_of_ten_and_reference(self):
        svg = str(log_hbar_chart([1e-4, 3e65], ["XOR", "SBX"],
                                 reference=(1.4e10, "idade do universo")))
        self.assertIn("idade do universo", svg)
        self.assertIn("10⁶⁵ anos", svg)
        self.assertEqual(svg.count('class="series-0"'), 2)

    def test_years_text_is_human_readable(self):
        self.assertEqual(years_text(8.9e-05), "47 min")
        self.assertEqual(years_text(2.8e65), "2,8 × 10⁶⁵ anos")
        self.assertEqual(years_text(1.4e10), "1,4 × 10¹⁰ anos")
