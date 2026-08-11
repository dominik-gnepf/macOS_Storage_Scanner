from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan.model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo
from storagescan.ui import report

HOME = "/Users/example"


def sample(**overrides):
    child = Node(path=HOME + "/Library", size=900, apparent=900, count=5, mtime=0.0)
    other = Node(path=HOME + "/Downloads", size=100, apparent=100, count=2, mtime=0.0)
    base = dict(
        root=Node(path=HOME, size=1000, apparent=1000, count=7, mtime=0.0,
                  children=(child, other)),
        findings=(Finding("homebrew.cache", "Homebrew downloads",
                          HOME + "/Library/Caches/Homebrew", 4200, Risk.SAFE,
                          "regenerable", "brew cleanup -s"),),
        volumes=(VolumeInfo("/System/Volumes/Data", 10000, 9000, 1000),),
        errors=(ScanError("/x", "PermissionError"),),
        mode="fast", duration=1.0, fda_ok=True, started_at=0.0,
    )
    base.update(overrides)
    return ScanResult(**base)


class SquarifyTest(unittest.TestCase):
    def test_rectangles_cover_the_area_exactly(self):
        rects = report.squarify([("a", 60), ("b", 40)], 0, 0, 100, 100)
        self.assertAlmostEqual(sum(w * h for _l, _v, _x, _y, w, h in rects),
                               10000, delta=1)

    def test_rectangles_do_not_overlap(self):
        rects = report.squarify([("a", 50), ("b", 30), ("c", 20)], 0, 0, 200, 100)
        for index, first in enumerate(rects):
            for second in rects[index + 1:]:
                _l1, _v1, x1, y1, w1, h1 = first
                _l2, _v2, x2, y2, w2, h2 = second
                separated = (x1 + w1 <= x2 + 1e-6 or x2 + w2 <= x1 + 1e-6
                             or y1 + h1 <= y2 + 1e-6 or y2 + h2 <= y1 + 1e-6)
                self.assertTrue(separated, "{} overlaps {}".format(first, second))

    def test_areas_are_proportional_to_values(self):
        rects = report.squarify([("a", 75), ("b", 25)], 0, 0, 100, 100)
        areas = {label: w * h for label, _v, _x, _y, w, h in rects}
        self.assertAlmostEqual(areas["a"] / areas["b"], 3.0, delta=0.05)

    def test_zero_and_empty_inputs_are_safe(self):
        self.assertEqual(report.squarify([], 0, 0, 100, 100), [])
        self.assertEqual(report.squarify([("a", 0)], 0, 0, 100, 100), [])
        self.assertEqual(report.squarify([("a", 5)], 0, 0, 0, 100), [])


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.html = report.render(sample(), home=HOME, generated_at=0.0)

    def test_is_a_complete_document(self):
        self.assertIn("<!doctype html>", self.html.lower())
        self.assertIn("</html>", self.html.lower())

    def test_contains_no_external_references(self):
        self.assertNotIn("http://", self.html)
        self.assertNotIn("https://", self.html)
        self.assertNotIn("//cdn", self.html)
        self.assertNotIn("<script", self.html.lower())

    def test_leaks_no_home_path(self):
        self.assertNotIn(HOME, self.html)
        self.assertIn("~/Library", self.html)

    def test_contains_a_treemap_svg(self):
        self.assertIn("<svg", self.html)
        self.assertIn("<rect", self.html)

    def test_findings_table_present_with_command(self):
        self.assertIn("Homebrew downloads", self.html)
        self.assertIn("brew cleanup -s", self.html)

    def test_escapes_html_in_paths(self):
        evil = ScanResult(root=Node(path=HOME + "/<script>x</script>", size=10,
                                    apparent=10, count=1, mtime=0.0))
        html_out = report.render(evil, home=HOME, generated_at=0.0)
        self.assertNotIn("<script>x</script>", html_out)

    def test_theme_aware_in_both_directions(self):
        self.assertIn("prefers-color-scheme", self.html)
        self.assertIn('[data-theme="dark"]', self.html)
        self.assertIn("background: var(--bg)", self.html)

    def test_incomplete_banner_when_fda_missing(self):
        html_out = report.render(sample(fda_ok=False), home=HOME, generated_at=0.0)
        self.assertIn("INCOMPLETE", html_out)
        self.assertIn("Full Disk Access", html_out)

    def test_unaccounted_space_is_surfaced(self):
        # Volume says 9000 used; the scan attributed only 1000.
        self.assertIn("unaccounted", self.html)

    def test_sizeless_findings_render_a_dash_not_zero(self):
        result = sample(findings=(
            Finding("apfs.snapshot", "Local Time Machine snapshot", None, 0,
                    Risk.REVIEW, "com.apple.TimeMachine.x",
                    "tmutil deletelocalsnapshots x"),))
        html_out = report.render(result, home=HOME, generated_at=0.0)
        self.assertIn("—", html_out)
        self.assertIn("tmutil deletelocalsnapshots", html_out)

    def test_empty_result_does_not_crash(self):
        html_out = report.render(ScanResult(root=None), home=HOME, generated_at=0.0)
        self.assertIn("No findings.", html_out)


class WriteTest(unittest.TestCase):
    def test_writes_file_and_returns_path(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        target = os.path.join(tmp, "nested", "report.html")
        self.assertEqual(
            report.write(sample(), home=HOME, path=target, generated_at=0.0), target)
        self.assertTrue(os.path.exists(target))


if __name__ == "__main__":
    unittest.main()
