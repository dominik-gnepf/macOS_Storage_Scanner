from __future__ import annotations

import unittest

from storagescan.model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo
from storagescan.ui import term

HOME = "/Users/example"


def result(**overrides):
    base = dict(
        root=Node(path=HOME, size=1_000_000_000, apparent=1_000_000_000,
                  count=10, mtime=0.0,
                  children=(Node(path=HOME + "/Library", size=900_000_000,
                                 apparent=900_000_000, count=5, mtime=0.0),)),
        findings=(Finding("homebrew.cache", "Homebrew downloads",
                          HOME + "/Library/Caches/Homebrew",
                          4_200_000_000, Risk.SAFE, "", "brew cleanup -s"),),
        volumes=(VolumeInfo("/System/Volumes/Data", 240_000_000_000,
                            160_000_000_000, 22_000_000_000),),
        errors=(),
        mode="fast", duration=1.0, fda_ok=True, started_at=0.0,
    )
    base.update(overrides)
    return ScanResult(**base)


class UnaccountedTest(unittest.TestCase):
    def test_gap_between_volume_and_scan(self):
        self.assertEqual(term.unaccounted(result(), HOME),
                         160_000_000_000 - 1_000_000_000)

    def test_no_gap_when_scan_exceeds_volume_usage(self):
        big = Node(path=HOME, size=999_000_000_000, apparent=1, count=1, mtime=0.0)
        self.assertIsNone(term.unaccounted(result(root=big), HOME))

    def test_none_without_a_volume_or_root(self):
        self.assertIsNone(term.unaccounted(result(volumes=()), HOME))
        self.assertIsNone(term.unaccounted(result(root=None), HOME))


class UnaccountedScopeTest(unittest.TestCase):
    def test_suppressed_when_the_scan_did_not_cover_home(self):
        # After --path ~/Developer the "gap" is just the rest of the disk.
        narrowed = result(roots=(HOME + "/Developer",))
        self.assertIsNone(term.unaccounted(narrowed, HOME))

    def test_reported_when_the_scan_covered_home(self):
        self.assertIsNotNone(term.unaccounted(result(roots=(HOME,)), HOME))

    def test_reported_when_roots_are_unknown(self):
        # Scans cached before roots were recorded still get an answer.
        self.assertIsNotNone(term.unaccounted(result(roots=()), HOME))


class RenderTest(unittest.TestCase):
    def test_includes_free_space_and_top_finding(self):
        out = term.render(result(), home=HOME, color=False)
        self.assertIn("22.0 GB", out)
        self.assertIn("Homebrew", out)
        self.assertIn("4.2 GB", out)

    def test_shows_the_reclaim_command(self):
        self.assertIn("brew cleanup -s", term.render(result(), home=HOME, color=False))

    def test_paths_are_redacted(self):
        out = term.render(result(), home=HOME, color=False)
        self.assertIn("~/Library/Caches/Homebrew", out)
        self.assertNotIn(HOME, out)

    def test_no_ansi_when_color_disabled(self):
        self.assertNotIn("\x1b[", term.render(result(), home=HOME, color=False))

    def test_ansi_present_when_color_enabled(self):
        self.assertIn("\x1b[", term.render(result(), home=HOME, color=True))

    def test_incomplete_banner_when_fda_missing(self):
        out = term.render(result(fda_ok=False), home=HOME, color=False)
        self.assertIn("INCOMPLETE", out)
        self.assertIn("Full Disk Access", out)

    def test_unaccounted_space_is_explained(self):
        out = term.render(result(), home=HOME, color=False)
        self.assertIn("not attributable", out)

    def test_error_count_is_surfaced(self):
        errors = tuple(ScanError("/x/%d" % i, "PermissionError") for i in range(3))
        out = term.render(result(errors=errors), home=HOME, color=False)
        self.assertIn("3 items were unreadable", out)

    def test_sizeless_findings_listed_separately(self):
        out = term.render(result(findings=(
            Finding("apfs.snapshot", "Local Time Machine snapshot", None, 0,
                    Risk.REVIEW, "com.apple.TimeMachine.x",
                    "tmutil deletelocalsnapshots x"),)), home=HOME, color=False)
        self.assertIn("Not measured", out)
        self.assertIn("does not report a size", out)
        self.assertIn("tmutil deletelocalsnapshots", out)

    def test_empty_result_does_not_crash(self):
        self.assertIsInstance(
            term.render(ScanResult(root=None), home=HOME, color=False), str)

    def test_risk_labels_are_shown(self):
        self.assertIn("SAFE", term.render(result(), home=HOME, color=False))


if __name__ == "__main__":
    unittest.main()
