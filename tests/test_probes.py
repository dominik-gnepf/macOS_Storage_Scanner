from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan import safety
from storagescan.model import Risk
from storagescan.scan import probes
from tests.support import build_tree


class RegistryTest(unittest.TestCase):
    def test_categories_are_unique(self):
        categories = [p.category for p in probes.PROBES]
        self.assertGreater(len(categories), 20)
        self.assertEqual(len(categories), len(set(categories)))

    def test_covers_the_headline_hoarders(self):
        categories = {p.category for p in probes.PROBES}
        for expected in [
            "xcode.derived_data", "xcode.device_support", "ios.backups",
            "docker.image", "homebrew.cache", "npm.cache", "trash",
            "downloads", "node_modules", "mail.downloads", "photos.library",
        ]:
            self.assertIn(expected, categories)

    def test_patterns_are_home_relative(self):
        for probe in probes.PROBES:
            for pattern in probe.patterns:
                self.assertFalse(pattern.startswith("/"), probe.category)

    def test_every_category_has_a_deliberate_risk_tier(self):
        # A category in neither set falls through to DANGER. That is allowed,
        # but it must be a decision, not an oversight — so assert the exact
        # set of fall-through categories.
        known = safety.SAFE_CATEGORIES | safety.REVIEW_CATEGORIES
        fallthrough = {p.category for p in probes.PROBES} - known
        self.assertEqual(fallthrough, {"photos.library", "mail.store"})

    def test_specific_probes_precede_general_ones(self):
        order = [p.category for p in probes.PROBES]
        self.assertLess(order.index("browser.cache"), order.index("app.cache"))


class RunProbesTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def run_probes(self, **kw):
        kw.setdefault("scan_roots", (self.home,))
        kw.setdefault("min_bytes", 1)
        return probes.run_probes(self.home, **kw)

    def test_finds_a_matching_directory(self):
        build_tree(self.home, {"Library": {"Caches": {"Homebrew": {"big": 50_000}}}})
        homebrew = [f for f in self.run_probes() if f.category == "homebrew.cache"]
        self.assertEqual(len(homebrew), 1)
        self.assertEqual(homebrew[0].risk, Risk.SAFE)
        self.assertGreaterEqual(homebrew[0].bytes_, 50_000)
        self.assertEqual(homebrew[0].reclaim_hint, "brew cleanup -s")

    def test_skips_results_below_min_bytes(self):
        build_tree(self.home, {"Library": {"Caches": {"Homebrew": {"tiny": 10}}}})
        findings = self.run_probes(min_bytes=10_000_000)
        self.assertEqual([f for f in findings if f.category == "homebrew.cache"], [])

    def test_downloads_is_review_not_safe(self):
        build_tree(self.home, {"Downloads": {"big.dmg": 50_000}})
        downloads = [f for f in self.run_probes() if f.category == "downloads"][0]
        self.assertEqual(downloads.risk, Risk.REVIEW)

    def test_photos_library_is_danger(self):
        build_tree(self.home,
                   {"Pictures": {"Photos Library.photoslibrary": {"db": 50_000}}})
        photos = [f for f in self.run_probes() if f.category == "photos.library"][0]
        self.assertEqual(photos.risk, Risk.DANGER)

    def test_a_path_is_attributed_to_only_one_probe(self):
        # Library/Caches/com.apple.Safari matches both browser.cache and the
        # general app.cache glob. It must be counted once.
        build_tree(self.home,
                   {"Library": {"Caches": {"com.apple.Safari": {"f": 50_000}}}})
        matched = [f for f in self.run_probes()
                   if f.path.endswith("com.apple.Safari")]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].category, "browser.cache")

    def test_missing_paths_produce_no_findings_and_no_errors(self):
        errors = []
        self.assertEqual(self.run_probes(errors=errors), ())
        self.assertEqual(errors, [])

    def test_symlinked_match_is_ignored(self):
        build_tree(self.home, {"real": {"f": 50_000}})
        os.makedirs(os.path.join(self.home, "Library", "Caches"))
        os.symlink(os.path.join(self.home, "real"),
                   os.path.join(self.home, "Library", "Caches", "Homebrew"))
        self.assertEqual(
            [f for f in self.run_probes() if f.category == "homebrew.cache"], [])

    def test_findings_are_sorted_by_size_descending(self):
        build_tree(self.home, {
            "Downloads": {"a": 20_000},
            "Library": {"Caches": {"Homebrew": {"b": 90_000}}},
        })
        sizes = [f.bytes_ for f in self.run_probes()]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_sizer_is_injectable(self):
        os.makedirs(os.path.join(self.home, "Downloads"))
        calls = []

        def sizer(path):
            calls.append(path)
            return (123, 123, 1)

        findings = self.run_probes(sizer=sizer)
        self.assertTrue(calls)
        self.assertEqual(findings[0].bytes_, 123)


if __name__ == "__main__":
    unittest.main()
