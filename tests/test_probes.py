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
            "uv.cache", "bun.cache", "huggingface.cache", "ollama.models",
            "xcode.simulator_devices", "xcode.simulator_caches",
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

    def test_simulator_devices_are_review_caches_are_safe(self):
        build_tree(self.home, {
            "Library": {"Developer": {"CoreSimulator": {
                "Caches": {"c": 50_000},
                "Devices": {"iPhone": {"d": 50_000}},
            }}},
        })
        findings = {f.category: f for f in self.run_probes()}
        self.assertEqual(findings["xcode.simulator_caches"].risk, Risk.SAFE)
        self.assertEqual(findings["xcode.simulator_devices"].risk, Risk.REVIEW)

    def test_uv_and_huggingface_caches_are_safe(self):
        build_tree(self.home, {
            ".cache": {
                "uv": {"x": 50_000},
                "huggingface": {"y": 50_000},
            },
            ".bun": {"install": {"cache": {"z": 50_000}}},
            ".ollama": {"models": {"blob": 50_000}},
        })
        findings = {f.category: f for f in self.run_probes()}
        self.assertEqual(findings["uv.cache"].risk, Risk.SAFE)
        self.assertEqual(findings["huggingface.cache"].risk, Risk.SAFE)
        self.assertEqual(findings["bun.cache"].risk, Risk.SAFE)
        self.assertEqual(findings["ollama.models"].risk, Risk.REVIEW)

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




class NonOverlapTest(unittest.TestCase):
    """Findings must never nest: nesting double-counts bytes and makes a
    batch delete remove a parent then fail on its child."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def run_probes(self):
        return probes.run_probes(self.home, scan_roots=(self.home,), min_bytes=1)

    def test_child_and_parent_are_not_both_reported(self):
        # Caches/Google/Chrome matches browser.cache; Caches/Google matches
        # the generic app.cache glob. Only one may survive.
        build_tree(self.home, {"Library": {"Caches": {"Google": {
            "Chrome": {"f": 50_000}, "other": {"g": 10_000}}}}})
        paths = [f.path for f in self.run_probes()]
        self.assertEqual(len(paths), len(set(paths)))
        google = os.path.join(self.home, "Library/Caches/Google")
        chrome = os.path.join(google, "Chrome")
        self.assertIn(chrome, paths)
        self.assertNotIn(google, paths)

    def test_no_finding_is_inside_another(self):
        build_tree(self.home, {
            "Library": {"Caches": {
                "Google": {"Chrome": {"f": 50_000}},
                "Firefox": {"f": 20_000},
                "pip": {"f": 30_000},
            }},
            "Downloads": {"a.dmg": 40_000},
        })
        paths = [f.path for f in self.run_probes()]
        for outer in paths:
            for inner in paths:
                if outer is inner:
                    continue
                self.assertFalse(
                    inner.startswith(outer.rstrip("/") + "/"),
                    "{} nests inside {}".format(inner, outer))

    def test_total_does_not_double_count(self):
        build_tree(self.home, {"Library": {"Caches": {"Google": {
            "Chrome": {"f": 50_000}}}}})
        total = sum(f.bytes_ for f in self.run_probes())
        # The 50 KB exists once on disk, so it may be counted once.
        self.assertLess(total, 100_000)


class OverlapHelperTest(unittest.TestCase):
    def test_detects_identical_paths(self):
        self.assertTrue(probes._overlaps("/a/b", ["/a/b"]))

    def test_detects_a_path_inside_a_claim(self):
        self.assertTrue(probes._overlaps("/a/b/c", ["/a/b"]))

    def test_detects_a_path_that_would_swallow_a_claim(self):
        self.assertTrue(probes._overlaps("/a", ["/a/b/c"]))

    def test_allows_siblings(self):
        self.assertFalse(probes._overlaps("/a/c", ["/a/b"]))

    def test_does_not_match_a_shared_name_prefix(self):
        self.assertFalse(probes._overlaps("/a/bcd", ["/a/b"]))

    def test_empty_claims_never_overlap(self):
        self.assertFalse(probes._overlaps("/a/b", []))


if __name__ == "__main__":
    unittest.main()
