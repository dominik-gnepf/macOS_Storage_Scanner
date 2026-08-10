from __future__ import annotations

import unittest

from storagescan import safety
from storagescan.model import Risk

HOME = "/Users/example"
ROOTS = (HOME,)


def classify(path, category=None, **kw):
    kw.setdefault("home", HOME)
    kw.setdefault("scan_roots", ROOTS)
    return safety.classify(path, category, **kw)


class BlockedFloorTest(unittest.TestCase):
    def test_exact_blocked_directories(self):
        for path in [
            HOME,
            "/",
            "/Users",
            "/Volumes/Data",
            HOME + "/Documents",
            HOME + "/Desktop",
            HOME + "/Library",
            HOME + "/Applications",
        ]:
            self.assertEqual(classify(path), Risk.BLOCKED, path)

    def test_descendants_of_blocked_dirs_are_classifiable(self):
        self.assertEqual(
            classify(HOME + "/Library/Caches/Homebrew", "homebrew.cache"),
            Risk.SAFE,
        )

    def test_trailing_slash_is_normalized(self):
        self.assertEqual(classify(HOME + "/Documents/"), Risk.BLOCKED)

    def test_path_outside_scan_roots_is_blocked(self):
        self.assertEqual(
            classify("/System/Library/Foo", "homebrew.cache"), Risk.BLOCKED)

    def test_traversal_above_root_is_blocked(self):
        self.assertEqual(classify(HOME + "/../../etc", "homebrew.cache"), Risk.BLOCKED)

    def test_symlinks_are_blocked(self):
        self.assertEqual(
            classify(HOME + "/Library/Caches/x", "homebrew.cache", is_symlink=True),
            Risk.BLOCKED,
        )


class TierTest(unittest.TestCase):
    def test_safe_categories(self):
        self.assertEqual(classify(HOME + "/Library/Caches/pip", "pip.cache"), Risk.SAFE)
        self.assertEqual(classify(HOME + "/.Trash/old", "trash"), Risk.SAFE)

    def test_review_categories(self):
        self.assertEqual(classify(HOME + "/Downloads/x.dmg", "downloads"), Risk.REVIEW)
        self.assertEqual(classify(HOME + "/big.iso", "aging.stale"), Risk.REVIEW)

    def test_unmatched_path_defaults_to_danger(self):
        self.assertEqual(classify(HOME + "/Movies/wedding.mov", None), Risk.DANGER)

    def test_unknown_category_defaults_to_danger(self):
        self.assertEqual(
            classify(HOME + "/Movies/x.mov", "not.a.real.category"), Risk.DANGER)

    def test_risk_ignores_size_and_extension(self):
        # Location and category decide. Nothing else.
        self.assertEqual(classify(HOME + "/Library/Caches/huge.bin", "pip.cache"),
                         Risk.SAFE)
        self.assertEqual(classify(HOME + "/Movies/tiny.tmp", None), Risk.DANGER)


class ConfirmationTest(unittest.TestCase):
    def test_escalating_confirmation(self):
        self.assertEqual(safety.confirmation_for(Risk.SAFE), "single")
        self.assertEqual(safety.confirmation_for(Risk.REVIEW), "recap")
        self.assertEqual(safety.confirmation_for(Risk.DANGER), "retype")
        self.assertEqual(safety.confirmation_for(Risk.BLOCKED), "none")


if __name__ == "__main__":
    unittest.main()
