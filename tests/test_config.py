from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from storagescan import config


class LoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, payload):
        path = os.path.join(self.tmp, "config.json")
        with open(path, "w") as handle:
            handle.write(payload)
        return path

    def test_missing_file_returns_defaults(self):
        cfg = config.load(os.path.join(self.tmp, "nope.json"))
        self.assertEqual(cfg.fast_depth, 6)
        self.assertEqual(cfg.scan_paths, ("~/",))
        self.assertTrue(cfg.trash_by_default)

    def test_overrides_are_applied(self):
        path = self.write(json.dumps({"fast_depth": 3, "stale_days": 30}))
        cfg = config.load(path)
        self.assertEqual(cfg.fast_depth, 3)
        self.assertEqual(cfg.stale_days, 30)
        self.assertEqual(cfg.large_file_bytes, 100_000_000)

    def test_unknown_keys_are_ignored(self):
        path = self.write(json.dumps({"fast_depth": 2, "wat": True}))
        self.assertEqual(config.load(path).fast_depth, 2)

    def test_malformed_json_raises_with_context(self):
        path = self.write("{not json")
        with self.assertRaises(config.ConfigError) as ctx:
            config.load(path)
        self.assertIn(path, str(ctx.exception))

    def test_non_object_json_raises(self):
        path = self.write("[1, 2, 3]")
        with self.assertRaises(config.ConfigError):
            config.load(path)


class ExpansionTest(unittest.TestCase):
    def test_expands_and_dedupes(self):
        cfg = config.Config(scan_paths=("~/", "~", "/Applications"))
        home = os.path.expanduser("~")
        self.assertEqual(cfg.expanded_scan_paths(), (home, "/Applications"))

    def test_is_excluded_matches_subpaths(self):
        cfg = config.Config(exclude=("~/Library/CloudStorage",))
        home = os.path.expanduser("~")
        self.assertTrue(cfg.is_excluded(home + "/Library/CloudStorage/Dropbox"))
        self.assertFalse(cfg.is_excluded(home + "/Library/Caches"))

    def test_is_excluded_does_not_match_partial_component(self):
        cfg = config.Config(exclude=("~/Movies",))
        home = os.path.expanduser("~")
        self.assertFalse(cfg.is_excluded(home + "/MoviesArchive"))


if __name__ == "__main__":
    unittest.main()
