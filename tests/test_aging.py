from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan.model import Risk
from storagescan.scan import aging

DAY = 86400.0
NOW = 1_800_000_000.0


class FindStaleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.kw = dict(home=self.tmp, scan_roots=(self.tmp,),
                       min_bytes=1000, stale_days=180, now=NOW)

    def write(self, name, size, age_days):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as handle:
            handle.write(b"x" * size)
        stamp = NOW - age_days * DAY
        os.utime(path, (stamp, stamp))
        return path

    def test_large_and_old_is_reported(self):
        self.write("old.iso", 5000, 400)
        findings = aging.find_stale(self.tmp, **self.kw)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "aging.stale")
        self.assertEqual(findings[0].risk, Risk.REVIEW)

    def test_large_but_recent_is_ignored(self):
        self.write("new.iso", 5000, 3)
        self.assertEqual(aging.find_stale(self.tmp, **self.kw), ())

    def test_old_but_small_is_ignored(self):
        self.write("old.txt", 10, 400)
        self.assertEqual(aging.find_stale(self.tmp, **self.kw), ())

    def test_threshold_is_inclusive(self):
        # stale_days=180 means "untouched for at least 180 days", so a file
        # exactly that old qualifies and one a day younger does not.
        self.write("edge.iso", 5000, 180)
        self.assertEqual(len(aging.find_stale(self.tmp, **self.kw)), 1)

    def test_just_under_the_threshold_is_not_stale(self):
        self.write("fresh.iso", 5000, 179)
        self.assertEqual(aging.find_stale(self.tmp, **self.kw), ())

    def test_detail_mentions_age(self):
        self.write("old.iso", 5000, 400)
        self.assertIn("ago", aging.find_stale(self.tmp, **self.kw)[0].detail)

    def test_sorted_by_size_descending(self):
        self.write("a.iso", 9000, 400)
        self.write("b.iso", 3000, 400)
        sizes = [f.bytes_ for f in aging.find_stale(self.tmp, **self.kw)]
        self.assertEqual(sizes, sorted(sizes, reverse=True))


if __name__ == "__main__":
    unittest.main()
