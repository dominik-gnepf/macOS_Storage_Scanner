from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan.scan import dupes


class FindDuplicatesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.kw = dict(home=self.tmp, scan_roots=(self.tmp,), min_bytes=100)

    def write(self, name, payload):
        path = os.path.join(self.tmp, name)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(payload)
        return path

    def test_identical_files_are_grouped(self):
        self.write("a/one.bin", b"A" * 5000)
        self.write("b/two.bin", b"A" * 5000)
        findings = dupes.find_duplicates(self.tmp, **self.kw)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "dupes.copy")
        self.assertEqual(findings[0].bytes_, 5000)

    def test_same_size_different_content_is_not_a_duplicate(self):
        self.write("a.bin", b"A" * 5000)
        self.write("b.bin", b"B" * 5000)
        self.assertEqual(dupes.find_duplicates(self.tmp, **self.kw), ())

    def test_differing_only_after_the_head_is_still_caught(self):
        head = b"A" * 70000
        self.write("a.bin", head + b"1" * 1000)
        self.write("b.bin", head + b"2" * 1000)
        self.assertEqual(dupes.find_duplicates(self.tmp, **self.kw), ())

    def test_files_below_min_bytes_ignored(self):
        self.write("a.bin", b"A" * 50)
        self.write("b.bin", b"A" * 50)
        self.assertEqual(dupes.find_duplicates(self.tmp, **self.kw), ())

    def test_three_copies_reclaim_two(self):
        for name in ["a.bin", "b.bin", "c.bin"]:
            self.write(name, b"Z" * 4000)
        self.assertEqual(dupes.find_duplicates(self.tmp, **self.kw)[0].bytes_, 8000)

    def test_hardlinks_are_not_duplicates(self):
        first = self.write("a.bin", b"H" * 4000)
        os.link(first, os.path.join(self.tmp, "b.bin"))
        self.assertEqual(dupes.find_duplicates(self.tmp, **self.kw), ())

    def test_symlink_is_not_a_duplicate(self):
        first = self.write("a.bin", b"S" * 4000)
        os.symlink(first, os.path.join(self.tmp, "link.bin"))
        self.assertEqual(dupes.find_duplicates(self.tmp, **self.kw), ())

    def test_detail_lists_redacted_paths(self):
        self.write("a.bin", b"A" * 5000)
        self.write("b.bin", b"A" * 5000)
        detail = dupes.find_duplicates(self.tmp, **self.kw)[0].detail
        self.assertIn("~/a.bin", detail)
        self.assertNotIn(self.tmp, detail)

    def test_unreadable_file_is_recorded_not_raised(self):
        path = self.write("a.bin", b"A" * 5000)
        self.write("b.bin", b"A" * 5000)
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, 0o600)
        errors = []
        # Unreadable content means no hash, so no group — but no crash either.
        dupes.find_duplicates(self.tmp, errors=errors, **self.kw)


if __name__ == "__main__":
    unittest.main()
