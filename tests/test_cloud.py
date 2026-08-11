from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan.model import Risk
from storagescan.scan import cloud


class FakeStat:
    def __init__(self, flags):
        self.st_flags = flags


class IsDatalessTest(unittest.TestCase):
    def test_detects_the_dataless_flag(self):
        self.assertTrue(cloud.is_dataless(FakeStat(cloud.SF_DATALESS)))

    def test_ordinary_file_is_not_dataless(self):
        self.assertFalse(cloud.is_dataless(FakeStat(0)))

    def test_other_flags_do_not_false_positive(self):
        self.assertFalse(cloud.is_dataless(FakeStat(0x00000002)))

    def test_platform_without_st_flags_is_not_dataless(self):
        class NoFlags:
            pass

        self.assertFalse(cloud.is_dataless(NoFlags()))


class CloudRootsTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def test_finds_existing_cloud_directories_only(self):
        os.makedirs(os.path.join(self.home, "Library", "CloudStorage"))
        roots = cloud.cloud_roots(self.home)
        self.assertEqual(roots, (os.path.join(self.home, "Library/CloudStorage"),))

    def test_no_cloud_directories_yields_empty(self):
        self.assertEqual(cloud.cloud_roots(self.home), ())

    def test_symlinked_cloud_root_is_ignored(self):
        # ~/OneDrive is a symlink into Library/CloudStorage on a real machine;
        # following it would scan the same tree twice.
        target = os.path.join(self.home, "elsewhere")
        os.makedirs(target)
        os.symlink(target, os.path.join(self.home, "Dropbox"))
        self.assertEqual(cloud.cloud_roots(self.home), ())

    def test_is_cloud_path_matches_descendants_not_siblings(self):
        roots = ("/h/Library/CloudStorage",)
        self.assertTrue(cloud.is_cloud_path("/h/Library/CloudStorage", roots))
        self.assertTrue(cloud.is_cloud_path("/h/Library/CloudStorage/OneDrive/a", roots))
        self.assertFalse(cloud.is_cloud_path("/h/Library/CloudStorageOther", roots))
        self.assertFalse(cloud.is_cloud_path("/h/Library/Caches", roots))


class CloudFindingsTest(unittest.TestCase):
    def test_reports_each_root_as_blocked_and_sizeless(self):
        findings = cloud.cloud_findings("/h", ("/h/Library/CloudStorage",))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "cloud.folder")
        self.assertEqual(findings[0].risk, Risk.BLOCKED)
        self.assertEqual(findings[0].bytes_, 0)

    def test_explains_why_it_was_skipped(self):
        detail = cloud.cloud_findings("/h", ("/h/Dropbox",))[0].detail
        self.assertIn("--include-cloud", detail)

    def test_no_roots_yields_no_findings(self):
        self.assertEqual(cloud.cloud_findings("/h", ()), ())


if __name__ == "__main__":
    unittest.main()
