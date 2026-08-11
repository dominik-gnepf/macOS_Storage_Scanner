from __future__ import annotations

import os
import shutil
import stat
import tempfile
import unittest

from storagescan.model import Risk
from storagescan.scan import cloud
from tests.support import build_tree


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
    def findings(self, size, roots=("/h/Library/CloudStorage",)):
        return cloud.cloud_findings("/h", roots, measure=lambda _p: size)

    def test_reports_measured_size_and_stays_blocked(self):
        findings = self.findings(12_000_000_000)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "cloud.folder")
        self.assertEqual(findings[0].bytes_, 12_000_000_000)
        # Measured, but still never deletable by this tool.
        self.assertEqual(findings[0].risk, Risk.BLOCKED)

    def test_explains_that_only_downloaded_files_count(self):
        detail = self.findings(1)[0].detail
        self.assertIn("downloaded", detail)
        self.assertIn("online-only", detail)

    def test_warns_against_deleting_synced_files(self):
        # Deleting a synced file locally deletes it from the cloud too. The
        # tool must say so rather than present it as free space.
        self.assertIn("remove them from the cloud", self.findings(1)[0].detail)

    def test_unmeasurable_folder_reports_zero_and_says_so(self):
        findings = self.findings(None)
        self.assertEqual(findings[0].bytes_, 0)
        self.assertIn("size unknown", findings[0].title)
        self.assertIn("did not respond", findings[0].detail)

    def test_no_roots_yields_no_findings(self):
        self.assertEqual(cloud.cloud_findings("/h", ()), ())

    def test_every_root_is_reported(self):
        findings = self.findings(5, roots=("/h/a", "/h/b", "/h/c"))
        self.assertEqual(len(findings), 3)


class MeasureBoundedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_sums_on_disk_blocks(self):
        build_tree(self.tmp, {"a": {"f": 5000}, "b": 3000})
        measured = cloud.measure_bounded(self.tmp)
        self.assertIsNotNone(measured)
        # Block-rounded, so at least the apparent total.
        self.assertGreaterEqual(measured, 8000)

    def test_returns_none_when_out_of_time(self):
        build_tree(self.tmp, {"a": {"f": 100}})
        self.assertIsNone(cloud.measure_bounded(self.tmp, budget=-1))

    def test_symlinks_are_not_followed(self):
        build_tree(self.tmp, {"real": {"f": 4000}})
        os.symlink(os.path.join(self.tmp, "real"),
                   os.path.join(self.tmp, "link"))
        doubled = cloud.measure_bounded(self.tmp)
        only_real = cloud.measure_bounded(os.path.join(self.tmp, "real"))
        self.assertEqual(doubled, only_real)

    def test_unreadable_subdirectory_does_not_raise(self):
        secret = os.path.join(self.tmp, "secret")
        build_tree(secret, {"f": 100})
        os.chmod(secret, 0)
        self.addCleanup(os.chmod, secret, stat.S_IRWXU)
        self.assertIsNotNone(cloud.measure_bounded(self.tmp))

    def test_empty_directory_measures_zero(self):
        self.assertEqual(cloud.measure_bounded(self.tmp), 0)

    def test_never_opens_a_file(self):
        # Opening a placeholder downloads it. Measuring must be metadata-only.
        build_tree(self.tmp, {"f": 4000})
        real_open = open
        opened = []

        import builtins
        def tracking_open(path, *a, **kw):
            opened.append(path)
            return real_open(path, *a, **kw)

        builtins.open = tracking_open
        try:
            cloud.measure_bounded(self.tmp)
        finally:
            builtins.open = real_open
        self.assertEqual(opened, [])


if __name__ == "__main__":
    unittest.main()
