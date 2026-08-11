from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan.model import Risk
from storagescan.scan import system
from tests.support import build_tree


class AreaRegistryTest(unittest.TestCase):
    def test_areas_are_absolute_and_unique(self):
        paths = [a.path for a in system.AREAS]
        self.assertEqual(len(paths), len(set(paths)))
        for path in paths:
            self.assertTrue(path.startswith("/"), path)

    def test_no_area_nests_inside_another(self):
        # Nesting would double-count, exactly as it did for probes.
        paths = [a.path for a in system.AREAS]
        for outer in paths:
            for inner in paths:
                if outer == inner:
                    continue
                self.assertFalse(inner.startswith(outer.rstrip("/") + "/"),
                                 "{} nests in {}".format(inner, outer))

    def test_system_managed_areas_are_danger(self):
        risks = {a.category: system._RISK[a.category] for a in system.AREAS}
        self.assertEqual(risks["system.library"], Risk.DANGER)
        self.assertEqual(risks["system.var"], Risk.DANGER)

    def test_user_managed_areas_are_review(self):
        self.assertEqual(system._RISK["system.applications"], Risk.REVIEW)

    def test_no_area_is_ever_safe(self):
        # Nothing outside the home directory should be auto-reclaimable.
        for area in system.AREAS:
            self.assertNotEqual(system._RISK[area.category], Risk.SAFE,
                                area.category)


class ScanAreasTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def area(self, name, category="system.applications"):
        return system.SystemArea(os.path.join(self.tmp, name), name,
                                 category, "detail")

    def test_measures_areas_that_exist(self):
        build_tree(self.tmp, {"Apps": {"big": 50_000}})
        findings = system.scan_areas(min_bytes=1, areas=(self.area("Apps"),))
        self.assertEqual(len(findings), 1)
        self.assertGreaterEqual(findings[0].bytes_, 50_000)
        self.assertEqual(findings[0].risk, Risk.REVIEW)

    def test_missing_areas_are_skipped_silently(self):
        errors = []
        findings = system.scan_areas(min_bytes=1, errors=errors,
                                     areas=(self.area("Nope"),))
        self.assertEqual(findings, ())
        self.assertEqual(errors, [])

    def test_areas_below_the_threshold_are_omitted(self):
        build_tree(self.tmp, {"Apps": {"tiny": 10}})
        self.assertEqual(
            system.scan_areas(min_bytes=10_000_000, areas=(self.area("Apps"),)),
            ())

    def test_symlinked_area_is_ignored(self):
        build_tree(self.tmp, {"real": {"f": 50_000}})
        os.symlink(os.path.join(self.tmp, "real"), os.path.join(self.tmp, "Apps"))
        self.assertEqual(
            system.scan_areas(min_bytes=1, areas=(self.area("Apps"),)), ())

    def test_reports_on_disk_size_not_apparent(self):
        # A sparse file claims far more than it occupies. Reporting apparent
        # size would promise space that deleting it cannot deliver.
        os.makedirs(os.path.join(self.tmp, "Apps"))
        sparse = os.path.join(self.tmp, "Apps", "sparse.bin")
        with open(sparse, "wb") as handle:
            handle.truncate(500_000_000)
        findings = system.scan_areas(min_bytes=1, areas=(self.area("Apps"),))
        if findings:
            self.assertLess(findings[0].bytes_, 500_000_000)

    def test_sorted_biggest_first(self):
        build_tree(self.tmp, {"A": {"f": 10_000}, "B": {"f": 90_000}})
        findings = system.scan_areas(
            min_bytes=1,
            areas=(self.area("A"), self.area("B", "system.opt")))
        self.assertEqual([f.bytes_ for f in findings],
                         sorted([f.bytes_ for f in findings], reverse=True))

    def test_sizer_is_injectable(self):
        os.makedirs(os.path.join(self.tmp, "Apps"))
        findings = system.scan_areas(
            min_bytes=1, areas=(self.area("Apps"),),
            sizer=lambda _p: (777, 999, 1))
        self.assertEqual(findings[0].bytes_, 777)


class LargestApplicationsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_lists_app_bundles_by_size(self):
        build_tree(self.tmp, {
            "Big.app": {"bin": 90_000},
            "Small.app": {"bin": 20_000},
        })
        findings = system.largest_applications(
            applications=self.tmp, min_bytes=1)
        self.assertEqual([f.title for f in findings], ["Big", "Small"])
        self.assertTrue(all(f.risk == Risk.REVIEW for f in findings))

    def test_ignores_non_app_entries(self):
        build_tree(self.tmp, {"Big.app": {"bin": 90_000}, "notes.txt": 90_000})
        findings = system.largest_applications(
            applications=self.tmp, min_bytes=1)
        self.assertEqual([f.title for f in findings], ["Big"])

    def test_respects_the_top_limit(self):
        build_tree(self.tmp, {
            "A.app": {"f": 10}, "B.app": {"f": 20}, "C.app": {"f": 30}})
        self.assertEqual(
            len(system.largest_applications(
                applications=self.tmp, min_bytes=1, top=2)), 2)

    def test_small_apps_are_omitted(self):
        build_tree(self.tmp, {"Tiny.app": {"f": 10}})
        self.assertEqual(
            system.largest_applications(
                applications=self.tmp, min_bytes=1_000_000), ())

    def test_missing_directory_is_not_an_error(self):
        errors = []
        self.assertEqual(
            system.largest_applications(
                applications=os.path.join(self.tmp, "gone"), errors=errors), ())
        self.assertEqual(errors, [])

    def test_symlinked_app_is_ignored(self):
        build_tree(self.tmp, {"real": {"f": 90_000}})
        os.symlink(os.path.join(self.tmp, "real"),
                   os.path.join(self.tmp, "Linked.app"))
        self.assertEqual(
            system.largest_applications(applications=self.tmp, min_bytes=1), ())


if __name__ == "__main__":
    unittest.main()
