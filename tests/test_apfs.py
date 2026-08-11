from __future__ import annotations

import os
import unittest

from storagescan.model import Risk
from storagescan.scan import apfs

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name, binary=False):
    with open(os.path.join(FIXTURES, name), "rb" if binary else "r") as handle:
        return handle.read()


class ParseDfTest(unittest.TestCase):
    def test_parses_volumes_in_bytes(self):
        volumes = apfs.parse_df(fixture("df_output.txt"))
        data = [v for v in volumes if v.mount == "/System/Volumes/Data"][0]
        self.assertEqual(data.used, 165056324 * 1024)
        self.assertEqual(data.free, 22398672 * 1024)

    def test_ignores_header_and_blank_lines(self):
        self.assertEqual(apfs.parse_df("Filesystem 1024-blocks\n\n"), ())

    def test_malformed_line_is_skipped(self):
        self.assertEqual(apfs.parse_df("Filesystem x\ngarbage\n"), ())


class VolumeSelectionTest(unittest.TestCase):
    def setUp(self):
        self.volumes = apfs.parse_df(fixture("df_output.txt"))

    def test_primary_volume_is_the_data_volume(self):
        self.assertEqual(apfs.primary_volume(self.volumes).mount,
                         "/System/Volumes/Data")

    def test_primary_falls_back_to_root(self):
        only_root = tuple(v for v in self.volumes if v.mount == "/")
        self.assertEqual(apfs.primary_volume(only_root).mount, "/")

    def test_primary_of_nothing_is_none(self):
        self.assertIsNone(apfs.primary_volume(()))

    def test_interesting_volumes_drops_system_mounts(self):
        mounts = {v.mount for v in apfs.interesting_volumes(self.volumes)}
        self.assertIn("/System/Volumes/Data", mounts)
        self.assertIn("/", mounts)
        self.assertNotIn("/dev", mounts)
        self.assertNotIn("/System/Volumes/VM", mounts)


class ParseSnapshotsTest(unittest.TestCase):
    def test_extracts_all_snapshot_names_not_just_time_machine(self):
        names = apfs.parse_snapshots(fixture("tmutil_snapshots.txt"))
        self.assertEqual(len(names), 3)
        self.assertTrue(all(n.startswith("com.apple.") for n in names))

    def test_header_line_is_skipped(self):
        names = apfs.parse_snapshots(fixture("tmutil_snapshots.txt"))
        self.assertFalse(any("Snapshots for volume" in n for n in names))

    def test_no_snapshots_yields_empty(self):
        self.assertEqual(apfs.parse_snapshots("Snapshots for volume group:\n"), ())


class ParseContainerCapacityTest(unittest.TestCase):
    def test_reads_container_free_and_used(self):
        free, used = apfs.parse_container_capacity(
            fixture("diskutil_info.plist", True))
        self.assertEqual(free, 22899179520)
        self.assertEqual(used, 169017692160)

    def test_malformed_plist_returns_none(self):
        self.assertIsNone(apfs.parse_container_capacity(b"not a plist"))

    def test_plist_without_capacity_keys_returns_none(self):
        import plistlib
        self.assertIsNone(apfs.parse_container_capacity(plistlib.dumps({"a": 1})))


class SnapshotFindingsTest(unittest.TestCase):
    def setUp(self):
        self.findings = apfs.snapshot_findings(
            apfs.parse_snapshots(fixture("tmutil_snapshots.txt")))

    def test_time_machine_snapshot_is_review_with_a_command(self):
        tm = [f for f in self.findings if f.category == "apfs.snapshot"]
        self.assertEqual(len(tm), 1)
        self.assertEqual(tm[0].risk, Risk.REVIEW)
        self.assertIn("tmutil deletelocalsnapshots", tm[0].reclaim_hint)

    def test_os_update_snapshots_are_blocked_with_no_command(self):
        os_snaps = [f for f in self.findings if f.category == "apfs.os_snapshot"]
        self.assertEqual(len(os_snaps), 2)
        for finding in os_snaps:
            self.assertEqual(finding.risk, Risk.BLOCKED)
            self.assertEqual(finding.reclaim_hint, "")

    def test_snapshots_never_carry_a_deletable_path(self):
        for finding in self.findings:
            self.assertIsNone(finding.path)

    def test_snapshots_claim_no_size(self):
        # tmutil exposes no per-snapshot size; claiming one would be a lie.
        for finding in self.findings:
            self.assertEqual(finding.bytes_, 0)


class CollectTest(unittest.TestCase):
    def test_uses_injected_runner(self):
        def run(argv):
            if argv[0] == "df":
                return fixture("df_output.txt").encode()
            if argv[0] == "tmutil":
                return fixture("tmutil_snapshots.txt").encode()
            return None

        volumes, findings, errors = apfs.collect(run=run)
        self.assertTrue(volumes)
        self.assertEqual(len(findings), 3)
        self.assertEqual(errors, ())

    def test_missing_tool_degrades_that_section_only(self):
        def run(argv):
            if argv[0] == "df":
                return fixture("df_output.txt").encode()
            return None

        volumes, findings, errors = apfs.collect(run=run)
        self.assertTrue(volumes)
        self.assertEqual(findings, ())
        self.assertEqual([e.path for e in errors], ["tmutil"])

    def test_everything_missing_is_survivable(self):
        volumes, findings, errors = apfs.collect(run=lambda argv: None)
        self.assertEqual(volumes, ())
        self.assertEqual(findings, ())
        self.assertEqual(len(errors), 2)


if __name__ == "__main__":
    unittest.main()
