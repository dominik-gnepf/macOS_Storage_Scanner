from __future__ import annotations

import dataclasses
import unittest

from storagescan.model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo


def make_finding(category, bytes_, risk):
    return Finding(category=category, title=category, path=None,
                   bytes_=bytes_, risk=risk)


class NodeTest(unittest.TestCase):
    def test_is_frozen(self):
        node = Node(path="/a", size=1, apparent=1, count=1, mtime=0.0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            node.size = 2

    def test_sorted_children_is_descending_by_size(self):
        small = Node(path="/a/s", size=10, apparent=10, count=1, mtime=0.0)
        big = Node(path="/a/b", size=99, apparent=99, count=1, mtime=0.0)
        parent = Node(path="/a", size=109, apparent=109, count=2, mtime=0.0,
                      children=(small, big))
        self.assertEqual([c.path for c in parent.sorted_children()], ["/a/b", "/a/s"])

    def test_defaults(self):
        node = Node(path="/a", size=1, apparent=1, count=1, mtime=0.0)
        self.assertEqual(node.children, ())
        self.assertFalse(node.truncated)
        self.assertEqual(node.unreadable, 0)


class ScanResultTest(unittest.TestCase):
    def build(self):
        return ScanResult(
            root=Node(path="/a", size=100, apparent=100, count=1, mtime=0.0),
            findings=(
                make_finding("cache", 500, Risk.SAFE),
                make_finding("downloads", 300, Risk.REVIEW),
                make_finding("movies", 900, Risk.DANGER),
            ),
            volumes=(VolumeInfo(mount="/", total=10, used=6, free=4),),
            errors=(ScanError(path="/x", error="PermissionError"),),
            mode="fast",
            duration=1.5,
            fda_ok=True,
            started_at=0.0,
        )

    def test_reclaimable_sums_selected_risks(self):
        result = self.build()
        self.assertEqual(result.reclaimable(Risk.SAFE), 500)
        self.assertEqual(result.reclaimable(Risk.SAFE, Risk.REVIEW), 800)

    def test_findings_by_size_is_descending(self):
        result = self.build()
        self.assertEqual(
            [f.category for f in result.findings_by_size()],
            ["movies", "cache", "downloads"],
        )

    def test_volume_info_purgeable_defaults_to_none(self):
        self.assertIsNone(VolumeInfo(mount="/", total=1, used=1, free=0).purgeable)


class RiskTest(unittest.TestCase):
    def test_values_are_stable_strings(self):
        self.assertEqual([r.value for r in Risk],
                         ["safe", "review", "danger", "blocked"])


if __name__ == "__main__":
    unittest.main()
