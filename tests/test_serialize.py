from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from storagescan import serialize
from storagescan.model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo


def sample():
    leaf = Node(path="/a/b", size=10, apparent=12, count=1, mtime=1.0)
    root = Node(path="/a", size=10, apparent=12, count=1, mtime=2.0, children=(leaf,))
    return ScanResult(
        root=root,
        findings=(Finding("trash", "Trash", "/a/.Trash", 99, Risk.SAFE, "d", "h"),),
        volumes=(VolumeInfo("/", 100, 60, 40, purgeable=5),),
        errors=(ScanError("/x", "PermissionError"),),
        mode="deep",
        duration=2.5,
        fda_ok=False,
        started_at=123.0,
    )


class RoundTripTest(unittest.TestCase):
    def test_round_trip_preserves_everything(self):
        original = sample()
        self.assertEqual(serialize.loads(serialize.dumps(original)), original)

    def test_risk_survives_as_enum(self):
        restored = serialize.loads(serialize.dumps(sample()))
        self.assertIs(restored.findings[0].risk, Risk.SAFE)

    def test_nested_children_survive(self):
        restored = serialize.loads(serialize.dumps(sample()))
        self.assertEqual(restored.root.children[0].path, "/a/b")

    def test_none_root_round_trips(self):
        self.assertIsNone(serialize.loads(serialize.dumps(ScanResult(root=None))).root)

    def test_deep_tree_round_trips_without_recursion_error(self):
        # 340 is roughly the deepest tree macOS can hold: PATH_MAX is 1024
        # bytes and a component costs at least two ("a/"). CPython's json
        # codec recurses per level, so this is the case that matters.
        node = Node(path="/leaf", size=1, apparent=1, count=1, mtime=0.0)
        for index in range(340):
            node = Node(path="/d{}".format(index), size=1, apparent=1,
                        count=1, mtime=0.0, children=(node,))
        restored = serialize.loads(serialize.dumps(ScanResult(root=node)))
        depth = 0
        current = restored.root
        while current.children:
            depth += 1
            current = current.children[0]
        self.assertEqual(depth, 340)

    def test_schema_mismatch_raises(self):
        payload = json.loads(serialize.dumps(sample()))
        payload["schema"] = 999
        with self.assertRaises(serialize.SchemaMismatch):
            serialize.loads(json.dumps(payload))


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = os.path.join(self.tmp, "nested", "last.json")

    def test_save_creates_parents_and_load_returns_result(self):
        serialize.save(sample(), self.path)
        self.assertTrue(os.path.exists(self.path))
        self.assertEqual(serialize.load_cached(self.path), sample())

    def test_missing_cache_returns_none(self):
        self.assertIsNone(serialize.load_cached(os.path.join(self.tmp, "nope.json")))

    def test_corrupt_cache_returns_none(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as handle:
            handle.write("{broken")
        self.assertIsNone(serialize.load_cached(self.path))


class DiffTest(unittest.TestCase):
    def build(self, sizes):
        children = tuple(
            Node(path=p, size=s, apparent=s, count=1, mtime=0.0)
            for p, s in sizes.items()
        )
        total = sum(sizes.values())
        root = Node(path="/a", size=total, apparent=total, count=len(sizes),
                    mtime=0.0, children=children)
        return ScanResult(root=root)

    def test_reports_growth_and_shrinkage(self):
        old = self.build({"/a/x": 100, "/a/y": 500})
        new = self.build({"/a/x": 900, "/a/y": 100})
        changes = dict(serialize.diff(old, new))
        self.assertEqual(changes["/a/x"], 800)
        self.assertEqual(changes["/a/y"], -400)

    def test_new_paths_count_as_full_growth(self):
        old = self.build({"/a/x": 100})
        new = self.build({"/a/x": 100, "/a/z": 700})
        self.assertEqual(dict(serialize.diff(old, new))["/a/z"], 700)

    def test_sorted_by_absolute_delta(self):
        old = self.build({"/a/x": 0, "/a/y": 0})
        new = self.build({"/a/x": 10, "/a/y": 900})
        self.assertEqual([p for p, _ in serialize.diff(old, new)][:2],
                         ["/a", "/a/y"])

    def test_identical_scans_report_nothing(self):
        scan = self.build({"/a/x": 100})
        self.assertEqual(serialize.diff(scan, scan), ())


if __name__ == "__main__":
    unittest.main()
