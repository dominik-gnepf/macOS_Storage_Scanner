from __future__ import annotations

import os
import shutil
import stat
import tempfile
import unittest

from storagescan.scan import walker
from tests.support import build_tree


def totals(node):
    return (node.size, node.apparent, node.count)


class EquivalenceTest(unittest.TestCase):
    """walk_parallel must agree with walk. Anything else is a concurrency bug."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def assert_same(self, **kw):
        depth = kw.pop("max_depth", None)
        serial = walker.walk(self.tmp, max_depth=depth, **kw)
        parallel = walker.walk_parallel(self.tmp, max_depth=depth, workers=8, **kw)
        self.assertEqual(totals(serial), totals(parallel))
        return serial, parallel

    def test_agrees_on_a_wide_tree(self):
        build_tree(self.tmp, {
            "a": {"f": 1000, "sub": {"g": 2000}},
            "b": {"f": 3000},
            "c": {"d": {"e": {"f": 4000}}},
            "loose": 500,
        })
        serial, parallel = self.assert_same()
        self.assertEqual(serial.apparent, 10500)
        self.assertEqual(
            sorted(c.path for c in serial.children),
            sorted(c.path for c in parallel.children))

    def test_agrees_with_a_depth_limit(self):
        build_tree(self.tmp, {"a": {"b": {"c": {"d": {"f": 7000}}}}})
        for depth in (1, 2, 3, 10):
            with self.subTest(depth=depth):
                serial, parallel = self.assert_same(max_depth=depth)
                self.assertEqual(serial.apparent, 7000)

    def test_agrees_with_exclusions(self):
        build_tree(self.tmp, {"keep": {"f": 100}, "skip": {"f": 9999}})
        self.assert_same(exclude=(os.path.join(self.tmp, "skip"),))

    def test_agrees_on_an_empty_directory(self):
        self.assert_same()

    def test_agrees_when_only_loose_files_exist(self):
        build_tree(self.tmp, {"a": 100, "b": 200})
        serial, _ = self.assert_same()
        self.assertEqual(serial.apparent, 300)

    def test_worker_count_does_not_change_the_answer(self):
        build_tree(self.tmp, {
            "a": {"f": 1000}, "b": {"f": 2000}, "c": {"f": 3000},
            "d": {"f": 4000}, "e": {"f": 5000},
        })
        answers = {
            workers: totals(walker.walk_parallel(self.tmp, workers=workers))
            for workers in (1, 2, 4, 16, 64)
        }
        self.assertEqual(len(set(answers.values())), 1, answers)

    def test_zero_workers_is_clamped_not_crashing(self):
        build_tree(self.tmp, {"a": {"f": 100}})
        self.assertEqual(walker.walk_parallel(self.tmp, workers=0).apparent, 100)


class ParallelSpecificsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_symlinks_are_not_followed(self):
        build_tree(self.tmp, {"real": {"f": 1000}})
        os.symlink(os.path.join(self.tmp, "real"), os.path.join(self.tmp, "link"))
        self.assertEqual(walker.walk_parallel(self.tmp).apparent, 1000)

    def test_errors_from_every_thread_are_collected(self):
        for name in ("s1", "s2", "s3"):
            secret = os.path.join(self.tmp, name)
            build_tree(secret, {"f": 100})
            os.chmod(secret, 0)
            self.addCleanup(os.chmod, secret, stat.S_IRWXU)
        errors = []
        walker.walk_parallel(self.tmp, errors=errors, workers=4)
        # One EPERM per unreadable directory, none swallowed by the pool.
        self.assertEqual(len(errors), 3)

    def test_error_collection_is_not_corrupted_by_concurrency(self):
        # Many threads appending to one list: every error must survive and
        # every entry must be well-formed.
        for index in range(24):
            secret = os.path.join(self.tmp, "s{}".format(index))
            build_tree(secret, {"f": 10})
            os.chmod(secret, 0)
            self.addCleanup(os.chmod, secret, stat.S_IRWXU)
        errors = []
        walker.walk_parallel(self.tmp, errors=errors, workers=16)
        self.assertEqual(len(errors), 24)
        self.assertEqual(len({e.path for e in errors}), 24)
        for error in errors:
            self.assertTrue(error.error)

    def test_unreadable_root_is_reported_not_raised(self):
        os.chmod(self.tmp, 0)
        self.addCleanup(os.chmod, self.tmp, stat.S_IRWXU)
        errors = []
        node = walker.walk_parallel(self.tmp, errors=errors)
        self.assertEqual(node.apparent, 0)
        self.assertEqual(len(errors), 1)

    def test_missing_root_is_reported_not_raised(self):
        errors = []
        node = walker.walk_parallel(os.path.join(self.tmp, "gone"), errors=errors)
        self.assertEqual(node.apparent, 0)
        self.assertEqual(len(errors), 1)

    def test_hardlinks_within_one_subtree_are_still_deduped(self):
        # Dedup is per-thread by design; within a single top-level directory
        # one thread owns the whole subtree, so it must still hold.
        sub = os.path.join(self.tmp, "one")
        build_tree(sub, {"a": 4000})
        os.link(os.path.join(sub, "a"), os.path.join(sub, "b"))
        node = walker.walk_parallel(self.tmp, workers=8)
        self.assertEqual(node.apparent, 4000)
        self.assertEqual(node.count, 1)

    def test_hardlinks_across_top_level_dirs_are_counted_twice(self):
        # Documented, accepted tradeoff: sharing the seen-set across threads
        # would need a lock on the hot path. If this ever changes, this test
        # should be the thing that fails.
        first = os.path.join(self.tmp, "one")
        second = os.path.join(self.tmp, "two")
        build_tree(first, {"a": 4000})
        os.makedirs(second)
        os.link(os.path.join(first, "a"), os.path.join(second, "b"))
        node = walker.walk_parallel(self.tmp, workers=8)
        self.assertEqual(node.count, 2)
        self.assertEqual(node.apparent, 8000)

    def test_progress_starts_immediately_and_ticks_per_directory(self):
        build_tree(self.tmp, {"a": {"b": {"f": 1}}, "c": {"f": 1}})
        seen = []
        walker.walk_parallel(
            self.tmp, workers=2,
            on_progress=lambda done, total, path: seen.append((done, path)))
        self.assertGreaterEqual(len(seen), 3)
        self.assertEqual(seen[0][0], 0)
        self.assertTrue(any(done > 0 for done, _path in seen))

    def test_children_are_returned_for_every_subdirectory(self):
        build_tree(self.tmp, {"a": {"f": 1}, "b": {"f": 1}, "c": {"f": 1}})
        node = walker.walk_parallel(self.tmp, workers=4)
        self.assertEqual(len(node.children), 3)
        self.assertEqual(sorted(os.path.basename(c.path) for c in node.children),
                         ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
