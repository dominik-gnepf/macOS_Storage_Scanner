from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import unittest

from storagescan.scan import walker
from tests.support import build_tree


class WalkerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def find(self, node, name):
        for child in node.children:
            if os.path.basename(child.path) == name:
                return child
        raise AssertionError("no child named {}".format(name))

    def test_sums_apparent_sizes_over_subtree(self):
        build_tree(self.tmp, {"a": {"f1": 1000, "f2": 2000}, "b": {"f3": 500}})
        node = walker.walk(self.tmp)
        self.assertEqual(node.apparent, 3500)
        self.assertEqual(node.count, 3)
        self.assertEqual(self.find(node, "a").apparent, 3000)

    def test_on_disk_size_is_block_based(self):
        build_tree(self.tmp, {"tiny": 1})
        node = walker.walk(self.tmp)
        self.assertGreaterEqual(node.size, 1)
        self.assertEqual(node.apparent, 1)

    def test_symlinks_are_not_followed(self):
        build_tree(self.tmp, {"real": {"f": 1000}})
        os.symlink(os.path.join(self.tmp, "real"), os.path.join(self.tmp, "link"))
        node = walker.walk(self.tmp)
        self.assertEqual(node.apparent, 1000)

    def test_symlink_loop_terminates(self):
        os.makedirs(os.path.join(self.tmp, "d"))
        os.symlink(self.tmp, os.path.join(self.tmp, "d", "loop"))
        node = walker.walk(self.tmp)
        self.assertIsNotNone(node)

    def test_hardlinks_counted_once(self):
        build_tree(self.tmp, {"a": 1000})
        os.link(os.path.join(self.tmp, "a"), os.path.join(self.tmp, "b"))
        node = walker.walk(self.tmp)
        self.assertEqual(node.apparent, 1000)
        self.assertEqual(node.count, 1)

    def test_unreadable_dir_is_recorded_not_raised(self):
        secret = os.path.join(self.tmp, "secret")
        build_tree(secret, {"f": 100})
        os.chmod(secret, 0)
        self.addCleanup(os.chmod, secret, stat.S_IRWXU)
        errors = []
        node = walker.walk(self.tmp, errors=errors)
        self.assertEqual(len(errors), 1)
        self.assertGreaterEqual(node.unreadable, 1)

    def test_max_depth_truncates_but_keeps_totals(self):
        build_tree(self.tmp, {"a": {"b": {"c": {"f": 4000}}}})
        node = walker.walk(self.tmp, max_depth=1)
        child = self.find(node, "a")
        self.assertTrue(child.truncated)
        self.assertEqual(child.children, ())
        self.assertEqual(child.apparent, 4000)
        self.assertEqual(node.apparent, 4000)

    def test_exclude_prunes_subtree(self):
        build_tree(self.tmp, {"keep": {"f": 100}, "skip": {"f": 9999}})
        node = walker.walk(self.tmp, exclude=(os.path.join(self.tmp, "skip"),))
        self.assertEqual(node.apparent, 100)

    def test_weird_filenames_survive(self):
        os.makedirs(os.path.join(self.tmp, "we ird\nname"))
        with open(os.path.join(self.tmp, "we ird\nname", "f"), "wb") as handle:
            handle.write(b"x" * 10)
        node = walker.walk(self.tmp)
        self.assertEqual(node.apparent, 10)

    def test_non_utf8_filename_is_counted(self):
        raw_dir = os.path.join(os.fsencode(self.tmp), b"caf\xe9")
        try:
            os.mkdir(raw_dir)
        except (OSError, UnicodeError):
            self.skipTest("filesystem rejected a non-UTF-8 name")
        with open(os.path.join(raw_dir, b"f"), "wb") as handle:
            handle.write(b"x" * 10)
        node = walker.walk(self.tmp)
        self.assertEqual(node.apparent, 10)

    def test_walk_is_iterative_not_recursive(self):
        # A 1200-deep tree can't be built on macOS (PATH_MAX is 1024), so
        # depth alone can't prove this. Instead: build a 100-deep tree and
        # lower the recursion limit below it. A per-directory recursive walk
        # would raise RecursionError; an iterative one does not care.
        #
        # Built and torn down one level at a time, because os.makedirs and
        # shutil.rmtree are themselves recursive.
        depth = 100
        path = self.tmp
        levels = []
        for index in range(depth):
            path = os.path.join(path, "d{}".format(index))
            os.mkdir(path)
            levels.append(path)
        leaf = os.path.join(path, "f")
        with open(leaf, "wb") as handle:
            handle.write(b"x" * 42)

        def teardown():
            os.remove(leaf)
            for directory in reversed(levels):
                os.rmdir(directory)

        self.addCleanup(teardown)

        current = sys.getrecursionlimit()
        self.addCleanup(sys.setrecursionlimit, current)
        stack_depth = 0
        frame = sys._getframe()
        while frame is not None:
            stack_depth += 1
            frame = frame.f_back
        sys.setrecursionlimit(stack_depth + 40)

        node = walker.walk(self.tmp)
        self.assertEqual(node.apparent, 42)
        self.assertEqual(node.count, 1)

    def test_missing_root_records_error(self):
        errors = []
        node = walker.walk(os.path.join(self.tmp, "gone"), errors=errors)
        self.assertEqual(node.apparent, 0)
        self.assertEqual(len(errors), 1)


class DirSizeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_returns_totals(self):
        build_tree(self.tmp, {"a": {"f": 1000}, "b": 2000})
        size, apparent, count = walker.dir_size(self.tmp)
        self.assertEqual(apparent, 3000)
        self.assertEqual(count, 2)
        self.assertGreaterEqual(size, 0)

    def test_single_file_path(self):
        build_tree(self.tmp, {"f": 700})
        _, apparent, count = walker.dir_size(os.path.join(self.tmp, "f"))
        self.assertEqual(apparent, 700)
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
