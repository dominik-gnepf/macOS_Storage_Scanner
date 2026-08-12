from __future__ import annotations

import io
import os
import shutil
import tempfile
import unittest

from storagescan import cli
from storagescan.config import Config
from storagescan.model import Finding, Node, Risk, ScanResult


class ReclaimBatchTest(unittest.TestCase):
    """What a bulk delete is allowed to touch. Deliberately narrow."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def make(self, name, size=100):
        path = os.path.join(self.home, name)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(b"x" * size)
        return path

    def result(self, findings):
        return ScanResult(
            root=Node(path=self.home, size=1, apparent=1, count=1, mtime=0.0),
            findings=tuple(findings), roots=(self.home,))

    def test_includes_safe_findings_that_exist(self):
        path = self.make("Library/Caches/Homebrew/a.bin")
        batch = cli.reclaimable_batch(
            self.result([Finding("homebrew.cache", "Homebrew", path, 100,
                                 Risk.SAFE)]), self.home)
        self.assertEqual([f.path for f in batch], [path])

    def test_excludes_review_and_danger_tiers(self):
        review = self.make("Downloads/a.dmg")
        danger = self.make("Movies/a.mov")
        batch = cli.reclaimable_batch(self.result([
            Finding("downloads", "Downloads", review, 100, Risk.REVIEW),
            Finding("photos.library", "Photos", danger, 100, Risk.DANGER),
        ]), self.home)
        self.assertEqual(batch, ())

    def test_excludes_blocked_findings(self):
        batch = cli.reclaimable_batch(self.result([
            Finding("cloud.folder", "Cloud", self.make("c.bin"), 100,
                    Risk.BLOCKED)]), self.home)
        self.assertEqual(batch, ())

    def test_excludes_pathless_findings(self):
        batch = cli.reclaimable_batch(self.result([
            Finding("apfs.snapshot", "Snapshot", None, 0, Risk.SAFE)]), self.home)
        self.assertEqual(batch, ())

    def test_excludes_findings_whose_path_has_vanished(self):
        path = self.make("Library/Caches/Homebrew/a.bin")
        os.remove(path)
        batch = cli.reclaimable_batch(self.result([
            Finding("homebrew.cache", "Homebrew", path, 100, Risk.SAFE)]),
            self.home)
        self.assertEqual(batch, ())

    def test_excludes_zero_byte_findings(self):
        path = self.make("Library/Caches/Homebrew/a.bin")
        batch = cli.reclaimable_batch(self.result([
            Finding("homebrew.cache", "Homebrew", path, 0, Risk.SAFE)]), self.home)
        self.assertEqual(batch, ())

    def test_excludes_user_media_even_with_a_safe_category(self):
        path = self.make("Movies/vacation.mov")
        batch = cli.reclaimable_batch(self.result([
            Finding("homebrew.cache", "Homebrew", path, 100, Risk.SAFE)]),
            self.home)
        self.assertEqual(batch, ())

    def test_ordered_biggest_first(self):
        small = self.make("Library/Caches/pip/s.bin")
        big = self.make("Library/Caches/Homebrew/b.bin")
        batch = cli.reclaimable_batch(self.result([
            Finding("pip.cache", "pip", small, 10, Risk.SAFE),
            Finding("homebrew.cache", "Homebrew", big, 900, Risk.SAFE),
        ]), self.home)
        self.assertEqual([f.path for f in batch], [big, small])


class RunReclaimTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        os.makedirs(os.path.join(self.home, ".Trash"))
        self.cfg = Config(scan_paths=(self.home,))

    def make(self, name, size=100):
        path = os.path.join(self.home, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(b"x" * size)
        return path

    def result(self, findings):
        return ScanResult(
            root=Node(path=self.home, size=1, apparent=1, count=1, mtime=0.0),
            findings=tuple(findings), roots=(self.home,))

    def run_it(self, findings, answer, extra_argv=()):
        args = cli.build_parser().parse_args(list(extra_argv))
        out = io.StringIO()
        code = cli.run_reclaim(
            self.result(findings), self.cfg, args, home=self.home,
            stdin=io.StringIO(answer), stdout=out)
        return code, out.getvalue()

    def safe_finding(self, name, size=100):
        path = self.make(name, size)
        return Finding("homebrew.cache", "Homebrew downloads", path, size,
                       Risk.SAFE), path

    def test_yes_removes_everything_in_the_batch(self):
        first, path1 = self.safe_finding("Library/Caches/Homebrew/a.bin")
        second, path2 = self.safe_finding("Library/Caches/pip/b.bin")
        code, out = self.run_it([first, second], "y\n")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertFalse(os.path.exists(path1))
        self.assertFalse(os.path.exists(path2))
        self.assertIn("Reclaimed", out)

    def test_no_removes_nothing(self):
        finding, path = self.safe_finding("Library/Caches/Homebrew/a.bin")
        code, out = self.run_it([finding], "n\n")
        self.assertTrue(os.path.exists(path))
        self.assertIn("Nothing was deleted", out)

    def test_empty_answer_is_treated_as_no(self):
        finding, path = self.safe_finding("Library/Caches/Homebrew/a.bin")
        _code, out = self.run_it([finding], "\n")
        self.assertTrue(os.path.exists(path))
        self.assertIn("Nothing was deleted", out)

    def test_purge_requires_the_word_purge(self):
        finding, path = self.safe_finding("Library/Caches/Homebrew/a.bin")
        _code, out = self.run_it([finding], "y\nnope\n", extra_argv=["--purge"])
        self.assertTrue(os.path.exists(path))
        self.assertIn("Nothing was deleted", out)

    def test_purge_deletes_permanently_after_the_phrase(self):
        finding, path = self.safe_finding("Library/Caches/Homebrew/a.bin")
        self.run_it([finding], "y\nPURGE\n", extra_argv=["--purge"])
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(
            os.path.join(self.home, ".Trash", "a.bin")))

    def test_dry_run_never_prompts_or_deletes(self):
        finding, path = self.safe_finding("Library/Caches/Homebrew/a.bin")
        _code, out = self.run_it([finding], "y\n", extra_argv=["--dry-run"])
        self.assertTrue(os.path.exists(path))
        self.assertIn("dry-run", out)
        self.assertNotIn("Reclaimed", out)

    def test_items_go_to_the_trash_not_oblivion(self):
        finding, path = self.safe_finding("Library/Caches/Homebrew/a.bin")
        self.run_it([finding], "y\n")
        self.assertTrue(
            os.path.exists(os.path.join(self.home, ".Trash", "a.bin")))

    def test_lists_what_it_will_do_before_asking(self):
        finding, _path = self.safe_finding("Library/Caches/Homebrew/a.bin", 4096)
        _code, out = self.run_it([finding], "n\n")
        self.assertIn("~/Library/Caches/Homebrew/a.bin", out)
        self.assertIn("total", out)
        self.assertNotIn(self.home, out)

    def test_empty_batch_says_so_and_does_not_prompt(self):
        code, out = self.run_it([], "y\n")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Nothing in the SAFE tier", out)

    def test_a_smuggled_unsafe_path_is_still_refused(self):
        # The batch prompt auto-confirms, so safety.classify is the only thing
        # standing between a mislabelled finding and real data. It must hold.
        victim = self.make("Documents/thesis.txt", 500)
        smuggled = Finding("homebrew.cache", "Homebrew downloads",
                           os.path.join(self.home, "Documents"), 500, Risk.SAFE)
        self.run_it([smuggled], "y\n")
        self.assertTrue(os.path.exists(victim))
        self.assertFalse(os.path.lexists(
            os.path.join(self.home, ".Trash", "Documents")))

    def test_a_smuggled_safe_category_on_movies_is_still_refused(self):
        # Category wins over location in classify: Movies + homebrew.cache
        # is SAFE. Bulk reclaim must not trust that — a probe bug or a
        # tampered cache must not send a vacation video to the Trash.
        victim = self.make("Movies/vacation.mov", 500)
        smuggled = Finding("homebrew.cache", "Homebrew downloads",
                           victim, 500, Risk.SAFE)
        self.run_it([smuggled], "y\n")
        self.assertTrue(os.path.exists(victim))
        self.assertFalse(os.path.lexists(
            os.path.join(self.home, ".Trash", "vacation.mov")))

    def test_reclassify_refuses_a_review_item_labelled_safe(self):
        victim = self.make("Downloads/installer.dmg", 500)
        smuggled = Finding("downloads", "Downloads", victim, 500, Risk.SAFE)
        _code, out = self.run_it([smuggled], "y\n")
        self.assertTrue(os.path.exists(victim))
        self.assertIn("could not be removed", out)

    def test_failures_are_reported_and_do_not_stop_the_rest(self):
        good, good_path = self.safe_finding("Library/Caches/pip/b.bin")
        victim = self.make("Downloads/installer.dmg", 100)
        smuggled = Finding("downloads", "Downloads", victim, 100, Risk.SAFE)
        _code, out = self.run_it([smuggled, good], "y\n")
        self.assertFalse(os.path.exists(good_path))
        self.assertTrue(os.path.exists(victim))
        self.assertIn("could not be removed", out)


class ProgressTest(unittest.TestCase):
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True

    def test_returns_none_when_not_a_terminal(self):
        self.assertIsNone(cli.make_progress(io.StringIO(), "/h", enabled=True))

    def test_returns_none_when_disabled(self):
        self.assertIsNone(cli.make_progress(self.FakeTTY(), "/h", enabled=False))

    def test_writes_counts_and_redacted_path(self):
        stream = self.FakeTTY()
        report = cli.make_progress(stream, "/h", enabled=True)
        report(1, 4, "/h/Library")
        self.assertIn("1/4", stream.getvalue())
        self.assertIn("~/Library", stream.getvalue())
        self.assertNotIn("/h/Library", stream.getvalue())

    def test_clears_the_line_when_finished(self):
        stream = self.FakeTTY()
        report = cli.make_progress(stream, "/h", enabled=True)
        report(4, 4, "/h/x")
        self.assertTrue(stream.getvalue().endswith("\r\033[2K"))

    def test_long_paths_are_shortened(self):
        stream = self.FakeTTY()
        report = cli.make_progress(stream, "/h", enabled=True)
        report(1, 2, "/h/" + "d" * 200)
        for line in stream.getvalue().split("\r"):
            self.assertLess(len(line), 80)


if __name__ == "__main__":
    unittest.main()
