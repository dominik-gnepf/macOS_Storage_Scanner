from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan import actions


def always(_path, _risk, _mode):
    return True


def never(_path, _risk, _mode):
    return False


class PerformTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.trash = os.path.join(self.home, ".Trash")
        os.makedirs(self.trash)
        self.log = os.path.join(self.home, "actions.log")
        self.kw = dict(home=self.home, scan_roots=(self.home,),
                       trash_dir=self.trash, log_path=self.log)

    def make(self, relpath, size=100):
        path = os.path.join(self.home, relpath)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(b"x" * size)
        return path

    def test_safe_file_is_moved_to_trash(self):
        path = self.make("Library/Caches/Homebrew/a.bin")
        outcome = actions.perform(path, category="homebrew.cache",
                                  confirm=always, **self.kw)
        self.assertEqual(outcome.status, actions.TRASHED)
        self.assertFalse(os.path.exists(path))
        self.assertTrue(os.path.exists(os.path.join(self.trash, "a.bin")))

    def test_blocked_path_is_refused_without_prompting(self):
        prompted = []

        def confirm(path, risk, mode):
            prompted.append(path)
            return True

        outcome = actions.perform(self.home, category=None, confirm=confirm,
                                  **self.kw)
        self.assertEqual(outcome.status, actions.REFUSED)
        self.assertEqual(prompted, [])
        self.assertTrue(os.path.isdir(self.home))

    def test_path_outside_scan_roots_is_refused(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        victim = os.path.join(outside, "precious.bin")
        with open(victim, "wb") as handle:
            handle.write(b"x" * 100)
        outcome = actions.perform(victim, category="homebrew.cache",
                                  confirm=always, **self.kw)
        self.assertEqual(outcome.status, actions.REFUSED)
        self.assertTrue(os.path.exists(victim))

    def test_declining_leaves_the_file(self):
        path = self.make("Library/Caches/Homebrew/a.bin")
        outcome = actions.perform(path, category="homebrew.cache",
                                  confirm=never, **self.kw)
        self.assertEqual(outcome.status, actions.DECLINED)
        self.assertTrue(os.path.exists(path))

    def test_dry_run_never_touches_the_filesystem(self):
        path = self.make("Library/Caches/Homebrew/a.bin")
        outcome = actions.perform(path, category="homebrew.cache",
                                  confirm=always, dry_run=True, **self.kw)
        self.assertEqual(outcome.status, actions.DRY_RUN)
        self.assertTrue(os.path.exists(path))

    def test_purge_removes_permanently(self):
        path = self.make("Library/Caches/Homebrew/a.bin")
        outcome = actions.perform(path, category="homebrew.cache",
                                  confirm=always, use_trash=False, **self.kw)
        self.assertEqual(outcome.status, actions.PURGED)
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(os.path.join(self.trash, "a.bin")))

    def test_directory_is_trashed_whole(self):
        self.make("Library/Caches/Homebrew/inner/a.bin", 500)
        target = os.path.join(self.home, "Library/Caches/Homebrew")
        outcome = actions.perform(target, category="homebrew.cache",
                                  confirm=always, **self.kw)
        self.assertEqual(outcome.status, actions.TRASHED)
        self.assertEqual(outcome.bytes_, 500)
        self.assertTrue(os.path.isdir(os.path.join(self.trash, "Homebrew")))

    def test_symlink_is_refused_and_target_survives(self):
        real = self.make("Library/Caches/Homebrew/real.bin")
        link = os.path.join(self.home, "Library/Caches/Homebrew/link.bin")
        os.symlink(real, link)
        outcome = actions.perform(link, category="homebrew.cache",
                                  confirm=always, **self.kw)
        self.assertEqual(outcome.status, actions.REFUSED)
        self.assertTrue(os.path.exists(real))
        self.assertTrue(os.path.islink(link))

    def test_missing_path_fails_cleanly(self):
        outcome = actions.perform(
            os.path.join(self.home, "Library/Caches/Homebrew/x"),
            category="homebrew.cache", confirm=always, **self.kw)
        self.assertEqual(outcome.status, actions.FAILED)

    def test_confirmation_mode_escalates_with_risk(self):
        modes = []

        def confirm(path, risk, mode):
            modes.append(mode)
            return True

        actions.perform(self.make("Library/Caches/Homebrew/a.bin"),
                        category="homebrew.cache", confirm=confirm, **self.kw)
        actions.perform(self.make("Downloads/b.dmg"),
                        category="downloads", confirm=confirm, **self.kw)
        actions.perform(self.make("Movies/c.mov"),
                        category=None, confirm=confirm, **self.kw)
        self.assertEqual(modes, ["single", "recap", "retype"])

    def test_trash_collision_keeps_both(self):
        with open(os.path.join(self.trash, "a.bin"), "wb") as handle:
            handle.write(b"older")
        path = self.make("Library/Caches/Homebrew/a.bin")
        actions.perform(path, category="homebrew.cache", confirm=always, **self.kw)
        self.assertEqual(len(os.listdir(self.trash)), 2)

    def test_every_action_is_logged_with_a_redacted_path(self):
        path = self.make("Library/Caches/Homebrew/a.bin")
        actions.perform(path, category="homebrew.cache", confirm=always, **self.kw)
        with open(self.log) as handle:
            body = handle.read()
        self.assertIn("trashed", body)
        self.assertIn("~/Library/Caches/Homebrew/a.bin", body)
        self.assertNotIn(self.home, body)

    def test_refusals_are_logged_too(self):
        actions.perform(self.home, category=None, confirm=always, **self.kw)
        with open(self.log) as handle:
            self.assertIn("refused", handle.read())


class TrashPathTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_uses_the_basename_when_free(self):
        self.assertEqual(actions.trash_path("/a/b/c.txt", trash_dir=self.tmp),
                         os.path.join(self.tmp, "c.txt"))

    def test_suffixes_on_collision_preserving_extension(self):
        with open(os.path.join(self.tmp, "c.txt"), "w") as handle:
            handle.write("x")
        result = actions.trash_path("/a/b/c.txt", trash_dir=self.tmp)
        self.assertNotEqual(result, os.path.join(self.tmp, "c.txt"))
        self.assertTrue(result.endswith(".txt"))

    def test_trailing_slash_on_directories(self):
        self.assertEqual(actions.trash_path("/a/b/dir/", trash_dir=self.tmp),
                         os.path.join(self.tmp, "dir"))


if __name__ == "__main__":
    unittest.main()
