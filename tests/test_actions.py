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

    def test_require_safe_refuses_a_review_path(self):
        path = self.make("Downloads/a.dmg")
        outcome = actions.perform(
            path, category="downloads", confirm=always,
            require_safe=True, **self.kw)
        self.assertEqual(outcome.status, actions.REFUSED)
        self.assertTrue(os.path.exists(path))

    def test_require_safe_refuses_user_media_even_with_a_safe_category(self):
        path = self.make("Movies/vacation.mov")
        outcome = actions.perform(
            path, category="homebrew.cache", confirm=always,
            require_safe=True, **self.kw)
        self.assertEqual(outcome.status, actions.REFUSED)
        self.assertTrue(os.path.exists(path))

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

    def test_measure_reports_on_disk_bytes(self):
        path = self.make("Library/Caches/Homebrew/a.bin", 1)
        on_disk = os.lstat(path).st_blocks * 512
        self.assertEqual(actions.measure(path), on_disk)
        self.assertNotEqual(actions.measure(path), 1)

    def test_aborts_if_the_path_is_replaced_during_confirm(self):
        path = self.make("Library/Caches/Homebrew/a.bin")

        def confirm(_path, _risk, _mode):
            os.remove(path)
            with open(path, "wb") as handle:
                handle.write(b"replaced-with-something-else")
            return True

        outcome = actions.perform(path, category="homebrew.cache",
                                  confirm=confirm, **self.kw)
        self.assertEqual(outcome.status, actions.CHANGED)
        self.assertTrue(os.path.exists(path))
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), b"replaced-with-something-else")

    def test_directory_is_trashed_whole(self):
        self.make("Library/Caches/Homebrew/inner/a.bin", 500)
        target = os.path.join(self.home, "Library/Caches/Homebrew")
        outcome = actions.perform(target, category="homebrew.cache",
                                  confirm=always, **self.kw)
        self.assertEqual(outcome.status, actions.TRASHED)
        self.assertEqual(outcome.bytes_, actions.measure(
            os.path.join(self.trash, "Homebrew")))
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

    def test_same_second_collision_does_not_reuse_the_stamped_name(self):
        with open(os.path.join(self.tmp, "c.txt"), "w") as handle:
            handle.write("first")
        stamped = actions.trash_path("/a/b/c.txt", trash_dir=self.tmp)
        with open(stamped, "w") as handle:
            handle.write("second")
        again = actions.trash_path("/a/b/c.txt", trash_dir=self.tmp)
        self.assertNotEqual(again, os.path.join(self.tmp, "c.txt"))
        self.assertNotEqual(again, stamped)
        self.assertTrue(again.endswith(".txt"))
        self.assertFalse(os.path.lexists(again))

    def test_trailing_slash_on_directories(self):
        self.assertEqual(actions.trash_path("/a/b/dir/", trash_dir=self.tmp),
                         os.path.join(self.tmp, "dir"))




class TrashDirForTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.other, ignore_errors=True)

    def test_same_volume_uses_home_trash(self):
        path = os.path.join(self.home, "a.bin")
        with open(path, "w") as handle:
            handle.write("x")
        self.assertEqual(actions.trash_dir_for(path, self.home),
                         os.path.join(self.home, ".Trash"))

    def test_other_volume_uses_dot_trashes_on_that_volume(self):
        path = os.path.join(self.other, "big.img")
        with open(path, "w") as handle:
            handle.write("x")
        original = actions._device
        other_root = os.path.abspath(self.other)

        def fake(p):
            if os.path.abspath(p) == other_root or os.path.abspath(p).startswith(
                    other_root + os.sep):
                return 99
            return 1

        actions._device = fake
        try:
            chosen = actions.trash_dir_for(path, self.home)
        finally:
            actions._device = original
        self.assertEqual(
            chosen,
            os.path.join(self.other, ".Trashes", str(os.getuid())))


class ConfinementTest(unittest.TestCase):
    """Regression: a deletion must resolve its Trash from the `home` it was
    given, never from $HOME. Getting this wrong once moved test files into the
    real user's Trash."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def test_trash_dir_is_derived_from_home(self):
        self.assertEqual(actions.default_trash_dir(self.home),
                         os.path.join(self.home, ".Trash"))

    def test_log_path_is_derived_from_home(self):
        self.assertTrue(
            actions.default_log_path(self.home).startswith(self.home))

    def test_trash_path_follows_home_without_an_explicit_dir(self):
        chosen = actions.trash_path(
            os.path.join(self.home, "a.bin"), home=self.home)
        self.assertTrue(chosen.startswith(os.path.join(self.home, ".Trash")))

    def test_delete_without_trash_dir_stays_inside_home(self):
        target = os.path.join(self.home, "Library", "Caches", "Homebrew")
        os.makedirs(target)
        victim = os.path.join(target, "a.bin")
        with open(victim, "wb") as handle:
            handle.write(b"x" * 10)

        outcome = actions.perform(
            victim, home=self.home, scan_roots=(self.home,),
            category="homebrew.cache", confirm=always,
            log_path=os.path.join(self.home, "log"))

        self.assertEqual(outcome.status, actions.TRASHED)
        # The decisive assertion: the file landed under the given home.
        self.assertTrue(outcome.message.startswith(self.home), outcome.message)
        self.assertTrue(os.path.exists(
            os.path.join(self.home, ".Trash", "a.bin")))

    def test_real_home_is_never_touched_by_a_scoped_delete(self):
        real_trash = os.path.expanduser("~/.Trash")
        target = os.path.join(self.home, "Library", "Caches", "pip")
        os.makedirs(target)
        marker = "storagescan-confinement-probe.bin"
        victim = os.path.join(target, marker)
        with open(victim, "wb") as handle:
            handle.write(b"x" * 10)

        actions.perform(victim, home=self.home, scan_roots=(self.home,),
                        category="pip.cache", confirm=always,
                        log_path=os.path.join(self.home, "log"))

        self.assertFalse(os.path.lexists(os.path.join(real_trash, marker)))


if __name__ == "__main__":
    unittest.main()
