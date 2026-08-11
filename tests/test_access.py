from __future__ import annotations

import os
import shutil
import stat
import tempfile
import unittest

from storagescan import access


class HostApplicationTest(unittest.TestCase):
    def setUp(self):
        self.saved = os.environ.get("TERM_PROGRAM")
        self.addCleanup(self.restore)

    def restore(self):
        if self.saved is None:
            os.environ.pop("TERM_PROGRAM", None)
        else:
            os.environ["TERM_PROGRAM"] = self.saved

    def test_recognises_known_terminals(self):
        os.environ["TERM_PROGRAM"] = "Apple_Terminal"
        self.assertEqual(access.host_application(), "Terminal")
        os.environ["TERM_PROGRAM"] = "vscode"
        self.assertEqual(access.host_application(), "Visual Studio Code")

    def test_passes_through_an_unknown_name(self):
        os.environ["TERM_PROGRAM"] = "SomeNewTerm"
        self.assertEqual(access.host_application(), "SomeNewTerm")

    def test_falls_back_to_a_description_not_a_guess(self):
        os.environ.pop("TERM_PROGRAM", None)
        self.assertIn("app you run", access.host_application())


class BlockedPathsTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def test_reports_unreadable_directories(self):
        blocked = os.path.join(self.home, "Downloads")
        os.makedirs(blocked)
        os.chmod(blocked, 0)
        self.addCleanup(os.chmod, blocked, stat.S_IRWXU)
        self.assertEqual(access.blocked_paths(self.home), (blocked,))

    def test_readable_directories_are_not_reported(self):
        os.makedirs(os.path.join(self.home, "Downloads"))
        self.assertEqual(access.blocked_paths(self.home), ())

    def test_absent_directories_are_not_reported(self):
        self.assertEqual(access.blocked_paths(self.home), ())


class InstructionsTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def test_names_the_terminal_not_the_script(self):
        # The permission belongs to the process that runs the scanner.
        text = access.instructions(self.home, app="Ghostty")
        self.assertIn("Ghostty", text)
        self.assertIn("terminal app itself", text)

    def test_is_honest_that_no_app_can_grant_itself_access(self):
        self.assertIn("No app can grant itself",
                      access.instructions(self.home, app="Terminal"))

    def test_lists_currently_blocked_paths_redacted(self):
        blocked = os.path.join(self.home, "Downloads")
        os.makedirs(blocked)
        os.chmod(blocked, 0)
        self.addCleanup(os.chmod, blocked, stat.S_IRWXU)
        text = access.instructions(self.home, app="Terminal")
        self.assertIn("~/Downloads", text)
        self.assertNotIn(self.home, text)


class OpenSettingsTest(unittest.TestCase):
    def test_opens_the_full_disk_access_pane(self):
        seen = []
        access.open_settings(runner=lambda args: seen.append(args) or 0)
        self.assertEqual(seen[0][0], "open")
        self.assertIn("Privacy_AllFiles", seen[0][1])

    def test_failure_is_reported_not_raised(self):
        self.assertFalse(access.open_settings(runner=lambda args: 1))


if __name__ == "__main__":
    unittest.main()
