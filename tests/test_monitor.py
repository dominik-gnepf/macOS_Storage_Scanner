from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest

from storagescan import monitor
from storagescan.model import Finding, Node, Risk, ScanResult, VolumeInfo


def result(free=5_000_000_000, safe_bytes=0, volumes=None):
    findings = ()
    if safe_bytes:
        findings = (Finding("homebrew.cache", "Homebrew", "/h/c", safe_bytes,
                            Risk.SAFE),)
    if volumes is None:
        volumes = (VolumeInfo("/System/Volumes/Data", 245_000_000_000,
                              240_000_000_000, free),)
    return ScanResult(
        root=Node(path="/h", size=1, apparent=1, count=1, mtime=0.0),
        findings=findings, volumes=volumes)


class PlistTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.contents = monitor.plist_contents(
            launcher="/opt/storagescan/bin/storagescan", home=self.home)

    def test_runs_the_wrapper_not_the_checkout(self):
        # The plist must not point into the repo: if the clone moves,
        # launchd would fail silently. The wrapper lives under $HOME.
        self.assertEqual(self.contents["ProgramArguments"],
                         [monitor.wrapper_path(self.home)])

    def test_weekly_by_default(self):
        self.assertEqual(self.contents["StartInterval"], 7 * 24 * 60 * 60)

    def test_does_not_run_at_load(self):
        # Installing a monitor must not start a minute of disk activity.
        self.assertFalse(self.contents["RunAtLoad"])

    def test_runs_at_low_priority(self):
        self.assertTrue(self.contents["LowPriorityIO"])
        self.assertEqual(self.contents["ProcessType"], "Background")

    def test_logs_inside_the_given_home(self):
        self.assertTrue(self.contents["StandardOutPath"].startswith(self.home))

    def test_is_valid_plist_that_round_trips(self):
        path = monitor.write_plist(
            os.path.join(self.home, "a.plist"), self.contents)
        with open(path, "rb") as handle:
            self.assertEqual(plistlib.load(handle), self.contents)

    def test_write_creates_missing_directories(self):
        path = os.path.join(self.home, "Library", "LaunchAgents", "x.plist")
        monitor.write_plist(path, self.contents)
        self.assertTrue(os.path.exists(path))

    def test_agent_and_log_paths_derive_from_home(self):
        self.assertTrue(monitor.agent_path(self.home).startswith(self.home))
        self.assertTrue(monitor.log_path(self.home).startswith(self.home))
        self.assertTrue(monitor.wrapper_path(self.home).startswith(self.home))


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.calls = []

    def runner(self, code=0):
        def run(args):
            self.calls.append(list(args))
            return code, ""
        return run

    def test_writes_the_plist_and_bootstraps(self):
        ok, path = monitor.install(launcher="/x/storagescan", home=self.home,
                                   runner=self.runner())
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(os.path.exists(monitor.wrapper_path(self.home)))
        self.assertIn("bootstrap", [c[0] for c in self.calls])

    def test_unloads_any_previous_copy_first(self):
        # Without this, bootstrap fails and the user silently keeps the old job.
        monitor.install(launcher="/x/storagescan", home=self.home,
                        runner=self.runner())
        self.assertEqual(self.calls[0][0], "bootout")

    def test_reports_failure_from_launchctl(self):
        ok, message = monitor.install(launcher="/x/s", home=self.home,
                                      runner=self.runner(code=1))
        self.assertFalse(ok)
        self.assertIn("bootstrap failed", message)

    def test_uninstall_removes_the_plist(self):
        monitor.install(launcher="/x/s", home=self.home, runner=self.runner())
        self.assertTrue(monitor.is_installed(self.home))
        ok, _msg = monitor.uninstall(home=self.home, runner=self.runner())
        self.assertTrue(ok)
        self.assertFalse(monitor.is_installed(self.home))
        self.assertFalse(os.path.exists(monitor.wrapper_path(self.home)))

    def test_uninstall_when_nothing_installed_is_not_an_error(self):
        ok, message = monitor.uninstall(home=self.home, runner=self.runner())
        self.assertTrue(ok)
        self.assertIn("no agent", message)

    def test_status_reports_each_state(self):
        self.assertEqual(monitor.status(self.home, runner=self.runner()),
                         "not installed")
        monitor.install(launcher="/x/s", home=self.home, runner=self.runner())
        self.assertEqual(monitor.status(self.home, runner=self.runner(0)),
                         "installed and loaded")
        self.assertEqual(monitor.status(self.home, runner=self.runner(1)),
                         "installed but not loaded")


class WrapperTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def test_wrapper_is_executable_and_points_at_the_launcher(self):
        path = monitor.wrapper_path(self.home)
        monitor.write_wrapper(path, "/opt/macosscanner")
        self.assertTrue(os.access(path, os.X_OK))
        with open(path) as handle:
            body = handle.read()
        self.assertIn("/opt/macosscanner", body)
        self.assertIn("--check", body)

    def test_missing_launcher_exits_nonzero_with_a_message(self):
        path = monitor.wrapper_path(self.home)
        missing = os.path.join(self.home, "gone")
        monitor.write_wrapper(path, missing)
        proc = subprocess.run(
            [path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"missing", proc.stdout)


class AlertTest(unittest.TestCase):
    def test_alerts_below_the_threshold(self):
        self.assertTrue(monitor.should_alert(result(free=5_000_000_000),
                                             threshold=20_000_000_000))

    def test_silent_above_the_threshold(self):
        self.assertFalse(monitor.should_alert(result(free=90_000_000_000),
                                              threshold=20_000_000_000))

    def test_exactly_at_the_threshold_is_silent(self):
        self.assertFalse(monitor.should_alert(result(free=20_000_000_000),
                                              threshold=20_000_000_000))

    def test_no_volume_never_alerts(self):
        self.assertFalse(monitor.should_alert(result(volumes=())))

    def test_message_names_free_space_and_the_win(self):
        message = monitor.alert_message(
            result(free=5_000_000_000, safe_bytes=36_500_000_000))
        self.assertIn("5.0 GB free", message)
        self.assertIn("36.5 GB", message)

    def test_message_omits_the_win_when_there_is_none(self):
        message = monitor.alert_message(result(free=5_000_000_000))
        self.assertIn("5.0 GB free", message)
        self.assertNotIn("reclaimed", message)


class AppleScriptQuotingTest(unittest.TestCase):
    """Scan output contains file names, and file names contain anything."""

    def test_plain_text_is_quoted(self):
        self.assertEqual(monitor._applescript_string("hi"), '"hi"')

    def test_double_quotes_are_escaped(self):
        # Unescaped, this would close the string and run the rest as code.
        self.assertEqual(monitor._applescript_string('a"b'), '"a\\"b"')

    def test_backslashes_are_escaped(self):
        self.assertEqual(monitor._applescript_string("a\\b"), '"a\\\\b"')

    def test_a_quote_after_a_backslash_cannot_escape_the_terminator(self):
        quoted = monitor._applescript_string('a\\"; do evil')
        self.assertTrue(quoted.startswith('"') and quoted.endswith('"'))
        self.assertIn("\\\\", quoted)

    def test_notify_passes_a_single_argument_not_a_shell_string(self):
        seen = []

        def runner(args):
            seen.append(args)
            return 0

        monitor.notify('boom"; rm -rf /', runner=runner)
        # osascript is invoked directly with an argv list, so there is no
        # shell to interpret anything in the message.
        self.assertEqual(seen[0][0], "osascript")
        self.assertEqual(seen[0][1], "-e")
        self.assertEqual(len(seen[0]), 3)


if __name__ == "__main__":
    unittest.main()
