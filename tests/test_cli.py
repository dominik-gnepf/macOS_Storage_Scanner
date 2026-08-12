from __future__ import annotations

import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from storagescan import cli, serialize
from storagescan.config import Config
from tests.support import build_tree


class ParserTest(unittest.TestCase):
    def test_defaults(self):
        args = cli.build_parser().parse_args([])
        self.assertFalse(args.deep)
        self.assertFalse(args.json)
        self.assertFalse(args.dry_run)
        self.assertFalse(args.include_cloud)
        self.assertEqual(args.workers, 8)

    def test_flags(self):
        args = cli.build_parser().parse_args(
            ["--deep", "--json", "--no-color", "--dry-run", "--include-cloud"])
        self.assertTrue(args.deep)
        self.assertTrue(args.json)
        self.assertTrue(args.no_color)
        self.assertTrue(args.dry_run)
        self.assertTrue(args.include_cloud)

    def test_repeatable_path(self):
        args = cli.build_parser().parse_args(["--path", "/a", "--path", "/b"])
        self.assertEqual(args.path, ["/a", "/b"])

    def test_version_prints_and_exits_zero(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as ctx:
            cli.build_parser().parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("0.2.0", out.getvalue())

    def test_purge_flag(self):
        self.assertTrue(cli.build_parser().parse_args(["--purge"]).purge)

    def test_bad_flag_exits_two(self):
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stderr(io.StringIO()):
                cli.build_parser().parse_args(["--nope"])
        self.assertEqual(ctx.exception.code, cli.EXIT_USAGE)


class CheckFdaTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def test_absent_protected_dirs_count_as_fine(self):
        self.assertTrue(cli.check_fda(self.home))

    def test_readable_protected_dir_is_fine(self):
        os.makedirs(os.path.join(self.home, "Downloads"))
        self.assertTrue(cli.check_fda(self.home))

    def test_unreadable_protected_dir_is_detected(self):
        blocked = os.path.join(self.home, "Downloads")
        os.makedirs(blocked)
        os.chmod(blocked, 0)
        self.addCleanup(os.chmod, blocked, stat.S_IRWXU)
        self.assertFalse(cli.check_fda(self.home))

    def test_out_of_scope_protected_dir_is_not_probed(self):
        # --path ~/Developer must not warn about ~/Downloads.
        blocked = os.path.join(self.home, "Downloads")
        os.makedirs(blocked)
        os.chmod(blocked, 0)
        self.addCleanup(os.chmod, blocked, stat.S_IRWXU)
        developer = os.path.join(self.home, "Developer")
        os.makedirs(developer)
        self.assertTrue(cli.check_fda(self.home, (developer,)))

    def test_in_scope_protected_dir_is_still_probed(self):
        blocked = os.path.join(self.home, "Downloads")
        os.makedirs(blocked)
        os.chmod(blocked, 0)
        self.addCleanup(os.chmod, blocked, stat.S_IRWXU)
        self.assertFalse(cli.check_fda(self.home, (self.home,)))


class RunScanTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        build_tree(self.home, {
            "Library": {"Caches": {"Homebrew": {"big": 2_000_000}}},
            "Downloads": {"a.dmg": 3_000_000},
        })

    def scan(self, argv):
        cfg = Config(scan_paths=(self.home,), fast_depth=4)
        args = cli.build_parser().parse_args(argv)
        return cli.run_scan(cfg, args, home=self.home, now=1_800_000_000.0)

    def test_fast_scan_produces_a_tree_and_findings(self):
        result = self.scan([])
        self.assertIsNotNone(result.root)
        self.assertEqual(result.mode, "fast")
        self.assertTrue(result.findings)

    def test_roots_are_recorded_on_the_result(self):
        self.assertEqual(self.scan([]).roots, (self.home,))

    def test_deep_mode_is_labelled(self):
        self.assertEqual(self.scan(["--deep"]).mode, "deep")

    def test_scan_never_raises_on_unreadable_paths(self):
        secret = os.path.join(self.home, "secret")
        os.makedirs(secret)
        os.chmod(secret, 0)
        self.addCleanup(os.chmod, secret, stat.S_IRWXU)
        self.assertIsNotNone(self.scan([]).root)

    def test_cloud_folders_are_excluded_and_reported(self):
        os.makedirs(os.path.join(self.home, "Library", "CloudStorage", "X"))
        with open(os.path.join(self.home, "Library", "CloudStorage", "X", "f"),
                  "wb") as handle:
            handle.write(b"z" * 50_000_000)
        result = self.scan([])
        categories = {f.category for f in result.findings}
        self.assertIn("cloud.folder", categories)
        # The excluded tree must not be counted. The other fixtures total
        # ~5 MB, so a 50 MB cloud file gives an unambiguous threshold.
        self.assertLess(result.root.size, 20_000_000)

    def test_include_cloud_opts_back_in(self):
        os.makedirs(os.path.join(self.home, "Library", "CloudStorage", "X"))
        with open(os.path.join(self.home, "Library", "CloudStorage", "X", "f"),
                  "wb") as handle:
            handle.write(b"z" * 50_000_000)
        result = self.scan(["--include-cloud"])
        self.assertGreaterEqual(result.root.apparent, 50_000_000)
        self.assertNotIn("cloud.folder", {f.category for f in result.findings})

    def test_deep_scan_does_not_walk_cloud_folders(self):
        payload = b"D" * 1_200_000
        cloud = os.path.join(self.home, "Library", "CloudStorage", "X")
        os.makedirs(cloud)
        for name in ("a.bin", "b.bin"):
            with open(os.path.join(cloud, name), "wb") as handle:
                handle.write(payload)
        result = self.scan(["--deep"])
        for finding in result.findings:
            if finding.category != "dupes.copy":
                continue
            self.assertNotIn("CloudStorage", finding.detail or "")
            self.assertNotIn("CloudStorage", finding.path or "")


class WantsMenuTest(unittest.TestCase):
    class TTY:
        def isatty(self):
            return True

    class Pipe:
        def isatty(self):
            return False

    def parse(self, argv):
        return cli.build_parser().parse_args(argv)

    def test_bare_invocation_on_a_tty_wants_the_menu(self):
        self.assertTrue(cli.wants_menu(
            self.parse([]), stdin=self.TTY(), stdout=self.TTY()))

    def test_path_skips_the_menu(self):
        self.assertFalse(cli.wants_menu(
            self.parse(["--path", "/tmp"]), stdin=self.TTY(), stdout=self.TTY()))

    def test_menu_flag_wins_over_path(self):
        self.assertTrue(cli.wants_menu(
            self.parse(["--path", "/tmp", "--menu"]),
            stdin=self.TTY(), stdout=self.TTY()))

    def test_pipe_skips_the_menu(self):
        self.assertFalse(cli.wants_menu(
            self.parse([]), stdin=self.Pipe(), stdout=self.TTY()))


class LauncherPathTest(unittest.TestCase):
    def test_resolves_to_macosscanner(self):
        path = cli.launcher_path()
        self.assertTrue(os.path.exists(path))
        self.assertEqual(os.path.basename(path), "macosscanner")


class ScopeTest(unittest.TestCase):
    def test_home_inside_roots_is_covered(self):
        self.assertTrue(cli._covers_home(("/Users/x",), "/Users/x"))
        self.assertTrue(cli._covers_home(("/Users",), "/Users/x"))

    def test_unrelated_root_does_not_cover_home(self):
        self.assertFalse(cli._covers_home(("/Volumes/Ext",), "/Users/x"))

    def test_sibling_prefix_does_not_count_as_covering(self):
        self.assertFalse(cli._covers_home(("/Users/x2",), "/Users/x"))

    def test_narrowing_to_a_subdir_does_not_cover_home(self):
        # --path ~/Developer must not drag the whole home directory back in.
        self.assertFalse(cli._covers_home(("/Users/x/Developer",), "/Users/x"))


class MainTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        build_tree(self.home, {"Downloads": {"a.dmg": 2_000_000}})
        self.cache = os.path.join(self.home, "cache.json")

    def argv(self, extra):
        return ["--path", self.home, "--cache-file", self.cache,
                "--no-color"] + extra

    def run_main(self, extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(self.argv(extra))
        return code, out.getvalue()

    def test_json_output_is_valid_and_parses_back(self):
        code, out = self.run_main(["--json"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(json.loads(out)["schema"], serialize.SCHEMA)

    def test_summary_output_is_printed(self):
        code, out = self.run_main(["--summary"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Downloads", out)

    def test_scan_writes_the_cache(self):
        self.run_main(["--summary"])
        self.assertTrue(os.path.exists(self.cache))

    def test_cached_reuses_previous_scan(self):
        self.run_main(["--summary"])
        shutil.rmtree(os.path.join(self.home, "Downloads"))
        code, out = self.run_main(["--summary", "--cached"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Downloads", out)

    def test_cached_without_cache_returns_error(self):
        with redirect_stderr(io.StringIO()):
            code = cli.main(["--cache-file", os.path.join(self.home, "none.json"),
                             "--cached", "--summary"])
        self.assertEqual(code, cli.EXIT_ERROR)

    def test_diff_reports_growth_between_runs(self):
        self.run_main(["--summary"])
        with open(os.path.join(self.home, "Downloads", "b.dmg"), "wb") as handle:
            handle.write(b"y" * 4_000_000)
        code, out = self.run_main(["--summary", "--diff"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Changes since the previous scan", out)

    def test_report_writes_html(self):
        target = os.path.join(self.home, "r.html")
        code, _out = self.run_main(
            ["--report", "--report-file", target, "--no-open"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertTrue(os.path.exists(target))

    def test_scheduled_env_refuses_reclaim(self):
        os.environ["STORAGESCAN_SCHEDULED"] = "1"
        self.addCleanup(os.environ.pop, "STORAGESCAN_SCHEDULED", None)
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = cli.main(self.argv(["--reclaim"]))
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("read-only", err.getvalue())

    def test_bad_config_returns_error_not_traceback(self):
        bad = os.path.join(self.home, "bad.json")
        with open(bad, "w") as handle:
            handle.write("{broken")
        with redirect_stderr(io.StringIO()):
            code = cli.main(["--config", bad, "--summary"])
        self.assertEqual(code, cli.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main()
