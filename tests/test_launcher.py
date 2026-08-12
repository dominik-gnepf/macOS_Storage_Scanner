from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER = os.path.join(ROOT, "bin", "macosscanner")
ALIAS = os.path.join(ROOT, "bin", "storagescan")


def run(args, env=None, cwd=None):
    return subprocess.run(
        [LAUNCHER] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=env, cwd=cwd, timeout=120)


class LauncherTest(unittest.TestCase):
    def test_launcher_exists_and_is_executable(self):
        self.assertTrue(os.path.exists(LAUNCHER))
        self.assertTrue(os.access(LAUNCHER, os.X_OK))

    def test_help_passes_through_to_python(self):
        proc = run(["--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn(b"macosscanner", proc.stdout)
        self.assertIn(b"--deep", proc.stdout)

    def test_works_from_an_unrelated_working_directory(self):
        proc = run(["--help"], cwd="/")
        self.assertEqual(proc.returncode, 0)
        self.assertIn(b"--deep", proc.stdout)

    def test_missing_python_exits_three_with_guidance(self):
        env = dict(os.environ)
        env["STORAGESCAN_PYTHON"] = "/nonexistent/python3"
        proc = run(["--help"], env=env)
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"xcode-select --install", proc.stdout)

    def test_bad_arguments_reach_the_cli(self):
        self.assertEqual(run(["--nope"]).returncode, 2)

    def test_legacy_name_still_works(self):
        proc = subprocess.run([ALIAS, "--help"], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=120)
        self.assertEqual(proc.returncode, 0)


class SymlinkInvocationTest(unittest.TestCase):
    """install.sh puts a symlink on PATH. Invoked through it, BASH_SOURCE is
    the link rather than the script, so a naive dirname resolves to the link's
    parent and the Python package is never found. This is exactly how the
    first install attempt failed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.link = os.path.join(self.tmp, "macosscanner")
        os.symlink(LAUNCHER, self.link)

    def run_link(self, cwd):
        return subprocess.run([self.link, "--help"], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, cwd=cwd, timeout=120)

    def test_works_through_a_symlink(self):
        proc = self.run_link(cwd=ROOT)
        self.assertEqual(proc.returncode, 0, proc.stdout[:400])
        self.assertIn(b"--deep", proc.stdout)

    def test_works_through_a_symlink_from_an_unrelated_directory(self):
        proc = self.run_link(cwd="/")
        self.assertEqual(proc.returncode, 0, proc.stdout[:400])
        self.assertIn(b"--deep", proc.stdout)

    def test_works_through_a_chain_of_symlinks(self):
        second = os.path.join(self.tmp, "indirect")
        os.symlink(self.link, second)
        proc = subprocess.run([second, "--help"], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, cwd="/", timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout[:400])

    def test_works_through_a_relative_symlink(self):
        # bin/storagescan -> macosscanner is itself a relative link, which is
        # the case a naive absolute-path resolver gets wrong.
        nested = os.path.join(self.tmp, "nested")
        os.makedirs(nested)
        os.symlink(os.path.join("..", "macosscanner"),
                   os.path.join(nested, "rel"))
        proc = subprocess.run([os.path.join(nested, "rel"), "--help"],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              cwd="/", timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout[:400])


if __name__ == "__main__":
    unittest.main()
