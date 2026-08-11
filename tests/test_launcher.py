from __future__ import annotations

import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER = os.path.join(ROOT, "bin", "storagescan")


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
        self.assertIn(b"storagescan", proc.stdout)
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


if __name__ == "__main__":
    unittest.main()
