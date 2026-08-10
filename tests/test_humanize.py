from __future__ import annotations

import unittest

from storagescan import humanize


class HumanBytesTest(unittest.TestCase):
    def test_formats_decimal_units(self):
        self.assertEqual(humanize.human_bytes(0), "0 B")
        self.assertEqual(humanize.human_bytes(512), "512 B")
        self.assertEqual(humanize.human_bytes(1000), "1.0 KB")
        self.assertEqual(humanize.human_bytes(4_200_000_000), "4.2 GB")
        self.assertEqual(humanize.human_bytes(2_000_000_000_000), "2.0 TB")

    def test_negative_is_signed(self):
        self.assertEqual(humanize.human_bytes(-1000), "-1.0 KB")


class RedactTest(unittest.TestCase):
    def test_replaces_home_prefix(self):
        self.assertEqual(
            humanize.redact("/Users/example/Library/Caches", "/Users/example"),
            "~/Library/Caches",
        )

    def test_home_itself_becomes_tilde(self):
        self.assertEqual(humanize.redact("/Users/example", "/Users/example"), "~")

    def test_leaves_other_paths_alone(self):
        self.assertEqual(
            humanize.redact("/Applications", "/Users/example"), "/Applications")

    def test_does_not_match_partial_component(self):
        self.assertEqual(
            humanize.redact("/Users/example2/x", "/Users/example"),
            "/Users/example2/x",
        )


class HumanAgeTest(unittest.TestCase):
    def test_buckets(self):
        now = 1_000_000_000.0
        day = 86400.0
        self.assertEqual(humanize.human_age(now, now), "today")
        self.assertEqual(humanize.human_age(now - 3 * day, now), "3 days ago")
        self.assertEqual(humanize.human_age(now - 60 * day, now), "2 months ago")
        self.assertEqual(humanize.human_age(now - 800 * day, now), "2 years ago")

    def test_future_mtime_is_today(self):
        now = 1_000_000_000.0
        self.assertEqual(humanize.human_age(now + 5000, now), "today")


if __name__ == "__main__":
    unittest.main()
