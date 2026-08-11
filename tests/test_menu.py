from __future__ import annotations

import unittest

from storagescan.model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo
from storagescan.ui import menu

NOW = 1_800_000_000.0


def result(**kw):
    base = dict(
        root=Node(path="/h", size=1, apparent=1, count=1, mtime=0.0),
        findings=(Finding("homebrew.cache", "Homebrew", "/h/c",
                          36_100_000_000, Risk.SAFE),),
        volumes=(VolumeInfo("/System/Volumes/Data", 245_000_000_000,
                            233_000_000_000, 11_800_000_000),),
        errors=(), mode="fast", fda_ok=True, started_at=NOW - 120,
    )
    base.update(kw)
    return ScanResult(**base)


class ParseChoiceTest(unittest.TestCase):
    def test_matches_the_number(self):
        self.assertEqual(menu.parse_choice("3").action, "reclaim")

    def test_matches_the_action_name(self):
        self.assertEqual(menu.parse_choice("reclaim").action, "reclaim")

    def test_matches_a_unique_prefix(self):
        self.assertEqual(menu.parse_choice("rec").action, "reclaim")

    def test_is_case_and_space_insensitive(self):
        self.assertEqual(menu.parse_choice("  QUIT \n").action, "quit")

    def test_rejects_empty_input(self):
        self.assertIsNone(menu.parse_choice(""))
        self.assertIsNone(menu.parse_choice("   "))

    def test_rejects_unknown_input(self):
        self.assertIsNone(menu.parse_choice("banana"))

    def test_refuses_an_ambiguous_prefix(self):
        # Guessing here could start a deletion the user did not ask for.
        items = (menu.Item("1", "reclaim", "Reclaim", ""),
                 menu.Item("2", "report", "Report", ""))
        self.assertIsNone(menu.parse_choice("re", items))

    def test_every_item_is_reachable_by_its_key(self):
        for item in menu.ITEMS:
            self.assertEqual(menu.parse_choice(item.key), item)


class RenderTest(unittest.TestCase):
    def test_shows_free_space_and_every_option(self):
        text = menu.render(result(), now=NOW, color=False)
        self.assertIn("11.8 GB free of 245.0 GB", text)
        # 11.8 free of 245 is 95% full. Deriving the percentage from the
        # "used" column instead reads 74%, because on APFS used + free does
        # not equal total.
        self.assertIn("(95% used)", text)
        for item in menu.ITEMS:
            self.assertIn(item.label, text)

    def test_shows_reclaimable_total(self):
        self.assertIn("36.1 GB", menu.render(result(), now=NOW, color=False))

    def test_warns_when_access_is_missing(self):
        text = menu.render(
            result(fda_ok=False,
                   errors=tuple(ScanError("/x/%d" % i, "PermissionError")
                                for i in range(152))),
            now=NOW, color=False)
        self.assertIn("not granted", text)
        self.assertIn("hidden", text)
        # The raw error count includes /private/var denials that need root,
        # not Full Disk Access, so it must not be quoted as if granting
        # access would fix them all.
        self.assertNotIn("152", text)

    def test_says_granted_when_access_is_fine(self):
        self.assertIn("granted", menu.render(result(), now=NOW, color=False))

    def test_handles_never_having_scanned(self):
        text = menu.render(None, now=NOW, color=False)
        self.assertIn("Last scan    never", text)
        self.assertIn("Scan now", text)

    def test_reports_scan_age(self):
        self.assertIn("2 min ago", menu.render(result(), now=NOW, color=False))
        self.assertIn("just now", menu.render(
            result(started_at=NOW - 5), now=NOW, color=False))
        self.assertIn("3 days ago", menu.render(
            result(started_at=NOW - 3 * 86400), now=NOW, color=False))

    def test_no_ansi_when_color_disabled(self):
        self.assertNotIn("\x1b[", menu.render(result(), now=NOW, color=False))

    def test_ansi_present_when_color_enabled(self):
        self.assertIn("\x1b[", menu.render(result(), now=NOW, color=True))

    def test_status_message_is_shown(self):
        self.assertIn("all done",
                      menu.render(result(), now=NOW, color=False,
                                  status="all done"))

    def test_low_free_space_is_highlighted(self):
        text = menu.render(result(), now=NOW, color=True)
        self.assertIn(menu.RED, text)

    def test_healthy_disk_is_not_alarming(self):
        healthy = result(volumes=(VolumeInfo("/System/Volumes/Data",
                                             245_000_000_000, 50_000_000_000,
                                             195_000_000_000),))
        self.assertNotIn(menu.RED, menu.render(healthy, now=NOW, color=True))


if __name__ == "__main__":
    unittest.main()
