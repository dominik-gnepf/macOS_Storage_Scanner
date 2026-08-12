from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan.model import Finding, Node, Risk, ScanResult
from storagescan.ui import tui
from tests.support import build_tree

HOME = "/Users/example"


def tree():
    deep = Node(path=HOME + "/Library/Caches", size=400, apparent=400,
                count=2, mtime=0.0)
    lib = Node(path=HOME + "/Library", size=900, apparent=900, count=5,
               mtime=0.0, children=(deep,))
    dls = Node(path=HOME + "/Downloads", size=100, apparent=100, count=2, mtime=0.0)
    return Node(path=HOME, size=1000, apparent=1000, count=7, mtime=0.0,
                children=(lib, dls))


def result():
    return ScanResult(
        root=tree(),
        findings=(
            Finding("downloads", "Downloads", HOME + "/Downloads", 100, Risk.REVIEW),
            Finding("homebrew.cache", "Homebrew", HOME + "/Library/Caches/Homebrew",
                    900, Risk.SAFE),
        ),
    )


class TreeStateTest(unittest.TestCase):
    def test_rows_are_children_sorted_by_size(self):
        state = tui.TreeState(result())
        self.assertEqual([r.path for r in state.rows()],
                         [HOME + "/Library", HOME + "/Downloads"])

    def test_select_moves_and_clamps(self):
        state = tui.TreeState(result())
        state.select(1)
        self.assertEqual(state.index, 1)
        state.select(5)
        self.assertEqual(state.index, 1)
        state.select(-99)
        self.assertEqual(state.index, 0)

    def test_enter_descends_and_up_returns(self):
        state = tui.TreeState(result())
        state.enter()
        self.assertEqual(state.current_dir().path, HOME + "/Library")
        state.up()
        self.assertEqual(state.current_dir().path, HOME)

    def test_up_at_root_is_a_noop(self):
        state = tui.TreeState(result())
        state.up()
        self.assertEqual(state.current_dir().path, HOME)

    def test_enter_on_leaf_is_a_noop(self):
        state = tui.TreeState(result())
        state.select(1)  # Downloads has no children
        state.enter()
        self.assertEqual(state.current_dir().path, HOME)

    def test_enter_resets_selection(self):
        state = tui.TreeState(result())
        state.select(1)
        state.index = 0
        state.enter()
        self.assertEqual(state.index, 0)

    def test_sort_toggles_between_size_and_name(self):
        state = tui.TreeState(result())
        state.toggle_sort()
        self.assertEqual(state.sort_key, "name")
        self.assertEqual([r.path for r in state.rows()],
                         [HOME + "/Downloads", HOME + "/Library"])
        state.toggle_sort()
        self.assertEqual(state.sort_key, "size")

    def test_findings_view_lists_findings_by_size(self):
        state = tui.TreeState(result())
        state.toggle_view()
        self.assertEqual(state.view, "findings")
        self.assertEqual([f.category for f in state.rows()],
                         ["homebrew.cache", "downloads"])

    def test_enter_does_nothing_in_findings_view(self):
        state = tui.TreeState(result())
        state.toggle_view()
        state.enter()
        self.assertEqual(state.view, "findings")

    def test_current_returns_selected_row_in_either_view(self):
        state = tui.TreeState(result())
        self.assertEqual(state.current().path, HOME + "/Library")
        state.toggle_view()
        self.assertEqual(state.current().category, "homebrew.cache")

    def test_breadcrumb_is_redacted(self):
        state = tui.TreeState(result())
        self.assertEqual(state.breadcrumb(HOME), "~")
        state.enter()
        self.assertEqual(state.breadcrumb(HOME), "~/Library")

    def test_empty_result_has_no_rows_and_does_not_crash(self):
        state = tui.TreeState(ScanResult(root=None))
        self.assertEqual(state.rows(), ())
        self.assertIsNone(state.current())
        state.select(1)
        state.enter()
        state.up()
        self.assertEqual(state.breadcrumb(HOME), "(no scan)")

    def test_remove_current_drops_the_row_and_shrinks_ancestors(self):
        state = tui.TreeState(result())
        self.assertEqual([r.path for r in state.rows()],
                         [HOME + "/Library", HOME + "/Downloads"])
        state.remove_current()
        self.assertEqual([r.path for r in state.rows()],
                         [HOME + "/Downloads"])
        self.assertEqual(state.current_dir().size, 100)
        self.assertEqual(state.current_dir().count, 2)
        self.assertEqual(state.current().path, HOME + "/Downloads")

    def test_remove_current_finding_drops_it_from_the_list(self):
        state = tui.TreeState(result())
        state.toggle_view()
        self.assertEqual(len(state.rows()), 2)
        state.remove_current()
        self.assertEqual([f.category for f in state.rows()], ["downloads"])

    def test_replace_current_fills_in_a_truncated_folder(self):
        truncated = Node(path=HOME + "/Downloads", size=100, apparent=100,
                         count=2, mtime=0.0, truncated=True)
        lib = Node(path=HOME + "/Library", size=900, apparent=900,
                   count=5, mtime=0.0)
        root = Node(path=HOME, size=1000, apparent=1000, count=7, mtime=0.0,
                    children=(lib, truncated))
        state = tui.TreeState(ScanResult(root=root))
        state.select(1)
        inner = Node(path=HOME + "/Downloads/iso", size=80, apparent=80,
                     count=1, mtime=0.0)
        full = Node(path=HOME + "/Downloads", size=100, apparent=100,
                    count=2, mtime=0.0, children=(inner,))
        state.replace_current(full)
        self.assertFalse(state.current().truncated)
        self.assertEqual(len(state.current().children), 1)
        state.enter()
        self.assertEqual(state.current_dir().path, HOME + "/Downloads")

    def test_expand_selected_refuses_a_fully_scanned_folder(self):
        state = tui.TreeState(result())
        self.assertEqual(tui.expand_selected(state), "Already fully scanned.")

    def test_remove_current_updates_the_result_the_browser_returns(self):
        # The menu and --cached reuse whatever run() last saw. If deletes
        # only live in TreeState and never write back, the next screen
        # still claims the space is there.
        state = tui.TreeState(result())
        state.remove_current()
        self.assertEqual([c.path for c in state.result.root.children],
                         [HOME + "/Downloads"])
        self.assertEqual([f.category for f in state.result.findings],
                         ["downloads"])

    def test_expand_selected_walks_a_real_truncated_folder(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        build_tree(tmp, {"keep": {"deep": {"f": 1000}}})
        truncated = Node(path=os.path.join(tmp, "keep"), size=1000,
                         apparent=1000, count=1, mtime=0.0, truncated=True)
        root = Node(path=tmp, size=1000, apparent=1000, count=1, mtime=0.0,
                    children=(truncated,))
        state = tui.TreeState(ScanResult(root=root))
        message = tui.expand_selected(state)
        self.assertIn("keep", message)
        self.assertFalse(state.current().truncated)
        self.assertTrue(state.current().children)

    def test_remove_current_nested_rewrites_the_stack(self):
        state = tui.TreeState(result())
        state.enter()
        state.remove_current()
        self.assertEqual(state.current_dir().path, HOME + "/Library")
        self.assertEqual(state.current_dir().size, 500)
        self.assertEqual(state.rows(), ())
        state.up()
        self.assertEqual(state.current_dir().size, 600)


class PercentageBaseTest(unittest.TestCase):
    def test_tree_base_is_the_current_directory_total(self):
        state = tui.TreeState(result())
        self.assertEqual(state.percentage_base(), 1000)
        state.enter()
        self.assertEqual(state.percentage_base(), 900)

    def test_findings_base_is_total_reclaimable(self):
        state = tui.TreeState(result())
        state.toggle_view()
        self.assertEqual(state.percentage_base(), 1000)

    def test_base_is_zero_without_a_scan(self):
        self.assertEqual(tui.TreeState(ScanResult(root=None)).percentage_base(), 0)


class FormatRowTest(unittest.TestCase):
    def row(self, item, **kw):
        kw.setdefault("home", HOME)
        kw.setdefault("total", 1000)
        kw.setdefault("scale", 1000)
        kw.setdefault("width", 70)
        return tui.format_row(item, **kw)

    def test_includes_size_bar_and_name(self):
        node = Node(path=HOME + "/Library", size=900, apparent=900,
                    count=5, mtime=0.0)
        row = self.row(node)
        self.assertIn("Library", row)
        self.assertIn("900 B", row)
        self.assertIn("90%", row)
        self.assertLessEqual(len(row), 70)

    def test_truncated_folder_is_marked(self):
        node = Node(path=HOME + "/Library", size=900, apparent=900,
                    count=5, mtime=0.0, truncated=True)
        self.assertIn("…", self.row(node))

    def test_percentage_uses_total_not_scale(self):
        # The biggest row must not read 100% just for being the biggest.
        node = Node(path=HOME + "/a", size=500, apparent=500, count=1, mtime=0.0)
        self.assertIn("50%", self.row(node, total=1000, scale=500))

    def test_bar_is_full_for_the_largest_row(self):
        node = Node(path=HOME + "/a", size=500, apparent=500, count=1, mtime=0.0)
        row = self.row(node, total=1000, scale=500)
        self.assertNotIn(".", row.split("  ")[2])

    def test_findings_show_their_risk_marker_and_path(self):
        finding = Finding("downloads", "Downloads", HOME + "/Downloads",
                          100, Risk.REVIEW)
        row = self.row(finding, total=100, scale=100, width=90)
        self.assertIn("REVW", row)
        self.assertIn("~/Downloads", row)

    def test_pathless_finding_falls_back_to_detail(self):
        finding = Finding("apfs.snapshot", "Snapshot", None, 0, Risk.REVIEW,
                          "com.apple.TimeMachine.x")
        self.assertIn("com.apple.TimeMachine.x",
                      self.row(finding, total=0, scale=0, width=90))

    def test_zero_total_and_scale_do_not_divide_by_zero(self):
        node = Node(path=HOME + "/x", size=0, apparent=0, count=0, mtime=0.0)
        self.assertIn("0%", self.row(node, total=0, scale=0))

    def test_long_names_are_truncated_keeping_the_tail(self):
        node = Node(path=HOME + "/" + "n" * 200, size=1, apparent=1,
                    count=1, mtime=0.0)
        row = self.row(node, total=10, scale=10, width=60)
        self.assertLessEqual(len(row), 60)

    def test_title_is_dropped_before_the_path_is_mangled(self):
        # Eight findings can share the title "Application caches"; only the
        # path tells them apart, so the path must survive intact.
        finding = Finding("app.cache", "Application caches",
                          HOME + "/Library/Caches/Cypress", 100, Risk.SAFE)
        # 80 columns fits the path but not "title  path", so the title goes.
        row = self.row(finding, total=100, scale=100, width=80)
        self.assertIn("~/Library/Caches/Cypress", row)
        self.assertNotIn("Application", row)

    def test_path_too_long_for_the_row_is_tail_truncated(self):
        finding = Finding("app.cache", "Application caches",
                          HOME + "/Library/Caches/Cypress", 100, Risk.SAFE)
        row = self.row(finding, total=100, scale=100, width=68)
        self.assertTrue(row.endswith("Caches/Cypress"))
        self.assertLessEqual(len(row), 68)

    def test_title_and_path_both_shown_when_they_fit(self):
        finding = Finding("app.cache", "Caches", HOME + "/x", 100, Risk.SAFE)
        row = self.row(finding, total=100, scale=100, width=90)
        self.assertIn("Caches  ~/x", row)

    def test_long_finding_path_keeps_the_distinguishing_end(self):
        finding = Finding("app.cache", "Application caches",
                          HOME + "/Library/Caches/" + "x" * 60 + "/DistinctName",
                          100, Risk.SAFE)
        row = self.row(finding, total=100, scale=100, width=70)
        self.assertIn("DistinctName", row)
        self.assertLessEqual(len(row), 70)

    def test_narrow_width_still_produces_a_line(self):
        node = Node(path=HOME + "/x", size=5, apparent=5, count=1, mtime=0.0)
        row = self.row(node, total=10, scale=10, width=MIN_WIDTH)
        self.assertLessEqual(len(row), MIN_WIDTH)


MIN_WIDTH = tui.MIN_SIZE[0]


if __name__ == "__main__":
    unittest.main()
