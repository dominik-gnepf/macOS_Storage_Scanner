"""Interactive curses browser.

All navigation lives in TreeState, which knows nothing about curses. That
split is deliberate: every behaviour is unit-testable without a pty, and
``run`` stays a thin shell that draws state and dispatches keys.
"""

from __future__ import annotations

import curses
import os
import subprocess
import time
from typing import Optional, Tuple

from .. import actions
from ..humanize import human_bytes, redact
from ..model import Finding, Node, Risk, ScanResult
from . import report as report_module

MIN_SIZE = (60, 15)

RISK_MARK = {
    Risk.SAFE: "SAFE",
    Risk.REVIEW: "REVW",
    Risk.DANGER: "DNGR",
    Risk.BLOCKED: "----",
}

HELP = ("^v move   > enter   < up   d delete   f findings   "
        "r report   s sort   q quit")


class TreeState:
    """Pure navigation state. No curses, no I/O."""

    def __init__(self, result: ScanResult):
        self.result = result
        self.stack = [result.root] if result.root is not None else []
        self.index = 0
        self.sort_key = "size"
        self.view = "tree"

    def current_dir(self) -> Optional[Node]:
        return self.stack[-1] if self.stack else None

    def rows(self) -> Tuple:
        if self.view == "findings":
            return self.result.findings_by_size()
        node = self.current_dir()
        if node is None:
            return ()
        if self.sort_key == "name":
            return tuple(sorted(node.children, key=lambda n: n.path))
        return node.sorted_children()

    def current(self):
        rows = self.rows()
        if not rows:
            return None
        return rows[min(self.index, len(rows) - 1)]

    def select(self, delta: int) -> None:
        rows = self.rows()
        if not rows:
            self.index = 0
            return
        self.index = max(0, min(len(rows) - 1, self.index + delta))

    def enter(self) -> None:
        if self.view != "tree":
            return
        row = self.current()
        if isinstance(row, Node) and row.children:
            self.stack.append(row)
            self.index = 0

    def up(self) -> None:
        if self.view == "tree" and len(self.stack) > 1:
            self.stack.pop()
            self.index = 0

    def toggle_sort(self) -> None:
        self.sort_key = "name" if self.sort_key == "size" else "size"
        self.index = 0

    def toggle_view(self) -> None:
        self.view = "findings" if self.view == "tree" else "tree"
        self.index = 0

    def breadcrumb(self, home: str) -> str:
        node = self.current_dir()
        return redact(node.path, home) if node is not None else "(no scan)"

    def percentage_base(self) -> int:
        """The whole that each row's percentage is a share of.

        In the tree that is the directory being listed, so the numbers answer
        "how much of this folder is that". In the findings list it is the sum
        of everything reclaimable, so they answer "how much of the win is
        that". Using the largest row instead would print 100% on row one in
        every view.
        """
        if self.view == "findings":
            return sum(f.bytes_ for f in self.result.findings)
        node = self.current_dir()
        return node.size if node is not None else 0


def row_size(row) -> int:
    return row.bytes_ if isinstance(row, Finding) else row.size


def format_row(row, *, home: str, total: int, scale: int, width: int) -> str:
    """One display line, guaranteed to fit inside ``width``.

    ``total`` is the denominator for the percentage — the whole the row is a
    part of. ``scale`` is the largest row on screen and only sizes the bar, so
    small entries stay visible instead of all rendering as an empty bar. Using
    one number for both would make the first row read 100% every time.
    """
    size = row_size(row)
    pct = int(round(100.0 * size / total)) if total else 0
    bar_width = max(6, min(24, width - 46))
    filled = int(round(bar_width * (size / scale))) if scale else 0
    filled = max(0, min(bar_width, filled))
    bar = "#" * filled + "." * (bar_width - filled)

    if isinstance(row, Finding):
        mark = RISK_MARK[row.risk] + " "
    else:
        mark = ""
    prefix = "{}{:>10}  {}  {:>3}%  ".format(mark, human_bytes(size), bar, pct)
    room = max(0, width - len(prefix))

    if isinstance(row, Finding):
        where = redact(row.path, home) if row.path else row.detail
        # The path identifies the row — eight entries all say "Application
        # caches". So show "title  path" when both fit, and drop the title
        # rather than serve half of each.
        combined = "{}  {}".format(row.title, where) if where else row.title
        label = combined if len(combined) <= room else (where or row.title)
    else:
        redacted = redact(row.path, home)
        label = os.path.basename(redacted) or redacted

    if len(label) > room:
        # Keep the tail: for a path, the end identifies it, not the start.
        label = ("~" + label[-(room - 1):]) if room > 1 else ""
    return (prefix + label)[:width]


def _open_file(path: str) -> None:
    try:
        subprocess.run(["open", path], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def _prompt(stdscr, message: str) -> str:
    height, width = stdscr.getmaxyx()
    stdscr.move(height - 1, 0)
    stdscr.clrtoeol()
    stdscr.addnstr(height - 1, 0, message, width - 2)
    stdscr.refresh()
    curses.echo()
    curses.curs_set(1)
    try:
        column = min(len(message) + 1, width - 2)
        return stdscr.getstr(height - 1, column, 300).decode("utf-8", "replace")
    except KeyboardInterrupt:
        return ""
    finally:
        curses.noecho()
        curses.curs_set(0)


def _confirm_factory(stdscr, home):
    """Build the confirmation callback the escalating tiers require."""

    def confirm(path: str, risk: Risk, mode: str) -> bool:
        shown = redact(path, home)
        if mode == "single":
            answer = _prompt(stdscr, "Delete {} to Trash? [y/N] ".format(shown))
            return answer.strip().lower().startswith("y")
        if mode == "recap":
            size = human_bytes(actions.measure(path))
            answer = _prompt(stdscr, "Delete {} ({}) to Trash? [y/N] ".format(
                shown, size))
            return answer.strip().lower().startswith("y")
        if mode == "retype":
            typed = _prompt(
                stdscr,
                "This looks irreplaceable. Retype the path to confirm: ")
            return typed.strip() in (shown, path)
        return False

    return confirm


def _draw(stdscr, state: TreeState, home: str, status: str) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()

    from ..scan.apfs import primary_volume
    volume = primary_volume(state.result.volumes)

    header = "storagescan"
    if volume is not None:
        header += "   {} free of {}".format(
            human_bytes(volume.free), human_bytes(volume.total))
    if not state.result.fda_ok:
        header += "   [INCOMPLETE: no Full Disk Access]"
    stdscr.addnstr(0, 0, header.ljust(width - 1), width - 1, curses.A_BOLD)

    subtitle = "{}   [{} view, sorted by {}]".format(
        state.breadcrumb(home), state.view, state.sort_key)
    stdscr.addnstr(1, 0, subtitle.ljust(width - 1), width - 1, curses.A_DIM)

    rows = state.rows()
    scale = max((row_size(r) for r in rows), default=0)
    total = state.percentage_base()
    body_height = max(1, height - 4)
    start = max(0, state.index - body_height + 1)

    if not rows:
        stdscr.addnstr(3, 2, "Nothing to show here.", width - 3)
    for offset, row in enumerate(rows[start:start + body_height]):
        line = format_row(row, home=home, total=total, scale=scale,
                          width=width - 1)
        attr = curses.A_REVERSE if start + offset == state.index else curses.A_NORMAL
        stdscr.addnstr(2 + offset, 0, line.ljust(width - 1), width - 1, attr)

    stdscr.addnstr(height - 1, 0, (status or HELP)[:width - 1], width - 1,
                   curses.A_DIM)
    stdscr.refresh()


def _delete_selected(stdscr, state: TreeState, home: str, config) -> str:
    row = state.current()
    if row is None:
        return ""

    category = row.category if isinstance(row, Finding) else None
    if category in ("apfs.snapshot", "apfs.os_snapshot"):
        return "Snapshots are report-only — run the tmutil command shown."
    if category == "cloud.folder":
        return "Cloud folders are managed by their sync client, not here."

    path = getattr(row, "path", None)
    if not path:
        return "This finding has no deletable path."

    outcome = actions.perform(
        path, home=home, scan_roots=config.expanded_scan_paths(),
        category=category, confirm=_confirm_factory(stdscr, home),
        use_trash=config.trash_by_default)

    if outcome.status == actions.REFUSED:
        return "Refused: {}".format(outcome.message)
    if outcome.status == actions.TRASHED:
        return "Moved to Trash: {} ({})".format(
            redact(outcome.path, home), human_bytes(outcome.bytes_))
    return "{}: {}".format(outcome.status, redact(outcome.path, home))


def _loop(stdscr, result: ScanResult, home: str, config) -> None:
    curses.curs_set(0)
    state = TreeState(result)
    status = ""

    while True:
        height, width = stdscr.getmaxyx()
        if width < MIN_SIZE[0] or height < MIN_SIZE[1]:
            stdscr.erase()
            stdscr.addnstr(0, 0, "Terminal too small (need {}x{}). q to quit."
                           .format(*MIN_SIZE), max(1, width - 1))
            stdscr.refresh()
            if stdscr.getch() in (ord("q"), 27):
                return
            continue

        _draw(stdscr, state, home, status)
        status = ""
        key = stdscr.getch()

        if key in (ord("q"), 27):
            return
        if key in (curses.KEY_DOWN, ord("j")):
            state.select(1)
        elif key in (curses.KEY_UP, ord("k")):
            state.select(-1)
        elif key in (curses.KEY_NPAGE,):
            state.select(max(1, height - 5))
        elif key in (curses.KEY_PPAGE,):
            state.select(-max(1, height - 5))
        elif key in (curses.KEY_RIGHT, ord("l"), 10, 13):
            state.enter()
        elif key in (curses.KEY_LEFT, ord("h")):
            state.up()
        elif key == ord("s"):
            state.toggle_sort()
        elif key == ord("f"):
            state.toggle_view()
        elif key == ord("r"):
            path = report_module.write(result, home=home, generated_at=time.time())
            _open_file(path)
            status = "Report written to {}".format(redact(path, home))
        elif key == ord("d"):
            status = _delete_selected(stdscr, state, home, config)


def run(result: ScanResult, *, home: str, config) -> None:
    curses.wrapper(_loop, result, home, config)
