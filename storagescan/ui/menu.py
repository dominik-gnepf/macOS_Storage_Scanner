"""The front door: a menu shown when the program is run with no arguments.

Every flag remains available for people who know them, but nobody should have
to read --help to answer "what is eating my disk". The menu states the disk
situation, says plainly whether the scan can even see everything, and offers
the handful of things worth doing.

Rendering and choice-parsing live here and are pure. The handlers live in cli,
which owns the scanning and deleting — so this module stays testable without
touching a filesystem.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from ..humanize import human_bytes
from ..model import Risk, ScanResult
from ..scan.apfs import primary_volume

BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
RESET = "\x1b[0m"


@dataclass(frozen=True)
class Item:
    key: str
    action: str
    label: str
    hint: str


ITEMS: Tuple[Item, ...] = (
    Item("1", "scan", "Scan now",
         "find what is using space (about a minute)"),
    Item("2", "browse", "Browse the last scan",
         "open the interactive browser (instant)"),
    Item("3", "reclaim", "Reclaim safe space",
         "review caches and build files, then move them to the Trash"),
    Item("4", "report", "Save an HTML report",
         "a shareable page with a treemap"),
    Item("5", "deep", "Deep scan",
         "also find duplicate and long-untouched files (slower)"),
    Item("6", "access", "Grant Full Disk Access",
         "open the right System Settings pane"),
    Item("7", "monitor", "Weekly early warning",
         "get notified before the disk fills up"),
    Item("q", "quit", "Quit", ""),
)


def _paint(text: str, code: str, color: bool) -> str:
    return "{}{}{}".format(code, text, RESET) if color else text


def disk_line(result: Optional[ScanResult], color: bool = True) -> str:
    if result is None:
        return "Disk         run a scan to see where your space went"
    volume = primary_volume(result.volumes)
    if volume is None:
        return "Disk         unknown"
    # Derived from free space, not from the "used" column. On APFS those do
    # not sum to the total — the container reserves space and other volumes
    # share it — so used/total reads 74% on a disk that is really 95% full.
    # The number people care about is how close to zero they are.
    used_pct = (int(round(100.0 * (volume.total - volume.free) / volume.total))
                if volume.total else 0)
    free = human_bytes(volume.free)
    # Colour the number people actually react to.
    if used_pct >= 90:
        free = _paint(free, RED, color)
    elif used_pct >= 80:
        free = _paint(free, YELLOW, color)
    return "Disk         {} free of {}   ({}% used)".format(
        free, human_bytes(volume.total), used_pct)


def access_line(result: Optional[ScanResult], color: bool = True) -> str:
    if result is None:
        return "Full access  unknown until you scan"
    if result.fda_ok:
        return "Full access  " + _paint("granted", GREEN, color)
    # Deliberately not quoting result.errors here: that count includes
    # /private/var denials that need root rather than Full Disk Access, so it
    # would promise a fix that granting access cannot deliver.
    return "Full access  " + _paint(
        "not granted — parts of your home folder are hidden, so the "
        "totals below are too low", YELLOW, color)


def last_scan_line(result: Optional[ScanResult], now: float) -> str:
    if result is None or not result.started_at:
        return "Last scan    never"
    age = max(0, int(now - result.started_at))
    if age < 60:
        when = "just now"
    elif age < 3600:
        when = "{} min ago".format(age // 60)
    elif age < 86400:
        when = "{} hours ago".format(age // 3600)
    else:
        when = "{} days ago".format(age // 86400)
    return "Last scan    {} ({} scan)".format(when, result.mode)


def reclaimable_line(result: Optional[ScanResult], color: bool = True) -> str:
    if result is None:
        return ""
    safe = result.reclaimable(Risk.SAFE)
    if safe <= 0:
        return ""
    return "Reclaimable  {} in caches and build files".format(
        _paint(human_bytes(safe), GREEN, color))


def render(result: Optional[ScanResult], *, now: float, color: bool = True,
           items: Sequence[Item] = ITEMS, status: str = "") -> str:
    """The whole screen, as one string."""
    lines: List[str] = []
    lines.append("")
    lines.append("  " + _paint("macOS Storage Scanner", BOLD, color))
    lines.append("")
    for line in (disk_line(result, color), access_line(result, color),
                 last_scan_line(result, now), reclaimable_line(result, color)):
        if line:
            lines.append("  " + line)
    lines.append("")

    for item in items:
        if item.hint:
            lines.append("  {}  {:<24} {}".format(
                _paint(item.key, BOLD, color), item.label,
                _paint(item.hint, DIM, color)))
        else:
            lines.append("  {}  {}".format(_paint(item.key, BOLD, color),
                                           item.label))
    lines.append("")
    if status:
        lines.append("  " + status)
        lines.append("")
    return "\n".join(lines)


def parse_choice(raw: str, items: Sequence[Item] = ITEMS) -> Optional[Item]:
    """Match a typed line to a menu item.

    Accepts the number, the action name, or a unique prefix of the label, so
    "3", "reclaim" and "rec" all work. Returns None for anything else rather
    than guessing — picking the wrong entry here could start a deletion.
    """
    text = raw.strip().lower()
    if not text:
        return None

    for item in items:
        if text == item.key or text == item.action:
            return item

    matches = [item for item in items
               if item.label.lower().startswith(text)
               or item.action.startswith(text)]
    return matches[0] if len(matches) == 1 else None
