"""Colored one-screen summary — the non-interactive view."""

from __future__ import annotations

from typing import List, Optional

from ..humanize import human_bytes, redact
from ..model import Risk, ScanResult
from ..scan.apfs import primary_volume

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RED = "\x1b[31m"
YELLOW = "\x1b[33m"
GREEN = "\x1b[32m"

RISK_LABEL = {
    Risk.SAFE: "SAFE",
    Risk.REVIEW: "REVIEW",
    Risk.DANGER: "DANGER",
    Risk.BLOCKED: "LOCKED",
}

_RISK_COLOR = {
    Risk.SAFE: GREEN,
    Risk.REVIEW: YELLOW,
    Risk.DANGER: RED,
    Risk.BLOCKED: DIM,
}

FDA_STEPS = (
    "System Settings > Privacy & Security > Full Disk Access, "
    "add your terminal app, then restart it."
)


def unaccounted(result: ScanResult, home: str) -> Optional[int]:
    """Volume bytes the scan could not attribute to any scanned path.

    This is the honest replacement for a purgeable-space figure: macOS exposes
    no supported way to read purgeable from the command line, but the gap
    between what the volume reports as used and what the scan could see is
    both measurable and exactly the number people want when the folder sizes
    do not add up.

    It is only meaningful for a scan that covered the home directory. After
    ``--path ~/Developer`` the "gap" is just everything else on the disk, so
    None is returned rather than an alarming and useless number.
    """
    if result.roots and not result.covers(home):
        return None
    volume = primary_volume(result.volumes)
    if volume is None or result.root is None:
        return None
    gap = volume.used - attributed(result)
    return gap if gap > 0 else None


# Findings that describe space *outside* the scanned tree. Counting them
# alongside the tree is what turns a large mystery number into a small one;
# counting anything inside the tree here would double-count it.
_OUTSIDE_TREE = (
    "system.applications", "system.library", "system.var",
    "system.opt", "system.usr_local", "system.shared",
    "cloud.folder",
)


def attributed(result: ScanResult) -> int:
    """Bytes the scan can point at: the walked tree plus measured areas
    outside it (system directories, cloud folders)."""
    total = result.root.size if result.root is not None else 0
    total += sum(f.bytes_ for f in result.findings
                 if f.category in _OUTSIDE_TREE)
    return total


def render(result: ScanResult, *, home: str, color: bool = True) -> str:
    def paint(text, code):
        return "{}{}{}".format(code, text, RESET) if color else text

    lines: List[str] = []

    if not result.fda_ok:
        lines.append(paint("INCOMPLETE SCAN", BOLD + RED))
        lines.append("Full Disk Access is not granted, so parts of your home "
                     "folder were")
        lines.append("skipped and the totals below are too low. Grant it in:")
        lines.append("  " + FDA_STEPS)
        lines.append("")

    volume = primary_volume(result.volumes)
    if volume is not None:
        lines.append("{}  {} free of {}  ({} used)".format(
            paint(volume.mount, BOLD),
            human_bytes(volume.free),
            human_bytes(volume.total),
            human_bytes(volume.used),
        ))
        gap = unaccounted(result, home)
        if gap:
            lines.append(paint(
                "  {} used but not attributable to scanned files — usually "
                "APFS snapshots,".format(human_bytes(gap)), DIM))
            lines.append(paint(
                "  other volumes in the container, or paths this scan could "
                "not read.", DIM))
        lines.append("")

    outside = [f for f in result.findings_by_size()
               if f.category in _OUTSIDE_TREE and f.bytes_ > 0]
    if outside:
        lines.append(paint("Outside your home folder", BOLD))
        for finding in outside[:8]:
            lines.append("  {:>10}  {}".format(
                human_bytes(finding.bytes_),
                redact(finding.path, home) if finding.path else finding.title))
        lines.append("")

    if result.root is not None and result.root.children:
        lines.append(paint("Largest directories", BOLD))
        for node in result.root.sorted_children()[:10]:
            lines.append("  {:>10}  {}".format(
                human_bytes(node.size), redact(node.path, home)))
        lines.append("")

    # System areas and cloud folders are shown above for accounting. They are
    # not things this tool reclaims, so listing them here would pad the
    # headline number with space the user cannot actually get back.
    findings = [f for f in result.findings_by_size()
                if f.bytes_ > 0 and f.category not in _OUTSIDE_TREE]
    if findings:
        lines.append(paint("Reclaimable", BOLD))
        for finding in findings[:15]:
            label = paint(RISK_LABEL[finding.risk], _RISK_COLOR[finding.risk])
            where = redact(finding.path, home) if finding.path else finding.detail
            lines.append("  {:>10}  {:<8}  {}".format(
                human_bytes(finding.bytes_), label, finding.title))
            lines.append(paint("              {}".format(where), DIM))
            if finding.reclaim_hint:
                lines.append(paint("              $ {}".format(
                    finding.reclaim_hint), DIM))
        lines.append("")
        lines.append("Safe to reclaim now: {}".format(
            human_bytes(result.reclaimable(Risk.SAFE))))
        lines.append("With review:         {}".format(
            human_bytes(result.reclaimable(Risk.SAFE, Risk.REVIEW))))
        lines.append("")

    sizeless = [f for f in result.findings if f.bytes_ == 0]
    if sizeless:
        lines.append(paint("Not measured", BOLD))
        for finding in sizeless[:10]:
            where = redact(finding.path, home) if finding.path else ""
            lines.append("  {}{}".format(
                finding.title, "  {}".format(where) if where else ""))
            if finding.reclaim_hint:
                lines.append(paint("    $ {}".format(finding.reclaim_hint), DIM))
        lines.append(paint(
            "  macOS does not report a size for these. Snapshots hold space "
            "until", DIM))
        lines.append(paint(
            "  macOS releases it; cloud folders are skipped because reading "
            "them is slow", DIM))
        lines.append(paint(
            "  and can trigger downloads (--include-cloud to scan anyway).",
            DIM))
        lines.append("")

    if result.errors:
        lines.append(paint(
            "{} items were unreadable and are not counted above{}".format(
                len(result.errors),
                " — granting Full Disk Access will fix most of these"
                if not result.fda_ok else ""), DIM))

    return "\n".join(lines)
