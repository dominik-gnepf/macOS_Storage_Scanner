"""Self-contained HTML report.

No network requests of any kind: inline CSS, inline SVG, no external fonts or
scripts. The file is meant to be opened, kept, and shared on its own.
"""

from __future__ import annotations

import html
import os
import time
from typing import List, Optional, Sequence, Tuple

from ..humanize import human_bytes, redact
from ..model import Risk, ScanResult
from ..scan.apfs import primary_volume
from .term import FDA_STEPS, unaccounted

Rect = Tuple[str, float, float, float, float, float]

_RISK_CLASS = {
    Risk.SAFE: "safe",
    Risk.REVIEW: "review",
    Risk.DANGER: "danger",
    Risk.BLOCKED: "blocked",
}


def squarify(items: Sequence, x: float, y: float,
             width: float, height: float) -> List[Rect]:
    """Slice-and-dice treemap layout.

    Splits along whichever edge is currently longer, which keeps rectangles
    from degenerating into slivers without the complexity of a true squarified
    layout. Tiles the area exactly, with no gaps or overlaps.
    """
    entries = [(label, float(value)) for label, value in items if value > 0]
    if not entries or width <= 0 or height <= 0:
        return []
    entries.sort(key=lambda item: item[1], reverse=True)

    rects: List[Rect] = []
    remaining = sum(value for _label, value in entries)
    cx, cy, cw, ch = x, y, width, height

    for index, (label, value) in enumerate(entries):
        if index == len(entries) - 1:
            rects.append((label, value, cx, cy, cw, ch))
            break
        share = value / remaining if remaining else 0.0
        if cw >= ch:
            w = cw * share
            rects.append((label, value, cx, cy, w, ch))
            cx += w
            cw -= w
        else:
            h = ch * share
            rects.append((label, value, cx, cy, cw, h))
            cy += h
            ch -= h
        remaining -= value

    return rects


# Colour-blind-safe categorical palette, readable on light and dark.
_PALETTE = ("#4c78a8", "#72b7b2", "#54a24b", "#eeca3b", "#e45756",
            "#b279a2", "#ff9da6", "#9d755d", "#79706e", "#8cd17d")


def _treemap_svg(result: ScanResult, home: str,
                 width: int = 900, height: int = 420) -> str:
    if result.root is None or not result.root.children:
        return ""
    items = [(redact(node.path, home), node.size)
             for node in result.root.sorted_children()[:14]]
    rects = squarify(items, 0, 0, width, height)
    if not rects:
        return ""

    parts = ['<svg viewBox="0 0 {} {}" role="img" '
             'aria-label="Treemap of the largest directories">'.format(width, height)]
    for index, (label, value, rx, ry, rw, rh) in enumerate(rects):
        colour = _PALETTE[index % len(_PALETTE)]
        name = os.path.basename(label) or label
        parts.append(
            '<g><rect x="{:.1f}" y="{:.1f}" width="{:.1f}" height="{:.1f}" '
            'fill="{}" stroke="var(--bg)" stroke-width="2"/>'
            '<title>{} — {}</title>'.format(
                rx, ry, rw, rh, colour,
                html.escape(label), human_bytes(int(value))))
        if rw > 96 and rh > 38:
            parts.append(
                '<text x="{:.1f}" y="{:.1f}" fill="#ffffff" font-size="13" '
                'font-weight="600">{}</text>'.format(
                    rx + 9, ry + 23, html.escape(name[:26])))
            parts.append(
                '<text x="{:.1f}" y="{:.1f}" fill="#ffffff" font-size="12" '
                'opacity="0.85">{}</text>'.format(
                    rx + 9, ry + 41, human_bytes(int(value))))
        parts.append("</g>")
    parts.append("</svg>")
    return "".join(parts)


_CSS = """
:root {
  --bg: #ffffff; --fg: #16181d; --muted: #666c75; --line: #e3e5e9;
  --card: #fafbfc;
  --safe: #1f7a33; --review: #8a5a00; --danger: #b3261e;
}
:root:not([data-theme="light"]) {
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14161a; --fg: #e8ebf0; --muted: #949aa4; --line: #2a2e35;
    --card: #1a1d22;
    --safe: #6fcf7a; --review: #e6b95c; --danger: #ff8b80;
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #14161a; --fg: #e8ebf0; --muted: #949aa4; --line: #2a2e35;
  --card: #1a1d22;
  --safe: #6fcf7a; --review: #e6b95c; --danger: #ff8b80;
  color-scheme: dark;
}
* { box-sizing: border-box; }
body {
  background: var(--bg); color: var(--fg); margin: 0; padding: 2.5rem 1.25rem;
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "SF Pro Text", Segoe UI, sans-serif;
}
main { max-width: 64rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .3rem; letter-spacing: -0.01em; }
h2 { font-size: 1.05rem; margin: 2.5rem 0 .75rem; }
.sub { color: var(--muted); margin: 0 0 2rem; font-size: .9rem; }
.banner {
  border: 1px solid var(--danger); border-radius: 10px; padding: .9rem 1.1rem;
  margin-bottom: 1.75rem; color: var(--danger);
}
.banner b { letter-spacing: .04em; }
.banner span { color: var(--fg); display: block; margin-top: .35rem; }
.cards { display: flex; flex-wrap: wrap; gap: .85rem; margin-bottom: 1rem; }
.card {
  border: 1px solid var(--line); background: var(--card); border-radius: 11px;
  padding: .9rem 1.15rem; min-width: 11rem; flex: 1 1 11rem;
}
.card b { display: block; font-size: 1.4rem; letter-spacing: -0.02em; }
.card span { color: var(--muted); font-size: .82rem; }
.note { color: var(--muted); font-size: .88rem; margin: 0 0 1rem; }
figure { margin: 0; overflow-x: auto; }
svg { display: block; width: 100%; height: auto; min-width: 32rem; }
.wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; min-width: 38rem; }
th, td {
  text-align: left; padding: .6rem .65rem; vertical-align: top;
  border-bottom: 1px solid var(--line);
}
th {
  font-size: .74rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); font-weight: 600;
}
td.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.tier { white-space: nowrap; font-size: .78rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: .04em; }
.what { font-weight: 500; }
code {
  display: inline-block; margin-top: .3rem;
  font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
  color: var(--muted); word-break: break-all;
}
.safe { color: var(--safe); } .review { color: var(--review); }
.danger { color: var(--danger); } .blocked { color: var(--muted); }
footer { color: var(--muted); font-size: .85rem; margin-top: 3rem;
  border-top: 1px solid var(--line); padding-top: 1rem; }
"""


def render(result: ScanResult, *, home: str, generated_at: float) -> str:
    esc = html.escape
    volume = primary_volume(result.volumes)

    cards: List[str] = []
    if volume is not None:
        cards.append('<div class="card"><b>{}</b><span>free of {}</span></div>'
                     .format(human_bytes(volume.free), human_bytes(volume.total)))
    cards.append('<div class="card"><b>{}</b><span>safe to reclaim</span></div>'
                 .format(human_bytes(result.reclaimable(Risk.SAFE))))
    cards.append('<div class="card"><b>{}</b><span>with review</span></div>'
                 .format(human_bytes(result.reclaimable(Risk.SAFE, Risk.REVIEW))))
    gap = unaccounted(result)
    if gap:
        cards.append('<div class="card"><b>{}</b><span>unaccounted</span></div>'
                     .format(human_bytes(gap)))

    note = ""
    if gap:
        note = ('<p class="note">{} of this volume is in use but could not be '
                'attributed to any scanned file. That is normally APFS '
                'snapshots, other volumes sharing the container, or paths this '
                'scan was not permitted to read.</p>'.format(human_bytes(gap)))

    rows: List[str] = []
    for finding in result.findings_by_size():
        where = redact(finding.path, home) if finding.path else ""
        detail = finding.detail if not where else ""
        body = '<div class="what">{}</div>'.format(esc(finding.title))
        if where:
            body += "<code>{}</code>".format(esc(where))
        if detail:
            body += "<code>{}</code>".format(esc(detail))
        if finding.reclaim_hint:
            body += "<code>$ {}</code>".format(esc(finding.reclaim_hint))
        rows.append(
            '<tr><td class="num">{}</td><td class="tier {}">{}</td>'
            '<td>{}</td></tr>'.format(
                human_bytes(finding.bytes_) if finding.bytes_ else "—",
                _RISK_CLASS[finding.risk],
                esc(finding.risk.value),
                body,
            ))

    banner = ""
    if not result.fda_ok:
        banner = ('<div class="banner"><b>INCOMPLETE SCAN</b>'
                  '<span>Full Disk Access is not granted, so parts of your home '
                  'folder were skipped and every total here is too low. '
                  '{}</span></div>'.format(esc(FDA_STEPS)))

    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>storagescan report</title>\n"
        "<style>{css}</style>\n</head>\n<body>\n<main>\n"
        "<h1>storagescan</h1>\n"
        "<p class=\"sub\">{mode} scan &middot; {generated} &middot; "
        "{seconds} &middot; {files} files</p>\n"
        "{banner}"
        "<div class=\"cards\">{cards}</div>\n"
        "{note}"
        "<h2>Largest directories</h2>\n<figure>{svg}</figure>\n"
        "<h2>What is taking the space</h2>\n"
        "<div class=\"wrap\"><table>\n"
        "<thead><tr><th>Size</th><th>Tier</th><th>What</th></tr></thead>\n"
        "<tbody>{rows}</tbody>\n</table></div>\n"
        "<footer>{errors} items were unreadable and are not counted in these "
        "totals. Sizes are what the files occupy on disk, which is what you "
        "get back by deleting them.</footer>\n"
        "</main>\n</body>\n</html>\n"
    ).format(
        css=_CSS,
        mode=esc(result.mode),
        generated=time.strftime("%Y-%m-%d %H:%M", time.localtime(generated_at)),
        seconds="{:.1f}s".format(result.duration),
        files="{:,}".format(result.root.count if result.root else 0),
        banner=banner,
        cards="".join(cards),
        note=note,
        svg=_treemap_svg(result, home),
        rows="".join(rows) or '<tr><td colspan="3">No findings.</td></tr>',
        errors="{:,}".format(len(result.errors)),
    )


def default_report_path() -> str:
    return os.path.expanduser("~/.cache/storagescan/report.html")


def write(result: ScanResult, *, home: str, generated_at: float,
          path: Optional[str] = None) -> str:
    path = path or default_report_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w") as handle:
        handle.write(render(result, home=home, generated_at=generated_at))
    return path
