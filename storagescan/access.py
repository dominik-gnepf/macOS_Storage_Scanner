"""Full Disk Access: checking it, and helping the user grant it.

No application can grant itself Full Disk Access — that is the entire point of
the permission, and any tool claiming to "request" it is either lying or
describing a prompt macOS only offers for a few specific APIs. What a program
*can* do is detect that it lacks access, open the exact settings pane, and say
precisely which app to add and why.

The subtlety worth getting right: the permission belongs to the process that
runs the scanner — your terminal, or the editor whose integrated terminal you
launched it from — not to the storagescan script. Telling someone to "add
storagescan" sends them hunting for a binary that will not help.
"""

from __future__ import annotations

import os
import subprocess
from typing import Optional, Sequence, Tuple

# Apple's URL scheme for a specific Privacy pane. Stable across recent macOS.
PRIVACY_PANE = ("x-apple.systempreferences:com.apple.preference.security"
                "?Privacy_AllFiles")


def host_application() -> str:
    """A human name for the app that must be granted access.

    Derived from the process environment rather than guessed: TERM_PROGRAM is
    set by Terminal, iTerm, VS Code and others. Falls back to a description
    rather than a wrong specific name.
    """
    program = os.environ.get("TERM_PROGRAM", "").strip()
    friendly = {
        "Apple_Terminal": "Terminal",
        "iTerm.app": "iTerm",
        "vscode": "Visual Studio Code",
        "WarpTerminal": "Warp",
        "Hyper": "Hyper",
        "ghostty": "Ghostty",
        "WezTerm": "WezTerm",
        "kitty": "kitty",
        "Alacritty": "Alacritty",
    }
    if program in friendly:
        return friendly[program]
    if program:
        return program
    return "the app you run storagescan from"


def open_settings(runner=None) -> bool:
    """Open System Settings at Privacy & Security > Full Disk Access."""
    args = ["open", PRIVACY_PANE]
    if runner is not None:
        return runner(args) == 0
    try:
        completed = subprocess.run(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def blocked_paths(home: str, candidates: Sequence[str] = ()) -> Tuple[str, ...]:
    """Which protected locations are currently unreadable."""
    if not candidates:
        candidates = ("Downloads", "Documents", "Desktop",
                      "Library/Mail", "Library/Messages")
    blocked = []
    for relative in candidates:
        path = os.path.join(home, relative)
        if not os.path.exists(path):
            continue
        try:
            os.listdir(path)
        except OSError:
            blocked.append(path)
    return tuple(blocked)


def instructions(home: str, app: Optional[str] = None) -> str:
    """Exact, checkable steps — not a vague pointer at System Settings."""
    app = app or host_application()
    blocked = blocked_paths(home)
    lines = [
        "macOS is hiding part of your disk from this scan.",
        "",
        "No app can grant itself Full Disk Access, so this needs four clicks:",
        "",
        "  1. System Settings opens at Privacy & Security > Full Disk Access",
        "  2. Click + and add:  {}".format(app),
        "  3. Make sure its switch is ON",
        "  4. Quit and reopen {}, then scan again".format(app),
        "",
        "Add {} — the terminal app itself. The permission belongs to the".format(app),
        "program that runs the scanner, not to the scanner script.",
    ]
    if blocked:
        lines.append("")
        lines.append("Currently unreadable:")
        for path in blocked:
            lines.append("  {}".format(path.replace(home, "~", 1)))
    return "\n".join(lines)
