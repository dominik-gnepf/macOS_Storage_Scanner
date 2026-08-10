"""Formatting helpers. Every user-visible string passes through here."""

from __future__ import annotations

import os

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_bytes(n: int) -> str:
    """Format a byte count using decimal units, matching Finder."""
    sign = "-" if n < 0 else ""
    value = float(abs(n))
    for unit in _UNITS:
        if value < 1000 or unit == _UNITS[-1]:
            if unit == "B":
                return "{}{:.0f} B".format(sign, value)
            return "{}{:.1f} {}".format(sign, value, unit)
        value /= 1000.0
    raise AssertionError("unreachable")


def redact(path: str, home: str) -> str:
    """Collapse a leading home directory to ``~``.

    Matches whole path components only, so ``/Users/ann2`` is never treated as
    living inside ``/Users/ann``.
    """
    home = home.rstrip(os.sep)
    if not home:
        return path
    if path == home:
        return "~"
    if path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


def human_age(mtime: float, now: float) -> str:
    """Describe how long ago ``mtime`` was, in coarse buckets."""
    days = int((now - mtime) // 86400)
    if days <= 0:
        return "today"
    if days == 1:
        return "1 day ago"
    if days < 30:
        return "{} days ago".format(days)
    months = days // 30
    if months < 12:
        return "1 month ago" if months == 1 else "{} months ago".format(months)
    years = days // 365
    return "1 year ago" if years == 1 else "{} years ago".format(years)
