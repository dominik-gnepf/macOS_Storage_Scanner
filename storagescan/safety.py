"""Deletion policy. Pure functions only — no filesystem access happens here.

Tiered risk with escalating confirmation:

    SAFE     regenerable          -> single 'y'
    REVIEW   probably disposable  -> 'y' with a size/date recap
    DANGER   looks irreplaceable  -> retype the full path
    BLOCKED  never deletable      -> no prompt offered

Classification is conservative: an unmatched path is DANGER, never SAFE.
Size and file extension are deliberately ignored — only location and probe
category decide. A 40 GB file in a cache directory is SAFE; a 2 KB file in
~/Movies is DANGER.
"""

from __future__ import annotations

import posixpath
from typing import Optional, Sequence

from .model import Risk

SAFE_CATEGORIES = frozenset({
    "trash",
    "homebrew.cache",
    "pip.cache",
    "npm.cache",
    "pnpm.store",
    "yarn.cache",
    "cargo.cache",
    "go.modcache",
    "gradle.cache",
    "xcode.derived_data",
    "xcode.device_support",
    "xcode.simulator_caches",
    "browser.cache",
    "app.cache",
    "uv.cache",
    "bun.cache",
    "huggingface.cache",
})

REVIEW_CATEGORIES = frozenset({
    "downloads",
    "xcode.archives",
    "ios.backups",
    "docker.image",
    "orbstack.data",
    "vm.image",
    "android.sdk",
    "music.downloads",
    "mail.downloads",
    "aging.stale",
    "dupes.copy",
    "node_modules",
    "xcode.simulator_devices",
    "ollama.models",
})

# Deliberately absent from both sets, so they classify as DANGER and require
# the user to retype the path: photos.library, mail.store, apfs.* — these are
# either irreplaceable or managed by macOS itself.

_ROOT_LEVEL_BLOCKED = frozenset({
    "/", "/Users", "/Applications", "/System", "/Library", "/Volumes",
})


def _norm(path: str) -> str:
    """Normalize lexically. Never touches the filesystem, never reads links."""
    return posixpath.normpath(path)


# Folders whose contents stay out of bulk reclaim even when a SAFE category
# is attached. classify() still lets category win — an interactive delete
# of a mislabelled cache is a single `y` — but one `y` on a batch must not.
_BATCH_FORBIDDEN = ("Movies", "Pictures", "Music", "Photos",
                    "Documents", "Desktop")


def batch_allowed(path: str, home: str) -> bool:
    """False for user-media and document folders.

    Bulk reclaim auto-confirms. A probe bug or a tampered cache must not be
    able to put ``homebrew.cache`` on ``~/Movies/vacation.mov`` and have
    that file go to the Trash with the rest of the caches.
    """
    path = _norm(path)
    home = _norm(home)
    for name in _BATCH_FORBIDDEN:
        base = posixpath.join(home, name)
        if path == base or path.startswith(base + "/"):
            return False
    return True


def blocked_dirs(home: str) -> frozenset:
    """Directories blocked as *exact* matches, not as prefixes.

    ``~/Library`` is blocked but ``~/Library/Caches/Homebrew`` is not, so
    descendants stay classifiable.
    """
    home = _norm(home)
    return frozenset(
        set(_ROOT_LEVEL_BLOCKED)
        | {
            home,
            posixpath.join(home, "Documents"),
            posixpath.join(home, "Desktop"),
            posixpath.join(home, "Library"),
            posixpath.join(home, "Applications"),
        }
    )


def _under_any_root(path: str, scan_roots: Sequence[str]) -> bool:
    for root in scan_roots:
        root = _norm(root).rstrip("/")
        if not root:
            root = "/"
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return True
    return False


def classify(
    path: str,
    category: Optional[str],
    *,
    home: str,
    scan_roots: Sequence[str],
    is_symlink: bool = False,
) -> Risk:
    """Return the risk tier for deleting ``path``."""
    if is_symlink:
        return Risk.BLOCKED

    path = _norm(path)

    if path in blocked_dirs(home):
        return Risk.BLOCKED

    # Volume roots: /Volumes/Anything is a mount point, not a deletable dir.
    if posixpath.dirname(path) == "/Volumes":
        return Risk.BLOCKED

    if not _under_any_root(path, scan_roots):
        return Risk.BLOCKED

    if category in SAFE_CATEGORIES:
        return Risk.SAFE
    if category in REVIEW_CATEGORIES:
        return Risk.REVIEW
    return Risk.DANGER


def confirmation_for(risk: Risk) -> str:
    """How much the user must do to confirm a deletion at this tier."""
    return {
        Risk.SAFE: "single",
        Risk.REVIEW: "recap",
        Risk.DANGER: "retype",
        Risk.BLOCKED: "none",
    }[risk]
