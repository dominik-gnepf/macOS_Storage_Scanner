"""Cloud-synced folders, which a storage scanner must handle carefully.

Two distinct hazards, both measured on a real machine:

1. **They stall.** Directories served by a macOS File Provider extension
   (OneDrive, iCloud Drive, Dropbox, Google Drive) answer readdir over the
   network. Benchmark on a live OneDrive folder: 739 files in over 8 seconds,
   against 111,342 files in 1.6 seconds for a local directory — roughly a
   thousand times slower. A full-home scan that walks them takes an hour.

2. **Reading them costs disk space.** Files that are not downloaded are
   "dataless" placeholders: they report their full logical size but occupy
   zero blocks. Calling open() on one asks macOS to materialise it, which
   downloads the file. For a tool whose whole job is to free space, hashing a
   placeholder is actively harmful.

So: cloud roots are excluded from the walk by default and reported separately,
and any code that opens files must skip dataless ones.
"""

from __future__ import annotations

import glob
import os
import time
from typing import Callable, List, Optional, Sequence, Tuple

from ..model import Finding, Risk

# chflags(2): the file's data is not resident and must be fetched on access.
SF_DATALESS = 0x40000000

# Home-relative roots served by cloud providers.
CLOUD_PATTERNS: Tuple[str, ...] = (
    "Library/CloudStorage",      # OneDrive, Box, Google Drive, Dropbox (modern)
    "Library/Mobile Documents",  # iCloud Drive
    "Library/Group Containers/*OneDrive*",
    "Library/Group Containers/*Dropbox*",
    "Dropbox",
    "Google Drive",
)


def is_dataless(st) -> bool:
    """True when a file's contents are not on this disk.

    Opening such a file downloads it. Anything that reads file *contents*
    must check this first; anything that only reads metadata need not.
    """
    return bool(getattr(st, "st_flags", 0) & SF_DATALESS)


def cloud_roots(home: str) -> Tuple[str, ...]:
    """Cloud directories that exist on this machine."""
    found: List[str] = []
    for pattern in CLOUD_PATTERNS:
        for path in sorted(glob.glob(os.path.join(home, pattern))):
            if os.path.isdir(path) and not os.path.islink(path):
                found.append(path)
    return tuple(found)


def is_cloud_path(path: str, roots: Sequence[str]) -> bool:
    for root in roots:
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return True
    return False


DEFAULT_BUDGET_SECONDS = 20.0


def measure_bounded(path: str, budget: float = DEFAULT_BUDGET_SECONDS
                    ) -> Optional[int]:
    """On-disk bytes under ``path``, or None if it took too long.

    Only metadata is read — scandir and lstat, never open() — so this cannot
    trigger a download no matter how long it runs.

    The time budget exists because a File Provider answers readdir over the
    network. Measured on a live OneDrive folder: 1.95s once the provider had
    cached its metadata, but over 8 seconds for the first 739 entries while
    cold. Returning None beats hanging, and the caller reports honestly that
    the size is unknown.

    Only ``st_blocks`` is summed, which is what makes this worth doing: a
    placeholder occupies no blocks and contributes nothing, while a downloaded
    file contributes its real footprint. Apparent size would wildly overstate
    a sync folder.
    """
    deadline = time.monotonic() + budget
    total = 0
    stack = [path]
    while stack:
        if time.monotonic() > deadline:
            return None
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                stack.append(entry.path)
                continue
            total += getattr(st, "st_blocks", 0) * 512
    return total


def cloud_findings(home: str, roots: Sequence[str],
                   budget: float = DEFAULT_BUDGET_SECONDS,
                   measure: Optional[Callable[[str], Optional[int]]] = None
                   ) -> Tuple[Finding, ...]:
    """Report cloud folders: excluded from the tree, but still measured.

    These are left out of the walk because enumerating them is slow, but they
    are not left out of the accounting — on a real machine the cloud folders
    held 12.2 GB of downloaded files, which is a sixth of the space that would
    otherwise show up as unexplained.
    """
    sizer = measure or (lambda path: measure_bounded(path, budget))
    findings: List[Finding] = []

    for root in roots:
        size = sizer(root)
        if size is None:
            findings.append(Finding(
                category="cloud.folder",
                title="Cloud folder (size unknown)",
                path=root,
                bytes_=0,
                risk=Risk.BLOCKED,
                detail=(
                    "Served over the network by a sync client, and it did not "
                    "respond quickly enough to measure. Files you have not "
                    "downloaded occupy no disk space; downloaded ones do."
                ),
            ))
            continue
        findings.append(Finding(
            category="cloud.folder",
            title="Cloud folder (downloaded files)",
            path=root,
            bytes_=size,
            risk=Risk.BLOCKED,
            detail=(
                "Only the files you have actually downloaded are counted; "
                "placeholders occupy no disk space. Free this up from your "
                "sync client by making files online-only, not by deleting "
                "them here — deleting would remove them from the cloud too."
            ),
        ))

    return tuple(findings)
