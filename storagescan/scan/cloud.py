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

import os
from typing import List, Optional, Sequence, Tuple

from ..model import Finding, Risk

# chflags(2): the file's data is not resident and must be fetched on access.
SF_DATALESS = 0x40000000

# Home-relative roots served by cloud providers.
CLOUD_PATTERNS: Tuple[str, ...] = (
    "Library/CloudStorage",      # OneDrive, Box, Google Drive, Dropbox (modern)
    "Library/Mobile Documents",  # iCloud Drive
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
        path = os.path.join(home, pattern)
        if os.path.isdir(path) and not os.path.islink(path):
            found.append(path)
    return tuple(found)


def is_cloud_path(path: str, roots: Sequence[str]) -> bool:
    for root in roots:
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return True
    return False


def cloud_findings(home: str, roots: Sequence[str],
                   sizer: Optional[object] = None) -> Tuple[Finding, ...]:
    """Report cloud folders as present-but-unscanned.

    No size is claimed. Establishing one means enumerating the folder, which
    is the slow operation being avoided, and the answer would be near zero
    anyway because placeholders occupy no blocks.
    """
    return tuple(
        Finding(
            category="cloud.folder",
            title="Cloud folder (not scanned)",
            path=root,
            bytes_=0,
            risk=Risk.BLOCKED,
            detail=(
                "Served over the network by a sync client. Files that are not "
                "downloaded take no disk space; ones that are show up in your "
                "provider's own settings. Scanning it is slow and can trigger "
                "downloads, so storagescan skips it. Use --include-cloud to "
                "override."
            ),
        )
        for root in roots
    )
