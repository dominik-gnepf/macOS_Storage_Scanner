"""Large files that have not changed in a long time."""

from __future__ import annotations

import os
from typing import List, Optional, Sequence, Tuple

from ..humanize import human_age
from ..model import Finding, ScanError
from ..safety import classify
from .cloud import is_dataless
from .walker import _excluded, prune_dirnames

_DAY = 86400.0


def find_stale(
    root: str,
    *,
    home: str,
    scan_roots: Sequence[str],
    min_bytes: int,
    stale_days: int,
    now: float,
    errors: Optional[List[ScanError]] = None,
    exclude: Sequence[str] = (),
) -> Tuple[Finding, ...]:
    """Files of at least ``min_bytes`` untouched for ``stale_days``.

    st_mtime is used rather than st_atime: macOS does not reliably update
    access times, so a stale atime proves nothing about whether you use a file.
    """
    cutoff = now - stale_days * _DAY
    findings: List[Finding] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        prune_dirnames(dirpath, dirnames, exclude)
        if _excluded(dirpath, exclude):
            dirnames[:] = []
            continue
        for name in filenames:
            path = os.path.join(dirpath, name)
            if _excluded(path, exclude):
                continue
            try:
                st = os.lstat(path)
            except OSError as exc:
                if errors is not None:
                    errors.append(ScanError(path=path, error=type(exc).__name__))
                continue
            if os.path.islink(path) or st.st_size < min_bytes:
                continue
            # A cloud placeholder reports a size but occupies no blocks.
            # Offering to delete it would reclaim nothing.
            if is_dataless(st):
                continue
            if st.st_mtime > cutoff:
                continue
            findings.append(Finding(
                category="aging.stale",
                title="Large file, untouched",
                path=path,
                bytes_=st.st_size,
                risk=classify(path, "aging.stale", home=home,
                              scan_roots=scan_roots),
                detail="last modified {}".format(human_age(st.st_mtime, now)),
            ))

    findings.sort(key=lambda f: f.bytes_, reverse=True)
    return tuple(findings)
