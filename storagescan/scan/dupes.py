"""Duplicate detection via a three-stage funnel: size, head hash, full hash.

Hashing every file would dominate the scan, so full hashes are computed only
for files that already collide on both their size and their first 64 KB.

Hardlinked copies are not duplicates: they are one file with two names and
already occupy the space once.
"""

from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from ..humanize import redact
from ..model import Finding, ScanError
from ..safety import classify
from .cloud import is_dataless
from .walker import _excluded, prune_dirnames

_HEAD_BYTES = 65536
_CHUNK = 1024 * 1024


def _hash_file(path: str, limit: Optional[int] = None) -> Optional[str]:
    digest = hashlib.blake2b(digest_size=16)
    remaining = limit
    try:
        with open(path, "rb") as handle:
            while True:
                want = _CHUNK if remaining is None else min(_CHUNK, remaining)
                if want <= 0:
                    break
                chunk = handle.read(want)
                if not chunk:
                    break
                digest.update(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def find_duplicates(
    root: str,
    *,
    home: str,
    scan_roots: Sequence[str],
    min_bytes: int = 1_048_576,
    errors: Optional[List[ScanError]] = None,
    exclude: Sequence[str] = (),
) -> Tuple[Finding, ...]:
    """Groups of byte-identical files, one Finding per group."""
    by_size: Dict[int, List[str]] = defaultdict(list)
    seen_inodes = set()

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
            # Hashing opens the file, and opening a cloud placeholder makes
            # macOS download it. A tool for freeing space must never do that.
            if is_dataless(st):
                continue
            key = (st.st_dev, st.st_ino)
            if key in seen_inodes:
                continue
            seen_inodes.add(key)
            by_size[st.st_size].append(path)

    findings: List[Finding] = []
    for size, paths in by_size.items():
        if len(paths) < 2:
            continue
        by_head: Dict[str, List[str]] = defaultdict(list)
        for path in paths:
            head = _hash_file(path, _HEAD_BYTES)
            if head is not None:
                by_head[head].append(path)
        for head_group in by_head.values():
            if len(head_group) < 2:
                continue
            by_full: Dict[str, List[str]] = defaultdict(list)
            for path in head_group:
                full = _hash_file(path)
                if full is not None:
                    by_full[full].append(path)
            for group in by_full.values():
                if len(group) < 2:
                    continue
                group.sort()
                findings.append(Finding(
                    category="dupes.copy",
                    title="{} identical copies".format(len(group)),
                    path=group[0],
                    bytes_=size * (len(group) - 1),
                    risk=classify(group[0], "dupes.copy",
                                  home=home, scan_roots=scan_roots),
                    detail="\n".join(redact(p, home) for p in group),
                ))

    findings.sort(key=lambda f: f.bytes_, reverse=True)
    return tuple(findings)
