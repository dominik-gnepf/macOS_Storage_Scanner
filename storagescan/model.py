"""The shared vocabulary. Scanners produce these; UIs consume them."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Optional, Tuple


class Risk(enum.Enum):
    """How much confirmation deleting something should cost."""

    SAFE = "safe"        # regenerable: caches, build products
    REVIEW = "review"    # user data that is probably disposable
    DANGER = "danger"    # looks irreplaceable
    BLOCKED = "blocked"  # this tool will never delete it


@dataclass(frozen=True)
class Node:
    """One directory-tree entry, with its subtree totals already summed."""

    path: str
    size: int          # on-disk bytes (st_blocks * 512)
    apparent: int      # apparent bytes (st_size)
    count: int         # files in subtree
    mtime: float
    children: Tuple["Node", ...] = ()
    truncated: bool = False   # depth limit hit below here
    unreadable: int = 0       # entries skipped for permissions in subtree

    def sorted_children(self) -> Tuple["Node", ...]:
        return tuple(sorted(self.children, key=lambda n: n.size, reverse=True))


@dataclass(frozen=True)
class Finding:
    """A probe hit or analysis result: a specific chunk of reclaimable space."""

    category: str
    title: str
    path: Optional[str]
    bytes_: int
    risk: Risk
    detail: str = ""
    reclaim_hint: str = ""


@dataclass(frozen=True)
class ScanError:
    path: str
    error: str


@dataclass(frozen=True)
class VolumeInfo:
    mount: str
    total: int
    used: int
    free: int
    purgeable: Optional[int] = None


@dataclass(frozen=True)
class ScanResult:
    """One immutable snapshot. Every view reads this and nothing else."""

    root: Optional[Node]
    findings: Tuple[Finding, ...] = ()
    volumes: Tuple[VolumeInfo, ...] = ()
    errors: Tuple[ScanError, ...] = ()
    mode: str = "fast"
    duration: float = 0.0
    fda_ok: bool = True
    started_at: float = 0.0
    # What was actually scanned. Views need this to know which statements are
    # meaningful: "N GB unaccounted for on this volume" is informative after a
    # whole-home scan and misleading after `--path ~/Developer`.
    roots: Tuple[str, ...] = ()

    def covers(self, path: str) -> bool:
        for root in self.roots:
            root = root.rstrip("/")
            if path == root or path.startswith(root + "/"):
                return True
        return False

    def reclaimable(self, *risks: Risk) -> int:
        wanted = set(risks) or {Risk.SAFE}
        return sum(f.bytes_ for f in self.findings if f.risk in wanted)

    def findings_by_size(self) -> Tuple[Finding, ...]:
        return tuple(sorted(self.findings, key=lambda f: f.bytes_, reverse=True))
