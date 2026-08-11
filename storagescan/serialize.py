"""ScanResult <-> JSON, plus the on-disk cache and scan-to-scan diff."""

from __future__ import annotations

import contextlib
import json
import os
import sys
from typing import Dict, List, Optional, Tuple

from .model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo

SCHEMA = 2

# CPython's json encoder and decoder recurse once per nesting level, and a
# node tree nests as deeply as the directory tree. macOS caps a path at
# PATH_MAX (1024 bytes), so a real tree tops out near 340 components — but
# that is already close enough to the default 1000-frame limit to fail. The
# walker and the node builders here are iterative; only json is not, so the
# limit is raised just around the json call and restored immediately.
_JSON_RECURSION_LIMIT = 6000


@contextlib.contextmanager
def _deep_recursion():
    previous = sys.getrecursionlimit()
    if previous < _JSON_RECURSION_LIMIT:
        sys.setrecursionlimit(_JSON_RECURSION_LIMIT)
    try:
        yield
    finally:
        sys.setrecursionlimit(previous)


class SchemaMismatch(Exception):
    """Cached data was written by an incompatible version."""


def _node_to_dict(node: Node) -> dict:
    """Iterative, so a deep tree cannot blow the stack on serialization."""
    payload: dict = {}
    stack = [(node, payload)]
    while stack:
        current, target = stack.pop()
        target.update({
            "path": current.path, "size": current.size,
            "apparent": current.apparent, "count": current.count,
            "mtime": current.mtime, "truncated": current.truncated,
            "unreadable": current.unreadable, "children": [],
        })
        for child in current.children:
            slot: dict = {}
            target["children"].append(slot)
            stack.append((child, slot))
    return payload


def _node_from_dict(data: dict) -> Node:
    """Iterative post-order rebuild, mirroring _node_to_dict."""
    built: Dict[int, Node] = {}
    stack = [(data, False)]
    while stack:
        current, fold = stack.pop()
        if fold:
            children = tuple(built.pop(id(c)) for c in current.get("children", []))
            built[id(current)] = Node(
                path=current["path"], size=current["size"],
                apparent=current["apparent"], count=current["count"],
                mtime=current["mtime"],
                truncated=current.get("truncated", False),
                unreadable=current.get("unreadable", 0),
                children=children,
            )
            continue
        stack.append((current, True))
        for child in current.get("children", []):
            stack.append((child, False))
    return built[id(data)]


def dumps(result: ScanResult) -> str:
    payload = {
        "schema": SCHEMA,
        "root": _node_to_dict(result.root) if result.root else None,
        "findings": [
            {"category": f.category, "title": f.title, "path": f.path,
             "bytes": f.bytes_, "risk": f.risk.value, "detail": f.detail,
             "reclaim_hint": f.reclaim_hint}
            for f in result.findings
        ],
        "volumes": [
            {"mount": v.mount, "total": v.total, "used": v.used,
             "free": v.free, "purgeable": v.purgeable}
            for v in result.volumes
        ],
        "errors": [{"path": e.path, "error": e.error} for e in result.errors],
        "mode": result.mode, "duration": result.duration,
        "fda_ok": result.fda_ok, "started_at": result.started_at,
        "roots": list(result.roots),
    }
    with _deep_recursion():
        return json.dumps(payload)


def loads(text: str) -> ScanResult:
    with _deep_recursion():
        payload = json.loads(text)
    if payload.get("schema") != SCHEMA:
        raise SchemaMismatch("expected schema {}".format(SCHEMA))
    return ScanResult(
        root=_node_from_dict(payload["root"]) if payload.get("root") else None,
        findings=tuple(
            Finding(category=f["category"], title=f["title"], path=f["path"],
                    bytes_=f["bytes"], risk=Risk(f["risk"]),
                    detail=f.get("detail", ""),
                    reclaim_hint=f.get("reclaim_hint", ""))
            for f in payload.get("findings", [])
        ),
        volumes=tuple(
            VolumeInfo(mount=v["mount"], total=v["total"], used=v["used"],
                       free=v["free"], purgeable=v.get("purgeable"))
            for v in payload.get("volumes", [])
        ),
        errors=tuple(
            ScanError(path=e["path"], error=e["error"])
            for e in payload.get("errors", [])
        ),
        mode=payload.get("mode", "fast"),
        duration=payload.get("duration", 0.0),
        fda_ok=payload.get("fda_ok", True),
        started_at=payload.get("started_at", 0.0),
        roots=tuple(payload.get("roots", [])),
    )


def cache_path() -> str:
    return os.path.expanduser("~/.cache/storagescan/last.json")


def save(result: ScanResult, path: Optional[str] = None) -> str:
    path = path or cache_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w") as handle:
        handle.write(dumps(result))
    return path


def load_cached(path: Optional[str] = None) -> Optional[ScanResult]:
    """The cached scan, or None if it is absent, corrupt, or stale."""
    path = path or cache_path()
    try:
        with open(path, "r") as handle:
            return loads(handle.read())
    except (OSError, ValueError, KeyError, SchemaMismatch):
        return None


def _flatten(node: Optional[Node]) -> Dict[str, int]:
    sizes: Dict[str, int] = {}
    if node is None:
        return sizes
    stack = [node]
    while stack:
        current = stack.pop()
        sizes[current.path] = current.size
        stack.extend(current.children)
    return sizes


def diff(old: ScanResult, new: ScanResult) -> Tuple[Tuple[str, int], ...]:
    """Per-path size change between two scans, biggest movers first."""
    before = _flatten(old.root)
    after = _flatten(new.root)
    changes: List[Tuple[str, int]] = []
    for path in set(before) | set(after):
        delta = after.get(path, 0) - before.get(path, 0)
        if delta:
            changes.append((path, delta))
    changes.sort(key=lambda item: (-abs(item[1]), item[0]))
    return tuple(changes)
