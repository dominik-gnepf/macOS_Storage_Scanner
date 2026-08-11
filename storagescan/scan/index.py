"""A path -> subtree-size lookup built from a single walk.

The naive design measures each probe by walking its directory, which re-reads
trees the main scan already visited. On a full 156 GB home that turns one pass
into a dozen and takes minutes instead of seconds.

Instead: walk once, index every node, and let probes look their answer up.
Paths the walk never enumerated (files, or anything under a depth-truncated
node) fall back to a real measurement, so results stay correct either way.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional, Tuple

from ..model import Node

Measurement = Tuple[int, int, int]  # (size, apparent, count)


class SizeIndex:
    """Subtree totals keyed by absolute path, with a measuring fallback."""

    def __init__(self, fallback: Callable[[str], Measurement]):
        self._sizes: Dict[str, Measurement] = {}
        self._fallback = fallback
        self.hits = 0
        self.misses = 0

    def add_tree(self, node: Optional[Node]) -> None:
        """Index a walked tree. Iterative, to match the walker."""
        if node is None:
            return
        stack = [node]
        while stack:
            current = stack.pop()
            self._sizes[current.path] = (
                current.size, current.apparent, current.count)
            stack.extend(current.children)

    def measure(self, path: str) -> Measurement:
        """Subtree totals for ``path``, walking only when unknown."""
        known = self._sizes.get(path)
        if known is not None:
            self.hits += 1
            return known
        self.misses += 1
        return self._fallback(path)

    def __len__(self) -> int:
        return len(self._sizes)
