from __future__ import annotations

import os


def build_tree(base, spec):
    """Create a directory tree.

    ``spec`` maps names to either a dict (directory) or an int (a file of that
    many bytes).
    """
    os.makedirs(base, exist_ok=True)
    for name, value in spec.items():
        path = os.path.join(base, name)
        if isinstance(value, dict):
            build_tree(path, value)
        else:
            with open(path, "wb") as handle:
                handle.write(b"x" * value)
    return base
