"""Deletion. Trash first, permanent only on request, never without consent.

Nothing here decides policy — safety.classify does. This module enforces the
decision, performs the move, and records what happened.
"""

from __future__ import annotations

import os
import shutil
import stat
import time
from dataclasses import dataclass
from typing import Callable, Optional, Sequence, Tuple

from .humanize import human_bytes, redact
from .model import Risk
from .safety import batch_allowed, classify, confirmation_for
from .scan.walker import dir_size

# (path, risk, confirmation_mode) -> was it confirmed?
Confirm = Callable[[str, Risk, str], bool]

TRASHED = "trashed"
PURGED = "purged"
REFUSED = "refused"
DECLINED = "declined"
DRY_RUN = "dry-run"
FAILED = "failed"
CHANGED = "changed"


@dataclass(frozen=True)
class ActionOutcome:
    path: str
    risk: Risk
    status: str
    bytes_: int = 0
    message: str = ""


def default_log_path(home: Optional[str] = None) -> str:
    """Action log for a given home. Derived from ``home``, never from $HOME.

    Everything here that resolves a location does so from the ``home`` the
    caller passed in. Reaching for os.path.expanduser("~") instead would mean
    a caller operating on one home directory writes into another's — which is
    exactly how a test running against a temp directory ended up moving files
    into the real user's Trash.
    """
    base = home if home is not None else os.path.expanduser("~")
    return os.path.join(base, ".local", "state", "storagescan", "actions.log")


def default_trash_dir(home: Optional[str] = None) -> str:
    base = home if home is not None else os.path.expanduser("~")
    return os.path.join(base, ".Trash")


def _device(path: str) -> int:
    return os.lstat(path).st_dev


def mount_point(path: str) -> str:
    """The mount containing ``path``. Walks parents until ``st_dev`` changes."""
    path = os.path.abspath(path)
    if os.path.islink(path) or not os.path.isdir(path):
        path = os.path.dirname(path)
    try:
        dev = _device(path)
    except OSError:
        return path
    while True:
        parent = os.path.dirname(path)
        if parent == path:
            return path
        try:
            if _device(parent) != dev:
                return path
        except OSError:
            return path
        path = parent


def trash_dir_for(path: str, home: str) -> str:
    """Trash that lives on the same volume as ``path``.

    ``shutil.move`` to ``~/.Trash`` from another volume copies onto the boot
    disk first. Finder puts the file in ``.Trashes/<uid>/`` on the source
    volume instead — a large VM image on a USB drive must not fill the Mac.
    """
    home_trash = default_trash_dir(home)
    try:
        target = path if os.path.lexists(path) else os.path.dirname(path)
        home_anchor = home_trash if os.path.lexists(home_trash) else home
        if _device(target) == _device(home_anchor):
            return home_trash
    except OSError:
        return home_trash
    return os.path.join(mount_point(path), ".Trashes", str(os.getuid()))


def _write_log(outcome: ActionOutcome, home: str, path: Optional[str]) -> None:
    target = path or default_log_path(home)
    try:
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "a") as handle:
            handle.write("{}\t{}\t{}\t{}\n".format(
                time.strftime("%Y-%m-%dT%H:%M:%S"),
                outcome.status,
                human_bytes(outcome.bytes_),
                redact(outcome.path, home),
            ))
    except OSError:
        pass  # a failing log must never block or mask the action itself


def trash_path(path: str, *, trash_dir: Optional[str] = None,
               home: Optional[str] = None) -> str:
    """Destination inside the Trash, timestamped if the name is taken."""
    if trash_dir is None:
        trash_dir = trash_dir_for(path, home or os.path.expanduser("~"))
    base = os.path.basename(path.rstrip("/"))
    candidate = os.path.join(trash_dir, base)
    if not os.path.lexists(candidate):
        return candidate
    stamp = time.strftime("%Y-%m-%d %H.%M.%S")
    root, ext = os.path.splitext(base)
    n = 0
    while True:
        if n == 0:
            name = "{} {}{}".format(root, stamp, ext)
        else:
            name = "{} {} {}{}".format(root, stamp, n, ext)
        candidate = os.path.join(trash_dir, name)
        if not os.path.lexists(candidate):
            return candidate
        n += 1


def measure(path: str) -> int:
    """On-disk bytes held by a path — what deleting it actually gives back."""
    size, _apparent, _count = dir_size(path)
    return size


def _identity(path: str) -> Optional[Tuple[int, int, int]]:
    """(dev, ino, file type). Changes when the path is replaced under us."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode))


def perform(
    path: str,
    *,
    home: str,
    scan_roots: Sequence[str],
    confirm: Confirm,
    category: Optional[str] = None,
    dry_run: bool = False,
    use_trash: bool = True,
    trash_dir: Optional[str] = None,
    log_path: Optional[str] = None,
    require_safe: bool = False,
) -> ActionOutcome:
    """Delete ``path`` after classifying it and obtaining consent."""
    is_symlink = os.path.islink(path)
    risk = classify(path, category, home=home, scan_roots=scan_roots,
                    is_symlink=is_symlink)

    def done(status, bytes_=0, message=""):
        outcome = ActionOutcome(path, risk, status, bytes_, message)
        _write_log(outcome, home, log_path)
        return outcome

    if risk is Risk.BLOCKED:
        return done(REFUSED, message="storagescan will not delete this path")

    if require_safe and (
            risk is not Risk.SAFE or not batch_allowed(path, home)):
        return done(REFUSED, message="storagescan will not delete this path")

    if not os.path.lexists(path):
        return done(FAILED, message="path does not exist")

    identity = _identity(path)
    size = measure(path)

    if not confirm(path, risk, confirmation_for(risk)):
        return done(DECLINED, size)

    if dry_run:
        return done(DRY_RUN, size)

    # Re-check right before acting: the tree may have moved since the scan,
    # and acting on a stale path is how a tool deletes the wrong thing.
    if _identity(path) != identity:
        return done(CHANGED, message="path changed before deletion")

    try:
        if use_trash:
            destination = trash_path(path, trash_dir=trash_dir, home=home)
            parent = os.path.dirname(destination)
            if parent:
                os.makedirs(parent, mode=0o700, exist_ok=True)
            shutil.move(path, destination)
            return done(TRASHED, size, destination)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        return done(PURGED, size)
    except OSError as exc:
        return done(FAILED, size, str(exc))
