"""Deletion. Trash first, permanent only on request, never without consent.

Nothing here decides policy — safety.classify does. This module enforces the
decision, performs the move, and records what happened.
"""

from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from .humanize import human_bytes, redact
from .model import Risk
from .safety import classify, confirmation_for

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


def default_log_path() -> str:
    return os.path.expanduser("~/.local/state/storagescan/actions.log")


def _write_log(outcome: ActionOutcome, home: str, path: Optional[str]) -> None:
    target = path or default_log_path()
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


def trash_path(path: str, *, trash_dir: Optional[str] = None) -> str:
    """Destination inside the Trash, timestamped if the name is taken."""
    trash_dir = trash_dir or os.path.expanduser("~/.Trash")
    base = os.path.basename(path.rstrip("/"))
    candidate = os.path.join(trash_dir, base)
    if not os.path.lexists(candidate):
        return candidate
    stamp = time.strftime("%Y-%m-%d %H.%M.%S")
    root, ext = os.path.splitext(base)
    return os.path.join(trash_dir, "{} {}{}".format(root, stamp, ext))


def measure(path: str) -> int:
    """Apparent bytes held by a path, for reporting what was reclaimed."""
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    if os.path.islink(path) or not os.path.isdir(path):
        return st.st_size
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path, followlinks=False):
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
    return total


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

    if not os.path.lexists(path):
        return done(FAILED, message="path does not exist")

    size = measure(path)

    if not confirm(path, risk, confirmation_for(risk)):
        return done(DECLINED, size)

    if dry_run:
        return done(DRY_RUN, size)

    # Re-check right before acting: the tree may have moved since the scan,
    # and acting on a stale path is how a tool deletes the wrong thing.
    if not os.path.lexists(path):
        return done(CHANGED, message="path vanished before deletion")

    try:
        if use_trash:
            destination = trash_path(path, trash_dir=trash_dir)
            parent = os.path.dirname(destination)
            if parent:
                os.makedirs(parent, exist_ok=True)
            shutil.move(path, destination)
            return done(TRASHED, size, destination)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        return done(PURGED, size)
    except OSError as exc:
        return done(FAILED, size, str(exc))
