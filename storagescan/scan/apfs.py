"""APFS facts that a directory walk cannot see.

This module exists because of a specific, common confusion: you add up your
folder sizes, get far less than the disk claims is used, and conclude the
scanner is broken. It usually isn't. The difference is APFS snapshots, other
volumes in the same container, and space macOS considers reclaimable.

What the tools actually provide, verified on macOS 26:

- ``df -k -P`` gives per-mount totals. Note that every volume in an APFS
  container reports the *container's* free space, so the numbers do not sum.
- ``tmutil listlocalsnapshots /`` lists snapshots but exposes no per-snapshot
  size, and on a typical machine most entries are ``com.apple.os.update-*``
  (created by the OS updater) rather than ``com.apple.TimeMachine.*``.
- ``diskutil info -plist <mount>`` gives ``APFSContainerFree`` and
  ``CapacityInUse``.
- ``diskutil apfs list -plist`` does **not** report purgeable space on current
  macOS. There is no supported command-line source for it, so storagescan does
  not invent one: it reports unaccounted space instead, which is measurable.

Every external command is parsed defensively. A missing or unparseable tool
degrades its own section and nothing else.
"""

from __future__ import annotations

import plistlib
import subprocess
from typing import Callable, List, Optional, Sequence, Tuple

from ..model import Finding, Risk, ScanError, VolumeInfo

Runner = Callable[[Sequence[str]], Optional[bytes]]

# Snapshots created by the OS updater. macOS manages these itself and removes
# them when it is done; deleting them by hand can break a pending update.
_OS_UPDATE_PREFIX = "com.apple.os.update-"
_TIME_MACHINE_PREFIX = "com.apple.TimeMachine."

# Volumes that are macOS internals, not places a user stores anything.
_SYSTEM_MOUNTS = frozenset({
    "/dev", "/System/Volumes/VM", "/System/Volumes/Preboot",
    "/System/Volumes/Update", "/System/Volumes/xarts",
    "/System/Volumes/iSCPreboot", "/System/Volumes/Hardware",
    "/System/Volumes/Recovery",
})


def _default_run(argv: Sequence[str]) -> Optional[bytes]:
    try:
        completed = subprocess.run(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout


def parse_df(text: str) -> Tuple[VolumeInfo, ...]:
    """Parse ``df -k -P`` output into byte-denominated VolumeInfo records."""
    volumes: List[VolumeInfo] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            total = int(parts[1]) * 1024
            used = int(parts[2]) * 1024
            free = int(parts[3]) * 1024
        except ValueError:
            continue
        volumes.append(VolumeInfo(mount=parts[-1], total=total, used=used, free=free))
    return tuple(volumes)


def primary_volume(volumes: Sequence[VolumeInfo]) -> Optional[VolumeInfo]:
    """The volume a user actually fills up: the Data volume, else ``/``."""
    for volume in volumes:
        if volume.mount == "/System/Volumes/Data":
            return volume
    for volume in volumes:
        if volume.mount == "/":
            return volume
    return volumes[0] if volumes else None


def interesting_volumes(volumes: Sequence[VolumeInfo]) -> Tuple[VolumeInfo, ...]:
    """Drop macOS internal mounts that only add noise."""
    return tuple(
        v for v in volumes
        if v.mount not in _SYSTEM_MOUNTS and not v.mount.startswith("/System/Volumes/Preboot")
    )


def parse_snapshots(text: str) -> Tuple[str, ...]:
    """Every snapshot name, not just Time Machine ones.

    The header line ("Snapshots for volume group containing disk /:") is
    skipped by requiring the ``com.apple.`` prefix.
    """
    return tuple(
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("com.apple.")
    )


def parse_container_capacity(payload: bytes) -> Optional[Tuple[int, int]]:
    """(container free, capacity in use) from ``diskutil info -plist``."""
    try:
        data = plistlib.loads(payload)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    free = data.get("APFSContainerFree")
    used = data.get("CapacityInUse")
    if not isinstance(free, int) or not isinstance(used, int):
        return None
    return free, used


def snapshot_findings(names: Sequence[str]) -> Tuple[Finding, ...]:
    """Report snapshots; never delete them.

    ``tmutil deletelocalsnapshots`` is not reversible through the Trash, so
    storagescan shows the command instead of running it. tmutil exposes no
    per-snapshot size, so ``bytes_`` is 0 — these findings explain *where*
    unaccounted space went, they do not claim an amount.
    """
    findings: List[Finding] = []
    for name in names:
        if name.startswith(_TIME_MACHINE_PREFIX):
            findings.append(Finding(
                category="apfs.snapshot",
                title="Local Time Machine snapshot",
                path=None,
                bytes_=0,
                risk=Risk.REVIEW,
                detail=name,
                reclaim_hint="tmutil deletelocalsnapshots {}".format(name),
            ))
        elif name.startswith(_OS_UPDATE_PREFIX):
            findings.append(Finding(
                category="apfs.os_snapshot",
                title="macOS update snapshot",
                path=None,
                bytes_=0,
                risk=Risk.BLOCKED,
                detail=(
                    "{} — created by the macOS updater. It is removed "
                    "automatically; deleting it by hand can break a pending "
                    "update.".format(name)
                ),
            ))
    return tuple(findings)


def collect(*, run: Optional[Runner] = None):
    """Gather (volumes, findings, errors) from the system tools."""
    runner = run or _default_run
    errors: List[ScanError] = []

    volumes: Tuple[VolumeInfo, ...] = ()
    out = runner(["df", "-k", "-P"])
    if out is None:
        errors.append(ScanError(path="df", error="unavailable"))
    else:
        volumes = interesting_volumes(parse_df(out.decode("utf-8", "replace")))

    findings: Tuple[Finding, ...] = ()
    out = runner(["tmutil", "listlocalsnapshots", "/"])
    if out is None:
        errors.append(ScanError(path="tmutil", error="unavailable"))
    else:
        findings = snapshot_findings(parse_snapshots(out.decode("utf-8", "replace")))

    return volumes, findings, tuple(errors)
