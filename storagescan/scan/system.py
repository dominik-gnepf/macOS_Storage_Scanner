"""Space outside the home directory.

A home-only scan leaves a large, alarming gap: on a 245 GB machine the volume
reported 179 GB used while the home tree accounted for about 103 GB. The
missing space is not mysterious once you look — measured on a real system:

    /Library         25.1 GB
    /Applications    17.5 GB
    /private/var      7.3 GB
    /opt              1.5 GB
    /usr/local        0.3 GB

None of this needs sudo to measure, and measuring it turned "76 GB
unaccounted" into 12 GB on the machine this was developed against.

A note on verifying these numbers by hand: use ``du -sk``, not ``du -sxk``.
macOS presents /Library and /Applications as firmlinks onto the Data volume,
so ``-x`` (stay on one filesystem) refuses to cross and reports 7.8 GB for a
/Library that genuinely holds 25.1 GB. Crossing is the correct behaviour here
and is what this scanner does.

Almost none of it should be deleted by a storage tool, which is why the risk
tiers here are deliberately conservative: /Library and /private/var are
system-managed and classify as DANGER, while individual applications are
REVIEW because uninstalling an app is a normal thing to do — through the
usual means, not by this tool removing files underneath a running system.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from ..model import Finding, Risk, ScanError
from .walker import dir_size

Sizer = Callable[[str], Tuple[int, int, int]]


@dataclass(frozen=True)
class SystemArea:
    path: str
    title: str
    category: str
    detail: str


AREAS: Tuple[SystemArea, ...] = (
    SystemArea("/Applications", "Applications", "system.applications",
               "Installed apps. Uninstall the ones you do not use from Finder "
               "or the app's own uninstaller."),
    SystemArea("/Library", "System-wide support files", "system.library",
               "Shared application support, caches, and logs installed for all "
               "users. Managed by macOS and by installers, not by hand."),
    SystemArea("/private/var", "System data", "system.var",
               "Logs, databases, and system caches. macOS maintains this; "
               "deleting from it can break things."),
    SystemArea("/opt", "Package manager files", "system.opt",
               "Homebrew on Apple silicon installs here."),
    SystemArea("/usr/local", "Local software", "system.usr_local",
               "Homebrew on Intel, and anything installed with make install."),
    SystemArea("/Users/Shared", "Shared user files", "system.shared",
               "Files shared between accounts on this Mac."),
)

_RISK = {
    "system.applications": Risk.REVIEW,
    "system.opt": Risk.REVIEW,
    "system.usr_local": Risk.REVIEW,
    "system.shared": Risk.REVIEW,
    "system.library": Risk.DANGER,
    "system.var": Risk.DANGER,
}


def scan_areas(
    *,
    min_bytes: int = 100_000_000,
    errors: Optional[List[ScanError]] = None,
    sizer: Optional[Sizer] = None,
    areas: Sequence[SystemArea] = AREAS,
) -> Tuple[Finding, ...]:
    """Measure the system areas that exist and are worth mentioning.

    Risk is assigned from the area table rather than through safety.classify,
    because these paths sit outside every scan root and would all come back
    BLOCKED — true, but useless for explaining where space went. Deletion
    still goes through safety.classify, which refuses them; these findings are
    informational by construction.
    """
    measure = sizer or (lambda path: dir_size(path, errors=errors))
    present = [a for a in areas
               if os.path.isdir(a.path) and not os.path.islink(a.path)]
    if not present:
        return ()

    # These are large, independent trees (/Library and /private/var alone hold
    # hundreds of thousands of files). Measuring them serially added about 40
    # seconds to a 30-second scan; they overlap well because the work is
    # waiting on filesystem metadata, not computing.
    with ThreadPoolExecutor(max_workers=min(6, len(present))) as pool:
        sizes = list(pool.map(lambda a: measure(a.path), present))

    findings: List[Finding] = []
    for area, (size, _apparent, _count) in zip(present, sizes):
        # On-disk bytes only — see the note in probes.run_probes.
        bytes_ = size
        if bytes_ < min_bytes:
            continue
        findings.append(Finding(
            category=area.category,
            title=area.title,
            path=area.path,
            bytes_=bytes_,
            risk=_RISK.get(area.category, Risk.DANGER),
            detail=area.detail,
        ))

    findings.sort(key=lambda f: f.bytes_, reverse=True)
    return tuple(findings)


def largest_applications(
    *,
    top: int = 10,
    min_bytes: int = 500_000_000,
    applications: str = "/Applications",
    errors: Optional[List[ScanError]] = None,
    sizer: Optional[Sizer] = None,
) -> Tuple[Finding, ...]:
    """The biggest installed apps, which are the actionable part of /Applications.

    An app bundle is a directory, so it is measured like one. Deleting an app
    is a legitimate way to reclaim space, but it belongs to the user and their
    uninstaller — these are reported at REVIEW so they never auto-reclaim.
    """
    measure = sizer or (lambda path: dir_size(path, errors=errors))
    if not os.path.isdir(applications):
        return ()

    try:
        entries = list(os.scandir(applications))
    except OSError as exc:
        if errors is not None:
            errors.append(ScanError(path=applications, error=type(exc).__name__))
        return ()

    findings: List[Finding] = []
    for entry in entries:
        if entry.is_symlink() or not entry.name.endswith(".app"):
            continue
        size, _apparent, _count = measure(entry.path)
        bytes_ = size
        if bytes_ < min_bytes:
            continue
        findings.append(Finding(
            category="system.app",
            title=entry.name[:-4],
            path=entry.path,
            bytes_=bytes_,
            risk=Risk.REVIEW,
            detail="Installed application. Remove it the usual way if you no "
                   "longer use it.",
        ))

    findings.sort(key=lambda f: f.bytes_, reverse=True)
    return tuple(findings[:top])
