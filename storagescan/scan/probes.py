"""Registry of known space consumers.

Adding a probe is a single dataclass literal — this is the extension point.
Risk is deliberately *not* declared here; it comes from safety.classify, so
deletion policy lives in exactly one place and cannot drift.

Patterns are home-relative globs. A probe that matches nothing costs nothing.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from ..model import Finding, ScanError
from ..safety import classify
from .walker import dir_size


@dataclass(frozen=True)
class Probe:
    category: str
    title: str
    patterns: Tuple[str, ...]
    detail: str = ""
    reclaim_hint: str = ""


PROBES: Tuple[Probe, ...] = (
    # --- Developer -------------------------------------------------------
    Probe("xcode.derived_data", "Xcode DerivedData",
          ("Library/Developer/Xcode/DerivedData",),
          "Build intermediates. Xcode regenerates them on the next build."),
    Probe("xcode.archives", "Xcode Archives",
          ("Library/Developer/Xcode/Archives",),
          "Shipped app archives. Keep any you may need to re-symbolicate a "
          "crash report against."),
    Probe("xcode.device_support", "iOS DeviceSupport",
          ("Library/Developer/Xcode/iOS DeviceSupport",
           "Library/Developer/Xcode/watchOS DeviceSupport",
           "Library/Developer/Xcode/tvOS DeviceSupport"),
          "Debug symbols for every iOS version you ever attached a device "
          "from. Re-downloaded on demand."),
    Probe("xcode.simulator_caches", "Simulator devices and caches",
          ("Library/Developer/CoreSimulator/Caches",
           "Library/Developer/CoreSimulator/Devices"),
          "Simulator runtimes and device images.",
          "xcrun simctl delete unavailable"),
    Probe("node_modules", "node_modules",
          ("*/node_modules", "*/*/node_modules", "*/*/*/node_modules",
           "*/*/*/*/node_modules"),
          "Reinstallable with npm/pnpm/yarn install."),
    Probe("npm.cache", "npm cache", (".npm",),
          "", "npm cache clean --force"),
    Probe("pnpm.store", "pnpm store", ("Library/pnpm/store", ".pnpm-store"),
          "", "pnpm store prune"),
    Probe("yarn.cache", "Yarn cache", ("Library/Caches/Yarn",),
          "", "yarn cache clean"),
    Probe("pip.cache", "pip cache", ("Library/Caches/pip",),
          "", "pip3 cache purge"),
    Probe("cargo.cache", "Cargo registry", (".cargo/registry",),
          "Re-downloaded on the next build."),
    Probe("go.modcache", "Go module cache", ("go/pkg/mod",),
          "", "go clean -modcache"),
    Probe("homebrew.cache", "Homebrew downloads",
          ("Library/Caches/Homebrew",), "", "brew cleanup -s"),
    Probe("gradle.cache", "Gradle caches", (".gradle/caches",),
          "Re-downloaded on the next build."),
    Probe("android.sdk", "Android SDK", ("Library/Android/sdk",),
          "System images and build tools. Manage from Android Studio."),

    # --- Virtualization --------------------------------------------------
    Probe("docker.image", "Docker disk image",
          ("Library/Containers/com.docker.docker/Data/vms",
           "Library/Containers/com.docker.docker/Data/vpnkit",
           ".docker/desktop"),
          "The Docker VM disk. It does not shrink on its own after you "
          "delete images.",
          "docker system prune -a --volumes"),
    Probe("orbstack.data", "OrbStack data",
          ("Library/Containers/dev.orbstack.OrbStack/Data",
           ".orbstack"),
          "OrbStack VM and container storage."),
    Probe("vm.image", "Virtual machines",
          ("Parallels", "Virtual Machines.localized",
           "Library/Containers/com.utmapp.UTM/Data/Documents",
           "Library/Group Containers/*.com.vmware.fusion"),
          "Virtual machine disk images."),

    # --- Apple apps ------------------------------------------------------
    Probe("ios.backups", "iOS device backups",
          ("Library/Application Support/MobileSync/Backup",),
          "Full device backups. Check Finder before deleting — these are not "
          "the same as iCloud backups."),
    Probe("mail.downloads", "Mail attachments",
          ("Library/Containers/com.apple.mail/Data/Library/Mail Downloads",),
          "Downloaded attachments. Originals stay on the server for IMAP "
          "accounts."),
    # Deliberately a separate, unlisted category so it classifies as DANGER:
    # ~/Library/Mail is the mail store itself, not a cache.
    Probe("mail.store", "Mail store", ("Library/Mail",),
          "Your actual mailboxes. Shrink this from Mail's preferences, not "
          "by deleting files."),
    Probe("photos.library", "Photos library",
          ("Pictures/Photos Library.photoslibrary",),
          "Manage from Photos. Turn on Optimise Mac Storage to keep only "
          "thumbnails locally."),
    Probe("music.downloads", "Music and Podcasts downloads",
          ("Library/Group Containers/*.groups.com.apple.podcasts",
           "Music/Music/Media.localized/Apple Music"),
          "Re-downloadable from your subscription."),
    Probe("browser.cache", "Browser caches",
          ("Library/Caches/com.apple.Safari",
           "Library/Caches/Google/Chrome",
           "Library/Caches/Firefox",
           "Library/Caches/company.thebrowser.Browser",
           "Library/Caches/BraveSoftware"),
          "Regenerated as you browse."),
    Probe("app.cache", "Application caches",
          ("Library/Caches/*",),
          "Per-app caches, regenerated on demand."),

    # --- General ---------------------------------------------------------
    Probe("trash", "Trash", (".Trash",),
          "Already deleted, still occupying space."),
    Probe("downloads", "Downloads folder", ("Downloads",),
          "Usually re-downloadable. Worth a look before clearing."),
)

Sizer = Callable[[str], Tuple[int, int, int]]


def run_probes(
    home: str,
    *,
    scan_roots: Sequence[str],
    min_bytes: int = 10_000_000,
    errors: Optional[List[ScanError]] = None,
    sizer: Optional[Sizer] = None,
) -> Tuple[Finding, ...]:
    """Expand every probe pattern and size whatever exists.

    A path matched by two probes is attributed to the first one only, so
    totals never double-count. Probe order in PROBES is therefore
    significant: specific probes come before general ones (browser.cache
    before app.cache).
    """
    measure = sizer or (lambda path: dir_size(path, errors=errors))
    findings: List[Finding] = []
    claimed = set()

    for probe in PROBES:
        for pattern in probe.patterns:
            for path in sorted(glob.glob(os.path.join(home, pattern))):
                if path in claimed or os.path.islink(path):
                    continue
                claimed.add(path)
                size, apparent, _count = measure(path)
                bytes_ = max(size, apparent)
                if bytes_ < min_bytes:
                    continue
                findings.append(Finding(
                    category=probe.category,
                    title=probe.title,
                    path=path,
                    bytes_=bytes_,
                    risk=classify(path, probe.category,
                                  home=home, scan_roots=scan_roots),
                    detail=probe.detail,
                    reclaim_hint=probe.reclaim_hint,
                ))

    findings.sort(key=lambda f: f.bytes_, reverse=True)
    return tuple(findings)
