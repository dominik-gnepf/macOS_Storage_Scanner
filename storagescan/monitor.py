"""Scheduled monitoring via launchd.

The problem this solves is the original one: macOS tells you the disk is full
at the worst possible moment, with no warning and no explanation. A weekly
background scan can notice the trend first and say what is eating the space
while there is still room to act.

Nothing here runs automatically. Installing the agent is an explicit command,
uninstalling removes every trace, and the agent itself only ever *reads* —
the scheduled run posts a notification, it never deletes anything.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
from typing import List, Optional, Sequence, Tuple

from .humanize import human_bytes
from .model import Risk, ScanResult
from .scan.apfs import primary_volume

LABEL = "io.github.storagescan.monitor"

# Weekly. Frequent enough to catch a trend, rare enough that a minute of disk
# activity is never noticeable.
DEFAULT_INTERVAL_SECONDS = 7 * 24 * 60 * 60

# Warn while there is still room to do something about it. Below roughly this
# much free space macOS starts refusing updates and large downloads.
DEFAULT_ALERT_BYTES = 20_000_000_000


def agent_path(home: str) -> str:
    return os.path.join(home, "Library", "LaunchAgents", LABEL + ".plist")


def log_path(home: str) -> str:
    return os.path.join(home, ".local", "state", "storagescan", "monitor.log")


def plist_contents(
    *,
    launcher: str,
    home: str,
    interval: int = DEFAULT_INTERVAL_SECONDS,
    label: str = LABEL,
) -> dict:
    """The launchd job definition.

    StartInterval rather than StartCalendarInterval: a calendar entry that
    fires at a fixed hour is simply missed if the Mac is asleep then, whereas
    launchd runs an interval job as soon as the machine wakes. For a weekly
    check "within a day or so of schedule" is the right behaviour.

    RunAtLoad is deliberately false. Installing a monitor should not kick off
    a minute of disk activity right then.
    """
    return {
        "Label": label,
        "ProgramArguments": [launcher, "--check"],
        "StartInterval": int(interval),
        "RunAtLoad": False,
        # Nice values keep the scan out of the way of anything interactive.
        "Nice": 10,
        "LowPriorityIO": True,
        "ProcessType": "Background",
        "StandardOutPath": log_path(home),
        "StandardErrorPath": log_path(home),
        "EnvironmentVariables": {"STORAGESCAN_SCHEDULED": "1"},
    }


def write_plist(path: str, contents: dict) -> str:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as handle:
        plistlib.dump(contents, handle)
    return path


def _launchctl(args: Sequence[str]) -> Tuple[int, str]:
    try:
        completed = subprocess.run(
            ["launchctl"] + list(args), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)
    return completed.returncode, completed.stdout.decode("utf-8", "replace")


def install(*, launcher: str, home: str, interval: int = DEFAULT_INTERVAL_SECONDS,
            runner=None) -> Tuple[bool, str]:
    """Write the plist and load it. Returns (ok, message)."""
    run = runner or _launchctl
    path = agent_path(home)
    write_plist(path, plist_contents(launcher=launcher, home=home,
                                     interval=interval))
    os.makedirs(os.path.dirname(log_path(home)), exist_ok=True)

    domain = "gui/{}".format(os.getuid())
    # Unload any previous copy first, or bootstrap fails with "already
    # bootstrapped" and the user is left running the old definition.
    run(["bootout", "{}/{}".format(domain, LABEL)])
    code, output = run(["bootstrap", domain, path])
    if code != 0:
        return False, "launchctl bootstrap failed: {}".format(output.strip())
    return True, path


def uninstall(*, home: str, runner=None) -> Tuple[bool, str]:
    """Unload the agent and delete its plist."""
    run = runner or _launchctl
    path = agent_path(home)
    run(["bootout", "gui/{}/{}".format(os.getuid(), LABEL)])
    removed = False
    try:
        os.remove(path)
        removed = True
    except OSError:
        pass
    return True, ("removed {}".format(path) if removed
                  else "no agent was installed")


def is_installed(home: str) -> bool:
    return os.path.exists(agent_path(home))


def status(home: str, runner=None) -> str:
    run = runner or _launchctl
    if not is_installed(home):
        return "not installed"
    code, _output = run(["print", "gui/{}/{}".format(os.getuid(), LABEL)])
    return "installed and loaded" if code == 0 else "installed but not loaded"


def should_alert(result: ScanResult, threshold: int = DEFAULT_ALERT_BYTES
                 ) -> bool:
    volume = primary_volume(result.volumes)
    if volume is None:
        return False
    return volume.free < threshold


def alert_message(result: ScanResult) -> str:
    """One line, because that is all a macOS notification shows."""
    volume = primary_volume(result.volumes)
    free = human_bytes(volume.free) if volume is not None else "unknown"
    safe = result.reclaimable(Risk.SAFE)
    if safe > 0:
        return "{} free. {} can be reclaimed from caches.".format(
            free, human_bytes(safe))
    return "{} free.".format(free)


def notify(message: str, *, title: str = "storagescan", runner=None) -> bool:
    """Post a macOS notification.

    osascript is used rather than a dependency like terminal-notifier because
    it ships with the OS, which is the whole premise of this tool. The
    notification is best-effort: a machine with notifications disabled should
    not turn a storage warning into a crash.
    """
    script = 'display notification {} with title {}'.format(
        _applescript_string(message), _applescript_string(title))
    if runner is not None:
        return runner(["osascript", "-e", script]) == 0
    try:
        completed = subprocess.run(
            ["osascript", "-e", script], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _applescript_string(text: str) -> str:
    """Quote a string for AppleScript.

    AppleScript has no escape for a literal backslash inside a quoted string
    beyond doubling it, and an unescaped quote would end the string early and
    turn the rest into code. Both are handled here rather than trusting scan
    output — which contains file names, and file names contain anything.
    """
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return '"{}"'.format(escaped)
