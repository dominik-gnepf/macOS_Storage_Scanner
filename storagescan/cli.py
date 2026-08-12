"""Argument parsing and orchestration."""

from __future__ import annotations

import argparse
import os
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
import threading
import time
from typing import List, Optional, Tuple

from . import access
from . import actions
from . import config as config_module
from . import monitor
from . import serialize
from . import __version__
from .humanize import human_bytes, redact
from .model import Node, Risk, ScanError, ScanResult
from .safety import batch_allowed
from .scan import aging, apfs, cloud, dupes, probes, system, walker
from .scan.index import SizeIndex
from .ui import report as report_module
from .ui import menu as menu_ui
from .ui import term

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="macosscanner",
        description="Find where your macOS disk space went.",
        epilog="Run with no options for a menu. Nothing is ever deleted "
               "without you confirming it, and deletions go to the Trash.",
    )
    parser.add_argument("--deep", action="store_true",
                        help="also find duplicate and large untouched files "
                             "(slower)")
    parser.add_argument("--menu", action="store_true",
                        help="show the menu (the default when run with no "
                             "options)")
    parser.add_argument("--no-menu", action="store_true",
                        help="skip the menu and scan straight away")
    parser.add_argument("--summary", action="store_true",
                        help="print a text summary instead of opening the browser")
    parser.add_argument("--report", action="store_true",
                        help="write the HTML report and open it")
    parser.add_argument("--json", action="store_true",
                        help="write machine-readable JSON to stdout")
    parser.add_argument("--cached", action="store_true",
                        help="reuse the previous scan instead of rescanning")
    parser.add_argument("--diff", action="store_true",
                        help="show what changed since the previous scan")
    parser.add_argument("--path", action="append", default=None, metavar="DIR",
                        help="scan this directory instead of your home folder "
                             "(repeatable)")
    parser.add_argument("--no-system", action="store_true",
                        help="skip /Applications, /Library and other areas "
                             "outside your home folder")
    parser.add_argument("--include-cloud", action="store_true",
                        help="scan OneDrive/iCloud/Dropbox folders too; this is "
                             "slow and may cause your sync client to download "
                             "files")
    parser.add_argument("--workers", type=int, default=8, metavar="N",
                        help="parallel scan threads (default: 8)")
    parser.add_argument("--reclaim", action="store_true",
                        help="review every SAFE cache and move them all to the "
                             "Trash after one confirmation")
    parser.add_argument("--purge", action="store_true",
                        help="permanently delete instead of moving to Trash "
                             "(requires typing PURGE)")
    parser.add_argument("--dry-run", action="store_true",
                        help="never modify anything")
    parser.add_argument("--no-progress", action="store_true",
                        help="do not draw the scanning progress line")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-open", action="store_true",
                        help="write the report but do not open it")
    agent = parser.add_argument_group(
        "scheduled monitoring",
        "Run a weekly background check and get a notification while there is "
        "still room to act. The scheduled run only reads and notifies; it "
        "never deletes.")
    agent.add_argument("--install-agent", action="store_true",
                       help="install the weekly launchd agent")
    agent.add_argument("--uninstall-agent", action="store_true",
                       help="remove the launchd agent")
    agent.add_argument("--agent-status", action="store_true",
                       help="report whether the agent is installed")
    agent.add_argument("--check", action="store_true",
                       help="the scheduled check: scan and notify only if free "
                            "space is low (this is what the agent runs)")
    agent.add_argument("--alert-below", type=str, default=None, metavar="GB",
                       help="free-space threshold for --check (default: 20)")

    parser.add_argument("--config", default=None, metavar="FILE")
    parser.add_argument("--cache-file", default=None, metavar="FILE")
    parser.add_argument("--report-file", default=None, metavar="FILE")
    parser.add_argument("--version", action="version",
                        version="%(prog)s {}".format(__version__))
    return parser


PROTECTED_DIRS = ("Library/Mail", "Library/Messages", "Downloads",
                  "Documents", "Desktop")


def check_fda(home: str, roots: Tuple[str, ...] = ()) -> bool:
    """True when the protected locations *in scope* are readable.

    macOS hides these directories from processes without Full Disk Access, and
    it does so by returning EPERM on readdir rather than by hiding their
    existence — so probing is the only reliable signal.

    Only paths inside ``roots`` are probed. Warning that a scan is incomplete
    because ~/Downloads is unreadable makes no sense when the user asked for
    ~/Developer. An empty ``roots`` probes everything, for callers with no
    scope of their own.
    """
    for relative in PROTECTED_DIRS:
        path = os.path.join(home, relative)
        if not os.path.exists(path):
            continue
        if roots and not any(
                path == r.rstrip("/") or path.startswith(r.rstrip("/") + "/")
                for r in roots):
            continue
        try:
            os.listdir(path)
        except OSError:
            return False
    return True


def _scan_roots(cfg, args, home: str) -> Tuple[str, ...]:
    if args.path:
        return tuple(os.path.abspath(os.path.expanduser(p)) for p in args.path)
    return cfg.expanded_scan_paths() or (home,)


def _covers_home(roots: Tuple[str, ...], home: str) -> bool:
    """Is the home directory actually part of this scan?

    Probes and cloud detection are defined relative to $HOME. When the user
    narrows the scan with --path to somewhere else, running them anyway would
    both report irrelevant findings and re-walk the whole home directory,
    which is exactly the slow thing --path is meant to avoid.
    """
    for root in roots:
        root = root.rstrip("/")
        if home == root or home.startswith(root + "/"):
            return True
    return False


def _scan_system(errors: List[ScanError]) -> List:
    """Measure areas outside the home directory.

    These are absolute paths belonging to this machine, so callers must only
    reach here when the scan really is of this machine's home. A caller
    passing some other home — a test with a temp directory, most obviously —
    would otherwise walk the real /Library and /private/var. Same lesson as
    deriving the Trash from `home` rather than from $HOME.
    """
    findings: List = []
    findings.extend(system.scan_areas(errors=errors))
    findings.extend(system.largest_applications(errors=errors))
    return findings


def make_progress(stream, home: str, enabled: bool):
    """A progress reporter that redraws one line, or None when unwanted.

    Written to stderr so it never contaminates --json or a piped summary, and
    suppressed entirely when stderr is not a terminal — a progress bar in a
    log file is just noise.
    """
    if not enabled or not hasattr(stream, "isatty") or not stream.isatty():
        return None

    lock = threading.Lock()
    last = [0.0]

    def report(done: int, total: int, path: str) -> None:
        now = time.monotonic()
        with lock:
            if total and done == total:
                pass
            elif done and now - last[0] < 0.08:
                return
            last[0] = now
            name = redact(path, home)
            if len(name) > 40:
                name = "~" + name[-39:]
            if total:
                text = "scanning {}/{}  {}".format(done, total, name)
            else:
                text = "scanning {}  {}".format(done, name)
            stream.write("\r\033[2K  {}".format(text))
            stream.flush()
            if total and done == total:
                stream.write("\r\033[2K")
                stream.flush()

    return report


def make_phase(stream):
    """Print a one-line status for the current scan phase, or None."""
    if not hasattr(stream, "isatty") or not stream.isatty():
        return None

    def say(message: str) -> None:
        stream.write("\r\033[2K  {}\n".format(message))
        stream.flush()

    return say


def run_scan(cfg, args, *, home: str, now: float, progress=None,
             on_phase=None) -> ScanResult:
    started = time.time()
    if on_phase is not None:
        on_phase("Scanning folders…")
    errors: List[ScanError] = []
    roots = _scan_roots(cfg, args, home)
    scanning_home = _covers_home(roots, home)

    excludes = list(cfg.expanded_excludes())
    skipped_cloud: Tuple[str, ...] = ()
    if not args.include_cloud and scanning_home:
        skipped_cloud = cloud.cloud_roots(home)
        excludes.extend(skipped_cloud)

    # Deep scan is analysis (duplicates, stale files), not an unlimited
    # tree. A full-home walk with no depth limit tries to materialize every
    # directory — 20k+ truncated folders on a typical Mac, including File
    # Provider trees that answer readdir over the network. Press `e` in the
    # browser to expand one folder instead.
    max_depth = cfg.fast_depth

    # The system areas are entirely separate trees from the home directory, so
    # measuring them while the home walk runs costs no extra wall time. Done
    # serially it added ~35s to a ~30s scan; overlapped, the scan takes about
    # as long as its slowest half.
    system_future = None
    system_pool = None
    if (scanning_home and not args.no_system
            and home == os.path.expanduser("~")):
        system_pool = ThreadPoolExecutor(max_workers=1)
        system_future = system_pool.submit(_scan_system, errors)

    trees = [
        walker.walk_parallel(root, max_depth=max_depth, exclude=tuple(excludes),
                             errors=errors, workers=args.workers,
                             on_progress=progress)
        for root in roots
    ]

    if len(trees) == 1:
        root_node: Optional[Node] = trees[0]
    elif trees:
        root_node = Node(
            path=home,
            size=sum(t.size for t in trees),
            apparent=sum(t.apparent for t in trees),
            count=sum(t.count for t in trees),
            mtime=now,
            children=tuple(trees),
            unreadable=sum(t.unreadable for t in trees),
        )
    else:
        root_node = None

    # Probes read their sizes out of the walk instead of re-walking. Without
    # this the same trees get traversed a dozen more times.
    index = SizeIndex(lambda path: walker.dir_size(path, errors=errors))
    index.add_tree(root_node)

    findings: List = []
    if scanning_home:
        findings.extend(probes.run_probes(
            home, scan_roots=roots, errors=errors, sizer=index.measure))
        # Cloud folders stay out of the tree but not out of the accounting:
        # the downloaded files in them occupy real disk.
        findings.extend(cloud.cloud_findings(home, skipped_cloud))

    if system_future is not None:
        findings.extend(system_future.result())
        system_pool.shutdown()

    volumes, snapshot_findings, apfs_errors = apfs.collect()
    findings.extend(snapshot_findings)
    errors.extend(apfs_errors)

    if args.deep:
        skipped = tuple(excludes)
        if on_phase is not None:
            on_phase("Looking for duplicate files…")
        for root in roots:
            findings.extend(dupes.find_duplicates(
                root, home=home, scan_roots=roots, errors=errors,
                exclude=skipped, on_progress=progress))
        if on_phase is not None:
            on_phase("Looking for large untouched files…")
        for root in roots:
            findings.extend(aging.find_stale(
                root, home=home, scan_roots=roots,
                min_bytes=cfg.large_file_bytes, stale_days=cfg.stale_days,
                now=now, errors=errors, exclude=skipped, on_progress=progress))

    return ScanResult(
        root=root_node,
        findings=tuple(findings),
        volumes=volumes,
        errors=tuple(errors),
        mode="deep" if args.deep else "fast",
        duration=time.time() - started,
        fda_ok=check_fda(home, roots),
        started_at=started,
        roots=roots,
    )


def _open_file(path: str) -> None:
    try:
        subprocess.run(["open", path], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def reclaimable_batch(result: ScanResult, home: str) -> Tuple:
    """The findings a batch reclaim is allowed to touch.

    Deliberately narrow: SAFE tier only, must have a real path, and must still
    exist. Anything needing judgement stays in the interactive browser where
    it gets its own prompt.
    """
    return tuple(
        f for f in result.findings_by_size()
        if f.risk is Risk.SAFE and f.path and f.bytes_ > 0
        and os.path.lexists(f.path)
        and batch_allowed(f.path, home)
    )


def run_reclaim(result: ScanResult, cfg, args, *, home: str,
                stdin=None, stdout=None) -> int:
    """Review every SAFE finding, then move them all to the Trash on one yes."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout

    batch = reclaimable_batch(result, home)
    if not batch:
        print("Nothing in the SAFE tier to reclaim.", file=stdout)
        return EXIT_OK

    total = sum(f.bytes_ for f in batch)
    print("These {} items are caches and build products that regenerate "
          "themselves:\n".format(len(batch)), file=stdout)
    for finding in batch:
        print("  {:>10}  {}".format(human_bytes(finding.bytes_),
                                    redact(finding.path, home)), file=stdout)
    print("\n  {:>10}  total\n".format(human_bytes(total)), file=stdout)

    if args.dry_run:
        print("--dry-run: nothing was touched.", file=stdout)
        return EXIT_OK

    permanent = bool(getattr(args, "purge", False) or not cfg.trash_by_default)
    destination = "PERMANENT deletion" if permanent else "the Trash"
    print("Move all {} to {}? [y/N] ".format(len(batch), destination),
          end="", file=stdout, flush=True)
    answer = stdin.readline().strip().lower()
    if not answer.startswith("y"):
        print("Nothing was deleted.", file=stdout)
        return EXIT_OK

    if permanent:
        print("This permanently deletes the files. They will NOT go to the "
              "Trash.\nType PURGE to confirm: ",
              end="", file=stdout, flush=True)
        if stdin.readline().strip() != "PURGE":
            print("Nothing was deleted.", file=stdout)
            return EXIT_OK

    # One prompt covered the batch, so each item auto-confirms from here.
    # safety.classify still runs per path inside actions.perform, and anything
    # that is not SAFE is refused regardless of what was answered above.
    def confirmed(_path, _risk, _mode):
        return True

    reclaimed = 0
    failures = []
    for finding in batch:
        outcome = actions.perform(
            finding.path, home=home, scan_roots=cfg.expanded_scan_paths(),
            category=finding.category, confirm=confirmed,
            use_trash=not permanent, require_safe=True)
        if outcome.status in (actions.TRASHED, actions.PURGED):
            reclaimed += outcome.bytes_
        else:
            failures.append((finding.path, outcome.status, outcome.message))

    print("\nReclaimed {}.".format(human_bytes(reclaimed)), file=stdout)
    if failures:
        print("{} item(s) could not be removed:".format(len(failures)),
              file=stdout)
        for path, status, message in failures:
            print("  {}  {} {}".format(redact(path, home), status, message),
                  file=stdout)
    return EXIT_OK


def _print_diff(previous: ScanResult, current: ScanResult, home: str) -> None:
    changes = serialize.diff(previous, current)
    if not changes:
        print("Nothing changed since the previous scan.\n")
        return
    print("Changes since the previous scan:")
    for path, delta in changes[:20]:
        print("  {}{:>10}  {}".format(
            "+" if delta > 0 else "-", human_bytes(abs(delta)),
            redact(path, home)))
    print("")


# Flags that express a specific intention. If any is present the user has
# already said what they want, so putting a menu in front of them would be
# an obstacle rather than a front door.
_DIRECT_FLAGS = (
    "deep", "summary", "report", "json", "cached", "diff", "reclaim",
    "check", "install_agent", "uninstall_agent", "agent_status", "dry_run",
)


def wants_menu(args, *, stdin=None, stdout=None) -> bool:
    if args.no_menu:
        return False
    if args.menu:
        return True
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    if not stdout.isatty() or not stdin.isatty():
        return False
    if args.path:
        return False
    return not any(getattr(args, name, False) for name in _DIRECT_FLAGS)


def launcher_path() -> str:
    """Absolute path to the macosscanner launcher for this checkout.

    launchd has no working directory and no PATH to speak of, so the agent
    must record an absolute path. Symlinks are resolved so the plist points
    at the real file; if you move the checkout, run --install-agent again.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("macosscanner", "storagescan"):
        candidate = os.path.join(here, "bin", name)
        if os.path.exists(candidate):
            return os.path.realpath(candidate)
    return os.path.join(here, "bin", "macosscanner")


def run_agent_command(args, *, home: str, stdout=None) -> Optional[int]:
    """Handle the agent subcommands. Returns None if none was requested."""
    stdout = stdout or sys.stdout

    if args.agent_status:
        print("storagescan monitor: {}".format(monitor.status(home)),
              file=stdout)
        if monitor.is_installed(home):
            print("  agent: {}".format(monitor.agent_path(home)), file=stdout)
            print("  log:   {}".format(monitor.log_path(home)), file=stdout)
        return EXIT_OK

    if args.uninstall_agent:
        _ok, message = monitor.uninstall(home=home)
        print("storagescan monitor: {}".format(message), file=stdout)
        return EXIT_OK

    if args.install_agent:
        launcher = launcher_path()
        if not os.access(launcher, os.X_OK):
            print("storagescan: launcher not executable at {}".format(launcher),
                  file=sys.stderr)
            return EXIT_ERROR
        ok, message = monitor.install(launcher=launcher, home=home)
        if not ok:
            print("storagescan: {}".format(message), file=sys.stderr)
            return EXIT_ERROR
        print("Installed weekly check: {}\n"
              "It scans in the background and notifies you only when free "
              "space drops below the threshold.\n"
              "If you move this checkout, run --install-agent again.\n"
              "Remove it any time with: macosscanner --uninstall-agent"
              .format(message), file=stdout)
        return EXIT_OK

    return None


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    home = os.path.expanduser("~")

    # The launchd job sets this. A scheduled run is read-only even if the
    # plist is later edited to pass --reclaim.
    if os.environ.get("STORAGESCAN_SCHEDULED") == "1":
        if args.reclaim or args.purge:
            print("storagescan: scheduled runs are read-only", file=sys.stderr)
            return EXIT_ERROR
        args.check = True
        args.no_menu = True

    agent_result = run_agent_command(args, home=home)
    if agent_result is not None:
        return agent_result

    try:
        cfg = config_module.load(args.config)
    except config_module.ConfigError as exc:
        print("storagescan: {}".format(exc), file=sys.stderr)
        return EXIT_ERROR

    if args.path:
        cfg = config_module.Config(
            scan_paths=tuple(args.path), exclude=cfg.exclude,
            fast_depth=cfg.fast_depth, large_file_bytes=cfg.large_file_bytes,
            stale_days=cfg.stale_days, trash_by_default=cfg.trash_by_default)

    # Before any scanning: the menu is the front door, and it offers "scan"
    # as one of its choices. Reaching it only after a 60-second scan would
    # defeat the point.
    if wants_menu(args):
        return run_menu(cfg, args, home=home)

    previous = serialize.load_cached(args.cache_file)

    if args.cached:
        if previous is None:
            print("storagescan: no cached scan found; run without --cached first",
                  file=sys.stderr)
            return EXIT_ERROR
        result = previous
    else:
        progress = make_progress(sys.stderr, home,
                                 enabled=not args.no_progress and not args.json)
        phase = make_phase(sys.stderr) if not args.no_progress and not args.json else None
        if progress is None and phase is None and not args.json:
            print("Scanning... (first run on a full disk can take a minute)",
                  file=sys.stderr)
        try:
            result = run_scan(cfg, args, home=home, now=time.time(),
                              progress=progress, on_phase=phase)
        except OSError as exc:
            print("storagescan: scan failed: {}".format(exc), file=sys.stderr)
            return EXIT_ERROR
        serialize.save(result, args.cache_file)

    if args.json:
        print(serialize.dumps(result))
        return EXIT_OK

    if args.check:
        threshold = monitor.DEFAULT_ALERT_BYTES
        if args.alert_below:
            try:
                threshold = int(float(args.alert_below) * 1_000_000_000)
            except ValueError:
                print("storagescan: --alert-below wants a number of GB",
                      file=sys.stderr)
                return EXIT_USAGE
        if monitor.should_alert(result, threshold):
            message = monitor.alert_message(result)
            monitor.notify(message)
            print("low space: {}".format(message))
        else:
            volume = apfs.primary_volume(result.volumes)
            print("ok: {} free".format(
                human_bytes(volume.free) if volume else "unknown"))
        return EXIT_OK

    if args.diff and previous is not None and not args.cached:
        _print_diff(previous, result, home)

    if args.reclaim:
        return run_reclaim(result, cfg, args, home=home)

    if args.report:
        path = report_module.write(result, home=home, generated_at=time.time(),
                                   path=args.report_file)
        print("Report written to {}".format(redact(path, home)))
        if not args.no_open:
            _open_file(path)
        return EXIT_OK

    if args.summary or not sys.stdout.isatty():
        print(term.render(result, home=home, color=not args.no_color))
        return EXIT_OK

    from .ui import tui
    updated = tui.run(result, home=home, config=cfg)
    if updated is not None:
        serialize.save(updated, args.cache_file)
    return EXIT_OK


def _menu_scan(cfg, args, home: str, deep: bool):
    """Run a scan for a menu action, reusing the normal code path."""
    scan_args = build_parser().parse_args([])
    scan_args.deep = deep
    scan_args.workers = args.workers
    scan_args.include_cloud = args.include_cloud
    scan_args.no_system = args.no_system
    scan_args.path = args.path
    progress = make_progress(sys.stderr, home, enabled=not args.no_progress)
    phase = make_phase(sys.stderr) if not args.no_progress else None
    result = run_scan(cfg, scan_args, home=home, now=time.time(),
                      progress=progress, on_phase=phase)
    serialize.save(result, args.cache_file)
    return result


def run_menu(cfg, args, *, home: str, stdin=None, stdout=None) -> int:
    """The interactive front door."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    result = serialize.load_cached(args.cache_file)
    status = ""

    while True:
        print(menu_ui.render(result, now=time.time(),
                             color=not args.no_color, status=status),
              file=stdout)
        status = ""
        print("  Choose: ", end="", file=stdout, flush=True)
        raw = stdin.readline()
        if not raw:                     # EOF, e.g. piped input
            return EXIT_OK
        choice = menu_ui.parse_choice(raw)

        if choice is None:
            status = "Sorry, I did not understand that."
            continue

        if choice.action == "quit":
            return EXIT_OK

        if choice.action in ("scan", "deep"):
            result = _menu_scan(cfg, args, home, deep=choice.action == "deep")
            status = "Scan finished in {:.0f}s.".format(result.duration)
            continue

        if choice.action == "browse":
            if result is None:
                status = "Nothing scanned yet — choose 1 first."
                continue
            from .ui import tui
            updated = tui.run(result, home=home, config=cfg)
            if updated is not None:
                result = updated
                serialize.save(result, args.cache_file)
            continue

        if choice.action == "report":
            if result is None:
                status = "Nothing scanned yet — choose 1 first."
                continue
            path = report_module.write(result, home=home,
                                       generated_at=time.time(),
                                       path=args.report_file)
            if not args.no_open:
                _open_file(path)
            status = "Report saved to {}".format(redact(path, home))
            continue

        if choice.action == "reclaim":
            if result is None:
                status = "Nothing scanned yet — choose 1 first."
                continue
            run_reclaim(result, cfg, args, home=home, stdin=stdin,
                        stdout=stdout)
            # Sizes are stale the moment anything is removed.
            result = None
            status = "Scan again to see the updated figures."
            continue

        if choice.action == "access":
            print("", file=stdout)
            print(access.instructions(home), file=stdout)
            print("", file=stdout)
            access.open_settings()
            status = "System Settings opened. Reopen your terminal afterwards."
            continue

        if choice.action == "monitor":
            if monitor.is_installed(home):
                _ok, message = monitor.uninstall(home=home)
                status = "Weekly warning removed ({}).".format(message)
            else:
                ok, message = monitor.install(launcher=launcher_path(),
                                              home=home)
                status = ("Weekly warning installed." if ok
                          else "Could not install: {}".format(message))
            continue
