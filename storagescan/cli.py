"""Argument parsing and orchestration."""

from __future__ import annotations

import argparse
import os
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
import time
from typing import List, Optional, Tuple

from . import actions
from . import config as config_module
from . import serialize
from .humanize import human_bytes, redact
from .model import Node, Risk, ScanError, ScanResult
from .scan import aging, apfs, cloud, dupes, probes, system, walker
from .scan.index import SizeIndex
from .ui import report as report_module
from .ui import term

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="storagescan",
        description="Find where your macOS disk space went.",
        epilog="Nothing is deleted without you confirming it, and deletions "
               "go to the Trash unless you pass --purge.",
    )
    parser.add_argument("--deep", action="store_true",
                        help="unlimited depth, plus duplicate and stale-file "
                             "analysis (slower)")
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
    parser.add_argument("--dry-run", action="store_true",
                        help="never modify anything")
    parser.add_argument("--no-progress", action="store_true",
                        help="do not draw the scanning progress line")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-open", action="store_true",
                        help="write the report but do not open it")
    parser.add_argument("--config", default=None, metavar="FILE")
    parser.add_argument("--cache-file", default=None, metavar="FILE")
    parser.add_argument("--report-file", default=None, metavar="FILE")
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

    def report(done: int, total: int, path: str) -> None:
        name = redact(path, home)
        if len(name) > 40:
            name = "~" + name[-39:]
        stream.write("\r\033[2K  scanning {}/{}  {}".format(done, total, name))
        stream.flush()
        if done == total:
            stream.write("\r\033[2K")
            stream.flush()

    return report


def run_scan(cfg, args, *, home: str, now: float, progress=None) -> ScanResult:
    started = time.time()
    errors: List[ScanError] = []
    roots = _scan_roots(cfg, args, home)
    scanning_home = _covers_home(roots, home)

    excludes = list(cfg.expanded_excludes())
    skipped_cloud: Tuple[str, ...] = ()
    if not args.include_cloud and scanning_home:
        skipped_cloud = cloud.cloud_roots(home)
        excludes.extend(skipped_cloud)

    max_depth = None if args.deep else cfg.fast_depth

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
        for root in roots:
            findings.extend(dupes.find_duplicates(
                root, home=home, scan_roots=roots, errors=errors))
            findings.extend(aging.find_stale(
                root, home=home, scan_roots=roots,
                min_bytes=cfg.large_file_bytes, stale_days=cfg.stale_days,
                now=now, errors=errors))

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

    destination = "the Trash" if cfg.trash_by_default else "PERMANENT deletion"
    print("Move all {} to {}? [y/N] ".format(len(batch), destination),
          end="", file=stdout, flush=True)
    answer = stdin.readline().strip().lower()
    if not answer.startswith("y"):
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
            use_trash=cfg.trash_by_default)
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


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    home = os.path.expanduser("~")

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
        if progress is None and not args.json:
            print("Scanning... (first run on a full disk can take a minute)",
                  file=sys.stderr)
        try:
            result = run_scan(cfg, args, home=home, now=time.time(),
                              progress=progress)
        except OSError as exc:
            print("storagescan: scan failed: {}".format(exc), file=sys.stderr)
            return EXIT_ERROR
        serialize.save(result, args.cache_file)

    if args.json:
        print(serialize.dumps(result))
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
    tui.run(result, home=home, config=cfg)
    return EXIT_OK
