# storagescan — Design Spec

**Date:** 2026-08-10
**Status:** Approved
**Repo:** macOS_Storage_Scanner (public, MIT)

## Problem

A Mac on a minimum-spec disk (228 GB, 22 GB free) raises "not enough space"
notifications, and the built-in Storage pane gives coarse, misleading categories.
On APFS a plain directory walk also misses two large classes of consumed space:
local Time Machine snapshots and purgeable space. Users need to see where the
space actually went, and reclaim it without risking their data.

## Goals

1. Show, in one run, where disk space is consumed — both the file tree and the
   "invisible" APFS categories.
2. Let the user explore that interactively in the terminal.
3. Produce a shareable, self-contained HTML report.
4. Allow reclaiming space with explicit per-item confirmation and a bias toward
   reversible actions.
5. Require zero installation beyond what macOS ships.

## Non-Goals

- Deleting anything without confirmation.
- Requiring `sudo` or modifying system volumes.
- Scanning remote or network volumes.
- Background/daemon operation (deferred; see Future Work).

## Constraints

- **Python 3.9+, standard library only.** No pip, no venv, no third-party code.
  3.9 is the version shipped with Apple Command Line Tools, so no `tomllib`, no
  `match`, and runtime `X | Y` annotations are avoided (`from __future__ import
  annotations` is used for source-level convenience).
- **No `sudo`.** Anything requiring root is reported, not performed.
- **Public repo hygiene.** No personal paths, usernames, or machine identifiers
  in source, fixtures, docs, or committed sample output. All emitted paths have
  `$HOME` collapsed to `~`.

## Architecture

A thin Bash launcher performs preflight checks and hands off to a Python
package. All logic lives in Python.

```
storagescan                  # bash launcher: python3 check, FDA check, exec
storagescan/
  __init__.py
  cli.py                     # arg parsing, orchestration, exit codes
  config.py                  # ~/.config/storagescan/config.json
  model.py                   # Node, Finding, ScanResult, Risk — shared shapes
  safety.py                  # risk classification (pure functions, no I/O)
  actions.py                 # Trash-first deletion, confirmation prompts
  humanize.py                # byte/time formatting, path redaction
  scan/
    __init__.py
    walker.py                # os.scandir tree walk
    apfs.py                  # snapshots, purgeable, volume totals
    probes.py                # known-hoarder registry
    dupes.py                 # duplicate detection (--deep)
    aging.py                 # large & stale files (--deep)
  ui/
    __init__.py
    term.py                  # colored summary output
    tui.py                   # curses browser
    report.py                # self-contained HTML + SVG treemap
tests/                       # unittest, synthetic temp trees
```

**Rationale.** `model.py` is the single shared vocabulary: scanners produce
`Node` trees and `Finding` lists, UIs consume them, and nothing else crosses
module boundaries. `safety.py` is pure — path in, `Risk` out, no filesystem
access — so deletion policy is exhaustively testable and cannot drift from what
the tests assert. Each module is small enough to be read and changed in
isolation.

## Data Model (`model.py`)

```python
class Risk(enum.Enum):
    SAFE    = "safe"      # regenerable caches; delete freely
    REVIEW  = "review"    # user data that is probably disposable
    DANGER  = "danger"    # irreplaceable or system-critical
    BLOCKED = "blocked"   # never deletable by this tool

@dataclass(frozen=True)
class Node:              # a directory-tree entry
    path: str
    size: int            # on-disk bytes, subtree total
    apparent: int        # apparent bytes, subtree total
    count: int           # files in subtree
    mtime: float
    children: tuple[Node, ...]
    truncated: bool      # depth limit hit; size is a partial sum
    unreadable: int      # entries skipped due to EPERM in subtree

@dataclass(frozen=True)
class Finding:           # a probe hit or analysis result
    category: str        # e.g. "xcode.derived_data"
    title: str
    path: str | None
    bytes: int
    risk: Risk
    detail: str
    reclaim_hint: str    # shell command shown to the user
```

`ScanResult` bundles the root `Node`, the `Finding` list, volume totals, the
error ledger, and scan metadata (mode, duration, FDA status, timestamp).

## Data Flow

```
config + CLI args
      │
      ├─ walker    (home tree, depth-limited)  ─┐
      ├─ apfs      (snapshots, purgeable)      ─┤
      ├─ probes    (known hoarders)            ─┼→ ScanResult → safety.classify()
      └─ dupes / aging   (--deep only)         ─┘                     │
                                                                      │
                          ┌───────────────┬───────────────┬───────────┘
                        TUI            HTML report      JSON (--json)
                          │
                          └→ actions.py → Trash
```

The scan runs once and is cached; every output view reads the same immutable
`ScanResult`.

## Components

### `scan/walker.py`

`os.scandir`-based iterative walk (explicit stack, no recursion — depth is
unbounded on real filesystems and Python's recursion limit is not).

- On-disk size from `st_blocks * 512`; apparent size from `st_size`. Both are
  reported because sparse files and compressed files differ wildly.
- Symlinks are never followed.
- Hardlinks counted once per `(st_dev, st_ino)`; the seen-set is scoped to a
  single scan.
- `EPERM`/`EACCES`/`ENOENT` increment the error ledger and set `unreadable` on
  the ancestor chain; they never raise.
- Fast mode stops at depth 6 and marks deeper nodes `truncated=True`; the sizes
  of truncated subtrees are still summed via a cheap non-recursing `du`-style
  pass so totals stay correct.

### `scan/apfs.py`

Shells out to macOS tools and parses their output defensively; any failure
degrades that one section rather than the run.

- `df -k` for volume totals.
- `tmutil listlocalsnapshots /` for local Time Machine snapshots.
- `diskutil apfs list -plist` (parsed with `plistlib`) for container capacity
  and purgeable space.

Produces `Finding`s with `reclaim_hint` values such as
`tmutil deletelocalsnapshots <date>`. Snapshot deletion is *reported only* —
`actions.py` never performs it, because it is not reversible via the Trash.

### `scan/probes.py`

A declarative registry of known space consumers. Each probe is a dataclass with
a glob pattern, a category, a `Risk`, a human title, and an optional
`reclaim_hint`. Covers, at minimum:

| Group | Examples |
|---|---|
| Developer | Xcode `DerivedData`, `Archives`, `iOS DeviceSupport`, Simulator runtimes; `node_modules`; npm/pnpm/yarn/pip/cargo/Go module caches; Homebrew cache |
| Virtualization | `Docker.raw`, OrbStack data, Parallels `.pvm`, VMware `.vmwarevm`, UTM |
| Apple apps | iOS device backups, Mail downloads, Messages attachments, Photos library, Music/Podcasts downloads |
| General | Trash, `~/Downloads`, browser caches (Safari/Chrome/Firefox/Arc), per-app `Application Support` bloat |

Adding a probe is a single dataclass literal, so the registry is the extension
point.

### `scan/dupes.py` (`--deep`)

Three-stage funnel to avoid hashing everything: group by size → hash first 64 KB
→ full BLAKE2b hash. Files under 1 MB are ignored. Reports groups with their
reclaimable total (group size minus one copy).

### `scan/aging.py` (`--deep`)

Files over a configurable threshold (default 1 GB) not accessed in a
configurable window (default 180 days). Uses `st_mtime`; `st_atime` is
unreliable on macOS with `noatime`-like behavior and is not trusted.

### `safety.py`

Pure classification. `classify(path, category) -> Risk` decides what the
delete action is permitted to touch, with a hard `BLOCKED` floor for `$HOME`
itself, `/`, volume roots, `~/Documents`, `~/Desktop`, and anything outside the
configured scan paths. Deletion policy — strict allowlist vs. tiered risk with
escalating confirmation — is decided here and nowhere else.

### `actions.py`

- Default: move to `~/.Trash` (reversible), with collision-safe renaming.
- `--purge`: permanent removal, requires an additional confirmation.
- `--dry-run`: prints intent, touches nothing.
- Refuses any path whose `Risk` is `BLOCKED`. Refuses symlinks. Re-`stat`s the
  path immediately before acting and aborts if it changed since the scan.
- Every action is appended to `~/.local/state/storagescan/actions.log` with a
  timestamp, size, and outcome.

### `ui/tui.py`

`curses` browser over the `Node` tree.

```
 storagescan  ~/  ·  156.2 GB used  ·  22.1 GB free  ·  ⚠ Full Disk Access missing
 ─────────────────────────────────────────────────────────────────────────
   Library                    68.4 GB  ████████████████░░░░░░░░  43%   >
 ▸ Developer                  31.2 GB  ███████░░░░░░░░░░░░░░░░░  20%   >
   Downloads                  12.8 GB  ███░░░░░░░░░░░░░░░░░░░░░   8%   >
 ─────────────────────────────────────────────────────────────────────────
 ↑↓ move  → enter  ← up  d delete  f findings  r report  s sort  q quit
```

- `f` toggles the Findings view: probe hits ranked by reclaimable bytes, each
  tagged with its `Risk` color.
- `d` routes the selected row through `safety.classify` and then `actions.py`.
- `r` writes the HTML report and opens it.
- Degrades to `ui/term.py` output when stdout is not a TTY or the terminal is
  smaller than 60x15.

### `ui/report.py`

A single self-contained HTML file — inline CSS and JS, no network requests, no
CDN — containing a squarified-treemap SVG of the tree, a sortable findings
table, the error ledger, and the scan metadata. Renders correctly in both light
and dark browser themes. All paths redacted to `~`-relative form.

## Error Handling

Errors are collected into a ledger, never swallowed and never fatal:

- Permission denials are counted and surfaced as a dedicated report section
  ("2,140 items unreadable — 8.2 GB unaccounted"), so a truncated total is
  visibly truncated rather than quietly wrong.
- A missing or failing `diskutil`/`tmutil` degrades only its own section, with
  the reason shown.
- Symlink loops are impossible by construction (links are not followed).
- Any unexpected exception during a probe is caught, recorded with the probe
  name, and the remaining probes still run.

### Full Disk Access (`--fda`)

At startup, attempt to read a known-protected path (`~/Library/Mail`). On
`EPERM`, print a prominent warning with exact System Settings steps, mark the
`ScanResult` as incomplete, stamp an `INCOMPLETE` banner on the TUI header and
every report, and continue scanning.

## Caching

`ScanResult` is serialized to `~/.cache/storagescan/<volume-uuid>.json` after
each scan. `--cached` reopens the last result instantly. `--diff` compares the
current scan to the previous one and reports per-directory growth. Cache format
carries a schema version and is discarded on mismatch.

## CLI Surface

```
storagescan                 # fast scan, then TUI
storagescan --deep          # unlimited depth + dupes + aging
storagescan --report        # scan and open the HTML report, no TUI
storagescan --json          # machine-readable to stdout
storagescan --cached        # reuse last scan
storagescan --diff          # compare against previous scan
storagescan --path DIR      # scan a specific directory (repeatable)
storagescan --dry-run       # never modify anything
storagescan --no-color
```

Exit codes: `0` success, `1` scan error, `2` bad usage, `3` python3 unavailable.

## Configuration

`~/.config/storagescan/config.json`, all keys optional:

```json
{
  "scan_paths": ["~/", "/Applications"],
  "exclude": ["~/Library/CloudStorage"],
  "fast_depth": 6,
  "large_file_bytes": 1073741824,
  "stale_days": 180,
  "trash_by_default": true
}
```

## Testing

`unittest`, standard library only, run via `python3 -m unittest discover`.

- **walker:** synthetic temp trees covering sparse files, hardlinks, symlink
  loops, unreadable directories (`chmod 000`), deep nesting past the fast-mode
  limit, and filenames containing newlines and non-UTF-8 bytes.
- **safety:** exhaustive table test over every category plus adversarial paths
  (`~`, `/`, `~/Documents`, `../` traversal, symlinked cache dirs).
- **actions:** operate only inside `tempfile.mkdtemp()`, with a module-level
  guard that raises if a test target is not under the temp root.
- **apfs:** parse fixed sample outputs of `df`, `tmutil`, and `diskutil`
  captured as fixtures with all identifiers scrubbed; also test the
  tool-missing and malformed-output paths.
- **report:** assert the generated HTML contains no `http://` or `https://`
  references and no absolute home paths.

## Deliverables

1. Working `storagescan` CLI with TUI and HTML report.
2. Test suite passing on Python 3.9+.
3. `README.md` — screenshots, quickstart, Full Disk Access instructions, an
   explicit safety statement, and the future-work list below.
4. `LICENSE` (MIT).

## Future Work

Deferred from v1, documented in the README:

- **Scheduled monitoring** — an optional `launchd` agent running a weekly scan
  and posting a notification when free space crosses a threshold.

Five exotic extensions:

1. **Storage blame** — a daily size ledger enabling `storagescan blame --since 2w`,
   attributing growth to specific directories the way `git blame` attributes lines.
2. **Exhaustion forecasting** — fit per-directory growth rates and project the
   date free space reaches zero, naming the directory responsible.
3. **Clone-based deduplication** — instead of deleting duplicates, replace them
   with APFS `clonefile(2)` clones, reclaiming the space while keeping every
   file present at its original path.
4. **Uninstall residue tracing** — given an `.app`, locate every artifact it
   left behind across Containers, Application Support, Caches, Preferences, and
   LaunchAgents.
5. **Anonymized storage fingerprint** — export a path-free, category-only
   profile for comparison against community medians ("your Xcode caches are in
   the 97th percentile").
