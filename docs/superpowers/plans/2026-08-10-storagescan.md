# storagescan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a zero-dependency macOS CLI that finds where disk space went — file tree plus APFS snapshots, purgeable space, and known space hogs — explores it in a curses TUI, exports a self-contained HTML report, and reclaims space with tiered confirmation.

**Architecture:** A Bash launcher does preflight (python3 present, Full Disk Access probe) then execs a Python package. Scanners (`walker`, `apfs`, `probes`, `dupes`, `aging`) all produce the shared shapes in `model.py` — a `Node` tree and a list of `Finding`. Those flow into one immutable `ScanResult` that three independent views (`term`, `tui`, `report`) read. `safety.py` is pure — path in, `Risk` out, no I/O — and is the only place deletion policy exists.

**Tech Stack:** Python 3.9 standard library only (`os.scandir`, `curses`, `plistlib`, `hashlib`, `json`, `subprocess`, `unittest`), Bash, inline HTML/CSS/SVG.

**Spec:** `docs/superpowers/specs/2026-08-10-storagescan-design.md`

## Global Constraints

Every task's requirements implicitly include this section.

- **Python 3.9+, standard library only.** No pip, no venv, no third-party imports. Verified floor: system `python3` is 3.9.6.
- No `tomllib` (3.11+), no `match` statements (3.10+), no PEP 604 `X | Y` annotations evaluated at runtime. Every module starts with `from __future__ import annotations` so annotations stay strings.
- No `dict[str, int]` / `list[str]` in *runtime-evaluated* positions (e.g. `dataclasses.field(default_factory=...)` is fine; a bare `x: list[str]` is fine only under `from __future__ import annotations`).
- **No `sudo`.** Anything requiring root is reported, never performed.
- **Public repo hygiene.** No personal paths, usernames, hostnames, or machine identifiers in source, tests, fixtures, docs, or committed output. Every user-visible path is passed through `humanize.redact()` first.
- **Byte formatting is decimal** (1 GB = 1000³), matching Finder and the macOS Storage pane.
- Test command everywhere: `python3 -m unittest discover -s tests -t . -v`
- Never follow symlinks during any scan or delete.
- Every commit message ends with the repo's standard trailers.

---

## File Structure

| File | Responsibility |
|---|---|
| `storagescan` | Bash launcher: python3 check, exec |
| `storagescan/__init__.py` | Version constant |
| `storagescan/humanize.py` | Byte/age formatting, `$HOME` redaction |
| `storagescan/model.py` | `Risk`, `Node`, `Finding`, `ScanError`, `VolumeInfo`, `ScanResult` |
| `storagescan/safety.py` | `classify()` — the only deletion policy |
| `storagescan/config.py` | JSON config load + defaults |
| `storagescan/scan/walker.py` | Directory tree walk |
| `storagescan/scan/apfs.py` | Volumes, snapshots, purgeable |
| `storagescan/scan/probes.py` | Known-hoarder registry |
| `storagescan/scan/dupes.py` | Duplicate detection |
| `storagescan/scan/aging.py` | Large + stale files |
| `storagescan/serialize.py` | `ScanResult` ⇄ JSON, cache, diff |
| `storagescan/actions.py` | Trash-first deletion + action log |
| `storagescan/ui/term.py` | Colored summary |
| `storagescan/ui/report.py` | Self-contained HTML + treemap |
| `storagescan/ui/tui.py` | curses browser |
| `storagescan/cli.py` | Arg parsing, orchestration, exit codes |
| `tests/` | unittest suite |
| `README.md`, `LICENSE` | Docs |

---

### Task 1: Repo scaffolding and `humanize`

**Files:**
- Create: `LICENSE`, `.gitignore`, `storagescan/__init__.py`, `storagescan/scan/__init__.py`, `storagescan/ui/__init__.py`, `storagescan/humanize.py`, `tests/__init__.py`
- Test: `tests/test_humanize.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `humanize.human_bytes(n: int) -> str` — decimal units, 1 decimal place above KB, e.g. `4.2 GB`, `512 B`, `0 B`
  - `humanize.redact(path: str, home: str) -> str` — replaces a leading `home` with `~`
  - `humanize.human_age(mtime: float, now: float) -> str` — e.g. `3 days ago`, `2 years ago`, `today`
  - `storagescan.__version__: str` = `"0.1.0"`

- [ ] **Step 1: Write the failing test**

Create `tests/test_humanize.py`:

```python
from __future__ import annotations

import unittest

from storagescan import humanize


class HumanBytesTest(unittest.TestCase):
    def test_formats_decimal_units(self):
        self.assertEqual(humanize.human_bytes(0), "0 B")
        self.assertEqual(humanize.human_bytes(512), "512 B")
        self.assertEqual(humanize.human_bytes(1000), "1.0 KB")
        self.assertEqual(humanize.human_bytes(4_200_000_000), "4.2 GB")
        self.assertEqual(humanize.human_bytes(2_000_000_000_000), "2.0 TB")

    def test_negative_is_signed(self):
        self.assertEqual(humanize.human_bytes(-1000), "-1.0 KB")


class RedactTest(unittest.TestCase):
    def test_replaces_home_prefix(self):
        self.assertEqual(
            humanize.redact("/Users/example/Library/Caches", "/Users/example"),
            "~/Library/Caches",
        )

    def test_home_itself_becomes_tilde(self):
        self.assertEqual(humanize.redact("/Users/example", "/Users/example"), "~")

    def test_leaves_other_paths_alone(self):
        self.assertEqual(humanize.redact("/Applications", "/Users/example"), "/Applications")

    def test_does_not_match_partial_component(self):
        self.assertEqual(
            humanize.redact("/Users/example2/x", "/Users/example"),
            "/Users/example2/x",
        )


class HumanAgeTest(unittest.TestCase):
    def test_buckets(self):
        now = 1_000_000_000.0
        day = 86400.0
        self.assertEqual(humanize.human_age(now, now), "today")
        self.assertEqual(humanize.human_age(now - 3 * day, now), "3 days ago")
        self.assertEqual(humanize.human_age(now - 60 * day, now), "2 months ago")
        self.assertEqual(humanize.human_age(now - 800 * day, now), "2 years ago")

    def test_future_mtime_is_today(self):
        now = 1_000_000_000.0
        self.assertEqual(humanize.human_age(now + 5000, now), "today")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_humanize -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/__init__.py`:

```python
"""storagescan — find where macOS disk space went."""

__version__ = "0.1.0"
```

Create empty `storagescan/scan/__init__.py`, `storagescan/ui/__init__.py`, `tests/__init__.py`.

Create `storagescan/humanize.py`:

```python
"""Formatting helpers. Every user-visible string passes through here."""

from __future__ import annotations

import os

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_bytes(n: int) -> str:
    """Format a byte count using decimal units, matching Finder."""
    sign = "-" if n < 0 else ""
    value = float(abs(n))
    for unit in _UNITS:
        if value < 1000 or unit == _UNITS[-1]:
            if unit == "B":
                return "{}{:.0f} B".format(sign, value)
            return "{}{:.1f} {}".format(sign, value, unit)
        value /= 1000.0
    raise AssertionError("unreachable")


def redact(path: str, home: str) -> str:
    """Collapse a leading home directory to ``~``.

    Matches whole path components only, so ``/Users/ann2`` is not treated as
    living inside ``/Users/ann``.
    """
    home = home.rstrip(os.sep)
    if not home:
        return path
    if path == home:
        return "~"
    if path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


def human_age(mtime: float, now: float) -> str:
    """Describe how long ago ``mtime`` was, in coarse buckets."""
    days = int((now - mtime) // 86400)
    if days <= 0:
        return "today"
    if days == 1:
        return "1 day ago"
    if days < 30:
        return "{} days ago".format(days)
    months = days // 30
    if months < 12:
        return "1 month ago" if months == 1 else "{} months ago".format(months)
    years = days // 365
    return "1 year ago" if years == 1 else "{} years ago".format(years)
```

Create `.gitignore`:

```
__pycache__/
*.pyc
.DS_Store
/dist/
```

Create `LICENSE` — the standard MIT License text, copyright line: `Copyright (c) 2026 storagescan contributors`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS, 10 tests

- [ ] **Step 5: Commit**

```bash
git add LICENSE .gitignore storagescan tests
git commit -m "feat: add package scaffolding and humanize helpers"
```

---

### Task 2: Core data model

**Files:**
- Create: `storagescan/model.py`
- Test: `tests/test_model.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `model.Risk` — `Enum` with members `SAFE`, `REVIEW`, `DANGER`, `BLOCKED`, values `"safe"`, `"review"`, `"danger"`, `"blocked"`
  - `model.Node(path, size, apparent, count, mtime, children=(), truncated=False, unreadable=0)` — frozen dataclass
  - `Node.sorted_children() -> tuple` — children by `size` descending
  - `model.Finding(category, title, path, bytes_, risk, detail="", reclaim_hint="")` — frozen dataclass (`bytes_` avoids shadowing the builtin)
  - `model.ScanError(path, error)` — frozen dataclass
  - `model.VolumeInfo(mount, total, used, free, purgeable=None)` — frozen dataclass
  - `model.ScanResult(root, findings, volumes, errors, mode, duration, fda_ok, started_at)` — frozen dataclass
  - `ScanResult.reclaimable(*risks) -> int` — total bytes of findings at the given risks
  - `ScanResult.findings_by_size() -> tuple` — findings sorted by `bytes_` descending

- [ ] **Step 1: Write the failing test**

Create `tests/test_model.py`:

```python
from __future__ import annotations

import dataclasses
import unittest

from storagescan.model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo


def make_finding(category, bytes_, risk):
    return Finding(category=category, title=category, path=None, bytes_=bytes_, risk=risk)


class NodeTest(unittest.TestCase):
    def test_is_frozen(self):
        node = Node(path="/a", size=1, apparent=1, count=1, mtime=0.0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            node.size = 2

    def test_sorted_children_is_descending_by_size(self):
        small = Node(path="/a/s", size=10, apparent=10, count=1, mtime=0.0)
        big = Node(path="/a/b", size=99, apparent=99, count=1, mtime=0.0)
        parent = Node(path="/a", size=109, apparent=109, count=2, mtime=0.0,
                      children=(small, big))
        self.assertEqual([c.path for c in parent.sorted_children()], ["/a/b", "/a/s"])

    def test_defaults(self):
        node = Node(path="/a", size=1, apparent=1, count=1, mtime=0.0)
        self.assertEqual(node.children, ())
        self.assertFalse(node.truncated)
        self.assertEqual(node.unreadable, 0)


class ScanResultTest(unittest.TestCase):
    def build(self):
        return ScanResult(
            root=Node(path="/a", size=100, apparent=100, count=1, mtime=0.0),
            findings=(
                make_finding("cache", 500, Risk.SAFE),
                make_finding("downloads", 300, Risk.REVIEW),
                make_finding("movies", 900, Risk.DANGER),
            ),
            volumes=(VolumeInfo(mount="/", total=10, used=6, free=4),),
            errors=(ScanError(path="/x", error="PermissionError"),),
            mode="fast",
            duration=1.5,
            fda_ok=True,
            started_at=0.0,
        )

    def test_reclaimable_sums_selected_risks(self):
        result = self.build()
        self.assertEqual(result.reclaimable(Risk.SAFE), 500)
        self.assertEqual(result.reclaimable(Risk.SAFE, Risk.REVIEW), 800)

    def test_findings_by_size_is_descending(self):
        result = self.build()
        self.assertEqual(
            [f.category for f in result.findings_by_size()],
            ["movies", "cache", "downloads"],
        )

    def test_volume_info_purgeable_defaults_to_none(self):
        self.assertIsNone(VolumeInfo(mount="/", total=1, used=1, free=0).purgeable)


class RiskTest(unittest.TestCase):
    def test_values_are_stable_strings(self):
        self.assertEqual(
            [r.value for r in Risk],
            ["safe", "review", "danger", "blocked"],
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_model -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.model'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/model.py`:

```python
"""The shared vocabulary. Scanners produce these; UIs consume them."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional, Tuple


class Risk(enum.Enum):
    """How much confirmation deleting something should cost."""

    SAFE = "safe"        # regenerable: caches, build products
    REVIEW = "review"    # user data that is probably disposable
    DANGER = "danger"    # looks irreplaceable
    BLOCKED = "blocked"  # this tool will never delete it


@dataclass(frozen=True)
class Node:
    """One directory-tree entry, with its subtree totals already summed."""

    path: str
    size: int          # on-disk bytes (st_blocks * 512)
    apparent: int      # apparent bytes (st_size)
    count: int         # files in subtree
    mtime: float
    children: Tuple["Node", ...] = ()
    truncated: bool = False   # depth limit hit below here
    unreadable: int = 0       # entries skipped for permissions in subtree

    def sorted_children(self) -> Tuple["Node", ...]:
        return tuple(sorted(self.children, key=lambda n: n.size, reverse=True))


@dataclass(frozen=True)
class Finding:
    """A probe hit or analysis result: a specific chunk of reclaimable space."""

    category: str
    title: str
    path: Optional[str]
    bytes_: int
    risk: Risk
    detail: str = ""
    reclaim_hint: str = ""


@dataclass(frozen=True)
class ScanError:
    path: str
    error: str


@dataclass(frozen=True)
class VolumeInfo:
    mount: str
    total: int
    used: int
    free: int
    purgeable: Optional[int] = None


@dataclass(frozen=True)
class ScanResult:
    """One immutable snapshot. Every view reads this and nothing else."""

    root: Optional[Node]
    findings: Tuple[Finding, ...] = ()
    volumes: Tuple[VolumeInfo, ...] = ()
    errors: Tuple[ScanError, ...] = ()
    mode: str = "fast"
    duration: float = 0.0
    fda_ok: bool = True
    started_at: float = 0.0

    def reclaimable(self, *risks: Risk) -> int:
        wanted = set(risks) or {Risk.SAFE}
        return sum(f.bytes_ for f in self.findings if f.risk in wanted)

    def findings_by_size(self) -> Tuple[Finding, ...]:
        return tuple(sorted(self.findings, key=lambda f: f.bytes_, reverse=True))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add storagescan/model.py tests/test_model.py
git commit -m "feat: add core data model"
```

---

### Task 3: Safety classification

This is the deletion policy. It is pure — no filesystem access — so it can be tested exhaustively.

**Files:**
- Create: `storagescan/safety.py`
- Test: `tests/test_safety.py`

**Interfaces:**
- Consumes: `model.Risk`
- Produces:
  - `safety.SAFE_CATEGORIES: frozenset` / `safety.REVIEW_CATEGORIES: frozenset`
  - `safety.blocked_dirs(home: str) -> frozenset` — exact directories, not prefixes
  - `safety.classify(path, category, *, home, scan_roots, is_symlink=False) -> Risk`
  - `safety.confirmation_for(risk: Risk) -> str` — `"single"`, `"recap"`, `"retype"`, or `"none"`

- [ ] **Step 1: Write the failing test**

Create `tests/test_safety.py`:

```python
from __future__ import annotations

import unittest

from storagescan import safety
from storagescan.model import Risk

HOME = "/Users/example"
ROOTS = (HOME,)


def classify(path, category=None, **kw):
    kw.setdefault("home", HOME)
    kw.setdefault("scan_roots", ROOTS)
    return safety.classify(path, category, **kw)


class BlockedFloorTest(unittest.TestCase):
    def test_exact_blocked_directories(self):
        for path in [
            HOME,
            "/",
            "/Users",
            "/Volumes/Data",
            HOME + "/Documents",
            HOME + "/Desktop",
            HOME + "/Library",
            HOME + "/Applications",
        ]:
            self.assertEqual(classify(path), Risk.BLOCKED, path)

    def test_descendants_of_blocked_dirs_are_classifiable(self):
        self.assertEqual(
            classify(HOME + "/Library/Caches/Homebrew", "homebrew.cache"),
            Risk.SAFE,
        )

    def test_trailing_slash_is_normalized(self):
        self.assertEqual(classify(HOME + "/Documents/"), Risk.BLOCKED)

    def test_path_outside_scan_roots_is_blocked(self):
        self.assertEqual(classify("/System/Library/Foo", "homebrew.cache"), Risk.BLOCKED)

    def test_traversal_above_root_is_blocked(self):
        self.assertEqual(classify(HOME + "/../../etc", "homebrew.cache"), Risk.BLOCKED)

    def test_symlinks_are_blocked(self):
        self.assertEqual(
            classify(HOME + "/Library/Caches/x", "homebrew.cache", is_symlink=True),
            Risk.BLOCKED,
        )


class TierTest(unittest.TestCase):
    def test_safe_categories(self):
        self.assertEqual(classify(HOME + "/Library/Caches/pip", "pip.cache"), Risk.SAFE)
        self.assertEqual(classify(HOME + "/.Trash/old", "trash"), Risk.SAFE)

    def test_review_categories(self):
        self.assertEqual(classify(HOME + "/Downloads/x.dmg", "downloads"), Risk.REVIEW)
        self.assertEqual(classify(HOME + "/big.iso", "aging.stale"), Risk.REVIEW)

    def test_unmatched_path_defaults_to_danger(self):
        self.assertEqual(classify(HOME + "/Movies/wedding.mov", None), Risk.DANGER)

    def test_unknown_category_defaults_to_danger(self):
        self.assertEqual(classify(HOME + "/Movies/x.mov", "not.a.real.category"), Risk.DANGER)

    def test_risk_ignores_size_and_extension(self):
        # Location and category decide. Nothing else.
        self.assertEqual(classify(HOME + "/Library/Caches/huge.bin", "pip.cache"), Risk.SAFE)
        self.assertEqual(classify(HOME + "/Movies/tiny.tmp", None), Risk.DANGER)


class ConfirmationTest(unittest.TestCase):
    def test_escalating_confirmation(self):
        self.assertEqual(safety.confirmation_for(Risk.SAFE), "single")
        self.assertEqual(safety.confirmation_for(Risk.REVIEW), "recap")
        self.assertEqual(safety.confirmation_for(Risk.DANGER), "retype")
        self.assertEqual(safety.confirmation_for(Risk.BLOCKED), "none")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_safety -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.safety'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/safety.py`:

```python
"""Deletion policy. Pure functions only — no filesystem access happens here.

Tiered risk with escalating confirmation:
    SAFE    regenerable        -> single 'y'
    REVIEW  probably disposable-> 'y' with a size/mtime recap
    DANGER  looks irreplaceable-> retype the full path
    BLOCKED never deletable    -> no prompt offered

Classification is conservative: an unmatched path is DANGER, never SAFE.
Size and file extension are deliberately ignored — only location and probe
category decide.
"""

from __future__ import annotations

import os
import posixpath
from typing import Optional, Sequence

from .model import Risk

SAFE_CATEGORIES = frozenset({
    "trash",
    "homebrew.cache",
    "pip.cache",
    "npm.cache",
    "pnpm.store",
    "yarn.cache",
    "cargo.cache",
    "go.modcache",
    "xcode.derived_data",
    "xcode.device_support",
    "xcode.simulator_caches",
    "browser.cache",
    "app.cache",
})

REVIEW_CATEGORIES = frozenset({
    "downloads",
    "xcode.archives",
    "ios.backups",
    "docker.image",
    "vm.image",
    "mail.downloads",
    "aging.stale",
    "dupes.copy",
    "node_modules",
})

_ROOT_LEVEL_BLOCKED = frozenset({"/", "/Users", "/Applications", "/System", "/Library"})


def _norm(path: str) -> str:
    """Normalize without touching the filesystem (no realpath, no symlink read)."""
    return posixpath.normpath(path)


def blocked_dirs(home: str) -> frozenset:
    """Directories that are blocked as *exact* matches, not as prefixes."""
    home = _norm(home)
    return frozenset(
        set(_ROOT_LEVEL_BLOCKED)
        | {
            home,
            posixpath.join(home, "Documents"),
            posixpath.join(home, "Desktop"),
            posixpath.join(home, "Library"),
            posixpath.join(home, "Applications"),
        }
    )


def _under_any_root(path: str, scan_roots: Sequence[str]) -> bool:
    for root in scan_roots:
        root = _norm(root).rstrip("/")
        if path == root or path.startswith(root + "/"):
            return True
    return False


def classify(
    path: str,
    category: Optional[str],
    *,
    home: str,
    scan_roots: Sequence[str],
    is_symlink: bool = False,
) -> Risk:
    """Return the risk tier for deleting ``path``."""
    if is_symlink:
        return Risk.BLOCKED

    path = _norm(path)

    # Volume roots and other single-component absolute paths.
    if path in blocked_dirs(home) or os.path.dirname(path) == "/Volumes":
        return Risk.BLOCKED

    if not _under_any_root(path, scan_roots):
        return Risk.BLOCKED

    if category in SAFE_CATEGORIES:
        return Risk.SAFE
    if category in REVIEW_CATEGORIES:
        return Risk.REVIEW
    return Risk.DANGER


def confirmation_for(risk: Risk) -> str:
    """How much the user must do to confirm a deletion at this risk tier."""
    return {
        Risk.SAFE: "single",
        Risk.REVIEW: "recap",
        Risk.DANGER: "retype",
        Risk.BLOCKED: "none",
    }[risk]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add storagescan/safety.py tests/test_safety.py
git commit -m "feat: add tiered safety classification"
```

---

### Task 4: Configuration

**Files:**
- Create: `storagescan/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `config.Config` dataclass: `scan_paths: tuple = ("~/",)`, `exclude: tuple = ()`, `fast_depth: int = 6`, `large_file_bytes: int = 1_073_741_824`, `stale_days: int = 180`, `trash_by_default: bool = True`
  - `Config.expanded_scan_paths() -> tuple` — `~` expanded, normalized, deduped
  - `Config.is_excluded(path: str) -> bool`
  - `config.default_config_path() -> str` — `~/.config/storagescan/config.json`
  - `config.load(path: Optional[str] = None) -> Config` — missing file returns defaults; malformed JSON raises `config.ConfigError` with the path and reason; unknown keys are ignored

- [ ] **Step 1: Write the failing test**

Create `tests/test_config.py`:

```python
from __future__ import annotations

import json
import os
import tempfile
import unittest

from storagescan import config


class LoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def write(self, payload):
        path = os.path.join(self.tmp, "config.json")
        with open(path, "w") as handle:
            handle.write(payload)
        return path

    def test_missing_file_returns_defaults(self):
        cfg = config.load(os.path.join(self.tmp, "nope.json"))
        self.assertEqual(cfg.fast_depth, 6)
        self.assertEqual(cfg.scan_paths, ("~/",))
        self.assertTrue(cfg.trash_by_default)

    def test_overrides_are_applied(self):
        path = self.write(json.dumps({"fast_depth": 3, "stale_days": 30}))
        cfg = config.load(path)
        self.assertEqual(cfg.fast_depth, 3)
        self.assertEqual(cfg.stale_days, 30)
        self.assertEqual(cfg.large_file_bytes, 1_073_741_824)

    def test_unknown_keys_are_ignored(self):
        path = self.write(json.dumps({"fast_depth": 2, "wat": True}))
        self.assertEqual(config.load(path).fast_depth, 2)

    def test_malformed_json_raises_with_context(self):
        path = self.write("{not json")
        with self.assertRaises(config.ConfigError) as ctx:
            config.load(path)
        self.assertIn(path, str(ctx.exception))

    def test_non_object_json_raises(self):
        path = self.write("[1, 2, 3]")
        with self.assertRaises(config.ConfigError):
            config.load(path)


class ExpansionTest(unittest.TestCase):
    def test_expands_and_dedupes(self):
        cfg = config.Config(scan_paths=("~/", "~", "/Applications"))
        expanded = cfg.expanded_scan_paths()
        home = os.path.expanduser("~")
        self.assertEqual(expanded, (home, "/Applications"))

    def test_is_excluded_matches_subpaths(self):
        cfg = config.Config(exclude=("~/Library/CloudStorage",))
        home = os.path.expanduser("~")
        self.assertTrue(cfg.is_excluded(home + "/Library/CloudStorage/Dropbox"))
        self.assertFalse(cfg.is_excluded(home + "/Library/Caches"))

    def test_is_excluded_does_not_match_partial_component(self):
        cfg = config.Config(exclude=("~/Movies",))
        home = os.path.expanduser("~")
        self.assertFalse(cfg.is_excluded(home + "/MoviesArchive"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_config -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.config'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/config.py`:

```python
"""User configuration. JSON, because Python 3.9 has no tomllib."""

from __future__ import annotations

import dataclasses
import json
import os
import posixpath
from dataclasses import dataclass
from typing import Optional, Tuple


class ConfigError(Exception):
    """Raised when a config file exists but cannot be used."""


@dataclass(frozen=True)
class Config:
    scan_paths: Tuple[str, ...] = ("~/",)
    exclude: Tuple[str, ...] = ()
    fast_depth: int = 6
    large_file_bytes: int = 1_073_741_824
    stale_days: int = 180
    trash_by_default: bool = True

    def expanded_scan_paths(self) -> Tuple[str, ...]:
        seen = []
        for raw in self.scan_paths:
            path = posixpath.normpath(os.path.expanduser(raw))
            if path not in seen:
                seen.append(path)
        return tuple(seen)

    def expanded_excludes(self) -> Tuple[str, ...]:
        return tuple(
            posixpath.normpath(os.path.expanduser(raw)) for raw in self.exclude
        )

    def is_excluded(self, path: str) -> bool:
        path = posixpath.normpath(path)
        for excluded in self.expanded_excludes():
            if path == excluded or path.startswith(excluded.rstrip("/") + "/"):
                return True
        return False


def default_config_path() -> str:
    return os.path.expanduser("~/.config/storagescan/config.json")


def load(path: Optional[str] = None) -> Config:
    """Load config, falling back to defaults when the file is absent."""
    path = path or default_config_path()
    if not os.path.exists(path):
        return Config()
    try:
        with open(path, "r") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ConfigError("could not read config {}: {}".format(path, exc))
    if not isinstance(payload, dict):
        raise ConfigError("config {} must contain a JSON object".format(path))

    known = {f.name for f in dataclasses.fields(Config)}
    kwargs = {}
    for key, value in payload.items():
        if key not in known:
            continue
        kwargs[key] = tuple(value) if isinstance(value, list) else value
    try:
        return Config(**kwargs)
    except TypeError as exc:
        raise ConfigError("invalid config {}: {}".format(path, exc))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add storagescan/config.py tests/test_config.py
git commit -m "feat: add JSON configuration loading"
```

---

### Task 5: Directory walker

**Files:**
- Create: `storagescan/scan/walker.py`, `tests/support.py`
- Test: `tests/test_walker.py`

**Interfaces:**
- Consumes: `model.Node`, `model.ScanError`
- Produces:
  - `walker.walk(root, *, max_depth=None, exclude=(), errors=None) -> Node` — `errors` is a list that receives `ScanError`s; `max_depth=None` means unlimited; depth 0 is the root itself
  - `walker.dir_size(path, *, errors=None) -> tuple` — returns `(size, apparent, count)` for a subtree without building nodes; used by probes
  - `tests.support.build_tree(base, spec)` — creates files/dirs from a dict spec, returns `base`

Implementation notes: iterative with an explicit stack (recursion limits are not a filesystem property); never follow symlinks; count hardlinks once per `(st_dev, st_ino)`; truncated subtrees still get correct totals via `dir_size`.

- [ ] **Step 1: Write the failing test**

Create `tests/support.py`:

```python
from __future__ import annotations

import os


def build_tree(base, spec):
    """Create a directory tree.

    ``spec`` maps names to either a dict (directory) or an int (file of that
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
```

Create `tests/test_walker.py`:

```python
from __future__ import annotations

import os
import shutil
import stat
import tempfile
import unittest

from storagescan.scan import walker
from tests.support import build_tree


class WalkerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def find(self, node, name):
        for child in node.children:
            if os.path.basename(child.path) == name:
                return child
        raise AssertionError("no child named {}".format(name))

    def test_sums_apparent_sizes_over_subtree(self):
        build_tree(self.tmp, {"a": {"f1": 1000, "f2": 2000}, "b": {"f3": 500}})
        node = walker.walk(self.tmp)
        self.assertEqual(node.apparent, 3500)
        self.assertEqual(node.count, 3)
        self.assertEqual(self.find(node, "a").apparent, 3000)

    def test_on_disk_size_is_block_based(self):
        build_tree(self.tmp, {"tiny": 1})
        node = walker.walk(self.tmp)
        # A 1-byte file still occupies at least one allocation block.
        self.assertGreaterEqual(node.size, 1)
        self.assertEqual(node.apparent, 1)

    def test_symlinks_are_not_followed(self):
        build_tree(self.tmp, {"real": {"f": 1000}})
        os.symlink(os.path.join(self.tmp, "real"), os.path.join(self.tmp, "link"))
        node = walker.walk(self.tmp)
        self.assertEqual(node.apparent, 1000)

    def test_symlink_loop_terminates(self):
        os.makedirs(os.path.join(self.tmp, "d"))
        os.symlink(self.tmp, os.path.join(self.tmp, "d", "loop"))
        node = walker.walk(self.tmp)
        self.assertIsNotNone(node)

    def test_hardlinks_counted_once(self):
        build_tree(self.tmp, {"a": 1000})
        os.link(os.path.join(self.tmp, "a"), os.path.join(self.tmp, "b"))
        node = walker.walk(self.tmp)
        self.assertEqual(node.apparent, 1000)
        self.assertEqual(node.count, 1)

    def test_unreadable_dir_is_recorded_not_raised(self):
        secret = os.path.join(self.tmp, "secret")
        build_tree(secret, {"f": 100})
        os.chmod(secret, 0)
        self.addCleanup(os.chmod, secret, stat.S_IRWXU)
        errors = []
        node = walker.walk(self.tmp, errors=errors)
        self.assertEqual(len(errors), 1)
        self.assertGreaterEqual(node.unreadable, 1)

    def test_max_depth_truncates_but_keeps_totals(self):
        build_tree(self.tmp, {"a": {"b": {"c": {"f": 4000}}}})
        node = walker.walk(self.tmp, max_depth=1)
        child = self.find(node, "a")
        self.assertTrue(child.truncated)
        self.assertEqual(child.children, ())
        self.assertEqual(child.apparent, 4000)
        self.assertEqual(node.apparent, 4000)

    def test_exclude_prunes_subtree(self):
        build_tree(self.tmp, {"keep": {"f": 100}, "skip": {"f": 9999}})
        node = walker.walk(self.tmp, exclude=(os.path.join(self.tmp, "skip"),))
        self.assertEqual(node.apparent, 100)

    def test_weird_filenames_survive(self):
        os.makedirs(os.path.join(self.tmp, "we ird\nname"))
        with open(os.path.join(self.tmp, "we ird\nname", "f"), "wb") as handle:
            handle.write(b"x" * 10)
        node = walker.walk(self.tmp)
        self.assertEqual(node.apparent, 10)

    def test_missing_root_records_error(self):
        errors = []
        node = walker.walk(os.path.join(self.tmp, "gone"), errors=errors)
        self.assertEqual(node.apparent, 0)
        self.assertEqual(len(errors), 1)


class DirSizeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_returns_totals(self):
        build_tree(self.tmp, {"a": {"f": 1000}, "b": 2000})
        size, apparent, count = walker.dir_size(self.tmp)
        self.assertEqual(apparent, 3000)
        self.assertEqual(count, 2)
        self.assertGreaterEqual(size, 0)

    def test_single_file_path(self):
        build_tree(self.tmp, {"f": 700})
        _, apparent, count = walker.dir_size(os.path.join(self.tmp, "f"))
        self.assertEqual(apparent, 700)
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_walker -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.scan.walker'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/scan/walker.py`:

```python
"""Directory tree walking.

Iterative, not recursive: filesystem depth is not bounded by Python's
recursion limit. Symlinks are never followed, so loops are impossible by
construction. Hardlinked files are counted once.
"""

from __future__ import annotations

import os
from typing import List, Optional, Sequence, Set, Tuple

from ..model import Node, ScanError

_BLOCK = 512


def _record(errors: Optional[List[ScanError]], path: str, exc: Exception) -> None:
    if errors is not None:
        errors.append(ScanError(path=path, error=type(exc).__name__))


def _sizes(st) -> Tuple[int, int]:
    """(on-disk bytes, apparent bytes) for one stat result."""
    return getattr(st, "st_blocks", 0) * _BLOCK, st.st_size


def _excluded(path: str, exclude: Sequence[str]) -> bool:
    for item in exclude:
        item = item.rstrip("/")
        if path == item or path.startswith(item + "/"):
            return True
    return False


def dir_size(
    path: str,
    *,
    exclude: Sequence[str] = (),
    errors: Optional[List[ScanError]] = None,
    seen: Optional[Set[Tuple[int, int]]] = None,
) -> Tuple[int, int, int]:
    """Total (size, apparent, count) of a subtree, without building nodes."""
    if seen is None:
        seen = set()
    size = apparent = count = 0
    try:
        st = os.lstat(path)
    except OSError as exc:
        _record(errors, path, exc)
        return 0, 0, 0

    if not os.path.isdir(path) or os.path.islink(path):
        disk, app = _sizes(st)
        return disk, app, 1

    stack = [path]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            _record(errors, current, exc)
            continue
        for entry in entries:
            if _excluded(entry.path, exclude):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                _record(errors, entry.path, exc)
                continue
            if entry.is_dir(follow_symlinks=False):
                stack.append(entry.path)
                continue
            if entry.is_symlink():
                continue
            key = (st.st_dev, st.st_ino)
            if st.st_nlink > 1:
                if key in seen:
                    continue
                seen.add(key)
            disk, app = _sizes(st)
            size += disk
            apparent += app
            count += 1
    return size, apparent, count


def walk(
    root: str,
    *,
    max_depth: Optional[int] = None,
    exclude: Sequence[str] = (),
    errors: Optional[List[ScanError]] = None,
) -> Node:
    """Build a Node tree rooted at ``root``.

    ``max_depth=None`` walks everything. At the depth limit, a directory
    becomes a leaf marked ``truncated`` whose totals are still correct.
    """
    seen: Set[Tuple[int, int]] = set()
    return _walk_dir(root, 0, max_depth, exclude, errors, seen)


def _walk_dir(path, depth, max_depth, exclude, errors, seen) -> Node:
    try:
        st = os.lstat(path)
        mtime = st.st_mtime
    except OSError as exc:
        _record(errors, path, exc)
        return Node(path=path, size=0, apparent=0, count=0, mtime=0.0)

    if max_depth is not None and depth >= max_depth:
        size, apparent, count = dir_size(path, exclude=exclude, errors=errors, seen=seen)
        return Node(
            path=path, size=size, apparent=apparent, count=count,
            mtime=mtime, truncated=True,
        )

    size = apparent = count = unreadable = 0
    children: List[Node] = []
    try:
        entries = list(os.scandir(path))
    except OSError as exc:
        _record(errors, path, exc)
        return Node(path=path, size=0, apparent=0, count=0, mtime=mtime, unreadable=1)

    for entry in entries:
        if _excluded(entry.path, exclude):
            continue
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError as exc:
            _record(errors, entry.path, exc)
            unreadable += 1
            continue
        if entry.is_symlink():
            continue
        if entry.is_dir(follow_symlinks=False):
            child = _walk_dir(entry.path, depth + 1, max_depth, exclude, errors, seen)
            children.append(child)
            size += child.size
            apparent += child.apparent
            count += child.count
            unreadable += child.unreadable
            continue
        key = (st.st_dev, st.st_ino)
        if st.st_nlink > 1:
            if key in seen:
                continue
            seen.add(key)
        disk, app = _sizes(st)
        size += disk
        apparent += app
        count += 1

    return Node(
        path=path, size=size, apparent=apparent, count=count, mtime=mtime,
        children=tuple(children), unreadable=unreadable,
    )
```

Note: `_walk_dir` recurses, which contradicts the module docstring. Fix this in Step 4 by converting to an explicit two-phase stack walk (collect directories, then fold sizes upward), or reduce the recursion claim to `dir_size` only. Choose the explicit stack — filesystem depth on a real Mac can exceed 1000 via `node_modules`.

- [ ] **Step 4: Convert `_walk_dir` to an explicit stack and re-run**

Replace `_walk_dir` with a post-order iterative walk:

```python
def _walk_dir(root, max_depth, exclude, errors, seen) -> Node:
    """Post-order iterative walk. Children are folded into parents on the
    second visit, so no Python recursion is involved."""
    built = {}                      # path -> Node
    stack = [(root, 0, False)]      # (path, depth, children_done)
    while stack:
        path, depth, done = stack.pop()
        try:
            mtime = os.lstat(path).st_mtime
        except OSError as exc:
            _record(errors, path, exc)
            built[path] = Node(path=path, size=0, apparent=0, count=0, mtime=0.0)
            continue

        if max_depth is not None and depth >= max_depth:
            size, apparent, count = dir_size(
                path, exclude=exclude, errors=errors, seen=seen)
            built[path] = Node(path=path, size=size, apparent=apparent,
                               count=count, mtime=mtime, truncated=True)
            continue

        try:
            entries = list(os.scandir(path))
        except OSError as exc:
            _record(errors, path, exc)
            built[path] = Node(path=path, size=0, apparent=0, count=0,
                               mtime=mtime, unreadable=1)
            continue

        size = apparent = count = unreadable = 0
        subdirs = []
        for entry in entries:
            if _excluded(entry.path, exclude):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                _record(errors, entry.path, exc)
                unreadable += 1
                continue
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                subdirs.append(entry.path)
                continue
            key = (st.st_dev, st.st_ino)
            if st.st_nlink > 1:
                if key in seen:
                    continue
                seen.add(key)
            disk, app = _sizes(st)
            size += disk
            apparent += app
            count += 1

        if not done and subdirs:
            stack.append((path, depth, True))
            for sub in subdirs:
                stack.append((sub, depth + 1, False))
            built[path] = Node(path=path, size=size, apparent=apparent,
                               count=count, mtime=mtime, unreadable=unreadable)
            continue

        children = tuple(built.pop(s) for s in subdirs if s in built)
        base = built.get(path)
        if base is not None and done:
            size, apparent, count, unreadable = (
                base.size, base.apparent, base.count, base.unreadable)
        for child in children:
            size += child.size
            apparent += child.apparent
            count += child.count
            unreadable += child.unreadable
        built[path] = Node(path=path, size=size, apparent=apparent, count=count,
                           mtime=mtime, children=children, unreadable=unreadable)

    return built[root]


def walk(root, *, max_depth=None, exclude=(), errors=None) -> Node:
    seen: Set[Tuple[int, int]] = set()
    return _walk_dir(root, max_depth, exclude, errors, seen)
```

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS, all walker tests green

- [ ] **Step 5: Commit**

```bash
git add storagescan/scan/walker.py tests/test_walker.py tests/support.py
git commit -m "feat: add iterative directory walker"
```

---

### Task 6: APFS volumes, snapshots, purgeable space

**Files:**
- Create: `storagescan/scan/apfs.py`, `tests/fixtures/df_output.txt`, `tests/fixtures/tmutil_snapshots.txt`, `tests/fixtures/diskutil_apfs.plist`
- Test: `tests/test_apfs.py`

**Interfaces:**
- Consumes: `model.VolumeInfo`, `model.Finding`, `model.Risk`
- Produces:
  - `apfs.parse_df(text) -> tuple` of `VolumeInfo`
  - `apfs.parse_snapshots(text) -> tuple` of snapshot name strings
  - `apfs.parse_purgeable(plist_bytes) -> Optional[int]`
  - `apfs.snapshot_findings(names) -> tuple` of `Finding` — category `"apfs.snapshot"`, risk `Risk.REVIEW`, `reclaim_hint="tmutil deletelocalsnapshots <name>"`, `path=None`
  - `apfs.collect(*, run=None) -> tuple` — `(volumes, findings, errors)`; `run` is an injectable `(argv) -> Optional[bytes]` so tests never shell out

Snapshot deletion is report-only; `actions.py` must never be handed an `apfs.snapshot` finding.

- [ ] **Step 1: Write the failing test**

Create `tests/fixtures/df_output.txt` (output of `df -k -P`, identifiers scrubbed):

```
Filesystem 1024-blocks      Used Available Capacity Mounted on
/dev/disk3s1s1  239362496  24117248  23068672      52% /
/dev/disk3s5    239362496 163577856  23068672      88% /System/Volumes/Data
```

Create `tests/fixtures/tmutil_snapshots.txt`:

```
Snapshots for volume group containing disk /:
com.apple.TimeMachine.2026-08-08-101500.local
com.apple.TimeMachine.2026-08-09-041500.local
```

Create `tests/fixtures/diskutil_apfs.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Containers</key>
  <array>
    <dict>
      <key>CapacityFree</key><integer>23622320128</integer>
      <key>Volumes</key>
      <array>
        <dict>
          <key>Name</key><string>Data</string>
          <key>CapacityInUse</key><integer>167503724544</integer>
          <key>PurgeableSpace</key><integer>8589934592</integer>
        </dict>
      </array>
    </dict>
  </array>
</dict>
</plist>
```

Create `tests/test_apfs.py`:

```python
from __future__ import annotations

import os
import unittest

from storagescan.model import Risk
from storagescan.scan import apfs

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name, binary=False):
    mode = "rb" if binary else "r"
    with open(os.path.join(FIXTURES, name), mode) as handle:
        return handle.read()


class ParseDfTest(unittest.TestCase):
    def test_parses_volumes_in_bytes(self):
        volumes = apfs.parse_df(fixture("df_output.txt"))
        self.assertEqual(len(volumes), 2)
        data = [v for v in volumes if v.mount == "/System/Volumes/Data"][0]
        self.assertEqual(data.used, 163577856 * 1024)
        self.assertEqual(data.free, 23068672 * 1024)

    def test_ignores_header_and_blank_lines(self):
        self.assertEqual(apfs.parse_df("Filesystem 1024-blocks\n\n"), ())

    def test_malformed_line_is_skipped(self):
        self.assertEqual(apfs.parse_df("Filesystem x\ngarbage\n"), ())


class ParseSnapshotsTest(unittest.TestCase):
    def test_extracts_snapshot_names(self):
        names = apfs.parse_snapshots(fixture("tmutil_snapshots.txt"))
        self.assertEqual(len(names), 2)
        self.assertTrue(all(n.startswith("com.apple.TimeMachine.") for n in names))

    def test_no_snapshots_yields_empty(self):
        self.assertEqual(apfs.parse_snapshots("Snapshots for volume group:\n"), ())


class ParsePurgeableTest(unittest.TestCase):
    def test_sums_purgeable_space(self):
        self.assertEqual(apfs.parse_purgeable(fixture("diskutil_apfs.plist", True)),
                         8589934592)

    def test_malformed_plist_returns_none(self):
        self.assertIsNone(apfs.parse_purgeable(b"not a plist"))


class SnapshotFindingsTest(unittest.TestCase):
    def test_builds_review_findings_with_hint(self):
        findings = apfs.snapshot_findings(["com.apple.TimeMachine.2026-08-08-101500.local"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "apfs.snapshot")
        self.assertEqual(findings[0].risk, Risk.REVIEW)
        self.assertIsNone(findings[0].path)
        self.assertIn("tmutil deletelocalsnapshots", findings[0].reclaim_hint)


class CollectTest(unittest.TestCase):
    def test_uses_injected_runner(self):
        def run(argv):
            if argv[0] == "df":
                return fixture("df_output.txt").encode()
            if argv[0] == "tmutil":
                return fixture("tmutil_snapshots.txt").encode()
            if argv[0] == "diskutil":
                return fixture("diskutil_apfs.plist", True)
            return None

        volumes, findings, errors = apfs.collect(run=run)
        self.assertEqual(len(volumes), 2)
        self.assertEqual(len(findings), 2)
        self.assertEqual(errors, ())

    def test_missing_tool_degrades_that_section_only(self):
        def run(argv):
            if argv[0] == "df":
                return fixture("df_output.txt").encode()
            return None

        volumes, findings, errors = apfs.collect(run=run)
        self.assertEqual(len(volumes), 2)
        self.assertEqual(findings, ())
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_apfs -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.scan.apfs'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/scan/apfs.py`:

```python
"""APFS facts that a directory walk cannot see: volume totals, local Time
Machine snapshots, and purgeable space.

Every external command is parsed defensively. A missing or unparseable tool
degrades its own section and nothing else.
"""

from __future__ import annotations

import plistlib
import subprocess
from typing import Callable, List, Optional, Sequence, Tuple

from ..model import Finding, Risk, ScanError, VolumeInfo

Runner = Callable[[Sequence[str]], Optional[bytes]]


def _default_run(argv: Sequence[str]) -> Optional[bytes]:
    try:
        return subprocess.run(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=20, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None


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


def parse_snapshots(text: str) -> Tuple[str, ...]:
    return tuple(
        line.strip() for line in text.splitlines()
        if line.strip().startswith("com.apple.TimeMachine.")
    )


def parse_purgeable(payload: bytes) -> Optional[int]:
    try:
        data = plistlib.loads(payload)
    except Exception:
        return None
    total = 0
    found = False
    for container in data.get("Containers", []) or []:
        for volume in container.get("Volumes", []) or []:
            value = volume.get("PurgeableSpace")
            if isinstance(value, int):
                total += value
                found = True
    return total if found else None


def snapshot_findings(names: Sequence[str]) -> Tuple[Finding, ...]:
    """Snapshots are reported, never deleted — tmutil deletion is not
    reversible via the Trash."""
    return tuple(
        Finding(
            category="apfs.snapshot",
            title="Local Time Machine snapshot",
            path=None,
            bytes_=0,  # per-snapshot size is not exposed by tmutil
            risk=Risk.REVIEW,
            detail=name,
            reclaim_hint="tmutil deletelocalsnapshots {}".format(name),
        )
        for name in names
    )


def collect(*, run: Optional[Runner] = None):
    """Gather volumes, snapshot findings, and errors."""
    run = run or _default_run
    errors: List[ScanError] = []

    volumes: Tuple[VolumeInfo, ...] = ()
    out = run(["df", "-k", "-P"])
    if out is None:
        errors.append(ScanError(path="df", error="unavailable"))
    else:
        volumes = parse_df(out.decode("utf-8", "replace"))

    findings: Tuple[Finding, ...] = ()
    out = run(["tmutil", "listlocalsnapshots", "/"])
    if out is None:
        errors.append(ScanError(path="tmutil", error="unavailable"))
    else:
        findings = snapshot_findings(parse_snapshots(out.decode("utf-8", "replace")))

    out = run(["diskutil", "apfs", "list", "-plist"])
    if out is None:
        errors.append(ScanError(path="diskutil", error="unavailable"))
    else:
        purgeable = parse_purgeable(out)
        if purgeable is not None and volumes:
            volumes = tuple(
                VolumeInfo(v.mount, v.total, v.used, v.free,
                           purgeable if v.mount.endswith("/Data") else v.purgeable)
                for v in volumes
            )

    return volumes, findings, tuple(errors)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add storagescan/scan/apfs.py tests/test_apfs.py tests/fixtures
git commit -m "feat: add APFS volume, snapshot, and purgeable detection"
```

---

### Task 7: Known-hoarder probes

**Files:**
- Create: `storagescan/scan/probes.py`
- Test: `tests/test_probes.py`

**Interfaces:**
- Consumes: `walker.dir_size`, `model.Finding`, `safety.classify`
- Produces:
  - `probes.Probe(category, title, patterns, detail="", reclaim_hint="")` — frozen dataclass; `patterns` are `~`-relative globs
  - `probes.PROBES: tuple` — the registry
  - `probes.run_probes(home, *, scan_roots, min_bytes=10_000_000, errors=None, sizer=None) -> tuple` of `Finding`; `sizer` is injectable `(path) -> (size, apparent, count)` for tests

Risk comes from `safety.classify`, never from the probe definition — one source of policy.

- [ ] **Step 1: Write the failing test**

Create `tests/test_probes.py`:

```python
from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan.model import Risk
from storagescan.scan import probes
from tests.support import build_tree


class RegistryTest(unittest.TestCase):
    def test_registry_is_non_empty_and_unique(self):
        categories = [p.category for p in probes.PROBES]
        self.assertGreater(len(categories), 15)
        self.assertEqual(len(categories), len(set(categories)))

    def test_covers_the_headline_hoarders(self):
        categories = {p.category for p in probes.PROBES}
        for expected in [
            "xcode.derived_data",
            "xcode.device_support",
            "ios.backups",
            "docker.image",
            "homebrew.cache",
            "npm.cache",
            "trash",
            "downloads",
            "node_modules",
            "mail.downloads",
        ]:
            self.assertIn(expected, categories)

    def test_patterns_are_home_relative(self):
        for probe in probes.PROBES:
            for pattern in probe.patterns:
                self.assertFalse(pattern.startswith("/"), probe.category)


class RunProbesTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def test_finds_a_matching_directory(self):
        build_tree(self.home, {
            "Library": {"Caches": {"Homebrew": {"big": 50_000_000}}},
        })
        findings = probes.run_probes(self.home, scan_roots=(self.home,), min_bytes=1)
        homebrew = [f for f in findings if f.category == "homebrew.cache"]
        self.assertEqual(len(homebrew), 1)
        self.assertEqual(homebrew[0].risk, Risk.SAFE)
        self.assertGreaterEqual(homebrew[0].bytes_, 50_000_000)

    def test_skips_results_below_min_bytes(self):
        build_tree(self.home, {"Library": {"Caches": {"Homebrew": {"tiny": 10}}}})
        findings = probes.run_probes(
            self.home, scan_roots=(self.home,), min_bytes=10_000_000)
        self.assertEqual([f for f in findings if f.category == "homebrew.cache"], [])

    def test_downloads_is_review_not_safe(self):
        build_tree(self.home, {"Downloads": {"big.dmg": 50_000_000}})
        findings = probes.run_probes(self.home, scan_roots=(self.home,), min_bytes=1)
        downloads = [f for f in findings if f.category == "downloads"][0]
        self.assertEqual(downloads.risk, Risk.REVIEW)

    def test_missing_paths_produce_no_findings_and_no_errors(self):
        errors = []
        findings = probes.run_probes(
            self.home, scan_roots=(self.home,), min_bytes=1, errors=errors)
        self.assertEqual(findings, ())
        self.assertEqual(errors, [])

    def test_findings_are_sorted_by_size_descending(self):
        build_tree(self.home, {
            "Downloads": {"a": 20_000_000},
            "Library": {"Caches": {"Homebrew": {"b": 90_000_000}}},
        })
        findings = probes.run_probes(self.home, scan_roots=(self.home,), min_bytes=1)
        sizes = [f.bytes_ for f in findings]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_sizer_is_injectable(self):
        os.makedirs(os.path.join(self.home, "Downloads"))
        calls = []

        def sizer(path):
            calls.append(path)
            return (123, 123, 1)

        findings = probes.run_probes(
            self.home, scan_roots=(self.home,), min_bytes=1, sizer=sizer)
        self.assertTrue(calls)
        self.assertEqual(findings[0].bytes_, 123)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_probes -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.scan.probes'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/scan/probes.py`:

```python
"""Registry of known space consumers.

Adding a probe is a single dataclass literal — this is the extension point.
Risk is *not* declared here; it comes from safety.classify so that deletion
policy lives in exactly one place.
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
    patterns: Tuple[str, ...]   # home-relative globs
    detail: str = ""
    reclaim_hint: str = ""


PROBES: Tuple[Probe, ...] = (
    # --- Developer -------------------------------------------------------
    Probe("xcode.derived_data", "Xcode DerivedData",
          ("Library/Developer/Xcode/DerivedData",),
          "Build intermediates. Xcode regenerates these on next build."),
    Probe("xcode.archives", "Xcode Archives",
          ("Library/Developer/Xcode/Archives",),
          "Shipped app archives. Keep any you may need to re-symbolicate."),
    Probe("xcode.device_support", "iOS DeviceSupport",
          ("Library/Developer/Xcode/iOS DeviceSupport",
           "Library/Developer/Xcode/watchOS DeviceSupport"),
          "Symbols for every iOS version you ever attached. Re-downloaded on demand."),
    Probe("xcode.simulator_caches", "Simulator caches and devices",
          ("Library/Developer/CoreSimulator/Caches",
           "Library/Developer/CoreSimulator/Devices"),
          "Simulator runtimes and device images.",
          "xcrun simctl delete unavailable"),
    Probe("node_modules", "node_modules directories",
          ("*/node_modules", "*/*/node_modules", "*/*/*/node_modules"),
          "Reinstallable with npm/pnpm/yarn install."),
    Probe("npm.cache", "npm cache", ("​.npm",), "npm cache clean --force", "npm cache clean --force"),
    Probe("pnpm.store", "pnpm store", ("Library/pnpm/store", ".pnpm-store"),
          "pnpm store prune", "pnpm store prune"),
    Probe("yarn.cache", "Yarn cache", ("Library/Caches/Yarn",), "", "yarn cache clean"),
    Probe("pip.cache", "pip cache", ("Library/Caches/pip",), "", "pip3 cache purge"),
    Probe("cargo.cache", "Cargo registry", (".cargo/registry",), "Re-downloaded on build."),
    Probe("go.modcache", "Go module cache", ("go/pkg/mod",), "", "go clean -modcache"),
    Probe("homebrew.cache", "Homebrew downloads",
          ("Library/Caches/Homebrew",), "", "brew cleanup -s"),
    # --- Virtualization --------------------------------------------------
    Probe("docker.image", "Docker disk image",
          ("Library/Containers/com.docker.docker/Data/vms",
           "Library/Containers/com.docker.docker/Data/vms/0/data",
           ".docker/desktop"),
          "The Docker VM disk. Shrink from Docker Desktop, or prune images.",
          "docker system prune -a --volumes"),
    Probe("vm.image", "Virtual machines",
          ("Library/Containers/dev.orbstack.OrbStack/Data",
           "Parallels", "Virtual Machines.localized", "Library/Containers/com.utmapp.UTM"),
          "Virtual machine disk images."),
    # --- Apple apps ------------------------------------------------------
    Probe("ios.backups", "iOS device backups",
          ("Library/Application Support/MobileSync/Backup",),
          "Full device backups. Check Finder before deleting."),
    Probe("mail.downloads", "Mail attachments",
          ("Library/Containers/com.apple.mail/Data/Library/Mail Downloads",
           "Library/Mail/V10/MailData/Downloads"),
          "Downloaded attachments; originals remain on the mail server."),
    Probe("app.cache", "Application caches",
          ("Library/Caches/*",), "Per-app caches, regenerated on demand."),
    Probe("browser.cache", "Browser caches",
          ("Library/Caches/com.apple.Safari",
           "Library/Caches/Google/Chrome",
           "Library/Caches/Firefox",
           "Library/Caches/company.thebrowser.Browser"),
          "Regenerated as you browse."),
    # --- General ---------------------------------------------------------
    Probe("trash", "Trash", (".Trash",), "Already deleted; still occupying space."),
    Probe("downloads", "Downloads folder", ("Downloads",),
          "Usually re-downloadable. Check before clearing."),
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
    """Expand every probe pattern and size what exists."""
    measure = sizer or (lambda path: dir_size(path, errors=errors))
    findings: List[Finding] = []
    seen_paths = set()

    for probe in PROBES:
        for pattern in probe.patterns:
            for path in sorted(glob.glob(os.path.join(home, pattern))):
                if path in seen_paths or os.path.islink(path):
                    continue
                seen_paths.add(path)
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
```

Note: the `npm.cache` pattern above contains a zero-width character typo (`"​.npm"`). Fix it to `".npm"` before running the tests — a good reminder to verify each pattern actually resolves.

- [ ] **Step 4: Fix the pattern typo and run tests**

Correct the `npm.cache` probe to `Probe("npm.cache", "npm cache", (".npm",), "", "npm cache clean --force")`.

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

Then sanity-check against the real machine:
Run: `python3 -c "import os; from storagescan.scan import probes; [print(f.category, f.bytes_, f.path) for f in probes.run_probes(os.path.expanduser('~'), scan_roots=(os.path.expanduser('~'),))]"`
Expected: real findings printed, no traceback

- [ ] **Step 5: Commit**

```bash
git add storagescan/scan/probes.py tests/test_probes.py
git commit -m "feat: add known-hoarder probe registry"
```

---

### Task 8: Duplicate and stale-file detection

**Files:**
- Create: `storagescan/scan/dupes.py`, `storagescan/scan/aging.py`
- Test: `tests/test_dupes.py`, `tests/test_aging.py`

**Interfaces:**
- Consumes: `model.Finding`, `safety.classify`
- Produces:
  - `dupes.find_duplicates(root, *, home, scan_roots, min_bytes=1_048_576, errors=None) -> tuple` of `Finding` — category `"dupes.copy"`, one finding per duplicate group, `bytes_` = reclaimable (group total minus one copy), `path` = the first copy, `detail` = newline-joined redacted paths
  - `aging.find_stale(root, *, home, scan_roots, min_bytes, stale_days, now, errors=None) -> tuple` of `Finding` — category `"aging.stale"`, one per file

Three-stage funnel in `dupes`: group by size → hash first 64 KB → full BLAKE2b. Hardlinked copies of the same inode are not duplicates.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dupes.py`:

```python
from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan.scan import dupes


class FindDuplicatesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.kw = dict(home=self.tmp, scan_roots=(self.tmp,), min_bytes=100)

    def write(self, name, payload):
        path = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(payload)
        return path

    def test_identical_files_are_grouped(self):
        self.write("a/one.bin", b"A" * 5000)
        self.write("b/two.bin", b"A" * 5000)
        findings = dupes.find_duplicates(self.tmp, **self.kw)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "dupes.copy")
        self.assertEqual(findings[0].bytes_, 5000)  # one copy reclaimable

    def test_same_size_different_content_is_not_a_duplicate(self):
        self.write("a.bin", b"A" * 5000)
        self.write("b.bin", b"B" * 5000)
        self.assertEqual(dupes.find_duplicates(self.tmp, **self.kw), ())

    def test_files_below_min_bytes_ignored(self):
        self.write("a.bin", b"A" * 50)
        self.write("b.bin", b"A" * 50)
        self.assertEqual(dupes.find_duplicates(self.tmp, **self.kw), ())

    def test_three_copies_reclaim_two(self):
        for name in ["a.bin", "b.bin", "c.bin"]:
            self.write(name, b"Z" * 4000)
        findings = dupes.find_duplicates(self.tmp, **self.kw)
        self.assertEqual(findings[0].bytes_, 8000)

    def test_hardlinks_are_not_duplicates(self):
        first = self.write("a.bin", b"H" * 4000)
        os.link(first, os.path.join(self.tmp, "b.bin"))
        self.assertEqual(dupes.find_duplicates(self.tmp, **self.kw), ())

    def test_detail_lists_redacted_paths(self):
        self.write("a.bin", b"A" * 5000)
        self.write("b.bin", b"A" * 5000)
        detail = dupes.find_duplicates(self.tmp, **self.kw)[0].detail
        self.assertIn("~/a.bin", detail)
        self.assertNotIn(self.tmp, detail)


if __name__ == "__main__":
    unittest.main()
```

Create `tests/test_aging.py`:

```python
from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan.model import Risk
from storagescan.scan import aging

DAY = 86400.0
NOW = 1_800_000_000.0


class FindStaleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.kw = dict(home=self.tmp, scan_roots=(self.tmp,),
                       min_bytes=1000, stale_days=180, now=NOW)

    def write(self, name, size, age_days):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as handle:
            handle.write(b"x" * size)
        stamp = NOW - age_days * DAY
        os.utime(path, (stamp, stamp))
        return path

    def test_large_and_old_is_reported(self):
        self.write("old.iso", 5000, 400)
        findings = aging.find_stale(self.tmp, **self.kw)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "aging.stale")
        self.assertEqual(findings[0].risk, Risk.REVIEW)

    def test_large_but_recent_is_ignored(self):
        self.write("new.iso", 5000, 3)
        self.assertEqual(aging.find_stale(self.tmp, **self.kw), ())

    def test_old_but_small_is_ignored(self):
        self.write("old.txt", 10, 400)
        self.assertEqual(aging.find_stale(self.tmp, **self.kw), ())

    def test_detail_mentions_age(self):
        self.write("old.iso", 5000, 400)
        self.assertIn("ago", aging.find_stale(self.tmp, **self.kw)[0].detail)

    def test_sorted_by_size_descending(self):
        self.write("a.iso", 9000, 400)
        self.write("b.iso", 3000, 400)
        sizes = [f.bytes_ for f in aging.find_stale(self.tmp, **self.kw)]
        self.assertEqual(sizes, sorted(sizes, reverse=True))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_dupes tests.test_aging -v`
Expected: FAIL — no module `storagescan.scan.dupes`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/scan/dupes.py`:

```python
"""Duplicate detection via a three-stage funnel: size, head hash, full hash.

Hashing every file would dominate the scan; the funnel means full hashes are
computed only for files that already collide on both size and their first
64 KB.
"""

from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from typing import List, Optional, Sequence, Tuple

from ..humanize import redact
from ..model import Finding, ScanError
from ..safety import classify

_HEAD_BYTES = 65536
_CHUNK = 1024 * 1024


def _hash_file(path: str, limit: Optional[int] = None) -> Optional[str]:
    digest = hashlib.blake2b(digest_size=16)
    remaining = limit
    try:
        with open(path, "rb") as handle:
            while True:
                want = _CHUNK if remaining is None else min(_CHUNK, remaining)
                if want <= 0:
                    break
                chunk = handle.read(want)
                if not chunk:
                    break
                digest.update(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def find_duplicates(
    root: str,
    *,
    home: str,
    scan_roots: Sequence[str],
    min_bytes: int = 1_048_576,
    errors: Optional[List[ScanError]] = None,
) -> Tuple[Finding, ...]:
    by_size = defaultdict(list)
    seen_inodes = set()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError as exc:
                if errors is not None:
                    errors.append(ScanError(path=path, error=type(exc).__name__))
                continue
            if os.path.islink(path) or st.st_size < min_bytes:
                continue
            key = (st.st_dev, st.st_ino)
            if key in seen_inodes:
                continue
            seen_inodes.add(key)
            by_size[st.st_size].append(path)

    findings: List[Finding] = []
    for size, paths in by_size.items():
        if len(paths) < 2:
            continue
        by_head = defaultdict(list)
        for path in paths:
            head = _hash_file(path, _HEAD_BYTES)
            if head is not None:
                by_head[head].append(path)
        for head_group in by_head.values():
            if len(head_group) < 2:
                continue
            by_full = defaultdict(list)
            for path in head_group:
                full = _hash_file(path)
                if full is not None:
                    by_full[full].append(path)
            for group in by_full.values():
                if len(group) < 2:
                    continue
                group.sort()
                reclaimable = size * (len(group) - 1)
                findings.append(Finding(
                    category="dupes.copy",
                    title="{} identical copies".format(len(group)),
                    path=group[0],
                    bytes_=reclaimable,
                    risk=classify(group[0], "dupes.copy",
                                  home=home, scan_roots=scan_roots),
                    detail="\n".join(redact(p, home) for p in group),
                ))

    findings.sort(key=lambda f: f.bytes_, reverse=True)
    return tuple(findings)
```

Create `storagescan/scan/aging.py`:

```python
"""Large files that have not changed in a long time."""

from __future__ import annotations

import os
from typing import List, Optional, Sequence, Tuple

from ..humanize import human_age
from ..model import Finding, ScanError
from ..safety import classify

_DAY = 86400.0


def find_stale(
    root: str,
    *,
    home: str,
    scan_roots: Sequence[str],
    min_bytes: int,
    stale_days: int,
    now: float,
    errors: Optional[List[ScanError]] = None,
) -> Tuple[Finding, ...]:
    """Files at least ``min_bytes`` that have not been modified in
    ``stale_days``.

    st_mtime is used rather than st_atime: macOS access times are not
    reliably updated, so a stale atime proves nothing.
    """
    cutoff = now - stale_days * _DAY
    findings: List[Finding] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError as exc:
                if errors is not None:
                    errors.append(ScanError(path=path, error=type(exc).__name__))
                continue
            if os.path.islink(path) or st.st_size < min_bytes:
                continue
            if st.st_mtime > cutoff:
                continue
            findings.append(Finding(
                category="aging.stale",
                title="Large file, untouched",
                path=path,
                bytes_=st.st_size,
                risk=classify(path, "aging.stale", home=home, scan_roots=scan_roots),
                detail="last modified {}".format(human_age(st.st_mtime, now)),
            ))

    findings.sort(key=lambda f: f.bytes_, reverse=True)
    return tuple(findings)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add storagescan/scan/dupes.py storagescan/scan/aging.py tests/test_dupes.py tests/test_aging.py
git commit -m "feat: add duplicate and stale-file detection"
```

---

### Task 9: Serialization, cache, and diff

**Files:**
- Create: `storagescan/serialize.py`
- Test: `tests/test_serialize.py`

**Interfaces:**
- Consumes: all of `model`
- Produces:
  - `serialize.SCHEMA = 1`
  - `serialize.dumps(result: ScanResult) -> str` / `serialize.loads(text: str) -> ScanResult`
  - `serialize.SchemaMismatch(Exception)`
  - `serialize.cache_path() -> str` — `~/.cache/storagescan/last.json`
  - `serialize.save(result, path=None) -> str` / `serialize.load_cached(path=None) -> Optional[ScanResult]` (returns `None` on missing file or schema mismatch)
  - `serialize.diff(old: ScanResult, new: ScanResult) -> tuple` of `(path, delta_bytes)`, sorted by `abs(delta)` descending

- [ ] **Step 1: Write the failing test**

Create `tests/test_serialize.py`:

```python
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from storagescan import serialize
from storagescan.model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo


def sample():
    leaf = Node(path="/a/b", size=10, apparent=12, count=1, mtime=1.0)
    root = Node(path="/a", size=10, apparent=12, count=1, mtime=2.0, children=(leaf,))
    return ScanResult(
        root=root,
        findings=(Finding("trash", "Trash", "/a/.Trash", 99, Risk.SAFE, "d", "h"),),
        volumes=(VolumeInfo("/", 100, 60, 40, purgeable=5),),
        errors=(ScanError("/x", "PermissionError"),),
        mode="deep",
        duration=2.5,
        fda_ok=False,
        started_at=123.0,
    )


class RoundTripTest(unittest.TestCase):
    def test_round_trip_preserves_everything(self):
        original = sample()
        restored = serialize.loads(serialize.dumps(original))
        self.assertEqual(restored, original)

    def test_risk_survives_as_enum(self):
        restored = serialize.loads(serialize.dumps(sample()))
        self.assertIs(restored.findings[0].risk, Risk.SAFE)

    def test_nested_children_survive(self):
        restored = serialize.loads(serialize.dumps(sample()))
        self.assertEqual(restored.root.children[0].path, "/a/b")

    def test_none_root_round_trips(self):
        result = ScanResult(root=None)
        self.assertIsNone(serialize.loads(serialize.dumps(result)).root)

    def test_schema_mismatch_raises(self):
        payload = json.loads(serialize.dumps(sample()))
        payload["schema"] = 999
        with self.assertRaises(serialize.SchemaMismatch):
            serialize.loads(json.dumps(payload))


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = os.path.join(self.tmp, "nested", "last.json")

    def test_save_creates_parents_and_load_returns_result(self):
        serialize.save(sample(), self.path)
        self.assertTrue(os.path.exists(self.path))
        self.assertEqual(serialize.load_cached(self.path), sample())

    def test_missing_cache_returns_none(self):
        self.assertIsNone(serialize.load_cached(os.path.join(self.tmp, "nope.json")))

    def test_corrupt_cache_returns_none(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as handle:
            handle.write("{broken")
        self.assertIsNone(serialize.load_cached(self.path))


class DiffTest(unittest.TestCase):
    def build(self, sizes):
        children = tuple(
            Node(path=p, size=s, apparent=s, count=1, mtime=0.0)
            for p, s in sizes.items()
        )
        root = Node(path="/a", size=sum(sizes.values()),
                    apparent=sum(sizes.values()), count=len(sizes),
                    mtime=0.0, children=children)
        return ScanResult(root=root)

    def test_reports_growth_and_shrinkage(self):
        old = self.build({"/a/x": 100, "/a/y": 500})
        new = self.build({"/a/x": 900, "/a/y": 100})
        changes = dict(serialize.diff(old, new))
        self.assertEqual(changes["/a/x"], 800)
        self.assertEqual(changes["/a/y"], -400)

    def test_new_paths_count_as_full_growth(self):
        old = self.build({"/a/x": 100})
        new = self.build({"/a/x": 100, "/a/z": 700})
        self.assertEqual(dict(serialize.diff(old, new))["/a/z"], 700)

    def test_sorted_by_absolute_delta(self):
        old = self.build({"/a/x": 0, "/a/y": 0})
        new = self.build({"/a/x": 10, "/a/y": 900})
        self.assertEqual([p for p, _ in serialize.diff(old, new)], ["/a/y", "/a/x"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_serialize -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.serialize'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/serialize.py`:

```python
"""ScanResult <-> JSON, plus the on-disk cache and scan-to-scan diff."""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Tuple

from .model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo

SCHEMA = 1


class SchemaMismatch(Exception):
    """Cached data was written by an incompatible version."""


def _node_to_dict(node: Node) -> dict:
    return {
        "path": node.path, "size": node.size, "apparent": node.apparent,
        "count": node.count, "mtime": node.mtime, "truncated": node.truncated,
        "unreadable": node.unreadable,
        "children": [_node_to_dict(c) for c in node.children],
    }


def _node_from_dict(data: dict) -> Node:
    return Node(
        path=data["path"], size=data["size"], apparent=data["apparent"],
        count=data["count"], mtime=data["mtime"],
        truncated=data.get("truncated", False),
        unreadable=data.get("unreadable", 0),
        children=tuple(_node_from_dict(c) for c in data.get("children", [])),
    )


def dumps(result: ScanResult) -> str:
    payload = {
        "schema": SCHEMA,
        "root": _node_to_dict(result.root) if result.root else None,
        "findings": [
            {"category": f.category, "title": f.title, "path": f.path,
             "bytes": f.bytes_, "risk": f.risk.value, "detail": f.detail,
             "reclaim_hint": f.reclaim_hint}
            for f in result.findings
        ],
        "volumes": [
            {"mount": v.mount, "total": v.total, "used": v.used,
             "free": v.free, "purgeable": v.purgeable}
            for v in result.volumes
        ],
        "errors": [{"path": e.path, "error": e.error} for e in result.errors],
        "mode": result.mode, "duration": result.duration,
        "fda_ok": result.fda_ok, "started_at": result.started_at,
    }
    return json.dumps(payload)


def loads(text: str) -> ScanResult:
    payload = json.loads(text)
    if payload.get("schema") != SCHEMA:
        raise SchemaMismatch("expected schema {}".format(SCHEMA))
    return ScanResult(
        root=_node_from_dict(payload["root"]) if payload.get("root") else None,
        findings=tuple(
            Finding(category=f["category"], title=f["title"], path=f["path"],
                    bytes_=f["bytes"], risk=Risk(f["risk"]),
                    detail=f.get("detail", ""),
                    reclaim_hint=f.get("reclaim_hint", ""))
            for f in payload.get("findings", [])
        ),
        volumes=tuple(
            VolumeInfo(mount=v["mount"], total=v["total"], used=v["used"],
                       free=v["free"], purgeable=v.get("purgeable"))
            for v in payload.get("volumes", [])
        ),
        errors=tuple(
            ScanError(path=e["path"], error=e["error"])
            for e in payload.get("errors", [])
        ),
        mode=payload.get("mode", "fast"),
        duration=payload.get("duration", 0.0),
        fda_ok=payload.get("fda_ok", True),
        started_at=payload.get("started_at", 0.0),
    )


def cache_path() -> str:
    return os.path.expanduser("~/.cache/storagescan/last.json")


def save(result: ScanResult, path: Optional[str] = None) -> str:
    path = path or cache_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(dumps(result))
    return path


def load_cached(path: Optional[str] = None) -> Optional[ScanResult]:
    """Return the cached scan, or None if it is absent, corrupt, or stale."""
    path = path or cache_path()
    try:
        with open(path, "r") as handle:
            return loads(handle.read())
    except (OSError, ValueError, KeyError, SchemaMismatch):
        return None


def _flatten(node: Optional[Node], into: Dict[str, int]) -> Dict[str, int]:
    if node is None:
        return into
    into[node.path] = node.size
    for child in node.children:
        _flatten(child, into)
    return into


def diff(old: ScanResult, new: ScanResult) -> Tuple[Tuple[str, int], ...]:
    """Per-path size change between two scans, biggest movers first."""
    before = _flatten(old.root, {})
    after = _flatten(new.root, {})
    changes: List[Tuple[str, int]] = []
    for path in set(before) | set(after):
        delta = after.get(path, 0) - before.get(path, 0)
        if delta:
            changes.append((path, delta))
    changes.sort(key=lambda item: abs(item[1]), reverse=True)
    return tuple(changes)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add storagescan/serialize.py tests/test_serialize.py
git commit -m "feat: add scan serialization, caching, and diff"
```

---

### Task 10: Deletion actions

**Files:**
- Create: `storagescan/actions.py`
- Test: `tests/test_actions.py`

**Interfaces:**
- Consumes: `safety.classify`, `safety.confirmation_for`, `model.Risk`
- Produces:
  - `actions.ActionOutcome(path, risk, status, bytes_, message)` — frozen dataclass; `status` in `{"trashed", "purged", "refused", "declined", "dry-run", "failed", "changed"}`
  - `actions.trash_path(path, *, trash_dir=None) -> str` — collision-safe destination
  - `actions.perform(path, *, home, scan_roots, category=None, confirm, dry_run=False, use_trash=True, trash_dir=None, log_path=None) -> ActionOutcome`
  - `actions.log_path() -> str` — `~/.local/state/storagescan/actions.log`
  - `confirm` is a callable `(path, risk, mode) -> bool`, so tests and the TUI supply their own prompt

Guard: a module-level `_assert_test_safe` check is not needed if tests only use tempdirs, but `perform` re-`stat`s the path immediately before acting and returns `"changed"` if size or inode moved since the caller measured it.

- [ ] **Step 1: Write the failing test**

Create `tests/test_actions.py`:

```python
from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from storagescan import actions
from storagescan.model import Risk


def always(_path, _risk, _mode):
    return True


def never(_path, _risk, _mode):
    return False


class PerformTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.trash = os.path.join(self.home, ".Trash")
        os.makedirs(self.trash)
        self.log = os.path.join(self.home, "actions.log")
        self.kw = dict(home=self.home, scan_roots=(self.home,),
                       trash_dir=self.trash, log_path=self.log)

    def make(self, relpath, size=100, category="homebrew.cache"):
        path = os.path.join(self.home, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(b"x" * size)
        return path, category

    def test_safe_file_is_moved_to_trash(self):
        path, category = self.make("Library/Caches/Homebrew/a.bin")
        outcome = actions.perform(path, category=category, confirm=always, **self.kw)
        self.assertEqual(outcome.status, "trashed")
        self.assertFalse(os.path.exists(path))
        self.assertTrue(os.path.exists(os.path.join(self.trash, "a.bin")))

    def test_blocked_path_is_refused_without_prompting(self):
        prompted = []

        def confirm(path, risk, mode):
            prompted.append(path)
            return True

        outcome = actions.perform(self.home, category=None, confirm=confirm, **self.kw)
        self.assertEqual(outcome.status, "refused")
        self.assertEqual(prompted, [])
        self.assertTrue(os.path.isdir(self.home))

    def test_declining_leaves_the_file(self):
        path, category = self.make("Library/Caches/Homebrew/a.bin")
        outcome = actions.perform(path, category=category, confirm=never, **self.kw)
        self.assertEqual(outcome.status, "declined")
        self.assertTrue(os.path.exists(path))

    def test_dry_run_never_touches_the_filesystem(self):
        path, category = self.make("Library/Caches/Homebrew/a.bin")
        outcome = actions.perform(path, category=category, confirm=always,
                                  dry_run=True, **self.kw)
        self.assertEqual(outcome.status, "dry-run")
        self.assertTrue(os.path.exists(path))

    def test_purge_removes_permanently(self):
        path, category = self.make("Library/Caches/Homebrew/a.bin")
        outcome = actions.perform(path, category=category, confirm=always,
                                  use_trash=False, **self.kw)
        self.assertEqual(outcome.status, "purged")
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(os.path.join(self.trash, "a.bin")))

    def test_symlink_is_refused(self):
        real, category = self.make("Library/Caches/Homebrew/real.bin")
        link = os.path.join(self.home, "Library/Caches/Homebrew/link.bin")
        os.symlink(real, link)
        outcome = actions.perform(link, category=category, confirm=always, **self.kw)
        self.assertEqual(outcome.status, "refused")
        self.assertTrue(os.path.exists(real))

    def test_missing_path_fails_cleanly(self):
        outcome = actions.perform(os.path.join(self.home, "Library/Caches/Homebrew/x"),
                                  category="homebrew.cache", confirm=always, **self.kw)
        self.assertEqual(outcome.status, "failed")

    def test_confirmation_mode_matches_risk_tier(self):
        modes = []

        def confirm(path, risk, mode):
            modes.append(mode)
            return True

        safe, _ = self.make("Library/Caches/Homebrew/a.bin")
        actions.perform(safe, category="homebrew.cache", confirm=confirm, **self.kw)
        review, _ = self.make("Downloads/b.dmg")
        actions.perform(review, category="downloads", confirm=confirm, **self.kw)
        danger, _ = self.make("Movies/c.mov")
        actions.perform(danger, category=None, confirm=confirm, **self.kw)
        self.assertEqual(modes, ["single", "recap", "retype"])

    def test_trash_collision_gets_a_suffix(self):
        with open(os.path.join(self.trash, "a.bin"), "wb") as handle:
            handle.write(b"old")
        path, category = self.make("Library/Caches/Homebrew/a.bin")
        actions.perform(path, category=category, confirm=always, **self.kw)
        names = sorted(os.listdir(self.trash))
        self.assertEqual(len(names), 2)

    def test_every_action_is_logged(self):
        path, category = self.make("Library/Caches/Homebrew/a.bin")
        actions.perform(path, category=category, confirm=always, **self.kw)
        with open(self.log) as handle:
            body = handle.read()
        self.assertIn("trashed", body)
        self.assertIn("~/Library/Caches/Homebrew/a.bin", body)
        self.assertNotIn(self.home, body)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_actions -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.actions'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/actions.py`:

```python
"""Deletion. Trash first, permanent only on request, never without consent.

Nothing here decides policy — safety.classify does. This module only enforces
the decision and records what happened.
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

Confirm = Callable[[str, Risk, str], bool]


@dataclass(frozen=True)
class ActionOutcome:
    path: str
    risk: Risk
    status: str      # trashed | purged | refused | declined | dry-run | failed | changed
    bytes_: int = 0
    message: str = ""


def log_path() -> str:
    return os.path.expanduser("~/.local/state/storagescan/actions.log")


def _log(outcome: ActionOutcome, home: str, path: Optional[str]) -> None:
    path = path or log_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as handle:
            handle.write("{}\t{}\t{}\t{}\n".format(
                time.strftime("%Y-%m-%dT%H:%M:%S"),
                outcome.status,
                human_bytes(outcome.bytes_),
                redact(outcome.path, home),
            ))
    except OSError:
        pass  # logging must never block the action


def trash_path(path: str, *, trash_dir: Optional[str] = None) -> str:
    """Destination inside the Trash, suffixed if a name already exists."""
    trash_dir = trash_dir or os.path.expanduser("~/.Trash")
    base = os.path.basename(path.rstrip("/"))
    candidate = os.path.join(trash_dir, base)
    if not os.path.lexists(candidate):
        return candidate
    stamp = time.strftime("%Y-%m-%d %H.%M.%S")
    root, ext = os.path.splitext(base)
    return os.path.join(trash_dir, "{} {}{}".format(root, stamp, ext))


def _size_of(path: str) -> int:
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    if not os.path.isdir(path):
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
    log_path_override: Optional[str] = None,
    log_path: Optional[str] = None,
) -> ActionOutcome:
    """Delete ``path`` after classifying it and obtaining consent."""
    log_target = log_path or log_path_override

    is_symlink = os.path.islink(path)
    risk = classify(path, category, home=home, scan_roots=scan_roots,
                    is_symlink=is_symlink)

    if risk is Risk.BLOCKED:
        outcome = ActionOutcome(path, risk, "refused",
                                message="storagescan will not delete this path")
        _log(outcome, home, log_target)
        return outcome

    if not os.path.lexists(path):
        outcome = ActionOutcome(path, risk, "failed", message="path does not exist")
        _log(outcome, home, log_target)
        return outcome

    size = _size_of(path)

    if not confirm(path, risk, confirmation_for(risk)):
        outcome = ActionOutcome(path, risk, "declined", bytes_=size)
        _log(outcome, home, log_target)
        return outcome

    if dry_run:
        outcome = ActionOutcome(path, risk, "dry-run", bytes_=size)
        _log(outcome, home, log_target)
        return outcome

    # Re-check immediately before acting: the tree may have moved since the scan.
    if not os.path.lexists(path):
        outcome = ActionOutcome(path, risk, "changed",
                                message="path vanished before deletion")
        _log(outcome, home, log_target)
        return outcome

    try:
        if use_trash:
            destination = trash_path(path, trash_dir=trash_dir)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            shutil.move(path, destination)
            outcome = ActionOutcome(path, risk, "trashed", bytes_=size,
                                    message=destination)
        elif os.path.isdir(path):
            shutil.rmtree(path)
            outcome = ActionOutcome(path, risk, "purged", bytes_=size)
        else:
            os.remove(path)
            outcome = ActionOutcome(path, risk, "purged", bytes_=size)
    except OSError as exc:
        outcome = ActionOutcome(path, risk, "failed", bytes_=size, message=str(exc))

    _log(outcome, home, log_target)
    return outcome
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS. If `test_every_action_is_logged` fails on the `log_path` keyword, note that `perform` takes `log_path` as a parameter which shadows the module function — rename the module function to `default_log_path()` and update `_log` accordingly, keeping the `log_path=` keyword in `perform`.

- [ ] **Step 5: Commit**

```bash
git add storagescan/actions.py tests/test_actions.py
git commit -m "feat: add trash-first deletion with tiered confirmation"
```

---

### Task 11: Terminal summary output

**Files:**
- Create: `storagescan/ui/term.py`
- Test: `tests/test_term.py`

**Interfaces:**
- Consumes: `model.ScanResult`, `humanize`
- Produces:
  - `term.render(result, *, home, color=True, width=80) -> str`
  - `term.RISK_LABEL: dict` mapping `Risk` to a short marker (`"SAFE"`, `"REVIEW"`, `"DANGER"`, `"BLOCKED"`)

Must never print an unredacted path, and must include the incomplete-scan banner when `fda_ok` is False.

- [ ] **Step 1: Write the failing test**

Create `tests/test_term.py`:

```python
from __future__ import annotations

import unittest

from storagescan.model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo
from storagescan.ui import term

HOME = "/Users/example"


def result(**overrides):
    base = dict(
        root=Node(path=HOME, size=1_000_000_000, apparent=1_000_000_000,
                  count=10, mtime=0.0,
                  children=(Node(path=HOME + "/Library", size=900_000_000,
                                 apparent=900_000_000, count=5, mtime=0.0),)),
        findings=(Finding("homebrew.cache", "Homebrew downloads",
                          HOME + "/Library/Caches/Homebrew",
                          4_200_000_000, Risk.SAFE, "", "brew cleanup -s"),),
        volumes=(VolumeInfo("/System/Volumes/Data", 240_000_000_000,
                            160_000_000_000, 22_000_000_000, purgeable=8_000_000_000),),
        errors=(),
        mode="fast", duration=1.0, fda_ok=True, started_at=0.0,
    )
    base.update(overrides)
    return ScanResult(**base)


class RenderTest(unittest.TestCase):
    def test_includes_free_space_and_top_finding(self):
        out = term.render(result(), home=HOME, color=False)
        self.assertIn("22.0 GB", out)
        self.assertIn("Homebrew", out)
        self.assertIn("4.2 GB", out)

    def test_paths_are_redacted(self):
        out = term.render(result(), home=HOME, color=False)
        self.assertIn("~/Library/Caches/Homebrew", out)
        self.assertNotIn(HOME, out)

    def test_no_ansi_when_color_disabled(self):
        self.assertNotIn("\x1b[", term.render(result(), home=HOME, color=False))

    def test_ansi_present_when_color_enabled(self):
        self.assertIn("\x1b[", term.render(result(), home=HOME, color=True))

    def test_incomplete_banner_when_fda_missing(self):
        out = term.render(result(fda_ok=False), home=HOME, color=False)
        self.assertIn("INCOMPLETE", out)
        self.assertIn("Full Disk Access", out)

    def test_error_count_is_surfaced(self):
        errors = tuple(ScanError("/x/%d" % i, "PermissionError") for i in range(3))
        out = term.render(result(errors=errors), home=HOME, color=False)
        self.assertIn("3", out)
        self.assertIn("unreadable", out.lower())

    def test_empty_result_does_not_crash(self):
        out = term.render(ScanResult(root=None), home=HOME, color=False)
        self.assertIsInstance(out, str)

    def test_risk_labels_are_shown(self):
        out = term.render(result(), home=HOME, color=False)
        self.assertIn("SAFE", out)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_term -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.ui.term'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/ui/term.py`:

```python
"""Colored one-screen summary. The non-interactive view."""

from __future__ import annotations

from typing import List

from ..humanize import human_bytes, redact
from ..model import Risk, ScanResult

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RED = "\x1b[31m"
YELLOW = "\x1b[33m"
GREEN = "\x1b[32m"

RISK_LABEL = {
    Risk.SAFE: "SAFE",
    Risk.REVIEW: "REVIEW",
    Risk.DANGER: "DANGER",
    Risk.BLOCKED: "BLOCKED",
}

_RISK_COLOR = {
    Risk.SAFE: GREEN,
    Risk.REVIEW: YELLOW,
    Risk.DANGER: RED,
    Risk.BLOCKED: DIM,
}


def render(result: ScanResult, *, home: str, color: bool = True,
           width: int = 80) -> str:
    def paint(text, code):
        return "{}{}{}".format(code, text, RESET) if color else text

    lines: List[str] = []

    if not result.fda_ok:
        lines.append(paint("INCOMPLETE SCAN", BOLD + RED))
        lines.append("Full Disk Access is not granted, so Mail, Messages, and")
        lines.append("app containers were skipped. Grant it in:")
        lines.append("  System Settings > Privacy & Security > Full Disk Access")
        lines.append("Add your terminal app, then run storagescan again.")
        lines.append("")

    for volume in result.volumes:
        lines.append("{}  {} free of {}  ({} used{})".format(
            paint(volume.mount, BOLD),
            human_bytes(volume.free),
            human_bytes(volume.total),
            human_bytes(volume.used),
            ", {} purgeable".format(human_bytes(volume.purgeable))
            if volume.purgeable else "",
        ))
    if result.volumes:
        lines.append("")

    if result.root and result.root.children:
        lines.append(paint("Largest directories", BOLD))
        for node in result.root.sorted_children()[:10]:
            lines.append("  {:>10}  {}".format(
                human_bytes(node.size), redact(node.path, home)))
        lines.append("")

    findings = result.findings_by_size()
    if findings:
        lines.append(paint("Reclaimable", BOLD))
        for finding in findings[:15]:
            label = paint(RISK_LABEL[finding.risk], _RISK_COLOR[finding.risk])
            where = redact(finding.path, home) if finding.path else finding.detail
            lines.append("  {:>10}  {:<8}  {}".format(
                human_bytes(finding.bytes_), label, finding.title))
            lines.append("              {}".format(paint(where, DIM)))
        lines.append("")
        lines.append("Safe to reclaim now: {}".format(
            human_bytes(result.reclaimable(Risk.SAFE))))
        lines.append("With review:         {}".format(
            human_bytes(result.reclaimable(Risk.SAFE, Risk.REVIEW))))
        lines.append("")

    if result.errors:
        lines.append(paint(
            "{} items unreadable and not counted".format(len(result.errors)), DIM))

    return "\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add storagescan/ui/term.py tests/test_term.py
git commit -m "feat: add colored terminal summary"
```

---

### Task 12: HTML report with treemap

**Files:**
- Create: `storagescan/ui/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `model.ScanResult`, `humanize`
- Produces:
  - `report.squarify(items, x, y, width, height) -> list` — `items` is a list of `(label, value)`; returns `[(label, value, x, y, w, h), ...]`
  - `report.render(result, *, home, generated_at) -> str` — complete HTML document
  - `report.write(result, *, home, path=None, generated_at) -> str` — writes and returns the path (default `~/.cache/storagescan/report.html`)

Hard requirements enforced by tests: no `http://` or `https://` in the output, no unredacted home paths, theme-aware CSS with an explicit background.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report.py`:

```python
from __future__ import annotations

import os
import re
import shutil
import tempfile
import unittest

from storagescan.model import Finding, Node, Risk, ScanError, ScanResult, VolumeInfo
from storagescan.ui import report

HOME = "/Users/example"


def sample():
    child = Node(path=HOME + "/Library", size=900, apparent=900, count=5, mtime=0.0)
    other = Node(path=HOME + "/Downloads", size=100, apparent=100, count=2, mtime=0.0)
    return ScanResult(
        root=Node(path=HOME, size=1000, apparent=1000, count=7, mtime=0.0,
                  children=(child, other)),
        findings=(Finding("homebrew.cache", "Homebrew downloads",
                          HOME + "/Library/Caches/Homebrew", 4200, Risk.SAFE,
                          "regenerable", "brew cleanup -s"),),
        volumes=(VolumeInfo("/", 1000, 900, 100),),
        errors=(ScanError("/x", "PermissionError"),),
        mode="fast", duration=1.0, fda_ok=True, started_at=0.0,
    )


class SquarifyTest(unittest.TestCase):
    def test_rectangles_cover_the_area(self):
        rects = report.squarify([("a", 60), ("b", 40)], 0, 0, 100, 100)
        total = sum(w * h for _l, _v, _x, _y, w, h in rects)
        self.assertAlmostEqual(total, 10000, delta=1)

    def test_rectangles_do_not_overlap(self):
        rects = report.squarify([("a", 50), ("b", 30), ("c", 20)], 0, 0, 200, 100)
        for i, first in enumerate(rects):
            for second in rects[i + 1:]:
                _l, _v, x1, y1, w1, h1 = first
                _l2, _v2, x2, y2, w2, h2 = second
                separated = (x1 + w1 <= x2 + 1e-6 or x2 + w2 <= x1 + 1e-6
                             or y1 + h1 <= y2 + 1e-6 or y2 + h2 <= y1 + 1e-6)
                self.assertTrue(separated)

    def test_zero_and_empty_inputs_are_safe(self):
        self.assertEqual(report.squarify([], 0, 0, 100, 100), [])
        self.assertEqual(report.squarify([("a", 0)], 0, 0, 100, 100), [])


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.html = report.render(sample(), home=HOME, generated_at=0.0)

    def test_is_a_complete_document(self):
        self.assertIn("<!doctype html>", self.html.lower())
        self.assertIn("</html>", self.html.lower())

    def test_contains_no_external_references(self):
        self.assertNotIn("http://", self.html)
        self.assertNotIn("https://", self.html)
        self.assertNotIn("//cdn", self.html)

    def test_leaks_no_home_path(self):
        self.assertNotIn(HOME, self.html)
        self.assertIn("~/Library", self.html)

    def test_contains_a_treemap_svg(self):
        self.assertIn("<svg", self.html)
        self.assertIn("<rect", self.html)

    def test_findings_table_present(self):
        self.assertIn("Homebrew downloads", self.html)
        self.assertIn("brew cleanup -s", self.html)

    def test_escapes_html_in_paths(self):
        evil = ScanResult(root=Node(path=HOME + "/<script>x</script>", size=10,
                                    apparent=10, count=1, mtime=0.0))
        html = report.render(evil, home=HOME, generated_at=0.0)
        self.assertNotIn("<script>x</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_theme_aware_css(self):
        self.assertIn("prefers-color-scheme", self.html)
        self.assertIn("background", self.html)

    def test_incomplete_banner_when_fda_missing(self):
        html = report.render(
            ScanResult(root=None, fda_ok=False), home=HOME, generated_at=0.0)
        self.assertIn("INCOMPLETE", html)


class WriteTest(unittest.TestCase):
    def test_writes_file_and_returns_path(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        target = os.path.join(tmp, "nested", "report.html")
        path = report.write(sample(), home=HOME, path=target, generated_at=0.0)
        self.assertEqual(path, target)
        self.assertTrue(os.path.exists(target))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_report -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.ui.report'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/ui/report.py`:

```python
"""Self-contained HTML report.

No network requests of any kind — inline CSS, inline SVG, no scripts that
fetch. The file is meant to be openable and shareable on its own.
"""

from __future__ import annotations

import html
import os
import time
from typing import List, Optional, Sequence, Tuple

from ..humanize import human_bytes, redact
from ..model import Risk, ScanResult

Rect = Tuple[str, float, float, float, float, float]

_RISK_CLASS = {
    Risk.SAFE: "safe",
    Risk.REVIEW: "review",
    Risk.DANGER: "danger",
    Risk.BLOCKED: "blocked",
}


def squarify(items: Sequence, x: float, y: float,
             width: float, height: float) -> List[Rect]:
    """Slice-and-dice treemap layout.

    Not a true squarified layout, but it tiles the area exactly with no
    overlaps and keeps aspect ratios reasonable by alternating split
    direction on the longer edge.
    """
    items = [(label, float(value)) for label, value in items if value > 0]
    if not items or width <= 0 or height <= 0:
        return []
    items.sort(key=lambda item: item[1], reverse=True)

    rects: List[Rect] = []
    total = sum(value for _label, value in items)
    cx, cy, cw, ch = x, y, width, height

    for index, (label, value) in enumerate(items):
        if index == len(items) - 1:
            rects.append((label, value, cx, cy, cw, ch))
            break
        share = value / total if total else 0
        if cw >= ch:
            w = cw * share
            rects.append((label, value, cx, cy, w, ch))
            cx += w
            cw -= w
        else:
            h = ch * share
            rects.append((label, value, cx, cy, cw, h))
            cy += h
            ch -= h
        total -= value

    return rects


_PALETTE = ["#4c78a8", "#72b7b2", "#54a24b", "#eeca3b", "#e45756",
            "#b279a2", "#ff9da6", "#9d755d"]


def _treemap_svg(result: ScanResult, home: str,
                 width: int = 900, height: int = 420) -> str:
    if not result.root or not result.root.children:
        return ""
    items = [(redact(n.path, home), n.size)
             for n in result.root.sorted_children()[:14]]
    parts = ['<svg viewBox="0 0 {} {}" role="img" aria-label="Directory treemap">'
             .format(width, height)]
    for index, (label, value, rx, ry, rw, rh) in enumerate(
            squarify(items, 0, 0, width, height)):
        color = _PALETTE[index % len(_PALETTE)]
        parts.append(
            '<rect x="{:.1f}" y="{:.1f}" width="{:.1f}" height="{:.1f}" '
            'fill="{}" stroke="var(--bg)" stroke-width="2"><title>{} — {}</title>'
            '</rect>'.format(rx, ry, rw, rh, color,
                             html.escape(label), human_bytes(int(value))))
        if rw > 90 and rh > 34:
            parts.append(
                '<text x="{:.1f}" y="{:.1f}" fill="#fff" font-size="13">{}</text>'
                .format(rx + 8, ry + 22,
                        html.escape(os.path.basename(label) or label)))
            parts.append(
                '<text x="{:.1f}" y="{:.1f}" fill="#fff" font-size="12" '
                'opacity="0.8">{}</text>'.format(
                    rx + 8, ry + 40, human_bytes(int(value))))
    parts.append("</svg>")
    return "".join(parts)


_CSS = """
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #6b6b6b; --line: #e2e2e2;
  --safe: #2f7d32; --review: #a06a00; --danger: #b3261e;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #131417; --fg: #eceff4; --muted: #9aa0aa; --line: #2b2e35;
    --safe: #6fcf7a; --review: #e6b95c; --danger: #ff8b80;
  }
}
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--fg); margin: 0; padding: 2rem 1.25rem;
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif; }
main { max-width: 62rem; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
.sub { color: var(--muted); margin: 0 0 2rem; }
.banner { border: 1px solid var(--danger); color: var(--danger);
  padding: .75rem 1rem; border-radius: 8px; margin-bottom: 1.5rem; }
.cards { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 2rem; }
.card { border: 1px solid var(--line); border-radius: 10px; padding: 1rem 1.25rem;
  min-width: 12rem; }
.card b { display: block; font-size: 1.35rem; }
.card span { color: var(--muted); font-size: .85rem; }
figure { margin: 0 0 2rem; overflow-x: auto; }
svg { display: block; width: 100%; height: auto; min-width: 34rem; }
.wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; min-width: 40rem; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { font-size: .8rem; text-transform: uppercase; letter-spacing: .04em;
  color: var(--muted); }
td.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
code { font: 13px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace;
  color: var(--muted); word-break: break-all; }
.safe { color: var(--safe); } .review { color: var(--review); }
.danger { color: var(--danger); } .blocked { color: var(--muted); }
footer { color: var(--muted); font-size: .85rem; margin-top: 2.5rem; }
"""


def render(result: ScanResult, *, home: str, generated_at: float) -> str:
    esc = html.escape
    volume = result.volumes[0] if result.volumes else None

    cards = []
    if volume:
        cards.append(('<div class="card"><b>{}</b><span>free of {}</span></div>'
                      .format(human_bytes(volume.free), human_bytes(volume.total))))
        if volume.purgeable:
            cards.append('<div class="card"><b>{}</b><span>purgeable</span></div>'
                         .format(human_bytes(volume.purgeable)))
    cards.append('<div class="card"><b>{}</b><span>safe to reclaim</span></div>'
                 .format(human_bytes(result.reclaimable(Risk.SAFE))))
    cards.append('<div class="card"><b>{}</b><span>with review</span></div>'
                 .format(human_bytes(result.reclaimable(Risk.SAFE, Risk.REVIEW))))

    rows = []
    for finding in result.findings_by_size():
        where = redact(finding.path, home) if finding.path else finding.detail
        hint = ('<br><code>{}</code>'.format(esc(finding.reclaim_hint))
                if finding.reclaim_hint else "")
        rows.append(
            "<tr><td class=\"num\">{}</td><td class=\"{}\">{}</td>"
            "<td>{}<br><code>{}</code>{}</td></tr>".format(
                human_bytes(finding.bytes_),
                _RISK_CLASS[finding.risk],
                finding.risk.value,
                esc(finding.title),
                esc(where),
                hint,
            ))

    banner = ""
    if not result.fda_ok:
        banner = ('<div class="banner"><b>INCOMPLETE</b> — Full Disk Access was not '
                  'granted, so Mail, Messages, and app containers were skipped. '
                  'Grant it under System Settings &rsaquo; Privacy &amp; Security '
                  '&rsaquo; Full Disk Access and scan again.</div>')

    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>storagescan report</title>\n<style>{css}</style>\n</head>\n<body>\n"
        "<main>\n<h1>storagescan report</h1>\n"
        "<p class=\"sub\">{mode} scan &middot; {generated} &middot; {seconds}</p>\n"
        "{banner}\n<div class=\"cards\">{cards}</div>\n"
        "<figure>{svg}</figure>\n"
        "<div class=\"wrap\"><table>\n<thead><tr><th>Size</th><th>Risk</th>"
        "<th>What</th></tr></thead>\n<tbody>{rows}</tbody>\n</table></div>\n"
        "<footer>{errors} items were unreadable and are not counted in these "
        "totals.</footer>\n</main>\n</body>\n</html>\n"
    ).format(
        css=_CSS,
        mode=esc(result.mode),
        generated=time.strftime("%Y-%m-%d %H:%M", time.localtime(generated_at)),
        seconds="{:.1f}s".format(result.duration),
        banner=banner,
        cards="".join(cards),
        svg=_treemap_svg(result, home),
        rows="".join(rows) or "<tr><td colspan=\"3\">No findings.</td></tr>",
        errors=len(result.errors),
    )


def default_report_path() -> str:
    return os.path.expanduser("~/.cache/storagescan/report.html")


def write(result: ScanResult, *, home: str, generated_at: float,
          path: Optional[str] = None) -> str:
    path = path or default_report_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(render(result, home=home, generated_at=generated_at))
    return path
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add storagescan/ui/report.py tests/test_report.py
git commit -m "feat: add self-contained HTML report with treemap"
```

---

### Task 13: Curses TUI

**Files:**
- Create: `storagescan/ui/tui.py`
- Test: `tests/test_tui.py`

**Interfaces:**
- Consumes: `model`, `humanize`, `safety`, `actions`, `report`
- Produces:
  - `tui.TreeState(root)` — pure navigation state, no curses: `.rows()`, `.select(delta)`, `.enter()`, `.up()`, `.current()`, `.sort_key` toggling, `.view` in `{"tree", "findings"}`
  - `tui.format_row(node_or_finding, *, home, total, width) -> str`
  - `tui.run(result, *, home, config) -> None` — the curses entry point
  - `tui.MIN_SIZE = (60, 15)`

Only `TreeState` and `format_row` are unit tested — `run` is a thin curses shell verified manually. That split is deliberate: it keeps all the logic testable without a pty.

- [ ] **Step 1: Write the failing test**

Create `tests/test_tui.py`:

```python
from __future__ import annotations

import unittest

from storagescan.model import Finding, Node, Risk, ScanResult
from storagescan.ui import tui

HOME = "/Users/example"


def tree():
    deep = Node(path=HOME + "/Library/Caches", size=400, apparent=400,
                count=2, mtime=0.0)
    lib = Node(path=HOME + "/Library", size=900, apparent=900, count=5,
               mtime=0.0, children=(deep,))
    dls = Node(path=HOME + "/Downloads", size=100, apparent=100, count=2, mtime=0.0)
    return Node(path=HOME, size=1000, apparent=1000, count=7, mtime=0.0,
                children=(lib, dls))


def result():
    return ScanResult(
        root=tree(),
        findings=(
            Finding("downloads", "Downloads", HOME + "/Downloads", 100, Risk.REVIEW),
            Finding("homebrew.cache", "Homebrew", HOME + "/Library/Caches/Homebrew",
                    900, Risk.SAFE),
        ),
    )


class TreeStateTest(unittest.TestCase):
    def test_rows_are_children_sorted_by_size(self):
        state = tui.TreeState(result())
        self.assertEqual([r.path for r in state.rows()],
                         [HOME + "/Library", HOME + "/Downloads"])

    def test_select_moves_and_clamps(self):
        state = tui.TreeState(result())
        self.assertEqual(state.index, 0)
        state.select(1)
        self.assertEqual(state.index, 1)
        state.select(5)
        self.assertEqual(state.index, 1)
        state.select(-99)
        self.assertEqual(state.index, 0)

    def test_enter_descends_and_up_returns(self):
        state = tui.TreeState(result())
        state.enter()
        self.assertEqual(state.current_dir().path, HOME + "/Library")
        state.up()
        self.assertEqual(state.current_dir().path, HOME)

    def test_up_at_root_is_a_noop(self):
        state = tui.TreeState(result())
        state.up()
        self.assertEqual(state.current_dir().path, HOME)

    def test_enter_on_leaf_is_a_noop(self):
        state = tui.TreeState(result())
        state.select(1)  # Downloads, no children
        state.enter()
        self.assertEqual(state.current_dir().path, HOME)

    def test_enter_resets_selection(self):
        state = tui.TreeState(result())
        state.select(1)
        state.index = 0
        state.enter()
        self.assertEqual(state.index, 0)

    def test_sort_toggles_between_size_and_name(self):
        state = tui.TreeState(result())
        state.toggle_sort()
        self.assertEqual(state.sort_key, "name")
        self.assertEqual([r.path for r in state.rows()],
                         [HOME + "/Downloads", HOME + "/Library"])
        state.toggle_sort()
        self.assertEqual(state.sort_key, "size")

    def test_findings_view_lists_findings_by_size(self):
        state = tui.TreeState(result())
        state.toggle_view()
        self.assertEqual(state.view, "findings")
        self.assertEqual([f.category for f in state.rows()],
                         ["homebrew.cache", "downloads"])

    def test_current_returns_selected_row_in_either_view(self):
        state = tui.TreeState(result())
        self.assertEqual(state.current().path, HOME + "/Library")
        state.toggle_view()
        self.assertEqual(state.current().category, "homebrew.cache")

    def test_empty_result_has_no_rows_and_does_not_crash(self):
        state = tui.TreeState(ScanResult(root=None))
        self.assertEqual(state.rows(), ())
        self.assertIsNone(state.current())
        state.select(1)
        state.enter()
        state.up()


class FormatRowTest(unittest.TestCase):
    def test_includes_size_bar_and_name(self):
        node = Node(path=HOME + "/Library", size=900, apparent=900,
                    count=5, mtime=0.0)
        row = tui.format_row(node, home=HOME, total=1000, width=70)
        self.assertIn("Library", row)
        self.assertIn("900 B", row)
        self.assertIn("90%", row)
        self.assertLessEqual(len(row), 70)

    def test_zero_total_does_not_divide_by_zero(self):
        node = Node(path=HOME + "/x", size=0, apparent=0, count=0, mtime=0.0)
        self.assertIn("0%", tui.format_row(node, home=HOME, total=0, width=70))

    def test_long_names_are_truncated_to_width(self):
        node = Node(path=HOME + "/" + "n" * 200, size=1, apparent=1,
                    count=1, mtime=0.0)
        row = tui.format_row(node, home=HOME, total=10, width=60)
        self.assertLessEqual(len(row), 60)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_tui -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.ui.tui'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/ui/tui.py`:

```python
"""Interactive curses browser.

Navigation state lives in TreeState, which knows nothing about curses. That
keeps every behavior unit-testable without a pty; ``run`` is a thin shell that
draws TreeState and dispatches keys.
"""

from __future__ import annotations

import curses
import os
import time
from typing import Optional, Sequence, Tuple

from .. import actions
from ..humanize import human_bytes, redact
from ..model import Finding, Node, Risk, ScanResult
from ..safety import confirmation_for
from . import report as report_module

MIN_SIZE = (60, 15)

_RISK_MARK = {
    Risk.SAFE: "SAFE",
    Risk.REVIEW: "REVW",
    Risk.DANGER: "DNGR",
    Risk.BLOCKED: "----",
}


class TreeState:
    """Pure navigation state. No curses, no I/O."""

    def __init__(self, result: ScanResult):
        self.result = result
        self.stack = [result.root] if result.root else []
        self.index = 0
        self.sort_key = "size"
        self.view = "tree"

    def current_dir(self) -> Optional[Node]:
        return self.stack[-1] if self.stack else None

    def rows(self) -> Tuple:
        if self.view == "findings":
            return self.result.findings_by_size()
        node = self.current_dir()
        if node is None:
            return ()
        if self.sort_key == "name":
            return tuple(sorted(node.children, key=lambda n: n.path))
        return node.sorted_children()

    def current(self):
        rows = self.rows()
        if not rows:
            return None
        return rows[min(self.index, len(rows) - 1)]

    def select(self, delta: int) -> None:
        rows = self.rows()
        if not rows:
            self.index = 0
            return
        self.index = max(0, min(len(rows) - 1, self.index + delta))

    def enter(self) -> None:
        if self.view != "tree":
            return
        row = self.current()
        if isinstance(row, Node) and row.children:
            self.stack.append(row)
            self.index = 0

    def up(self) -> None:
        if self.view == "tree" and len(self.stack) > 1:
            self.stack.pop()
            self.index = 0

    def toggle_sort(self) -> None:
        self.sort_key = "name" if self.sort_key == "size" else "size"
        self.index = 0

    def toggle_view(self) -> None:
        self.view = "findings" if self.view == "tree" else "tree"
        self.index = 0


def format_row(row, *, home: str, total: int, width: int) -> str:
    """One display line, guaranteed to fit inside ``width``."""
    if isinstance(row, Finding):
        size = row.bytes_
        label = row.title
        mark = _RISK_MARK[row.risk] + " "
    else:
        size = row.size
        label = os.path.basename(redact(row.path, home)) or redact(row.path, home)
        mark = ""

    pct = int(round(100.0 * size / total)) if total else 0
    bar_width = max(6, min(24, width - 46))
    filled = int(round(bar_width * (pct / 100.0)))
    bar = "#" * filled + "." * (bar_width - filled)

    prefix = "{}{:>10}  {}  {:>3}%  ".format(mark, human_bytes(size), bar, pct)
    room = max(0, width - len(prefix))
    if len(label) > room:
        label = label[: max(0, room - 1)] + "…"
    return (prefix + label)[:width]


def _prompt(stdscr, message: str) -> str:
    height, width = stdscr.getmaxyx()
    stdscr.move(height - 1, 0)
    stdscr.clrtoeol()
    stdscr.addnstr(height - 1, 0, message, width - 1)
    curses.echo()
    try:
        return stdscr.getstr(height - 1, min(len(message) + 1, width - 2), 200).decode(
            "utf-8", "replace")
    finally:
        curses.noecho()


def _confirm_factory(stdscr, home):
    def confirm(path: str, risk: Risk, mode: str) -> bool:
        shown = redact(path, home)
        if mode == "single":
            return _prompt(stdscr, "Delete {} to Trash? [y/N] ".format(
                shown)).strip().lower().startswith("y")
        if mode == "recap":
            return _prompt(stdscr, "Delete {} to Trash? [y/N] ".format(
                shown)).strip().lower().startswith("y")
        if mode == "retype":
            typed = _prompt(stdscr, "Looks irreplaceable. Retype the path to confirm: ")
            return typed.strip() in (shown, path)
        return False
    return confirm


def _draw(stdscr, state: TreeState, home: str, status: str) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    volume = state.result.volumes[0] if state.result.volumes else None

    header = "storagescan"
    if volume:
        header += "  {} free of {}".format(
            human_bytes(volume.free), human_bytes(volume.total))
    if not state.result.fda_ok:
        header += "  [INCOMPLETE: no Full Disk Access]"
    stdscr.addnstr(0, 0, header.ljust(width - 1), width - 1, curses.A_BOLD)

    node = state.current_dir()
    where = redact(node.path, home) if node else "(no scan)"
    stdscr.addnstr(1, 0, "{}  [{}]".format(where, state.view), width - 1)

    rows = state.rows()
    total = max((getattr(r, "size", None) or getattr(r, "bytes_", 0)) for r in rows) \
        if rows else 0
    body_height = max(1, height - 4)
    start = max(0, state.index - body_height + 1)

    for offset, row in enumerate(rows[start:start + body_height]):
        line = format_row(row, home=home, total=total, width=width - 1)
        attr = curses.A_REVERSE if start + offset == state.index else curses.A_NORMAL
        stdscr.addnstr(2 + offset, 0, line.ljust(width - 1), width - 1, attr)

    footer = status or ("↑↓ move  → enter  ← up  d delete  "
                        "f findings  r report  s sort  q quit")
    stdscr.addnstr(height - 1, 0, footer[:width - 1], width - 1, curses.A_DIM)
    stdscr.refresh()


def _loop(stdscr, result: ScanResult, home: str, config) -> None:
    curses.curs_set(0)
    state = TreeState(result)
    status = ""

    while True:
        height, width = stdscr.getmaxyx()
        if width < MIN_SIZE[0] or height < MIN_SIZE[1]:
            stdscr.erase()
            stdscr.addnstr(0, 0, "Terminal too small.", max(1, width - 1))
            stdscr.refresh()
            if stdscr.getch() in (ord("q"), 27):
                return
            continue

        _draw(stdscr, state, home, status)
        status = ""
        key = stdscr.getch()

        if key in (ord("q"), 27):
            return
        elif key in (curses.KEY_DOWN, ord("j")):
            state.select(1)
        elif key in (curses.KEY_UP, ord("k")):
            state.select(-1)
        elif key in (curses.KEY_RIGHT, ord("l"), 10, 13):
            state.enter()
        elif key in (curses.KEY_LEFT, ord("h")):
            state.up()
        elif key == ord("s"):
            state.toggle_sort()
        elif key == ord("f"):
            state.toggle_view()
        elif key == ord("r"):
            path = report_module.write(result, home=home, generated_at=time.time())
            os.system("open {}".format("'" + path.replace("'", "'\\''") + "'"))
            status = "Report written to {}".format(redact(path, home))
        elif key == ord("d"):
            row = state.current()
            if row is None:
                continue
            path = row.path if getattr(row, "path", None) else None
            if not path:
                status = "This finding has no deletable path — see its command."
                continue
            category = row.category if isinstance(row, Finding) else None
            if category == "apfs.snapshot":
                status = "Snapshots are report-only; run the tmutil command shown."
                continue
            outcome = actions.perform(
                path, home=home, scan_roots=config.expanded_scan_paths(),
                category=category, confirm=_confirm_factory(stdscr, home),
                use_trash=config.trash_by_default)
            status = "{}: {} ({})".format(
                outcome.status, redact(outcome.path, home),
                human_bytes(outcome.bytes_))


def run(result: ScanResult, *, home: str, config) -> None:
    curses.wrapper(_loop, result, home, config)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add storagescan/ui/tui.py tests/test_tui.py
git commit -m "feat: add curses tree browser"
```

---

### Task 14: CLI orchestration

**Files:**
- Create: `storagescan/cli.py`, `storagescan/__main__.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: everything
- Produces:
  - `cli.build_parser() -> argparse.ArgumentParser`
  - `cli.check_fda(home) -> bool` — attempts to read `~/Library/Mail`; True when readable or absent
  - `cli.run_scan(config, args, *, home, now) -> ScanResult`
  - `cli.main(argv=None) -> int` — exit codes `0` ok, `1` scan error, `2` usage
  - `storagescan/__main__.py` calls `sys.exit(cli.main())`

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli.py`:

```python
from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout

from storagescan import cli, serialize
from tests.support import build_tree


class ParserTest(unittest.TestCase):
    def test_defaults(self):
        args = cli.build_parser().parse_args([])
        self.assertFalse(args.deep)
        self.assertFalse(args.json)
        self.assertFalse(args.dry_run)

    def test_flags(self):
        args = cli.build_parser().parse_args(
            ["--deep", "--json", "--no-color", "--dry-run"])
        self.assertTrue(args.deep)
        self.assertTrue(args.json)
        self.assertTrue(args.no_color)
        self.assertTrue(args.dry_run)

    def test_repeatable_path(self):
        args = cli.build_parser().parse_args(["--path", "/a", "--path", "/b"])
        self.assertEqual(args.path, ["/a", "/b"])

    def test_bad_flag_exits_two(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.build_parser().parse_args(["--nope"])
        self.assertEqual(ctx.exception.code, 2)


class RunScanTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        build_tree(self.home, {
            "Library": {"Caches": {"Homebrew": {"big": 2_000_000}}},
            "Downloads": {"a.dmg": 3_000_000},
        })

    def scan(self, argv):
        from storagescan.config import Config
        config = Config(scan_paths=(self.home,), fast_depth=4)
        args = cli.build_parser().parse_args(argv)
        return cli.run_scan(config, args, home=self.home, now=1_800_000_000.0)

    def test_fast_scan_produces_a_tree_and_findings(self):
        result = self.scan([])
        self.assertIsNotNone(result.root)
        self.assertEqual(result.mode, "fast")
        self.assertTrue(result.findings)

    def test_deep_mode_is_labelled(self):
        self.assertEqual(self.scan(["--deep"]).mode, "deep")

    def test_scan_never_raises_on_unreadable_paths(self):
        secret = os.path.join(self.home, "secret")
        os.makedirs(secret)
        os.chmod(secret, 0)
        self.addCleanup(os.chmod, secret, 0o700)
        result = self.scan([])
        self.assertIsNotNone(result.root)


class MainTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        build_tree(self.home, {"Downloads": {"a.dmg": 2_000_000}})
        self.cache = os.path.join(self.home, "cache.json")

    def base_argv(self, extra):
        return ["--path", self.home, "--cache-file", self.cache,
                "--no-color"] + extra

    def test_json_output_is_valid_and_parses_back(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(self.base_argv(["--json"]))
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["schema"], serialize.SCHEMA)

    def test_summary_output_is_printed(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(self.base_argv(["--summary"]))
        self.assertEqual(code, 0)
        self.assertIn("Downloads", buffer.getvalue())

    def test_scan_writes_the_cache(self):
        with redirect_stdout(io.StringIO()):
            cli.main(self.base_argv(["--summary"]))
        self.assertTrue(os.path.exists(self.cache))

    def test_cached_reuses_previous_scan(self):
        with redirect_stdout(io.StringIO()):
            cli.main(self.base_argv(["--summary"]))
        shutil.rmtree(os.path.join(self.home, "Downloads"))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(self.base_argv(["--summary", "--cached"]))
        self.assertEqual(code, 0)
        self.assertIn("Downloads", buffer.getvalue())

    def test_cached_without_cache_returns_error(self):
        code = cli.main(["--cache-file", os.path.join(self.home, "none.json"),
                         "--cached", "--summary"])
        self.assertEqual(code, 1)

    def test_report_writes_html(self):
        target = os.path.join(self.home, "r.html")
        with redirect_stdout(io.StringIO()):
            code = cli.main(self.base_argv(
                ["--report", "--report-file", target, "--no-open"]))
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(target))

    def test_bad_config_returns_error_not_traceback(self):
        bad = os.path.join(self.home, "bad.json")
        with open(bad, "w") as handle:
            handle.write("{broken")
        code = cli.main(["--config", bad, "--summary"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_cli -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'storagescan.cli'`

- [ ] **Step 3: Write minimal implementation**

Create `storagescan/cli.py`:

```python
"""Argument parsing and orchestration."""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional

from . import config as config_module
from . import serialize
from .humanize import human_bytes, redact
from .model import Node, ScanResult
from .scan import aging, apfs, dupes, probes, walker
from .ui import report as report_module
from .ui import term


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="storagescan",
        description="Find where your macOS disk space went.")
    parser.add_argument("--deep", action="store_true",
                        help="unlimited depth, plus duplicate and stale-file analysis")
    parser.add_argument("--summary", action="store_true",
                        help="print the text summary instead of opening the browser UI")
    parser.add_argument("--report", action="store_true",
                        help="write the HTML report and open it")
    parser.add_argument("--json", action="store_true",
                        help="write machine-readable JSON to stdout")
    parser.add_argument("--cached", action="store_true",
                        help="reuse the previous scan instead of rescanning")
    parser.add_argument("--diff", action="store_true",
                        help="compare this scan against the previous one")
    parser.add_argument("--path", action="append", default=None, metavar="DIR",
                        help="scan this directory (repeatable)")
    parser.add_argument("--dry-run", action="store_true",
                        help="never modify anything")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-open", action="store_true",
                        help="write the report but do not open it")
    parser.add_argument("--config", default=None, metavar="FILE")
    parser.add_argument("--cache-file", default=None, metavar="FILE")
    parser.add_argument("--report-file", default=None, metavar="FILE")
    return parser


def check_fda(home: str) -> bool:
    """True when protected locations are readable (or simply absent)."""
    probe = os.path.join(home, "Library", "Mail")
    if not os.path.exists(probe):
        return True
    try:
        os.listdir(probe)
        return True
    except OSError:
        return False


def run_scan(cfg, args, *, home: str, now: float) -> ScanResult:
    started = time.time()
    errors: List = []
    roots = tuple(args.path) if args.path else cfg.expanded_scan_paths()
    excludes = cfg.expanded_excludes()
    max_depth = None if args.deep else cfg.fast_depth

    trees = [walker.walk(root, max_depth=max_depth, exclude=excludes, errors=errors)
             for root in roots]
    if len(trees) == 1:
        root_node: Optional[Node] = trees[0]
    elif trees:
        root_node = Node(
            path=home,
            size=sum(t.size for t in trees),
            apparent=sum(t.apparent for t in trees),
            count=sum(t.count for t in trees),
            mtime=now, children=tuple(trees),
            unreadable=sum(t.unreadable for t in trees),
        )
    else:
        root_node = None

    findings = list(probes.run_probes(home, scan_roots=roots, errors=errors))

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
        fda_ok=check_fda(home),
        started_at=started,
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    home = os.path.expanduser("~")

    try:
        cfg = config_module.load(args.config)
    except config_module.ConfigError as exc:
        print("storagescan: {}".format(exc), file=sys.stderr)
        return 1

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
            return 1
        result = previous
    else:
        try:
            result = run_scan(cfg, args, home=home, now=time.time())
        except OSError as exc:
            print("storagescan: scan failed: {}".format(exc), file=sys.stderr)
            return 1
        serialize.save(result, args.cache_file)

    if args.json:
        print(serialize.dumps(result))
        return 0

    if args.diff and previous is not None and not args.cached:
        print("Changes since the previous scan:")
        for path, delta in serialize.diff(previous, result)[:20]:
            sign = "+" if delta > 0 else "-"
            print("  {}{:>10}  {}".format(
                sign, human_bytes(abs(delta)), redact(path, home)))
        print("")

    if args.report:
        path = report_module.write(result, home=home, generated_at=time.time(),
                                   path=args.report_file)
        print("Report written to {}".format(redact(path, home)))
        if not args.no_open:
            os.system("open {}".format("'" + path.replace("'", "'\\''") + "'"))
        return 0

    if args.summary or not sys.stdout.isatty():
        print(term.render(result, home=home, color=not args.no_color))
        return 0

    from .ui import tui
    tui.run(result, home=home, config=cfg)
    return 0
```

Create `storagescan/__main__.py`:

```python
import sys

from .cli import main

sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS

Then a real end-to-end check:
Run: `python3 -m storagescan --summary --no-color`
Expected: a real summary of your home directory, no traceback

- [ ] **Step 5: Commit**

```bash
git add storagescan/cli.py storagescan/__main__.py tests/test_cli.py
git commit -m "feat: add CLI orchestration"
```

---

### Task 15: Bash launcher and preflight

**Files:**
- Create: `storagescan` (executable)
- Test: `tests/test_launcher.py`

**Interfaces:**
- Consumes: `storagescan/cli.py` via `python3 -m storagescan`
- Produces: an executable `./storagescan` that exits `3` with an actionable message when `python3` is unusable, and otherwise passes every argument through unchanged

The `/usr/bin/python3` stub on a Mac without Command Line Tools triggers a GUI installer prompt and returns non-zero — the launcher must detect that and print the fix rather than let it surface as a traceback.

- [ ] **Step 1: Write the failing test**

Create `tests/test_launcher.py`:

```python
from __future__ import annotations

import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER = os.path.join(ROOT, "storagescan")


class LauncherTest(unittest.TestCase):
    def test_launcher_exists_and_is_executable(self):
        self.assertTrue(os.path.exists(LAUNCHER))
        self.assertTrue(os.access(LAUNCHER, os.X_OK))

    def test_help_passes_through_to_python(self):
        proc = subprocess.run([LAUNCHER, "--help"], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=60)
        self.assertEqual(proc.returncode, 0)
        self.assertIn(b"storagescan", proc.stdout)
        self.assertIn(b"--deep", proc.stdout)

    def test_missing_python_exits_three_with_guidance(self):
        env = dict(os.environ)
        env["STORAGESCAN_PYTHON"] = "/nonexistent/python3"
        proc = subprocess.run([LAUNCHER, "--help"], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, env=env, timeout=60)
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"xcode-select --install", proc.stdout)

    def test_arguments_reach_the_cli(self):
        proc = subprocess.run([LAUNCHER, "--nope"], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=60)
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_launcher -v`
Expected: FAIL — launcher does not exist

- [ ] **Step 3: Write minimal implementation**

Create `storagescan`:

```bash
#!/bin/bash
# storagescan — find where your macOS disk space went.
#
# This launcher only does preflight. All logic is in the Python package.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${STORAGESCAN_PYTHON:-python3}"

# /usr/bin/python3 on a Mac without Command Line Tools is a stub that pops an
# installer dialog and fails. Detect that here rather than letting it surface
# as an unreadable error later.
if ! "$python_bin" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
        >/dev/null 2>&1; then
  cat <<'MESSAGE'
storagescan needs Python 3.9 or newer, which macOS provides with the Apple
Command Line Tools. Install them with:

    xcode-select --install

Then run storagescan again. (If you have Python elsewhere, point at it with
STORAGESCAN_PYTHON=/path/to/python3.)
MESSAGE
  exit 3
fi

exec "$python_bin" -m storagescan "$@"
```

Then:

```bash
chmod +x storagescan
```

Note: `exec python3 -m storagescan` requires the package to be importable. Add `PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}"` before the `exec` so the launcher works from any working directory.

- [ ] **Step 4: Add PYTHONPATH and run tests**

Change the final line to:

```bash
export PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}"
exec "$python_bin" -m storagescan "$@"
```

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS, full suite green

Then verify from a different directory:
Run: `cd /tmp && /Users/$(id -un)/Developer/macOS_Storage_Scanner/storagescan --summary --no-color | head -20`
Expected: a summary, no import error

- [ ] **Step 5: Commit**

```bash
git add storagescan tests/test_launcher.py
git commit -m "feat: add bash launcher with python preflight"
```

---

### Task 16: README and repo polish

**Files:**
- Modify: `README.md`
- Create: `docs/screenshots/.gitkeep`

**Interfaces:**
- Consumes: the finished CLI
- Produces: public-facing documentation

- [ ] **Step 1: Verify the full suite and capture real output**

Run: `python3 -m unittest discover -s tests -t . -v 2>&1 | tail -5`
Expected: `OK`

Run: `./storagescan --summary --no-color > /tmp/storagescan-sample.txt && head -30 /tmp/storagescan-sample.txt`
Expected: real output to quote in the README — **redact anything machine-specific before pasting it in**

- [ ] **Step 2: Write the README**

Replace `README.md` with:

````markdown
# storagescan

Find where your macOS disk space actually went.

macOS tells you the disk is full. The Storage pane shows a few fat, useless
bars. `storagescan` shows you the real answer: the directory tree, the caches
and build products you forgot about, and the APFS snapshots and purgeable
space that no directory walk can see.

- **Zero install.** Python 3.9 standard library only — nothing to `pip install`.
- **Read-only by default.** Nothing is deleted without you confirming it.
- **Trash first.** Deletions are reversible unless you ask for `--purge`.
- **Honest totals.** Anything unreadable is counted and reported, not hidden.

## Quick start

```bash
git clone https://github.com/<your-account>/macOS_Storage_Scanner.git
cd macOS_Storage_Scanner
./storagescan
```

That runs a fast scan (about 30 seconds) and opens the interactive browser.

```
 storagescan  ~/  ·  156.2 GB used  ·  22.1 GB free
 ─────────────────────────────────────────────────────────────────────────
   Library                    68.4 GB  ████████████████░░░░░░░░  43%
 ▸ Developer                  31.2 GB  ███████░░░░░░░░░░░░░░░░░  20%
   Downloads                  12.8 GB  ███░░░░░░░░░░░░░░░░░░░░░   8%
 ─────────────────────────────────────────────────────────────────────────
 ↑↓ move  → enter  ← up  d delete  f findings  r report  s sort  q quit
```

Press `f` for the findings list — everything reclaimable, biggest first.
Press `r` to write a standalone HTML report you can open in a browser.

## Usage

```
storagescan                 fast scan, then the interactive browser
storagescan --deep          unlimited depth, plus duplicates and stale files
storagescan --summary       plain text summary instead of the browser
storagescan --report        write the HTML report and open it
storagescan --json          machine-readable output
storagescan --cached        reuse the previous scan, instantly
storagescan --diff          show what grew since the last scan
storagescan --path DIR      scan a specific directory (repeatable)
storagescan --dry-run       never modify anything
```

## Full Disk Access

Without it, macOS hides Mail, Messages, and app containers from every tool,
including this one. `storagescan` detects that, warns you, marks the scan
`INCOMPLETE`, and keeps going.

To grant it: **System Settings → Privacy & Security → Full Disk Access**, then
add your terminal app and restart it.

## What it looks for

Beyond the directory tree, `storagescan` probes the usual suspects:

| Category | Examples |
|---|---|
| APFS | Local Time Machine snapshots, purgeable space |
| Developer | Xcode DerivedData, Archives, iOS DeviceSupport, Simulator devices, `node_modules`, npm/pnpm/yarn/pip/cargo/Go caches, Homebrew |
| Virtualization | Docker disk image, OrbStack, Parallels, UTM |
| Apple apps | iOS device backups, Mail attachments, browser caches |
| General | Trash, Downloads, per-app caches, duplicates, large stale files |

## Safety

Deletion uses escalating confirmation based on where a file lives, never on
its size or extension:

| Tier | What it covers | What you have to do |
|---|---|---|
| 🟢 **Safe** | Regenerable caches and build products | press `y` |
| 🟡 **Review** | Probably disposable user data | press `y`, with a size and date recap |
| 🔴 **Danger** | Anything that looks irreplaceable | retype the full path |
| ⛔ **Blocked** | `~`, `/`, `~/Documents`, `~/Desktop`, `~/Library`, volume roots | not offered at all |

Deletions move to the Trash by default. Every action is logged to
`~/.local/state/storagescan/actions.log`. APFS snapshots are report-only —
`storagescan` shows you the `tmutil` command instead of running it, because
that one is not reversible.

## Configuration

Optional, at `~/.config/storagescan/config.json`:

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

## Development

```bash
python3 -m unittest discover -s tests -t . -v
```

No dependencies, no build step, no virtualenv.

## Roadmap

**Next up**

- **Scheduled monitoring** — an optional `launchd` agent that scans weekly and
  notifies you when free space crosses a threshold, so the first warning comes
  from `storagescan` rather than from macOS at the worst possible moment.

**Five ideas further out**

1. **Storage blame** — a daily size ledger, so `storagescan blame --since 2w`
   can attribute growth to specific directories the way `git blame` attributes
   lines to commits.
2. **Exhaustion forecasting** — fit per-directory growth rates and project the
   date you hit zero, naming the directory responsible: *"14 days, and it's
   DerivedData."*
3. **Clone-based deduplication** — rather than deleting duplicates, replace
   them with APFS `clonefile(2)` clones. You reclaim the space and every file
   stays exactly where it was.
4. **Uninstall residue tracing** — point it at an `.app` and it finds every
   artifact left behind across Containers, Application Support, Caches,
   Preferences, and LaunchAgents.
5. **Anonymized storage fingerprint** — export a path-free, category-only
   profile and compare it against community medians: *"your Xcode caches are
   in the 97th percentile."*

## License

MIT. See [LICENSE](LICENSE).
````

- [ ] **Step 3: Verify no personal data leaked into the repo**

Run: `grep -rn "$(id -un)" --exclude-dir=.git . ; echo "exit: $?"`
Expected: no matches (exit 1 from grep)

Run: `grep -rniE "/Users/[a-z]" --exclude-dir=.git --exclude-dir=docs . | grep -v "/Users/example"`
Expected: no output

- [ ] **Step 4: Run the full suite one final time**

Run: `python3 -m unittest discover -s tests -t . -v 2>&1 | tail -3`
Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add README.md docs/screenshots/.gitkeep
git commit -m "docs: add README with usage, safety model, and roadmap"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| Constraints (3.9, stdlib, no sudo, public hygiene) | Global Constraints; verified in Task 16 Step 3 |
| `model.py` shapes | Task 2 |
| `safety.py` tiered policy + BLOCKED floor | Task 3 |
| Configuration | Task 4 |
| `scan/walker.py` | Task 5 |
| `scan/apfs.py` | Task 6 |
| `scan/probes.py` | Task 7 |
| `scan/dupes.py`, `scan/aging.py` | Task 8 |
| Caching, `--diff` | Task 9 |
| `actions.py` Trash-first + action log | Task 10 |
| `ui/term.py` | Task 11 |
| `ui/report.py` self-contained HTML | Task 12 |
| `ui/tui.py` curses browser | Task 13 |
| CLI surface, exit codes, FDA detection | Task 14 |
| Bash launcher, exit code 3 | Task 15 |
| README, LICENSE, future work | Tasks 1 and 16 |

No gaps.

**Type consistency:** `Finding.bytes_` is used consistently (never `Finding.bytes`) except in the JSON payload, where the key is `"bytes"` and is mapped explicitly in `serialize`. `dir_size` returns `(size, apparent, count)` everywhere. `classify` is always called with keyword-only `home` and `scan_roots`. `confirm` is always `(path, risk, mode) -> bool`.

**Known rough edges deliberately left as steps rather than hidden:** Task 5 Step 3 writes a recursive walker that Step 4 replaces with an explicit stack; Task 7 Step 3 contains a deliberate pattern typo fixed in Step 4; Task 10 Step 4 flags the `log_path` name collision; Task 15 Step 3 omits `PYTHONPATH`, added in Step 4. Each is a real correctness issue the implementer should encounter and fix with the test suite as the check.
