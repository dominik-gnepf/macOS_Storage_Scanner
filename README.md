# storagescan

Find where your macOS disk space actually went.

macOS tells you the disk is full. The Storage pane shows a few fat, unhelpful
bars and a "System Data" blob that explains nothing. `storagescan` gives you
the real answer: the directory tree, the caches and build products you forgot
about, and the APFS snapshots and unaccounted space that no directory walk can
see on its own.

```
Reclaimable
     14.8 GB  SAFE      Simulator devices and caches
              ~/Library/Developer/CoreSimulator/Devices
              $ xcrun simctl delete unavailable
      7.9 GB  SAFE      npm cache
              ~/.npm
              $ npm cache clean --force
      6.1 GB  SAFE      iOS DeviceSupport
              ~/Library/Developer/Xcode/iOS DeviceSupport

Safe to reclaim now: 37.9 GB
```

- **Zero install.** Python 3.9 standard library only — nothing to `pip install`.
- **Nothing is deleted without you confirming it**, and deletions go to the
  Trash unless you explicitly ask otherwise.
- **Honest totals.** Anything unreadable or skipped is counted and reported,
  never quietly dropped.
- **Safe around cloud storage.** OneDrive and iCloud folders are skipped by
  default, because scanning them is slow and reading a placeholder file makes
  your sync client *download* it.

## Quick start

```bash
git clone https://github.com/dominik-gnepf/macOS_Storage_Scanner.git
cd macOS_Storage_Scanner
./bin/storagescan
```

A fast scan takes about 30 seconds on a full 250 GB disk, then opens an
interactive browser:

```
 storagescan   12.2 GB free of 245.1 GB
 ~/   [tree view, sorted by size]
───────────────────────────────────────────────────────────────────────
     79.1 GB  ######################..  79%  Library
      7.9 GB  ##......................   8%  .npm
      5.9 GB  #.......................   6%  .vscode
      4.2 GB  #.......................   4%  Developer
───────────────────────────────────────────────────────────────────────
 ^v move   > enter   < up   d delete   f findings   r report   s sort   q quit
```

Press `f` for the findings list — everything reclaimable, biggest first.
Press `r` to write a standalone HTML report with a treemap.
Press `d` to delete the selected item, with confirmation scaled to the risk.

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
storagescan --include-cloud scan OneDrive/iCloud too (slow; may download files)
storagescan --dry-run       never modify anything
storagescan --workers N     parallel scan threads (default 8)
```

## Full Disk Access

Without it, macOS hides Downloads, Mail, Messages, and app containers from
every tool, including this one — it returns "operation not permitted" on
directories that plainly exist. `storagescan` detects this, warns you, marks
the scan `INCOMPLETE`, and keeps going rather than reporting a confident wrong
number.

To grant it: **System Settings → Privacy & Security → Full Disk Access**, add
your terminal app, then restart the terminal.

## What it looks for

Beyond the directory tree, `storagescan` probes the usual suspects:

| Category | Examples |
|---|---|
| APFS | Local Time Machine snapshots, macOS update snapshots, unaccounted space |
| Developer | Xcode DerivedData, Archives, iOS DeviceSupport, Simulator devices, `node_modules`, npm/pnpm/yarn/pip/cargo/Go/Gradle caches, Homebrew, Android SDK |
| Virtualization | Docker disk image, OrbStack, Parallels, UTM, VMware |
| Apple apps | iOS device backups, Mail attachments, Photos library, browser caches |
| General | Trash, Downloads, per-app caches, duplicate files, large stale files |

Adding a probe is one line in `storagescan/scan/probes.py`.

## Safety

Deletion uses escalating confirmation based on **where a file lives**, never
on its size or extension:

| Tier | What it covers | What you have to do |
|---|---|---|
| 🟢 **Safe** | Regenerable caches and build products | press `y` |
| 🟡 **Review** | Probably disposable user data | press `y`, with a size recap |
| 🔴 **Danger** | Anything that looks irreplaceable | retype the full path |
| ⛔ **Blocked** | `~`, `/`, `~/Documents`, `~/Desktop`, `~/Library`, volume roots, anything outside the scan, any symlink | not offered at all |

An unmatched path is **Danger**, never Safe — the tool fails toward caution.

Deletions move to the Trash by default. Every action is logged to
`~/.local/state/storagescan/actions.log`. Snapshots are report-only:
`storagescan` prints the `tmutil` command rather than running it, because that
one cannot be undone from the Trash.

## A note on the numbers

Two sizes exist for every file, and they differ a lot on APFS:

- **On disk** (`st_blocks`) — what you actually get back by deleting it.
- **Apparent** (`st_size`) — what the file claims to be.

`storagescan` reports on-disk size. This matters most for cloud files: a
OneDrive placeholder reports 437 KB but occupies **zero** blocks. Reporting
apparent size would blame your sync folder for gigabytes it isn't using.

Where the volume reports more space used than the scan can attribute, that gap
is shown as **unaccounted** rather than guessed at. It is usually snapshots,
other volumes sharing the APFS container, or paths that could not be read.
macOS exposes no supported command-line way to read "purgeable" space, so this
tool does not pretend to.

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

214 tests, no dependencies, no build step, no virtualenv. `safety.py` is pure
and carries an exhaustive table test — if you change deletion policy, that is
the file and those are the tests.

## Roadmap

**Next up**

- **Scheduled monitoring** — an optional `launchd` agent that scans weekly and
  notifies you when free space crosses a threshold, so the first warning comes
  from `storagescan` rather than from macOS at the worst possible moment.

**Five ideas further out**

1. **Storage blame** — a daily size ledger, so `storagescan blame --since 2w`
   attributes growth to specific directories the way `git blame` attributes
   lines to commits.
2. **Exhaustion forecasting** — fit per-directory growth rates and project the
   date you hit zero, naming the culprit: *"14 days, and it's DerivedData."*
3. **Clone-based deduplication** — instead of deleting duplicates, replace them
   with APFS `clonefile(2)` clones. You reclaim the space and every file stays
   exactly where it was.
4. **Uninstall residue tracing** — point it at an `.app` and it finds every
   artifact left behind across Containers, Application Support, Caches,
   Preferences, and LaunchAgents.
5. **Anonymized storage fingerprint** — export a path-free, category-only
   profile and compare against community medians: *"your Xcode caches are in
   the 97th percentile."*

## License

MIT. See [LICENSE](LICENSE).
