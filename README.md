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

Safe to reclaim now: 36.5 GB
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
./install.sh          # puts `macosscanner` on your PATH
macosscanner
```

`install.sh` only creates a symlink — nothing is copied or compiled, and you
can undo it by deleting the link it prints. It picks a directory that needs no
`sudo`, and tells you the one line to add to `.zshrc` if that directory is not
on your PATH yet.

Skip it if you like and run `./bin/macosscanner` from the checkout instead.

Running it with no arguments opens the menu:

```
  macOS Storage Scanner

  Disk         11.8 GB free of 245.1 GB   (95% used)
  Full access  not granted — parts of your home folder are hidden, so the
               totals below are too low
  Last scan    4 min ago (fast scan)
  Reclaimable  36.1 GB in caches and build files

  1  Scan now                 find what is using space (about a minute)
  2  Browse the last scan     open the interactive browser (instant)
  3  Reclaim safe space       review caches and build files, then Trash them
  4  Save an HTML report      a shareable page with a treemap
  5  Deep scan                also find duplicate and long-untouched files
  6  Grant Full Disk Access   open the right System Settings pane
  7  Weekly early warning     get notified before the disk fills up
  q  Quit

  Choose:
```

Type the number, or the word — `3`, `reclaim` and `rec` all work. Every flag
below still works too, and passing any of them skips the menu.

A fast scan takes about a minute on a full 250 GB disk. Option 2 opens the
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
macosscanner                fast scan, then the interactive browser
macosscanner --deep          unlimited depth, plus duplicates and stale files
macosscanner --summary       plain text summary instead of the browser
macosscanner --report        write the HTML report and open it
macosscanner --json          machine-readable output
macosscanner --cached        reuse the previous scan, instantly
macosscanner --diff          show what grew since the last scan
macosscanner --path DIR      scan a specific directory (repeatable)
macosscanner --reclaim       review every SAFE cache, then Trash them all at once
macosscanner --include-cloud scan OneDrive/iCloud too (slow; may download files)
macosscanner --no-system     skip /Applications, /Library etc (~25s faster)
macosscanner --dry-run       never modify anything
macosscanner --workers N     parallel scan threads (default 8)
macosscanner --no-progress   suppress the scanning progress line
```

### Reclaiming in bulk

`--reclaim` lists every finding in the SAFE tier, shows the total, and moves
them all to the Trash after a single confirmation:

```
These 21 items are caches and build products that regenerate themselves:

     14.8 GB  ~/Library/Developer/CoreSimulator/Devices
      7.9 GB  ~/.npm
      6.1 GB  ~/Library/Developer/Xcode/iOS DeviceSupport
      ...
     36.5 GB  total

Move all 21 to the Trash? [y/N]
```

It refuses to touch anything outside the SAFE tier even if a finding claims
otherwise — every path still goes through `safety.classify` individually.
Add `--dry-run` to see the list without being asked anything.

## Getting warned early

The point of a storage tool is to hear about the problem before macOS raises
it at the worst possible moment. `storagescan` can install a weekly launchd
agent that checks in the background and notifies you only when free space
drops below a threshold:

```bash
macosscanner --install-agent          # weekly check, 20 GB default threshold
macosscanner --agent-status           # is it installed and loaded?
macosscanner --uninstall-agent        # removes the agent and its plist
```

The notification names the problem and the opportunity together:

> **storagescan** — 11.8 GB free. 36.1 GB can be reclaimed from caches.

The scheduled run **only reads and notifies**. It never deletes anything, and
it never will — reclaiming is always something you do deliberately.

Details worth knowing:

- It uses `StartInterval`, not a fixed hour. A calendar job scheduled for
  03:00 is simply skipped if the Mac is asleep then; an interval job runs when
  the machine next wakes.
- `RunAtLoad` is false, so installing it does not immediately start a scan.
- It runs at `Nice 10` with `LowPriorityIO`, so it stays out of the way.
- Output goes to `~/.local/state/storagescan/monitor.log`.
- Change the threshold with `--alert-below 30` (in GB).

You can run the check by hand at any time with `macosscanner --check`.

## Full Disk Access

Without it, macOS hides Downloads, Mail, Messages, and app containers from
every tool, including this one — it returns "operation not permitted" on
directories that plainly exist. `storagescan` detects this, warns you, marks
the scan `INCOMPLETE`, and keeps going rather than reporting a confident wrong
number.

Menu option **6** opens the right System Settings pane for you and prints the
exact steps, naming your actual terminal app rather than a generic
instruction.

No program can grant itself Full Disk Access — that is the entire point of the
permission. What matters, and what trips people up: the permission belongs to
**the terminal app that runs the scanner**, not to the scanner script. Add
Terminal, iTerm, VS Code or whatever you launched it from, then quit and
reopen that app.

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

## Where the space really goes

A home-only scan leaves a large, alarming gap. On the machine this was built
against, the volume reported 180 GB used while the home tree accounted for
about 103 GB — 76 GB unexplained, which is exactly the kind of number that
makes people distrust a tool.

So `storagescan` also measures what sits outside your home folder, without
needing `sudo`:

```
Outside your home folder
     25.1 GB  /Library
     17.5 GB  /Applications
     12.5 GB  ~/Library/CloudStorage
      7.3 GB  /private/var
      1.5 GB  /opt
```

That takes the unexplained remainder from 76 GB down to about 12 GB, which is
snapshots and paths the scan was not permitted to read. Nothing here is
auto-reclaimable — `/Library` and `/private/var` are system-managed and
classify as Danger — but individual applications are listed separately at
Review, since uninstalling an app you do not use is a normal way to get space
back.

Cloud folders are measured too, despite being excluded from the tree walk.
Only files you have actually **downloaded** are counted, because placeholders
occupy zero blocks. Free that space from your sync client by making files
online-only — deleting them locally would delete them from the cloud as well.

Add `--no-system` to skip all of this and save about 25 seconds.

## A note on the numbers

Two sizes exist for every file, and they differ a lot on APFS:

- **On disk** (`st_blocks`) — what you actually get back by deleting it.
- **Apparent** (`st_size`) — what the file claims to be.

Every size in this tool is the on-disk one. The difference is not academic:
`/Applications` on the development machine reports 23.5 GB apparent against
17.5 GB actually occupied.

If you check the numbers with `du`, use `du -sk`, not `du -sxk`. macOS presents
`/Library` and `/Applications` as firmlinks onto the Data volume, so `-x`
refuses to cross and reports 7.8 GB for a `/Library` that really holds 25.1 GB.

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

371 tests, no dependencies, no build step, no virtualenv. `safety.py` is pure
and carries an exhaustive table test — if you change deletion policy, that is
the file and those are the tests.

## Roadmap

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
