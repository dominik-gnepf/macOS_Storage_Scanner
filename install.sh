#!/bin/bash
# Put `macosscanner` on your PATH.
#
# This only creates a symlink. Nothing is copied, nothing is compiled, and
# nothing outside the target directory is touched. Undo it with:
#
#     rm <the symlink this prints>

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
launcher="$here/bin/macosscanner"

if [ ! -x "$launcher" ]; then
  echo "error: $launcher is missing or not executable" >&2
  exit 1
fi

# Prefer a location that needs no sudo. /usr/local/bin is only used when it
# already exists and is writable, which on a Mac usually means Homebrew set
# it up for you.
if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
  target_dir="/usr/local/bin"
else
  target_dir="$HOME/.local/bin"
  mkdir -p "$target_dir"
fi

target="$target_dir/macosscanner"

if [ -e "$target" ] && [ ! -L "$target" ]; then
  echo "error: $target already exists and is not a symlink." >&2
  echo "Move it aside first — this script will not overwrite a real file." >&2
  exit 1
fi

ln -sf "$launcher" "$target"
echo "Linked  $target  ->  $launcher"

case ":$PATH:" in
  *":$target_dir:"*)
    echo
    echo "Ready. Run it with:"
    echo
    echo "    macosscanner"
    ;;
  *)
    shell_rc="$HOME/.zshrc"
    [ -n "${BASH_VERSION:-}" ] && shell_rc="$HOME/.bash_profile"
    echo
    echo "$target_dir is not on your PATH yet. Add it:"
    echo
    echo "    echo 'export PATH=\"$target_dir:\$PATH\"' >> $shell_rc"
    echo "    source $shell_rc"
    echo
    echo "Then run:  macosscanner"
    ;;
esac
