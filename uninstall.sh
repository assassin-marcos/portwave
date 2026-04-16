#!/usr/bin/env bash
set -euo pipefail

CANDIDATES=(
  "$HOME/.local/bin/portwave"
  "/usr/local/bin/portwave"
)

echo "portwave uninstaller"
for bin in "${CANDIDATES[@]}"; do
  if [[ -f "$bin" ]]; then
    echo "Removing $bin"
    rm -f "$bin"
  fi
done

SHARES=(
  "$HOME/.local/share/portwave"
  "/usr/local/share/portwave"
)
for d in "${SHARES[@]}"; do
  if [[ -d "$d" ]]; then
    echo "Removing $d"
    rm -rf "$d"
  fi
done

CFG="$HOME/.config/portwave"
if [[ -d "$CFG" ]]; then
  read -r -p "Delete config directory $CFG? [y/N] " a
  [[ "$a" =~ ^[Yy] ]] && rm -rf "$CFG"
fi

read -r -p "Delete scan output directory too? (path: check $CFG/config.env before it was removed) [y/N] " a
if [[ "$a" =~ ^[Yy] ]]; then
  read -r -p "Full path to delete: " p
  [[ -n "$p" && -d "$p" ]] && rm -rf "$p" && echo "Removed $p"
fi
echo "Done."
