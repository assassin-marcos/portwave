#!/usr/bin/env bash
# portwave uninstaller (Linux / macOS) — LEGACY FALLBACK.
#
# Preferred since v0.8.6:   portwave --uninstall
# This script is kept as a zero-binary-dependency escape hatch for
# cases where the portwave binary is missing, corrupt, or otherwise
# unrunnable. Functionally identical to `portwave --uninstall`.
#
# Auto-detects the installed binary via `command -v portwave` plus a list
# of common install prefixes, then removes it and its associated share /
# config directories. If no installation is found, alerts the user and
# exits cleanly without modifying anything.

set -euo pipefail

RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'; RST='\033[0m'
say()  { printf "${GRN}==>${RST} %s\n" "$*"; }
warn() { printf "${YEL}[!]${RST} %s\n" "$*"; }

echo "portwave uninstaller"
echo

# ── 1. Binary discovery ──
# Start with whatever the shell's PATH resolution finds, then add a list
# of well-known install prefixes across Linux + macOS. Resolves symlinks
# so we delete the actual file, not just the link.
CANDIDATES=()

if command -v portwave >/dev/null 2>&1; then
  RESOLVED=$(command -v portwave)
  CANDIDATES+=("$RESOLVED")
  # Follow symlinks to the real target too (covers Homebrew cellar / nix style)
  if command -v readlink >/dev/null 2>&1; then
    REAL=$(readlink -f "$RESOLVED" 2>/dev/null || readlink "$RESOLVED" 2>/dev/null || echo "")
    [[ -n "$REAL" && "$REAL" != "$RESOLVED" && -f "$REAL" ]] && CANDIDATES+=("$REAL")
  fi
fi

CANDIDATES+=(
  "$HOME/.local/bin/portwave"
  "$HOME/bin/portwave"
  "$HOME/.cargo/bin/portwave"
  "/usr/local/bin/portwave"
  "/opt/homebrew/bin/portwave"
  "/opt/local/bin/portwave"
)

# Dedupe — keep only existing files, unique paths.
FOUND=()
declare -A SEEN
for c in "${CANDIDATES[@]}"; do
  if [[ -f "$c" && -z "${SEEN[$c]:-}" ]]; then
    FOUND+=("$c")
    SEEN[$c]=1
  fi
done

if [[ ${#FOUND[@]} -eq 0 ]]; then
  warn "No portwave installation found on this system."
  echo "    Checked via \`command -v portwave\` plus these prefixes:"
  for c in "${CANDIDATES[@]}"; do
    echo "      - $c"
  done
  echo
  warn "If portwave isn't installed yet, run ./install.sh first."
  exit 0
fi

# ── 2. Remove binary / binaries ──
echo "Found ${#FOUND[@]} binary file(s):"
for bin in "${FOUND[@]}"; do
  echo "  - $bin"
done
echo
for bin in "${FOUND[@]}"; do
  rm -f "$bin" && say "removed $bin" || warn "could not remove $bin (check permissions)"
done

# ── 3. Remove share directories (bundled ports, etc.) ──
SHARES=(
  "$HOME/.local/share/portwave"
  "/usr/local/share/portwave"
  "/opt/homebrew/share/portwave"
  "/opt/local/share/portwave"
)
for d in "${SHARES[@]}"; do
  if [[ -d "$d" ]]; then
    rm -rf "$d" && say "removed $d" || warn "could not remove $d"
  fi
done

# ── 4. Config directory (confirm before nuking) ──
CFG="$HOME/.config/portwave"
if [[ -d "$CFG" ]]; then
  read -r -p "Delete config directory $CFG? [y/N] " a
  if [[ "$a" =~ ^[Yy] ]]; then
    rm -rf "$CFG" && say "removed $CFG"
  else
    echo "kept $CFG"
  fi
fi

# ── 5. Cache directory ──
CACHE="$HOME/.cache/portwave"
if [[ -d "$CACHE" ]]; then
  rm -rf "$CACHE" && say "removed $CACHE"
fi

# ── 6. Optional: scan output directory ──
read -r -p "Delete scan output directory too? [y/N] " a
if [[ "$a" =~ ^[Yy] ]]; then
  read -r -p "Full path to delete: " p
  if [[ -n "$p" && -d "$p" ]]; then
    rm -rf "$p" && say "removed $p"
  else
    warn "path not provided or not a directory — skipped"
  fi
fi

echo
say "portwave uninstalled."
