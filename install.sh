#!/usr/bin/env bash
# portwave — interactive installer for Linux and macOS
# Prompts for paths, writes ~/.config/portwave/config.env, builds the release
# binary, installs it to the chosen prefix, and bundles the top-ports list
# under <prefix>/../share/portwave/ports/ so the binary finds it automatically.
#
# Non-interactive mode: set NONINTERACTIVE=1 to accept every default silently.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
say()  { printf "${C_GREEN}==>${C_RESET} %s\n" "$*"; }
warn() { printf "${C_YELLOW}[!]${C_RESET} %s\n" "$*"; }
die()  { printf "${C_RED}[x]${C_RESET} %s\n" "$*" >&2; exit 1; }

NONINTERACTIVE="${NONINTERACTIVE:-0}"

ask() {
  # ask "Prompt" "default"  -> echoes answer
  local prompt="$1"; local default="${2:-}"; local reply
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    echo "$default"; return
  fi
  if [[ -n "$default" ]]; then
    read -r -p "$(printf "${C_BOLD}?${C_RESET} %s [%s]: " "$prompt" "$default")" reply
    echo "${reply:-$default}"
  else
    read -r -p "$(printf "${C_BOLD}?${C_RESET} %s: " "$prompt")" reply
    echo "$reply"
  fi
}

# Return the first existing binary from a list of candidates.
find_bin() {
  local name="$1"; shift
  local p
  p="$(command -v "$name" 2>/dev/null || true)"
  if [[ -n "$p" ]]; then echo "$p"; return; fi
  for candidate in "$@"; do
    if [[ -x "$candidate" ]]; then echo "$candidate"; return; fi
  done
  echo ""
}

# Build a wide list of plausible places httpx / nuclei might live on Linux and macOS.
tool_candidates() {
  local name="$1"
  local -a dirs=(
    "$HOME/go/bin"
    "$HOME/.local/bin"
    "/opt/homebrew/bin"
    "/usr/local/bin"
    "/usr/local/go/bin"
    "/opt/local/bin"               # MacPorts
    "/home/go/bin"                 # user-specified non-standard path
    "${GOBIN:-}"
    "${GOPATH:-}/bin"
  )
  # Also scan any /home/<user>/go/bin for multi-user boxes.
  if [[ -d /home ]]; then
    for d in /home/*/go/bin; do
      [[ -d "$d" ]] && dirs+=("$d")
    done
  fi
  local -a out=()
  for d in "${dirs[@]}"; do
    [[ -n "$d" ]] && out+=("$d/$name")
  done
  printf '%s\n' "${out[@]}"
}

# ── 0. OS detection ──
OS="$(uname -s)"
case "$OS" in
  Linux)   PLATFORM="linux"   ;;
  Darwin)  PLATFORM="macos"   ;;
  MINGW*|MSYS*|CYGWIN*) die "Detected Windows shell. Use install.ps1 from PowerShell instead." ;;
  *) warn "Unrecognised OS '$OS'. Proceeding as generic Unix." ; PLATFORM="unix" ;;
esac

printf "\n${C_BOLD}portwave installer${C_RESET} — platform: ${PLATFORM}\n\n"

# ── 1. Rust toolchain ──
if ! command -v cargo >/dev/null 2>&1; then
  warn "cargo not found."
  if [[ "$(ask "Install Rust via rustup now?" "yes")" =~ ^[Yy] ]]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
  else
    die "cargo is required. Install Rust and retry."
  fi
fi
say "cargo: $(cargo --version)"

# ── 2. Default path discovery ──
DEFAULT_OUTPUT="${HOME}/scans"

# Install prefix: prefer locations that are **already on $PATH** so the user
# doesn't get "command not found" after install.
#
# macOS default $PATH includes /usr/local/bin and (on Apple Silicon with Homebrew)
# /opt/homebrew/bin, but NOT ~/.local/bin. On Linux distros vary.
if [[ "$PLATFORM" == "macos" ]]; then
  PREFIX_CANDIDATES=("/opt/homebrew/bin" "/usr/local/bin" "${HOME}/.local/bin")
else
  PREFIX_CANDIDATES=("${HOME}/.local/bin" "/usr/local/bin")
fi
DEFAULT_PREFIX=""
for p in "${PREFIX_CANDIDATES[@]}"; do
  if [[ -w "$p" ]] || { [[ ! -e "$p" ]] && mkdir -p "$p" 2>/dev/null && [[ -w "$p" ]]; }; then
    DEFAULT_PREFIX="$p"; break
  fi
done
[[ -n "$DEFAULT_PREFIX" ]] || DEFAULT_PREFIX="${HOME}/.local/bin"

BUNDLED_PORTS="$REPO_ROOT/ports/portwave-top-ports.txt"

# Smart auto-detect httpx / nuclei across a wide set of plausible locations.
# shellcheck disable=SC2207
HTTPX_CANDIDATES=($(tool_candidates httpx))
NUCLEI_CANDIDATES=($(tool_candidates nuclei))
DEFAULT_HTTPX="$(find_bin httpx  "${HTTPX_CANDIDATES[@]}")"
DEFAULT_NUCLEI="$(find_bin nuclei "${NUCLEI_CANDIDATES[@]}")"

printf "\nConfigure paths (press Enter to accept defaults):\n"
OUTPUT_DIR="$(ask "Scan output directory" "$DEFAULT_OUTPUT")"
# The comprehensive default port list (1400+ ports) is embedded in the
# binary since v0.5.3. Leave this blank to use the embedded list — it's
# also refreshed automatically by `portwave --update`. Only enter a path
# if you maintain a CUSTOM list.
PORTS_FILE="$(ask "Custom ports file (optional — leave blank to use embedded 1400+ ports)" "")"
HTTPX_BIN="$(ask  "Path to httpx  binary (blank to skip)" "$DEFAULT_HTTPX")"
NUCLEI_BIN="$(ask "Path to nuclei binary (blank to skip)" "$DEFAULT_NUCLEI")"
INSTALL_PREFIX="$(ask "Install binary to" "$DEFAULT_PREFIX")"

SHARE_DIR="$(dirname "$INSTALL_PREFIX")/share/portwave"
CONFIG_DIR="${HOME}/.config/portwave"
CONFIG_FILE="${CONFIG_DIR}/config.env"

mkdir -p "$OUTPUT_DIR" "$CONFIG_DIR" "$SHARE_DIR/ports" "$INSTALL_PREFIX"

# ── 3. Build ──
say "Building release binary (this takes ~30–60 s on first run)…"
cargo build --release

BIN_SRC="$REPO_ROOT/target/release/portwave"
[[ -x "$BIN_SRC" ]] || die "Build succeeded but binary not found at $BIN_SRC"

# ── 4. Install artefacts (portable cp + chmod, no GNU-isms) ──
cp "$BIN_SRC" "$INSTALL_PREFIX/portwave"
chmod 755 "$INSTALL_PREFIX/portwave"
cp "$BUNDLED_PORTS" "$SHARE_DIR/ports/portwave-top-ports.txt"
chmod 644 "$SHARE_DIR/ports/portwave-top-ports.txt"

# ── 5. Write config ──
{
  echo "# Generated by portwave install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "PORTWAVE_OUTPUT_DIR=$OUTPUT_DIR"
  # Only write PORTWAVE_PORTS if the user supplied a custom path. Blank =
  # embedded list (the default), which is auto-refreshed by --update.
  [[ -n "$PORTS_FILE" ]] && echo "PORTWAVE_PORTS=$PORTS_FILE"
  [[ -n "$HTTPX_BIN"  ]] && echo "PORTWAVE_HTTPX_BIN=$HTTPX_BIN"
  [[ -n "$NUCLEI_BIN" ]] && echo "PORTWAVE_NUCLEI_BIN=$NUCLEI_BIN"
} > "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"
say "Wrote config: $CONFIG_FILE"

# ── 6. PATH handling — auto-append to the right shell rc when missing ──
on_path=0
case ":$PATH:" in
  *":$INSTALL_PREFIX:"*) on_path=1 ;;
esac

if [[ "$on_path" -eq 0 ]]; then
  # Pick the user's likely shell rc based on $SHELL, falling back to what exists.
  rc=""
  case "${SHELL:-}" in
    */zsh)
      rc="${HOME}/.zshrc"
      ;;
    */bash)
      if [[ "$PLATFORM" == "macos" && -f "${HOME}/.bash_profile" ]]; then
        rc="${HOME}/.bash_profile"
      elif [[ -f "${HOME}/.bashrc" ]]; then
        rc="${HOME}/.bashrc"
      elif [[ "$PLATFORM" == "macos" ]]; then
        rc="${HOME}/.bash_profile"
      else
        rc="${HOME}/.bashrc"
      fi
      ;;
    *)
      [[ -f "${HOME}/.zshrc" ]]        && rc="${HOME}/.zshrc"
      [[ -z "$rc" && -f "${HOME}/.bashrc" ]]        && rc="${HOME}/.bashrc"
      [[ -z "$rc" && -f "${HOME}/.bash_profile" ]]  && rc="${HOME}/.bash_profile"
      [[ -z "$rc" ]] && rc="${HOME}/.profile"
      ;;
  esac

  # Is a PATH line for this prefix already present?
  already=0
  if [[ -f "$rc" ]] && grep -Fq "$INSTALL_PREFIX" "$rc" 2>/dev/null; then
    already=1
  fi

  if [[ "$already" -eq 1 ]]; then
    warn "PATH line for $INSTALL_PREFIX already in $rc. Open a new terminal (or: source $rc)."
  else
    ans="$(ask "Append 'export PATH=\"$INSTALL_PREFIX:\$PATH\"' to $rc now?" "yes")"
    if [[ "$ans" =~ ^[Yy] ]]; then
      {
        printf '\n# Added by portwave installer on %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'export PATH="%s:$PATH"\n' "$INSTALL_PREFIX"
      } >> "$rc"
      say "Updated $rc"
      warn "Open a new terminal, OR run:  source $rc   (so portwave is on PATH)"
    else
      warn "$INSTALL_PREFIX is not on \$PATH. Add manually:  export PATH=\"$INSTALL_PREFIX:\$PATH\""
    fi
  fi
fi

# ── 7. Sanity ──
if "$INSTALL_PREFIX/portwave" --version >/dev/null 2>&1; then
  say "Installed: $("$INSTALL_PREFIX/portwave" --version)"
else
  die "Install test failed."
fi

printf "\n${C_GREEN}Done.${C_RESET} Try:  portwave demo 127.0.0.1/32 --no-httpx --no-nuclei\n\n"
