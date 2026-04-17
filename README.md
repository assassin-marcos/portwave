# portwave

**Ultra-fast hybrid IPv4 / IPv6 port scanner with adaptive concurrency, banner grab, TLS sniff, and a built-in httpx + nuclei recon pipeline — written in async Rust.**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![Made for bug bounty](https://img.shields.io/badge/built%20for-bug%20bounty-red.svg)]()

> portwave sweeps a CIDR (v4 or v6), finds open TCP ports in a fast first pass, enriches the hits with banner grabs and TLS sniffing, then hands the targets to **httpx** and **nuclei** — all in a single binary. Think of it as a `masscan + rustscan + naabu` replacement with a proper recon pipeline bolted on.

---

## Why portwave?

| | masscan | rustscan | naabu | **portwave** |
|---|---|---|---|---|
| IPv4 scan | ✅ | ✅ | ✅ | ✅ |
| IPv6 scan | ⚠️ | ⚠️ | ✅ | ✅ |
| Adaptive concurrency | ❌ | ❌ | ❌ | ✅ |
| Banner grab + protocol classify | ❌ | ❌ | partial | ✅ |
| TLS sniff on non-443 | ❌ | ❌ | ❌ | ✅ |
| Resume after crash / Ctrl+C | ❌ | ❌ | ❌ | ✅ |
| Built-in httpx + nuclei chain | ❌ | via plugin | via chain | ✅ |
| Per-protocol nuclei tagging | ❌ | ❌ | ❌ | ✅ |
| Structured `scan_summary.json` | ❌ | ❌ | partial | ✅ |
| Single static binary | ✅ | ✅ | ✅ | ✅ |

---

## Features

- **Two-phase scan** — fast TCP discovery (default 600 ms timeout), then per-hit enrichment with passive read + HTTP probe + optional TLS ClientHello.
- **Adaptive concurrency controller** — watches timeout ratio every 2 s and shrinks/grows the worker pool. No manual thread tuning.
- **MPMC work queue via `flume`** — fixed worker pool (memory is `O(threads)`, not `O(IPs × ports)`).
- **Banner-based protocol classifier** — SSH, SMTP, FTP, POP3, IMAP, HTTP, TLS.
- **TLS sniff on any port** — detects TLS on 8443 / 9443 / any custom port and emits `https://` for nuclei.
- **Resume** — append-only `open_ports.jsonl` means re-runs skip already-known open ports.
- **Graceful `Ctrl+C`** — drains workers and flushes outputs before exit.
- **Progress bar + ETA** via `indicatif`; spinner mode auto-engages above 10 M probes.
- **Round-robin across subnets** — interleaves IP iteration across input CIDRs so you don't hammer one /24.
- **Skips broadcast / network addresses** for IPv4 CIDRs.
- **httpx + nuclei integration** — opt-in per-protocol `-tags` for nuclei, configurable concurrency and rate limits, optional path probing.
- **Structured output** — `open_ports.jsonl`, `scan_summary.json`, plus the usual `targets.txt` / `nuclei_targets.txt`.

---

## Install

portwave runs on **Linux, macOS, and Windows**. Pick the installer for your OS.

### Linux / macOS — one-command

```bash
git clone https://github.com/assassin-marcos/portwave
cd portwave
bash install.sh
```

The installer will:
1. Detect / offer to install Rust via `rustup`.
2. Auto-detect `httpx` / `nuclei` on `$PATH`, `~/go/bin`, Homebrew paths (`/opt/homebrew/bin` on Apple Silicon, `/usr/local/bin` on Intel), and `~/.local/bin`.
3. Prompt for: scan output directory, ports file, httpx/nuclei paths, install prefix. Press Enter to accept every default.
4. Build the release binary.
5. Copy it to the first writable prefix from: `~/.local/bin`, `/opt/homebrew/bin` (macOS, Apple Silicon), `/usr/local/bin`.
6. Write `~/.config/portwave/config.env` with your choices.
7. Run `portwave --version` as a sanity check.

Non-interactive mode (accept every default silently):
```bash
NONINTERACTIVE=1 bash install.sh
```

### Windows — one-command (PowerShell)

From an **elevated** PowerShell window (or regular user PowerShell if you want per-user install):

```powershell
git clone https://github.com/assassin-marcos/portwave
cd portwave
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The PowerShell installer will:
1. Detect / offer to download `rustup-init.exe` and install Rust.
2. Auto-detect `httpx.exe` / `nuclei.exe` on `$PATH`, `%USERPROFILE%\go\bin`, `%USERPROFILE%\.local\bin`, and `%ProgramFiles%\{tool}`.
3. Prompt for: scan output dir (default `%USERPROFILE%\scans`), ports file, httpx/nuclei paths, install prefix (default `%USERPROFILE%\.local\bin`).
4. Build with `cargo build --release`.
5. Copy `portwave.exe` to the install prefix.
6. Write `%APPDATA%\portwave\config.env`.
7. Offer to add the install prefix to your user `PATH`.

Non-interactive:
```powershell
$env:NONINTERACTIVE = '1'
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

### Manual (no installer, any OS)

```bash
# build
cargo build --release

# Linux / macOS
install -m 0755 target/release/portwave ~/.local/bin/   # or /usr/local/bin
mkdir -p ~/.local/share/portwave/ports
cp ports/portwave-top-ports.txt ~/.local/share/portwave/ports/
mkdir -p ~/.config/portwave
cp .env.example ~/.config/portwave/config.env
$EDITOR ~/.config/portwave/config.env

# Windows (PowerShell)
Copy-Item target\release\portwave.exe $env:USERPROFILE\.local\bin\
New-Item -ItemType Directory -Force $env:LOCALAPPDATA\portwave\ports | Out-Null
Copy-Item ports\portwave-top-ports.txt $env:LOCALAPPDATA\portwave\ports\
New-Item -ItemType Directory -Force $env:APPDATA\portwave | Out-Null
Copy-Item .env.example $env:APPDATA\portwave\config.env
notepad $env:APPDATA\portwave\config.env
```

### Uninstall

```bash
bash uninstall.sh                                        # Linux / macOS
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 # Windows
```

### Updating to the latest version

Once you have **v0.5.1 or newer** installed, update is a single command on every OS — no source clone, no rebuild, no Rust toolchain needed:

```bash
portwave --update          # download + replace the running binary
portwave --check-update    # just print whether a newer release exists
```

How it works: pulls the prebuilt binary for your OS+arch from the [GitHub Releases](https://github.com/assassin-marcos/portwave/releases) page (built by CI on every tag) and atomically replaces the running executable.

A startup banner reminds you when an update is available — checked at most once every 24 hours, with a 3-second timeout so a slow network never blocks a scan. Disable the banner per run with `--no-update-check`, or globally:

```bash
export PORTWAVE_NO_UPDATE_CHECK=1
```

**First-time upgrade from v0.5.0** (which doesn't have `--update` yet) — one-time manual step:
```bash
cd /path/to/portwave-clone
git pull
bash install.sh   # or .\install.ps1 on Windows
```
After that single rebuild, all future updates use `portwave --update`.

**macOS Gatekeeper note:** binaries downloaded by `--update` aren't notarised. If macOS refuses to launch the new binary, run:
```bash
xattr -d com.apple.quarantine "$(command -v portwave)"
```

### Platform notes

| Platform | FD-limit tuning | Config file location |
|---|---|---|
| Linux   | `setrlimit(RLIMIT_NOFILE, 50000)` on start | `~/.config/portwave/config.env` |
| macOS   | `setrlimit(RLIMIT_NOFILE, 50000)` on start | `~/.config/portwave/config.env` |
| Windows | no-op (Windows doesn't bound sockets by FD limit) | `%APPDATA%\portwave\config.env` |

On Linux, you may also need `ulimit -n 50000` at the shell level if your distro's user limits are below that (check `/etc/security/limits.conf`).

### Dependencies (optional, for the full pipeline)

- [`httpx`](https://github.com/projectdiscovery/httpx) (ProjectDiscovery) — HTTP fingerprinting
- [`nuclei`](https://github.com/projectdiscovery/nuclei) — vulnerability scanning

portwave still runs without them (pass `--no-httpx --no-nuclei`); it just won't do the post-scan enrichment.

---

## Quickstart

```bash
# Scan a single /24 and run the full pipeline
portwave acme_corp 203.0.113.0/24

# Multiple CIDRs (mixed v4 / v6)
portwave acme_corp "203.0.113.0/22,198.51.100.0/24,2001:db8::/120"

# Just port discovery, skip httpx + nuclei
portwave acme_corp 203.0.113.0/24 --no-httpx --no-nuclei

# Custom port list
portwave acme_corp 203.0.113.0/24 --port-file /path/to/ports.txt

# Localhost smoke test
portwave demo 127.0.0.1/32 --no-httpx --no-nuclei
```

---

## Full usage

```text
portwave [OPTIONS] <FOLDER_NAME> <CIDR_INPUT>
```

| Argument | Description |
|---|---|
| `<FOLDER_NAME>` | Subdirectory under your output root (e.g. `acme_corp`, `bounty_target_01`) |
| `<CIDR_INPUT>` | Comma-separated CIDRs, IPv4 or IPv6 (`203.0.113.0/24,2001:db8::/120`) |

| Flag | Default | Purpose |
|---|---|---|
| `--port-file <FILE>` | bundled 427 ports | Comma / whitespace-separated port list |
| `-t, --threads <N>` | `4000` | Max concurrent probes (adaptive controller may shrink) |
| `--timeout-ms <N>` | `600` | Phase-A (discovery) connect timeout |
| `--enrich-timeout-ms <N>` | `1500` | Phase-B (banner / TLS) connect timeout |
| `--retries <N>` | `0` | Retry count for Phase-A timeouts only |
| `--output-dir <PATH>` | from config | Base output directory |
| `--httpx-threads <N>` | `150` | httpx concurrency |
| `--httpx-paths <LIST>` | *(unset)* | Extra paths for httpx to probe (e.g. `/actuator,/.git/HEAD`) |
| `--httpx-follow-redirects` | off | Follow redirects in httpx |
| `--nuclei-concurrency <N>` | `50` | nuclei `-c` |
| `--nuclei-rate <N>` | `200` | nuclei `-rl` rate limit |
| `--tags-from-banner` | off | Pass nuclei `-tags` based on detected protocols |
| `--no-httpx` | off | Skip the httpx step |
| `--no-nuclei` | off | Skip the nuclei step |
| `--no-banner` | off | Skip Phase-B enrichment |
| `--no-tls-sniff` | off | Skip TLS sniff on non-443 ports |
| `--no-adaptive` | off | Disable adaptive concurrency controller |
| `--no-resume` | off | Don't load `open_ports.jsonl` as skip-set |

---

## Real-world example commands

### Bug-bounty wide sweep (/20 or bigger)
```bash
portwave acme_corp "203.0.113.0/20" \
    --threads 3000 \
    --timeout-ms 800 --retries 1 \
    --enrich-timeout-ms 2000 \
    --tags-from-banner \
    --httpx-threads 200 \
    --nuclei-concurrency 40 --nuclei-rate 150
```

### Small, high-accuracy asset list
```bash
portwave vip "1.2.3.0/28" \
    --threads 500 \
    --timeout-ms 1500 --retries 2 \
    --enrich-timeout-ms 3000
```

### Huge IPv6 range — spinner mode
```bash
portwave v6_probe "2001:db8::/96" \
    --threads 6000 --timeout-ms 500 --retries 0
```

### Resume a killed scan
```bash
# Just re-run with the same folder name — open_ports.jsonl is replayed.
portwave acme_corp 203.0.113.0/24
# To force a fresh scan:
portwave acme_corp 203.0.113.0/24 --no-resume
```

### Path probing for framework endpoints
```bash
portwave acme_corp 203.0.113.0/24 \
    --httpx-paths "/actuator,/.git/HEAD,/server-status,/.env,/admin,/api/v1"
```

### Only discovery, no enrichment, no pipeline
```bash
portwave acme_corp 203.0.113.0/24 --no-httpx --no-nuclei --no-banner
```

---

## Output artefacts

Every scan writes to `<OUTPUT_DIR>/<FOLDER_NAME>/`:

| File | Format | Purpose |
|---|---|---|
| `targets.txt` | `ip:port` per line | Raw open endpoints for tooling that wants `IP:PORT` |
| `nuclei_targets.txt` | URLs + `ip:port` | `http://`, `https://`, or `ip:port` — ready for nuclei |
| `open_ports.jsonl` | one JSON per line | Structured: `{ip, port, rtt_ms, tls, protocol, banner}` |
| `scan_summary.json` | single JSON | `{folder, duration_ms, attempts, timeouts, open, by_port, by_protocol, ranges, ports}` |
| `httpx_results.txt` | httpx default | Status, length, redirect, title |
| `nuclei_results.txt` | nuclei default | Vulnerability findings |

Example `open_ports.jsonl`:
```json
{"ip":"203.0.113.42","port":8443,"rtt_ms":84,"tls":true,"protocol":"tls","banner":null}
{"ip":"203.0.113.42","port":22,"rtt_ms":71,"tls":false,"protocol":"ssh","banner":"SSH-2.0-OpenSSH_8.9p1"}
```

Example `scan_summary.json`:
```json
{
  "folder": "acme_corp",
  "duration_ms": 142318,
  "attempts": 109567,
  "timeouts": 412,
  "open": 87,
  "by_port": { "80": 22, "443": 19, "22": 14, "8080": 11, "8443": 9 },
  "by_protocol": { "http": 41, "ssh": 14, "tls": 18, "unknown": 14 },
  "ranges": ["203.0.113.0/24"],
  "ports": 427
}
```

---

## Configuration

portwave looks up paths in this order of precedence:

1. CLI flag (`--output-dir`, `--port-file`, …)
2. Environment variable (`PORTWAVE_OUTPUT_DIR`, `PORTWAVE_PORTS`)
3. `~/.config/portwave/config.env` (created by `install.sh`)
4. Built-in fallback (`./scans` for output, bundled port list for `PORTWAVE_PORTS`)

`~/.config/portwave/config.env` uses simple `KEY=VALUE` lines. See `.env.example`.

```env
PORTWAVE_OUTPUT_DIR=/home/user/scans
PORTWAVE_PORTS=/home/user/.local/share/portwave/ports/portwave-top-ports.txt
PORTWAVE_HTTPX_BIN=/home/user/go/bin/httpx
PORTWAVE_NUCLEI_BIN=/home/user/go/bin/nuclei
```

---

## Performance tips

- **Raise the FD limit** — portwave calls `setrlimit(RLIMIT_NOFILE, 50000)` on start, but your shell may also need `ulimit -n 50000`.
- **Lower `--timeout-ms`** on LAN / local targets: `200`–`400` ms is plenty.
- **Raise `--threads`** only if you have the uplink — the adaptive controller will throttle back if you saturate.
- **Use `--retries 0`** on first sweep, then re-run with `--retries 2` on the same folder to re-check timeouts (resume will skip the confirmed-open).
- **`--tags-from-banner`** can cut nuclei runtime 30–60% on mixed port scans.

---

## How it works (brief)

```
             ┌────────────────────────────┐
CIDR + ports │ Producer: round-robin IPs  │
──────────▶  │ across subnets, push into  │
             │ a bounded flume MPMC queue │
             └──────────────┬─────────────┘
                            │ SocketAddr
                ┌───────────▼────────────┐         ┌──────────────┐
                │  N Phase-A workers     │         │  Adaptive    │
                │  TCP connect + timeout │◀────────┤  monitor     │
                │  + optional retry      │         │  (timeout %) │
                └───────────┬────────────┘         └──────────────┘
                            │ hits (mpsc)
                ┌───────────▼────────────┐
                │ Collector → Phase B    │
                │ banner grab, HTTP probe│
                │ TLS ClientHello sniff  │
                └───────────┬────────────┘
                            │ OpenPort
                ┌───────────▼────────────┐
                │ Writer: dedup + sort + │
                │ BufWriter to targets/  │
                │ nuclei_targets/jsonl   │
                └───────────┬────────────┘
                            │
                ┌───────────▼────────────┐
                │ httpx  → httpx_results │
                │ nuclei → nuclei_results│
                └────────────────────────┘
```

---

## FAQ

**Does portwave do SYN scanning?**
Not yet — portwave uses full TCP connects. SYN scanning requires raw sockets (root / capabilities). For stateless discovery of /16+ ranges, combine portwave with [`masscan`](https://github.com/robertdavidgraham/masscan) and feed its hits into portwave for enrichment.

**Why is port 22 detected but the banner is null?**
SSH sends its banner immediately, so you should see `SSH-2.0-...`. If not, the server had TCP-wrappers / was slow; increase `--enrich-timeout-ms`.

**Is portwave safe to run on my own network?**
Yes — that's what localhost smoke tests are for. Against third-party infrastructure, **only scan with authorization** (bug bounty scope, engagement contract, your own assets). The authors accept no liability for misuse.

**Can I use it from Python / Go?**
Parse `scan_summary.json` and `open_ports.jsonl` — both are stable structured formats.

**Does it work on macOS / Windows?**
Linux is the primary target. The code is mostly portable; `raise_fd_limit()` uses libc `setrlimit` which won't work on Windows. PRs welcome.

---

## Search terms (for folks looking for this kind of tool)

port scanner, port scanning, fast port scanner, rust port scanner, async port scanner, ipv6 port scanner, network scanner, pentest, pentesting, bug bounty, bug bounty tool, recon, reconnaissance, recon pipeline, offensive security, red team, red teaming, nuclei integration, httpx integration, masscan alternative, rustscan alternative, naabu alternative, banner grabber, tls sniffer, cidr scanner, tcp scanner, service detection.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

portwave is a security-research tool. **Only use it on systems you own or have written permission to test.** Unauthorized scanning may be illegal in your jurisdiction. The authors disclaim any liability for misuse.
