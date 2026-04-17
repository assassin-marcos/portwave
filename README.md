# portwave

**Ultra-fast hybrid IPv4 / IPv6 port scanner with adaptive concurrency, banner grab, TLS sniff, self-update, and a built-in httpx + nuclei recon pipeline — written in async Rust.**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![Built for bug bounty](https://img.shields.io/badge/built%20for-bug%20bounty-red.svg)]()

> portwave sweeps a CIDR (v4 or v6), finds open TCP ports in a fast first pass, enriches the hits with banner grabs and TLS sniffing, then feeds the targets to **httpx** and **nuclei** — all in a single binary. Think of it as a `masscan + rustscan + naabu` replacement with a proper recon pipeline bolted on, plus one-command self-update across Linux/macOS/Windows.

---

## Why portwave

|                                | masscan | rustscan | naabu | **portwave** |
|--------------------------------|---------|----------|-------|--------------|
| IPv4 scan                      | ✅      | ✅       | ✅    | ✅           |
| IPv6 scan                      | ⚠️      | ⚠️       | ✅    | ✅           |
| Adaptive concurrency           | ❌      | ❌       | ❌    | ✅           |
| Banner grab + protocol classify| ❌      | ❌       | partial | ✅         |
| TLS sniff on non-443           | ❌      | ❌       | ❌    | ✅           |
| Resume after crash / Ctrl+C    | ❌      | ❌       | ❌    | ✅           |
| Built-in httpx + nuclei chain  | ❌      | via plugin | via chain | ✅      |
| Per-protocol nuclei tagging    | ❌      | ❌       | ❌    | ✅           |
| Structured `scan_summary.json` | ❌      | ❌       | partial | ✅         |
| **Self-update** (`--update`)   | ❌      | ❌       | ❌    | ✅           |
| Single static binary           | ✅      | ✅       | ✅    | ✅           |

---

## Features

- **Two-phase scan** — fast TCP discovery (default 600 ms timeout), then per-hit enrichment with passive read + HTTP probe + optional TLS ClientHello.
- **Adaptive concurrency controller** — watches the timeout ratio every 2 s and shrinks/grows the worker pool. No manual thread tuning.
- **MPMC work queue via `flume`** — fixed worker pool, memory is `O(threads)` not `O(IPs × ports)`.
- **Banner-based protocol classifier** — SSH, SMTP, FTP, POP3, IMAP, HTTP, TLS.
- **TLS sniff on any port** — detects TLS on 8443 / 9443 / any custom port and emits `https://` for nuclei.
- **Resume** — append-only `open_ports.jsonl` means re-runs skip already-known open ports.
- **Graceful `Ctrl+C`** — drains workers and flushes outputs before exit.
- **Self-update via `--update`** — downloads the prebuilt binary for your OS+arch from the latest GitHub Release and replaces the running executable atomically. Also refreshes any on-disk ports file.
- **Embedded port list** — 1405 curated TCP ports baked into the binary (nmap-top-1000 ∪ bug-bounty/modern-app additions). Override per scan with `--port-file` or globally via `PORTWAVE_PORTS`.
- **Cross-platform** — Linux, macOS (Apple Silicon + Intel), Windows. One binary per platform built by CI.
- **Progress bar + ETA** via `indicatif`; spinner mode auto-engages above 10 M probes.
- **Round-robin across subnets** — interleaves IP iteration across input CIDRs so you don't hammer a single /24.
- **Skips broadcast / network addresses** for IPv4 CIDRs.
- **httpx + nuclei integration** — opt-in per-protocol `-tags` for nuclei; configurable concurrency and rate limits; optional path probing.
- **Structured output** — `targets.txt`, `nuclei_targets.txt`, `open_ports.jsonl`, `scan_summary.json`, plus the standard `httpx_results.txt` and `nuclei_results.txt`.

---

## Install

portwave runs on Linux, macOS, and Windows. Pick the installer for your OS.

### Linux / macOS

```bash
git clone https://github.com/assassin-marcos/portwave
cd portwave
bash install.sh
```

The installer:
1. Detects / offers to install Rust via `rustup`.
2. Auto-detects `httpx` / `nuclei` across `$PATH`, `$HOME/go/bin`, `$HOME/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/local/go/bin`, `/opt/local/bin`, `$GOBIN`, `$GOPATH/bin`, `$HOME/.pdtm/go/bin`, and any `/home/*/go/bin`.
3. Picks an install prefix that is **already on `$PATH`** so the binary is callable immediately:
   - macOS: `/opt/homebrew/bin` (Apple Silicon) → `/usr/local/bin` (Intel) → `~/.local/bin`
   - Linux: `~/.local/bin` → `/usr/local/bin`
4. If the chosen prefix isn't on `$PATH`, asks before appending the right `export PATH` line to `~/.zshrc` (zsh), `~/.bash_profile` (bash on macOS), or `~/.bashrc` (bash on Linux). Idempotent — skips if already present.
5. Builds the release binary and copies it to the prefix.
6. Writes `~/.config/portwave/config.env`.
7. Runs `portwave --version` as a sanity check.

Non-interactive (accept every default silently):
```bash
NONINTERACTIVE=1 bash install.sh
```

### Windows (PowerShell)

```powershell
git clone https://github.com/assassin-marcos/portwave
cd portwave
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The PowerShell installer:
1. Detects / offers to download `rustup-init.exe` and install Rust.
2. Auto-detects `httpx.exe` / `nuclei.exe` across `$PATH`, `%USERPROFILE%\go\bin`, `%USERPROFILE%\.local\bin`, `%ProgramFiles%\{tool}\`.
3. Prompts for: scan output dir (default `%USERPROFILE%\scans`), ports file, httpx/nuclei paths, install prefix (default `%USERPROFILE%\.local\bin`).
4. Builds with `cargo build --release` and copies `portwave.exe` to the prefix.
5. Writes `%APPDATA%\portwave\config.env`.
6. Offers to add the install prefix to your user `PATH`.

Non-interactive:
```powershell
$env:NONINTERACTIVE = '1'; powershell -ExecutionPolicy Bypass -File .\install.ps1
```

### Manual install (any OS, no installer)

```bash
cargo build --release

# Linux / macOS — pick a directory that's on your $PATH:
cp target/release/portwave /usr/local/bin/        # or ~/.local/bin
mkdir -p ~/.config/portwave
cp .env.example ~/.config/portwave/config.env
$EDITOR ~/.config/portwave/config.env

# Windows (PowerShell):
Copy-Item target\release\portwave.exe $env:USERPROFILE\.local\bin\
New-Item -ItemType Directory -Force $env:APPDATA\portwave | Out-Null
Copy-Item .env.example $env:APPDATA\portwave\config.env
notepad $env:APPDATA\portwave\config.env
```

The default 1405-port list is **embedded in the binary** — no separate file is required for scans.

### Uninstall

```bash
bash uninstall.sh                                        # Linux / macOS
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 # Windows
```

---

## Updating

After v0.5.1 is installed, every future update is one command on every OS — no source clone, no rebuild, no Rust toolchain needed:

```bash
portwave --update          # download + replace the running binary, then refresh
                           # any on-disk ports file the install left behind
portwave --check-update    # just print whether a newer release exists
```

How it works: pulls the prebuilt binary for your OS+arch from the [GitHub Releases](https://github.com/assassin-marcos/portwave/releases) page (built by CI on every tag) and atomically replaces the running executable. Also rewrites every on-disk copy of `portwave-top-ports.txt` it finds under the install share dir so config-driven setups stay current.

A startup banner reminds you when an update is available — checked at most once every 24 hours, with a 3-second timeout so a slow network never blocks a scan. Disable per-run with `--no-update-check` or globally:

```bash
export PORTWAVE_NO_UPDATE_CHECK=1
```

**First-time upgrade from v0.5.0** (which doesn't have `--update` yet) — one-time manual step, then `--update` works forever after:
```bash
cd /path/to/portwave-clone
git pull
bash install.sh         # Linux / macOS
# powershell -ExecutionPolicy Bypass -File .\install.ps1   # Windows
```

**macOS Gatekeeper note** — binaries downloaded by `--update` aren't notarised. If macOS refuses to launch the new binary:
```bash
xattr -d com.apple.quarantine "$(command -v portwave)"
```

---

## Quickstart

```bash
# Single /24 with the full pipeline
portwave acme_corp 203.0.113.0/24

# Multiple CIDRs, mixed v4 / v6
portwave acme_corp "203.0.113.0/22,198.51.100.0/24,2001:db8::/120"

# Just port discovery, skip httpx + nuclei
portwave acme_corp 203.0.113.0/24 --no-httpx --no-nuclei

# Custom port list (overrides the embedded 1405)
portwave acme_corp 203.0.113.0/24 --port-file /path/to/ports.txt

# Localhost smoke test
portwave demo 127.0.0.1/32 --no-httpx --no-nuclei
```

---

## Full usage

```text
portwave [OPTIONS] <FOLDER_NAME> <CIDR_INPUT>
portwave --update | --check-update
```

| Argument | Description |
|---|---|
| `<FOLDER_NAME>` | Subdirectory under your output root (e.g. `acme_corp`, `bounty_target_01`) |
| `<CIDR_INPUT>` | Comma-separated CIDRs, IPv4 or IPv6 (`203.0.113.0/24,2001:db8::/120`) |

| Flag | Default | Purpose |
|---|---|---|
| `--port-file <FILE>` | embedded 1405 ports | Comma / whitespace-separated port list |
| `-t, --threads <N>` | `4000` | Max concurrent probes (adaptive controller may shrink) |
| `--timeout-ms <N>` | `600` | Phase-A (discovery) connect timeout |
| `--enrich-timeout-ms <N>` | `1500` | Phase-B (banner / TLS) connect timeout |
| `--retries <N>` | `0` | Retry count for Phase-A timeouts only |
| `--output-dir <PATH>` | from config / env / `./scans` | Base output directory |
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
| `-u, --update` | — | Download latest binary, replace in place, refresh ports file |
| `--check-update` | — | Print whether a newer release exists, then exit |
| `--no-update-check` | off | Suppress the startup "update available" banner |

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

### Huge IPv6 range — spinner mode auto-engages
```bash
portwave v6_probe "2001:db8::/96" \
    --threads 6000 --timeout-ms 500 --retries 0
```

### Resume a killed scan
```bash
# Just re-run with the same folder name — open_ports.jsonl is replayed.
portwave acme_corp 203.0.113.0/24

# Force a fresh scan:
portwave acme_corp 203.0.113.0/24 --no-resume
```

### Path probing for framework endpoints
```bash
portwave acme_corp 203.0.113.0/24 \
    --httpx-paths "/actuator,/.git/HEAD,/server-status,/.env,/admin,/api/v1"
```

### Discovery only, no enrichment, no pipeline
```bash
portwave acme_corp 203.0.113.0/24 --no-httpx --no-nuclei --no-banner
```

---

## Output artefacts

Every scan writes to `<OUTPUT_DIR>/<FOLDER_NAME>/`:

| File | Format | Purpose |
|---|---|---|
| `targets.txt`         | `ip:port` per line       | Raw open endpoints for tooling that wants `IP:PORT` |
| `nuclei_targets.txt`  | URLs + `ip:port`         | `http://`, `https://`, or `ip:port` — ready for nuclei |
| `open_ports.jsonl`    | one JSON per line        | `{ip, port, rtt_ms, tls, protocol, banner}` |
| `scan_summary.json`   | single JSON              | `{folder, duration_ms, attempts, timeouts, open, by_port, by_protocol, ranges, ports}` |
| `httpx_results.txt`   | httpx default format     | Status, length, redirect, title |
| `nuclei_results.txt`  | nuclei default format    | Vulnerability findings |

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
  "ports": 1405
}
```

---

## Configuration

portwave looks up paths in this order of precedence:

1. CLI flag (`--output-dir`, `--port-file`, …)
2. Environment variable (`PORTWAVE_OUTPUT_DIR`, `PORTWAVE_PORTS`)
3. `~/.config/portwave/config.env` (Unix) or `%APPDATA%\portwave\config.env` (Windows) — created by `install.sh` / `install.ps1`
4. Built-in defaults (embedded ports list; `./scans` for output)

`config.env` uses simple `KEY=VALUE` lines. See `.env.example`:

```env
PORTWAVE_OUTPUT_DIR=/home/user/scans
PORTWAVE_PORTS=                          # blank → use embedded 1405-port list
PORTWAVE_HTTPX_BIN=/home/user/go/bin/httpx
PORTWAVE_NUCLEI_BIN=/home/user/go/bin/nuclei
```

---

## Performance tips

- **FD limit** — portwave calls `setrlimit(RLIMIT_NOFILE, 50000)` on Unix. Your shell may also need `ulimit -n 50000` if your distro's per-user limit is lower (check `/etc/security/limits.conf`).
- **Lower `--timeout-ms`** on LAN / local targets: `200`–`400` ms is plenty.
- **Raise `--threads`** only if you have the uplink — the adaptive controller throttles back automatically when timeouts spike past 30 %.
- **Use `--retries 0`** on first sweep, then re-run with `--retries 2` on the same folder to re-check timeouts (resume skips confirmed-open).
- **`--tags-from-banner`** can cut nuclei runtime 30–60 % on mixed-port scans.

---

## How it works

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

## Platform notes

| Platform | FD-limit tuning | Config file |
|---|---|---|
| Linux   | `setrlimit(RLIMIT_NOFILE, 50000)` on start | `~/.config/portwave/config.env` |
| macOS   | `setrlimit(RLIMIT_NOFILE, 50000)` on start | `~/.config/portwave/config.env` |
| Windows | no-op (Windows doesn't bound sockets by FD limit) | `%APPDATA%\portwave\config.env` |

---

## FAQ

**Does portwave do SYN scanning?**
Not yet — portwave uses full TCP connects (no root required, fully portable). SYN scanning needs raw sockets and root/`CAP_NET_RAW`. For stateless discovery of `/16+` ranges, combine portwave with [`masscan`](https://github.com/robertdavidgraham/masscan) and feed its hits into portwave for enrichment.

**Why is port 22 detected but the banner is null?**
SSH sends its banner immediately, so you should see `SSH-2.0-…`. If not, the server uses TCP wrappers or is slow — bump `--enrich-timeout-ms`.

**My VPS scan only finds a couple of ports — bug?**
Almost always one of: (a) services bound to `127.0.0.1` only, not `0.0.0.0`; (b) provider firewall (AWS Security Groups / Hetzner / DO Cloud Firewalls) blocking inbound; (c) host firewall (`ufw`, `firewalld`, `iptables`). Run `ss -tlnp` on the VPS to see what's actually listening externally.

**Is portwave safe to run on my own network?**
Yes. Against third-party infrastructure, **only scan with authorisation** (bug-bounty scope, engagement contract, your own assets). The author accepts no liability for misuse.

**Can I use it from Python / Go?**
Parse `scan_summary.json` and `open_ports.jsonl` — both are stable structured formats.

**Does it work on Docker / a CI runner?**
Yes — single static binary, no system services. `RLIMIT_NOFILE` may be capped low in containers; bump it with `--ulimit nofile=65535` on `docker run`.

---

## Searchable terms

port scanner, port scanning, fast port scanner, rust port scanner, async port scanner, ipv6 port scanner, network scanner, pentest, pentesting, bug bounty, bug bounty tool, recon, reconnaissance, recon pipeline, offensive security, red team, red teaming, nuclei integration, httpx integration, masscan alternative, rustscan alternative, naabu alternative, banner grabber, tls sniffer, cidr scanner, tcp scanner, service detection, self-update, cross-platform.

---

## Author / contact

Developed by **assassin-marcos**.

Found a bug, have an idea, want to suggest a feature, or just want to say hi?
**Reach out on Twitter / X: [@assassin_marcos](https://twitter.com/assassin_marcos)** — I'm always open to improvisations and suggestions.

Pull requests welcome. Open issues at [github.com/assassin-marcos/portwave/issues](https://github.com/assassin-marcos/portwave/issues).

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

portwave is a security-research tool. **Only use it on systems you own or have written permission to test.** Unauthorised scanning may be illegal in your jurisdiction. The author disclaims any liability for misuse.
