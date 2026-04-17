# portwave

**Ultra-fast, IP-focused hybrid IPv4 / IPv6 port scanner with CDN tagging, adaptive concurrency, banner grab, TLS sniff, self-update, and a built-in httpx + nuclei recon pipeline — written in async Rust.**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![Built for bug bounty](https://img.shields.io/badge/built%20for-bug%20bounty-red.svg)]()
[![Made by assassin_marcos](https://img.shields.io/badge/made%20by-%40assassin__marcos-1da1f2.svg)](https://twitter.com/assassin_marcos)

```
 ____   ___  ____ _______        ___   __     ___________
|  _ \ / _ \|  _ \_   _\ \      / / \ \ \ \   / / ____ __|
| |_) | | | | |_) || |  \ \ /\ / / _ \ \ \ \ / / |__|  _|
|  __/| |_| |  _ < | |   \ V  V / / \ \ \ \ V /|  __||
|_|    \___/|_| \_\|_|    \_/\_/_/   \_\ \_\_/ |_____|
                             portwave · by assassin_marcos
```

> portwave takes CIDRs, IPs, IP ranges, or an ASN — finds open TCP ports in a fast first pass, enriches hits with banner grabs + TLS sniff, tags any IP that belongs to a known CDN/WAF edge network (Cloudflare, Fastly, Akamai, Imperva, Sucuri, Stackpath, BunnyCDN, CacheFly, KeyCDN), then chains **httpx** and **nuclei** — all in a single binary. IP-only input by design: no hostnames, no CDN false-positives via domain fronting.

---

## Why portwave

|                                       | masscan | rustscan | naabu | **portwave** |
|---------------------------------------|---------|----------|-------|--------------|
| IPv4 + IPv6 scanning                  | ⚠️      | ⚠️       | ✅    | ✅           |
| Adaptive concurrency (no self-DoS)    | ❌      | ❌       | ❌    | ✅           |
| Banner grab + protocol classify       | ❌      | ❌       | partial | ✅         |
| TLS sniff on non-443                  | ❌      | ❌       | ❌    | ✅           |
| **CDN / WAF edge tagging**            | ❌      | ❌       | ❌    | ✅           |
| ASN expansion built in                | ❌      | ❌       | ❌    | ✅           |
| Port-range syntax `--ports 8000-9000` | ✅      | ✅       | ✅    | ✅           |
| Exclude list (scope discipline)       | ✅      | ❌       | ✅    | ✅           |
| Resume after crash / Ctrl+C           | ❌      | ❌       | ❌    | ✅           |
| Built-in httpx + nuclei chain         | ❌      | via plugin | via chain | ✅     |
| Structured `scan_summary.json`        | ❌      | ❌       | partial | ✅         |
| **Self-update** (`--update`)          | ❌      | ❌       | ❌    | ✅           |
| Single static cross-platform binary   | ✅      | ✅       | ✅    | ✅           |

---

## Install

Portwave runs on Linux, macOS (Apple Silicon + Intel), and Windows.

### Linux / macOS

```bash
git clone https://github.com/assassin-marcos/portwave
cd portwave
bash install.sh
```

### Windows (PowerShell)

```powershell
git clone https://github.com/assassin-marcos/portwave
cd portwave
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Both installers auto-detect `httpx` / `nuclei` on `$PATH` + `~/go/bin` + `~/.pdtm/go/bin` + Homebrew + MacPorts + `~/.local/bin`, pick an install prefix already on `$PATH`, and offer to append the PATH line to the right shell rc if not. Non-interactive: `NONINTERACTIVE=1`.

### Updating

After v0.5.1+ is installed, every future update is one command on every OS:

```bash
portwave --update          # download + replace binary, refresh any on-disk ports file
portwave --check-update    # just report if a newer version exists
```

The default 1400+ port list is **baked into the binary** — `--update` always ships the current list, no separate file to maintain.

### Uninstall

```bash
bash uninstall.sh                                        # Linux / macOS
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 # Windows
```

---

## Quickstart

```bash
# Single /24, full pipeline (scan → httpx → nuclei)
portwave acme_corp 203.0.113.0/24

# Mixed input: CIDRs + IPs + IP ranges
portwave acme_corp "203.0.113.0/24,1.2.3.4,5.6.7.10-5.6.7.20"

# Targets from a file (CIDRs/IPs/ranges, one per line, # for comments)
portwave acme_corp --input-file scope.txt

# Scan everything a company announces via BGP
portwave cloudflare_infra --asn AS13335

# Specific ports only
portwave acme_corp 203.0.113.0/24 --ports "22,80,443,8000-9000"

# Respect scope — exclude ranges
portwave acme_corp 203.0.113.0/22 --exclude "203.0.113.0/24,203.0.114.0/28"

# Discovery only, no httpx/nuclei chain
portwave acme_corp 203.0.113.0/24 --no-httpx --no-nuclei

# Piped from other tools
cat asn_ranges.txt | portwave acme_corp --input-file -
```

---

## All flags

```text
portwave [OPTIONS] <FOLDER_NAME> [CIDR_INPUT]
portwave --update | --check-update
```

### Targets (at least one required)

| Flag | Example |
|---|---|
| `<CIDR_INPUT>` positional | `203.0.113.0/24`, `1.2.3.4`, `5.6.7.10-5.6.7.20`, or comma-separated mix |
| `--input-file <FILE>` | One target per line, comments with `#` |
| `--asn <LIST>` | `AS13335,AS15169` — expanded via RIPE stat (public, no API key) |
| `--exclude <LIST>` | Same format as `<CIDR_INPUT>` — skipped in the producer |

### Ports

| Flag | Default | Purpose |
|---|---|---|
| `--ports <SPEC>` | — | `22,80,443,8000-9000` style. Overrides `--port-file` and embedded list |
| `--port-file <FILE>` | — | Comma/whitespace-separated |
| *(neither)* | embedded 1433 | Baked-in nmap-top-1000 ∪ bug-bounty service ports |

### Timing / concurrency

| Flag | Default | Purpose |
|---|---|---|
| `-t, --threads <N>` | `1500` | Max concurrent probes. Adaptive controller may shrink on saturation |
| `--timeout-ms <N>` | `800` | Phase-A connect timeout |
| `--enrich-timeout-ms <N>` | `1500` | Phase-B (banner / TLS) timeout |
| `--retries <N>` | `1` | Retries for Phase-A timeouts only (RST / refused never retry) |

### Output

| Flag | Default | Purpose |
|---|---|---|
| `--output-dir <PATH>` | `./scans` (or config) | Base output directory |
| `--no-resume` | off | Don't load `open_ports.jsonl` as a skip-set |

### httpx / nuclei

| Flag | Default |
|---|---|
| `--httpx-threads <N>` | `150` |
| `--httpx-paths <LIST>` | *(unset — root only)* |
| `--httpx-follow-redirects` | off |
| `--nuclei-concurrency <N>` | `50` |
| `--nuclei-rate <N>` | `200` |
| `--tags-from-banner` | off — enable to limit nuclei to detected protocols |
| `--no-httpx` / `--no-nuclei` | Skip either step |

### Misc

| Flag | Purpose |
|---|---|
| `-u, --update` | Download latest binary, replace, refresh on-disk ports files |
| `--check-update` | Peek releases + tags, report state, exit |
| `--no-update-check` | Suppress the startup "update available" banner |
| `--no-art` | Suppress the ASCII banner |
| `-q, --quiet` | Equivalent to `--no-art --no-update-check` |
| `--no-banner` / `--no-tls-sniff` / `--no-adaptive` | Turn off individual Phase-B features |

---

## Output files

Every scan writes to `<OUTPUT_DIR>/<FOLDER_NAME>/`:

| File | Contents |
|---|---|
| `targets.txt`        | `ip:port` per line — raw open endpoints |
| `nuclei_targets.txt` | URL form — `http://…`, `https://…`, or `ip:port` |
| `open_ports.jsonl`   | One JSON per line: `{ip, port, rtt_ms, tls, protocol, banner, cdn}` |
| `scan_summary.json`  | `{folder, duration_ms, attempts, timeouts, open, by_port, by_protocol, by_cdn, cdn_count, ranges, ports}` |
| `httpx_results.txt`  | httpx output |
| `nuclei_results.txt` | nuclei output |

Example `open_ports.jsonl`:
```json
{"ip":"151.101.1.1","port":443,"rtt_ms":12,"tls":true,"protocol":"http","banner":"HTTP/1.1 200 OK","cdn":"fastly"}
{"ip":"203.0.113.42","port":22,"rtt_ms":71,"tls":false,"protocol":"ssh","banner":"SSH-2.0-OpenSSH_8.9p1"}
```

Example live terminal output:
```
--- OPEN PORTS (4 total, 2 on CDN edge) ---
  151.101.1.1:80   [http, cdn:fastly]        HTTP/1.1 200 OK
  151.101.1.1:443  [http, tls, cdn:fastly]   HTTP/1.1 200 OK
  203.0.113.42:22  [ssh]                     SSH-2.0-OpenSSH_8.9p1
  203.0.113.42:443 [http, tls]               HTTP/1.1 200 OK
```

Anything tagged `cdn:<provider>` is on a CDN/WAF edge network — treat results with care, the origin is elsewhere.

---

## Real-world recipes

```bash
# Bug bounty /20 sweep, exclude out-of-scope /24s
portwave acme_corp 203.0.113.0/20 \
    --exclude "203.0.113.64/26,203.0.113.128/28" \
    --tags-from-banner

# Full company scan from ASN
portwave acme_corp --asn AS12345 --exclude 203.0.113.0/24

# Massive pipeline from external asset source
amass intel -asn 12345 -whois | portwave acme_corp --input-file -

# Fast top-20 scan of a wide range
portwave quick_sweep 203.0.113.0/16 \
    --ports "21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443,9200" \
    --no-httpx --no-nuclei

# Full 1-65535 sweep on a handful of known-interesting IPs
portwave deep 1.2.3.4,5.6.7.8 --ports "1-65535" --retries 2

# Re-run (resume skips already-open ports, only re-probes timeouts)
portwave acme_corp 203.0.113.0/24
portwave acme_corp 203.0.113.0/24 --no-resume     # force full re-scan
```

---

## Configuration

Precedence for every path: CLI flag > env var > `~/.config/portwave/config.env` (or `%APPDATA%\portwave\config.env` on Windows) > built-in default.

```env
# ~/.config/portwave/config.env
PORTWAVE_OUTPUT_DIR=/home/user/scans
PORTWAVE_PORTS=                              # blank = embedded 1433-port list
PORTWAVE_HTTPX_BIN=/home/user/go/bin/httpx
PORTWAVE_NUCLEI_BIN=/home/user/go/bin/nuclei
```

Leave `PORTWAVE_PORTS=` blank unless you maintain a custom list — the embedded list is what `--update` refreshes.

---

## How it works

```
CIDRs / IPs / ranges / ASN / input-file
      │
      ▼
┌─────────────────────────┐        ┌──────────────┐
│ Producer (round-robin   │◀──skip─│ exclude list │
│ per subnet, ephemeral-  │◀──skip─│ resume jsonl │
│ port safe, flume MPMC)  │        └──────────────┘
└────────────┬────────────┘
             │ SocketAddr
┌────────────▼────────────┐        ┌──────────────┐
│ Phase-A workers (1500)  │◀──────▶│ Adaptive     │
│ tcp_connect + SO_LINGER │        │ monitor      │
│ + NODELAY + retries     │        │ (timeout %)  │
└────────────┬────────────┘        └──────────────┘
             │ hits
┌────────────▼────────────┐
│ Phase-B enrichment       │
│ passive read → HTTP      │
│ probe → TLS ClientHello  │
│ + CDN CIDR lookup        │
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│ Writer: dedupe, sort,    │
│ targets.txt, nuclei_…,   │
│ open_ports.jsonl,        │
│ scan_summary.json        │
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│ httpx  → httpx_results   │
│ nuclei → nuclei_results  │
└──────────────────────────┘
```

---

## FAQ

**Why IP-only? I want to scan `example.com`.**
Hostnames behind CDNs (Cloudflare/Fastly/Akamai/...) and WAFs all resolve to the same edge IPs, which don't reveal origin-level ports and often give misleading banner responses. portwave is deliberately IP-focused so results are grounded in actual infrastructure. Use `--asn` or `--input-file` to feed IPs from your enumeration tool of choice.

**What does `cdn:fastly` mean next to an open port?**
The scanned IP is in Fastly's published edge-network CIDR range. Anything you see open there is Fastly's edge, not the origin behind it. Useful signal for triage.

**Does portwave do SYN scanning?**
Not yet — TCP-connect only. SYN needs raw sockets (root / CAP_NET_RAW / Npcap). For `/16+` ranges, pair portwave with [masscan](https://github.com/robertdavidgraham/masscan) for discovery.

**My VPS shows fewer ports than I expect.**
Three checks: (1) `ss -tlnp` on the VPS — services bound to `127.0.0.1` are invisible externally; (2) provider firewall (AWS SG, Hetzner, DO Cloud) — blocks inbound regardless of bind address; (3) host firewall (`ufw`, `firewalld`, `iptables`).

**Can I use the output from other tools?**
Yes. `open_ports.jsonl` and `scan_summary.json` are stable structured formats.

---

## Author / contact

Developed by **assassin-marcos**.

Got ideas, bug reports, or feature requests?
**DM me on Twitter / X: [@assassin_marcos](https://twitter.com/assassin_marcos)** — always open to suggestions and improvements.

Pull requests + issues: https://github.com/assassin-marcos/portwave

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

portwave is a security-research tool. **Only scan systems you own or have written permission to test.** Unauthorised scanning may be illegal in your jurisdiction. The author disclaims liability for misuse.
