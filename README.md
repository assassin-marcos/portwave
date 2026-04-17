# portwave

**Ultra-fast, IP-focused hybrid IPv4 / IPv6 port scanner with CDN tagging, adaptive concurrency, banner grab, TLS sniff, optional UDP discovery, scan-diff, webhook, self-update, and a built-in httpx + nuclei recon pipeline — written in async Rust.**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![Built for bug bounty](https://img.shields.io/badge/built%20for-bug%20bounty-red.svg)]()
[![Made by assassin_marcos](https://img.shields.io/badge/made%20by-%40assassin__marcos-1da1f2.svg)](https://twitter.com/assassin_marcos)

```
                 _
  _ __   ___  _ __| |___      ____ __   _____
 | '_ \ / _ \| '__| __\ \ /\ / / _` |\ / / _ \
 | |_) | (_) | |  | |_ \ V  V / (_| | V /  __/
 | .__/ \___/|_|   \__| \_/\_/ \__,_|\_/ \___|
 |_|     portwave · by assassin_marcos
```

> portwave takes CIDRs, IPs, IP ranges, or an ASN — finds open TCP ports in a **priority-first** first pass (top-20 common ports scanned across all IPs before the rest), enriches hits with banner grabs + TLS sniff, tags any IP that belongs to a known CDN/WAF edge network, optionally probes a curated UDP top-set, diffs the results against the last scan, posts to a webhook, then chains **httpx** and **nuclei** — all in a single binary. IP-only input by design: no hostnames, no CDN false-positives via domain fronting.

---

## Feature matrix

|                                       | masscan | rustscan | naabu | **portwave** |
|---------------------------------------|---------|----------|-------|--------------|
| IPv4 + IPv6 TCP discovery             | ⚠️      | ⚠️       | ✅    | ✅           |
| Adaptive concurrency (local-error)    | ❌      | ❌       | ❌    | ✅           |
| Banner grab + protocol classify       | ❌      | ❌       | partial | ✅         |
| TLS sniff on non-443                  | ❌      | ❌       | ❌    | ✅           |
| **CDN / WAF edge tagging**            | ❌      | ❌       | ❌    | ✅           |
| **ASN expansion built in**            | ❌      | ❌       | ❌    | ✅           |
| **Top-20 priority port scan** (early results) | ❌ | ❌    | ❌    | ✅           |
| **UDP top-20 opt-in**                 | partial | ❌       | partial | ✅         |
| **scan_diff.json** vs. prior run      | ❌      | ❌       | ❌    | ✅           |
| **Webhook on completion**             | ❌      | ❌       | ❌    | ✅           |
| **Dynamic CDN list refresh**          | ❌      | ❌       | ❌    | ✅           |
| Port range syntax `8000-9000`         | ✅      | ✅       | ✅    | ✅           |
| Exclude list (scope discipline)       | ✅      | ❌       | ✅    | ✅           |
| Resume after crash / Ctrl+C           | ❌      | ❌       | ❌    | ✅           |
| Built-in httpx + nuclei chain         | ❌      | plugin   | chain | ✅           |
| Structured JSON artefacts             | ❌      | ❌       | partial | ✅         |
| Self-update (`--update`)              | ❌      | ❌       | ❌    | ✅           |
| Single static cross-platform binary   | ✅      | ✅       | ✅    | ✅           |

---

## Install

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

Both installers auto-detect `httpx` / `nuclei` on `$PATH`, `~/go/bin`, `~/.pdtm/go/bin`, Homebrew, MacPorts, and `~/.local/bin`; pick an install prefix already on `$PATH`; and (on Unix) offer to append the PATH line to the right shell rc. Non-interactive: `NONINTERACTIVE=1`.

### Updating

```bash
portwave --update          # downloads prebuilt binary for your OS+arch
portwave --check-update    # just print whether a newer version exists
```

The default 1400+ port list, the CDN CIDR snapshot, and the banner art are **all baked into the binary** — `--update` always ships the current list.

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

# Mixed: CIDRs + single IPs + IP ranges
portwave acme_corp "203.0.113.0/24,1.2.3.4,5.6.7.10-5.6.7.20"

# Targets from a file (CIDRs/IPs/ranges, one per line, `#` comments)
portwave acme_corp --input-file scope.txt

# Scan everything a company announces via BGP
portwave cloudflare_infra --asn AS13335

# Inline port spec
portwave acme_corp 203.0.113.0/24 --ports "22,80,443,8000-9000"

# Exclude ranges you're not allowed to touch
portwave acme_corp 203.0.113.0/22 --exclude "203.0.113.0/24,203.0.114.0/28"

# Add UDP discovery (DNS, NTP, SNMP, SSDP, mDNS, IKE, OpenVPN, memcached, …)
portwave acme_corp 203.0.113.0/24 --udp

# Post a summary to Discord / Slack / custom collector when scan completes
portwave acme_corp 203.0.113.0/24 --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ

# Re-run daily — scan_diff.json shows which ports are new or closed since last run
portwave acme_corp 203.0.113.0/24   # diff auto-written to scan_diff.json
```

---

## Flags reference

```text
portwave [OPTIONS] <FOLDER_NAME> [CIDR_INPUT]
portwave --update | --check-update | --refresh-cdn
```

### Target inputs

| Flag | Accepts |
|---|---|
| `<CIDR_INPUT>` positional | `203.0.113.0/24`, `1.2.3.4`, `5.6.7.10-5.6.7.20`, or comma-separated mix |
| `--input-file <FILE>` | One target per line, `#` for comments. Accepts `-` for stdin. |
| `--asn <LIST>` | `AS13335,AS15169` — expanded via RIPE stat (public, no API key) |
| `--exclude <LIST>` | Same format as `<CIDR_INPUT>`; skipped in the producer (zero wasted probes) |

### Ports

| Flag | Default | Purpose |
|---|---|---|
| `--ports <SPEC>` | — | Inline: `22,80,443,8000-9000` |
| `--port-file <FILE>` | — | Comma / whitespace separated |
| *(neither)* | **embedded 1433** | nmap-top-1000 ∪ bug-bounty service ports |

Regardless of source, **top-20 priority ports** (`80, 443, 22, 21, 25, 53, 8080, 8443, 3389, 110, 143, 445, 3306, 5432, 6379, 27017, 9200, 1883, 5900, 11211`) are always scanned first.

### Timing / concurrency

| Flag | Default | Purpose |
|---|---|---|
| `-t, --threads <N>` | `1500` | Max concurrent TCP probes; adaptive controller shrinks only on actual local-resource pressure |
| `--timeout-ms <N>` | `800` | Phase-A (discovery) connect timeout |
| `--enrich-timeout-ms <N>` | `1500` | Phase-B (banner / TLS) connect timeout |
| `--retries <N>` | `1` | Retries on Phase-A timeout only (RSTs never retry) |

### UDP (opt-in)

| Flag | Purpose |
|---|---|
| `--udp` | Adds a UDP discovery phase with protocol-specific probes for ~15 services: DNS (53), NTP (123), SNMP (161), SSDP (1900), mDNS (5353), NetBIOS (137), MSSQL-browser (1434), portmap (111), TFTP (69), IKE (500), OpenVPN (1194), memcached (11211), WireGuard (51820), NFS (2049), QUIC (443). Responses are appended to `open_ports.jsonl` with `protocol: "udp/<label>"`. |

### Output

| Flag | Default | Purpose |
|---|---|---|
| `--output-dir <PATH>` | `./scans` (or config) | Base output directory |
| `--no-resume` | off | Don't load `open_ports.jsonl` as a skip-set |
| `--webhook <URL>` | — | POST scan_summary (with `diff` merged in) to URL on completion |

### httpx / nuclei chain

| Flag | Default |
|---|---|
| `--httpx-threads <N>` | `150` |
| `--httpx-paths <LIST>` | *(unset)* |
| `--httpx-follow-redirects` | off |
| `--nuclei-concurrency <N>` | `25` (matched to `--nuclei-max-host-error`) |
| `--nuclei-max-host-error <N>` | `25` |
| `--nuclei-rate <N>` | `200` |
| `--nuclei-all-ports` | off — by default nuclei targets are filtered to drop known non-HTTP ports (7/9/13/17/19/37/53/67/68/69/109/111/123/137/138/179/514/543/544/4789) where nuclei has no template coverage. Opt in with this flag. |
| `--tags-from-banner` | off — restrict nuclei to template tags matching detected protocols |
| `--no-httpx` / `--no-nuclei` | Skip either step |

### Update / CDN / UX

| Flag | Purpose |
|---|---|
| `-u, --update` | Download the latest release binary, replace in place, refresh any on-disk ports file |
| `--check-update` | Report whether a newer release exists; peeks tags API for "tag pushed, release not yet built" case |
| `--refresh-cdn` | Re-fetch Cloudflare + Fastly edge ranges live, merge with embedded non-API providers (akamai/sucuri/imperva/stackpath/bunnycdn/cachefly/keycdn), write to `~/.cache/portwave/cdn-ranges.txt`. Used automatically on next scan. |
| `--no-update-check` | Suppress startup "update available" banner |
| `--no-art` | Suppress the ASCII banner |
| `-q, --quiet` | `--no-art` + `--no-update-check` |
| `--no-banner` / `--no-tls-sniff` / `--no-adaptive` | Turn off individual Phase-B features |

---

## Output artefacts

Every scan writes to `<OUTPUT_DIR>/<FOLDER_NAME>/`:

| File | Contents |
|---|---|
| `targets.txt`        | `ip:port` per line — raw open endpoints (all, unfiltered) |
| `nuclei_targets.txt` | URL form; filtered to HTTP-candidate ports only (unless `--nuclei-all-ports`) |
| `open_ports.jsonl`   | One JSON per line: `{ip, port, rtt_ms, tls, protocol, banner, cdn}` |
| `scan_summary.json`  | `{folder, duration_ms, attempts, timeouts, open, by_port, by_protocol, by_cdn, cdn_count, ranges, ports}` |
| `scan_diff.json`     | **New in v0.7** — `{prior_opens, current_opens, new:[…], closed:[…], unchanged:N}` vs. the previous run |
| `httpx_results.txt`  | httpx output |
| `nuclei_results.txt` | nuclei output |

Example `open_ports.jsonl`:
```json
{"ip":"151.101.1.1","port":443,"rtt_ms":12,"tls":true,"protocol":"http","banner":"HTTP/1.1 200 OK","cdn":"fastly"}
{"ip":"203.0.113.42","port":22,"rtt_ms":71,"tls":false,"protocol":"ssh","banner":"SSH-2.0-OpenSSH_8.9p1"}
{"ip":"203.0.113.42","port":53,"rtt_ms":0,"tls":false,"protocol":"udp/dns","banner":"...........version.bind..."}
```

Example `scan_diff.json`:
```json
{
  "folder": "acme_corp",
  "prior_opens": 28,
  "current_opens": 31,
  "new": ["203.0.113.44:8443", "203.0.113.77:22", "203.0.113.92:9200"],
  "closed": ["203.0.113.14:3389"],
  "unchanged": 27
}
```

Example live terminal output:
```
--- OPEN PORTS (4 total, 2 on CDN edge) ---
  151.101.1.1:80   [http, cdn:fastly]        HTTP/1.1 200 OK
  151.101.1.1:443  [http, tls, cdn:fastly]   HTTP/1.1 200 OK
  203.0.113.42:22  [ssh]                     SSH-2.0-OpenSSH_8.9p1
  203.0.113.42:443 [http, tls]               HTTP/1.1 200 OK
```

---

## Real-world recipes

### Bug bounty /20 sweep + webhook on findings
```bash
portwave acme_corp 203.0.113.0/20 \
    --exclude "203.0.113.64/26" \
    --tags-from-banner \
    --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Full company scan from an ASN
```bash
portwave acme_corp --asn AS12345 --exclude 203.0.113.0/24
```

### Pipeline from external asset source
```bash
amass intel -asn 12345 -whois | portwave acme_corp --input-file -
```

### Fast top-20 only (ignore embedded 1433 list)
```bash
portwave quick 203.0.113.0/16 \
    --ports "21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443,9200" \
    --no-httpx --no-nuclei
```

### Full 1–65535 sweep on a handful of high-value IPs
```bash
portwave deep 1.2.3.4,5.6.7.8 --ports "1-65535" --retries 2
```

### UDP + TCP combined
```bash
portwave udp_sweep 203.0.113.0/24 --udp
```

### Continuous monitoring (cron the same command daily)
```bash
portwave acme_daily 203.0.113.0/24 --webhook $SLACK_URL
# Each re-run writes scan_diff.json — feed it to your alerting
```

### Refresh the CDN edge list (quarterly)
```bash
portwave --refresh-cdn     # pulls live CF + Fastly, keeps rest
```

---

## How it works

```
CIDRs / IPs / ranges / ASN / input-file
      │
      ▼
┌─────────────────────────┐        ┌──────────────┐
│ Two-pass producer:      │◀──skip─│ exclude list │
│   1. top-20 priority    │◀──skip─│ resume jsonl │
│   2. remaining ports    │        └──────────────┘
│  flume MPMC, round-     │
│  robin across subnets   │
└────────────┬────────────┘
             │ SocketAddr
┌────────────▼────────────┐        ┌──────────────┐
│ Phase-A workers (1500)  │◀──────▶│ Adaptive     │
│ SO_LINGER + NODELAY +   │        │ monitor      │
│ retries on timeout      │        │ (local errs) │
└────────────┬────────────┘        └──────────────┘
             │ hits
┌────────────▼────────────┐
│ Phase-B enrichment       │
│ passive read → HTTP      │
│ probe → TLS ClientHello  │
│ + CDN CIDR lookup        │
└────────────┬────────────┘
             │ OpenPort
┌────────────▼────────────┐    (optional)
│ Phase-C UDP probe        │◀── --udp
│ (DNS/NTP/SNMP/SSDP/…)    │
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│ Writer: dedupe, sort,    │
│ targets/nuclei_targets/  │
│ jsonl/summary/diff       │
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│ httpx  → httpx_results   │
│ nuclei → nuclei_results  │
│ webhook POST summary     │
└──────────────────────────┘
```

---

## FAQ

**Why IP-only? I want to scan `example.com`.**
Hostnames behind CDNs (Cloudflare/Fastly/Akamai/...) and WAFs all resolve to the same edge IPs. Those IPs don't reveal origin ports and give misleading responses. portwave stays IP-focused so results are grounded in actual infrastructure. Feed IPs from your own enumeration tool, or use `--asn`.

**What does `cdn:fastly` mean next to an open port?**
The scanned IP is in a published CDN/WAF edge range. Anything you see open there is that provider's edge, not the origin. Useful triage signal.

**Does portwave do SYN scanning?**
Not yet — TCP-connect only. SYN needs raw sockets (root / CAP_NET_RAW / Npcap). Planned for v0.8.0.

**My VPS shows fewer ports than I expect.**
Usually one of: (a) service bound to `127.0.0.1` only, (b) provider firewall (AWS SG / Hetzner / DO Cloud) blocks inbound, (c) host firewall (`ufw`, `firewalld`). Run `ss -tlnp` on the VPS to see what's truly listening externally.

**How does `scan_diff.json` work?**
Every scan reads the prior `open_ports.jsonl` from the same folder before overwriting it, then emits a diff against the current run. First scan writes `new: []`, `closed: []`, `unchanged: 0`.

**What happens if my webhook is down?**
Silent failure — portwave logs `Webhook: failed (<error>) — continuing.` and exits 0. Your scan data is safe on disk regardless.

**How often should I run `--refresh-cdn`?**
Quarterly is fine. Cloudflare and Fastly update their public ranges maybe 2-3× a year. The embedded snapshot stays reasonably accurate between refreshes.

---

## Changelog

Full history in [CHANGELOG.md](CHANGELOG.md).

---

## Author / contact

Developed by **assassin-marcos**.

Ideas, bugs, features? **DM me on X / Twitter: [@assassin_marcos](https://twitter.com/assassin_marcos)** — always open to suggestions.

Issues + pull requests: https://github.com/assassin-marcos/portwave

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

portwave is a security-research tool. **Only scan systems you own or have written permission to test.** Unauthorised scanning may be illegal in your jurisdiction. The author disclaims liability for misuse.
