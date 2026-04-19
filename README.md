# portwave

**Ultra-fast, IP-focused IPv4/IPv6 port scanner with a built-in httpx + nuclei recon pipeline — written in async Rust.**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![X / Twitter](https://img.shields.io/badge/DM-%40assassin__marcos-1da1f2.svg)](https://twitter.com/assassin_marcos)

```
                 _
  _ __   ___  _ __| |___      ____ __   _____
 | '_ \ / _ \| '__| __\ \ /\ / / _` |\ / / _ \
 | |_) | (_) | |  | |_ \ V  V / (_| | V /  __/
 | .__/ \___/|_|   \__| \_/\_/ \__,_|\_/ \___|
 |_|     portwave · by assassin_marcos
```

Takes CIDRs, IPs, IP ranges, or an ASN. Finds open TCP (and optional UDP) ports, enriches hits with banner grabs + TLS sniff, tags CDN/WAF edges, diffs against the last run, optionally POSTs to a webhook, then chains **httpx** + **nuclei** — all in a single binary.

---

## Benchmarks

Head-to-head against [naabu](https://github.com/projectdiscovery/naabu) — same hardware, same port list, same TCP-connect technique, same 800 ms timeout + 1 retry.

### `193.109.229.0/24` × 1433 ports (~367K probes, 99.94 % firewalled)

|                            | **portwave v0.8** | naabu |
|----------------------------|------------------:|------:|
| Wall-clock                 | **6 min 30 s**    | 18 min 27 s |
| User CPU                   | 19.7 s            | 89.6 s |
| Peak RSS                   | **10.3 MB**       | 81.5 MB |
| Concurrency model          | 1500 async tokio workers | 1000 socks + 2000 pps cap |
| Output style               | Streaming         | LevelDB buffer, end-flush |

**Accuracy — 100 % agreement:** both tools reported the exact same **75 open `ip:port`**. Zero false positives, zero false negatives on either side.

Reproduce:
```bash
tr '\n' ',' < ports/portwave-top-ports.txt | sed 's/,$//' > /tmp/ports.csv

/usr/bin/time -v portwave bench 193.109.229.0/24 \
    --threads 1500 --timeout-ms 800 --retries 1 --no-httpx --no-nuclei

/usr/bin/time -v naabu -host 193.109.229.0/24 \
    -pf /tmp/ports.csv -s c -rate 2000 -retries 1 -timeout 800 \
    -silent -o /tmp/naabu.txt
```

---

## Feature matrix

|                                    | masscan | rustscan | naabu | **portwave** |
|------------------------------------|:---:|:---:|:---:|:---:|
| IPv4 + IPv6 TCP discovery          | ⚠️ | ⚠️ | ✅ | ✅ |
| Adaptive concurrency (local-error) | ❌ | ❌ | ❌ | ✅ |
| Banner grab + protocol classify    | ❌ | ❌ | partial | ✅ |
| TLS sniff on non-443               | ❌ | ❌ | ❌ | ✅ |
| CDN / WAF edge tagging             | ❌ | ❌ | ❌ | ✅ |
| ASN expansion built in             | ❌ | ❌ | ❌ | ✅ |
| Top-20 priority port scan (early results) | ❌ | ❌ | ❌ | ✅ |
| UDP top-20 opt-in                  | partial | ❌ | partial | ✅ |
| `scan_diff.json` vs. prior run     | ❌ | ❌ | ❌ | ✅ |
| Webhook on completion              | ❌ | ❌ | ❌ | ✅ |
| Dynamic CDN list refresh           | ❌ | ❌ | ❌ | ✅ |
| Exclude list (scope discipline)    | ✅ | ❌ | ✅ | ✅ |
| Resume after crash / Ctrl+C        | ❌ | ❌ | ❌ | ✅ |
| Built-in httpx + nuclei chain      | ❌ | plugin | chain | ✅ |
| Structured JSON artefacts          | ❌ | ❌ | partial | ✅ |
| Self-update (`--update`)           | ❌ | ❌ | ❌ | ✅ |
| Single static cross-platform binary| ✅ | ✅ | ✅ | ✅ |

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

Both installers auto-detect `httpx` / `nuclei` across `$PATH`, `~/go/bin`, `~/.pdtm/go/bin`, Homebrew, MacPorts, `~/.local/bin`; pick an install prefix that's already on `$PATH`; and offer to append the PATH line to the right shell rc. Non-interactive: `NONINTERACTIVE=1`.

### Updating
```bash
portwave --update          # download + replace binary for current OS/arch
portwave --check-update    # report whether a newer version exists
```

The default 1433-port list, CDN CIDR snapshot, and banner art are baked into the binary — `--update` always ships the current versions.

### Uninstall
```bash
bash uninstall.sh                                         # Linux / macOS
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1  # Windows
```

---

## Quickstart

```bash
# Full pipeline: scan → httpx → nuclei
portwave acme 203.0.113.0/24

# Mixed input
portwave acme "203.0.113.0/24,1.2.3.4,5.6.7.10-5.6.7.20"

# From a file (CIDRs / IPs / ranges, `#` comments)
portwave acme --input-file scope.txt

# Everything a company announces via BGP
portwave acme --asn AS13335

# Inline port spec
portwave acme 203.0.113.0/24 --ports "22,80,443,8000-9000"

# Exclude out-of-scope ranges
portwave acme 203.0.113.0/22 --exclude "203.0.113.0/24,203.0.114.0/28"

# UDP discovery (DNS, NTP, SNMP, SSDP, mDNS, memcached, IKE, OpenVPN, …)
portwave acme 203.0.113.0/24 --udp

# Post summary to Discord/Slack/webhook on completion
portwave acme 203.0.113.0/24 --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ

# Re-run daily — scan_diff.json shows which ports are new / closed since last run
portwave acme 203.0.113.0/24
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
| `--input-file <FILE>` | One target per line, `#` for comments. `-` for stdin |
| `--asn <LIST>` | `AS13335,AS15169` — expanded via RIPE stat (public, no API key) |
| `--exclude <LIST>` | Same format as `<CIDR_INPUT>`; skipped in the producer |

### Ports

| Flag | Default | Purpose |
|---|---|---|
| `--ports <SPEC>` | — | `22,80,443,8000-9000` |
| `--port-file <FILE>` | — | Comma / whitespace separated |
| *(neither)* | **embedded 1433** | nmap top-1000 ∪ bug-bounty service ports |

Top-20 priority ports (`80, 443, 22, 21, 25, 53, 8080, 8443, 3389, 110, 143, 445, 3306, 5432, 6379, 27017, 9200, 1883, 5900, 11211`) are always scanned first regardless of source.

### Timing / concurrency

| Flag | Default | Purpose |
|---|---|---|
| `-t, --threads <N>` | `1500` | Max concurrent TCP probes; adaptive controller shrinks on actual local-resource pressure |
| `--timeout-ms <N>` | `800` | Phase-A (discovery) connect timeout |
| `--enrich-timeout-ms <N>` | `1500` | Phase-B (banner / TLS) connect timeout |
| `--retries <N>` | `1` | Retries on Phase-A timeout only (RSTs never retry) |

### UDP, output, httpx / nuclei

| Flag | Default | Purpose |
|---|---|---|
| `--udp` | off | UDP discovery phase against ~15 well-known services |
| `--output-dir <PATH>` | `./scans` | Base output directory |
| `--no-resume` | off | Don't load `open_ports.jsonl` as a skip-set |
| `--webhook <URL>` | — | POST summary JSON (with `diff` merged) on completion |
| `--httpx-threads <N>` | `150` | httpx concurrency |
| `--httpx-paths <LIST>` | — | Extra paths for httpx to probe |
| `--httpx-follow-redirects` | off | Follow redirects (folds chains into single entries) |
| `--nuclei-concurrency <N>` | `25` | Matched to max-host-error |
| `--nuclei-max-host-error <N>` | `25` | Fail host after N nuclei errors |
| `--nuclei-rate <N>` | `200` | nuclei rate-limit |
| `--nuclei-all-ports` | off | Keep non-HTTP ports in nuclei list (default: filtered) |
| `--tags-from-banner` | off | Restrict nuclei to template tags matching detected protocols |
| `--no-httpx` / `--no-nuclei` | — | Skip either step |

### Update / CDN / UX

| Flag | Purpose |
|---|---|
| `-u, --update` | Download latest release binary, replace in place, refresh any on-disk ports file |
| `--check-update` | Report whether a newer release exists (peeks both releases + tags API) |
| `--refresh-cdn` | Re-fetch Cloudflare + Fastly edge ranges live, merge with embedded non-API providers, cache to `~/.cache/portwave/cdn-ranges.txt` |
| `--no-update-check` | Suppress startup "update available" banner |
| `--no-art` / `-q, --quiet` | Suppress banner art / all banner output |
| `--no-banner` / `--no-tls-sniff` / `--no-adaptive` | Turn off individual Phase-B features |

---

## Output

Every scan writes to `<OUTPUT_DIR>/<FOLDER_NAME>/`:

| File | Contents |
|---|---|
| `targets.txt`        | `ip:port` per line — raw open endpoints |
| `nuclei_targets.txt` | URL form, filtered to HTTP-candidate ports (unless `--nuclei-all-ports`) |
| `open_ports.jsonl`   | One JSON per line: `{ip, port, rtt_ms, tls, protocol, banner, cdn}` |
| `scan_summary.json`  | `{duration_ms, attempts, open, closed, timeouts, by_port, by_protocol, by_cdn, phase_a_ms, phase_b_ms, ...}` |
| `scan_diff.json`     | `{prior_opens, current_opens, new:[…], closed:[…], unchanged}` vs. previous run |
| `httpx_results.txt`  | httpx output |
| `nuclei_results.txt` | nuclei output |

Example live terminal:
```text
--- OPEN PORTS (4 total, 2 on CDN edge) ---
  151.101.1.1:80   [http, cdn:fastly]        HTTP/1.1 200 OK
  151.101.1.1:443  [http, tls, cdn:fastly]   HTTP/1.1 200 OK
  203.0.113.42:22  [ssh]                     SSH-2.0-OpenSSH_8.9p1
  203.0.113.42:443 [http, tls]               HTTP/1.1 200 OK

Totals — 363,982 probes  ·  open: 75  ·  closed: 68  ·  filtered: 363,839 (99.94%)
```

Metric meanings:
- **open** — TCP handshake completed
- **closed** — RST / ICMP-unreachable (port closed, host alive)
- **filtered** — no reply within timeout (firewall dropped SYN or host down)

---

## Recipes

```bash
# Bug-bounty /20 + webhook on findings
portwave acme 203.0.113.0/20 --exclude "203.0.113.64/26" \
    --tags-from-banner --webhook $SLACK_URL

# Full company scan from an ASN
portwave acme --asn AS12345 --exclude 203.0.113.0/24

# Piped from external enumeration
amass intel -asn 12345 -whois | portwave acme --input-file -

# Fast top-20 only
portwave quick 203.0.113.0/16 --ports \
    "21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443,9200" \
    --no-httpx --no-nuclei

# Full 1-65535 sweep on selected IPs
portwave deep 1.2.3.4,5.6.7.8 --ports "1-65535" --retries 2

# UDP + TCP combined
portwave udp_sweep 203.0.113.0/24 --udp

# Continuous monitoring (cron the same command daily)
portwave acme_daily 203.0.113.0/24 --webhook $SLACK_URL
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
│  flume MPMC queue,      │
│  iterator-based (O(nets)│
│  memory, not O(IPs))    │
└────────────┬────────────┘
             │ SocketAddr
┌────────────▼────────────┐        ┌──────────────┐
│ Phase-A workers (1500)  │◀──────▶│ Adaptive     │
│ SO_LINGER + NODELAY     │        │ monitor      │
│ retries on timeout      │        │ (local errs) │
└────────────┬────────────┘        └──────────────┘
             │ hits
┌────────────▼────────────┐
│ Phase-B enrichment      │
│ passive read → HTTP     │
│ probe → TLS ClientHello │
│ + CDN CIDR lookup       │
└────────────┬────────────┘
             │ OpenPort
┌────────────▼────────────┐    (optional)
│ Phase-C UDP probes      │◀── --udp
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│ Writer: numeric sort,   │
│ dedupe, stream to disk  │
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│ httpx  → httpx_results  │
│ nuclei → nuclei_results │
│ webhook POST summary    │
└─────────────────────────┘
```

---

## FAQ

**Why IP-only?**
Hostnames behind CDNs/WAFs all resolve to the same edge IPs, which don't reveal origin ports. portwave stays IP-focused so results are grounded in real infrastructure. Feed IPs from your enum tool or use `--asn`.

**What does `cdn:fastly` next to an open port mean?**
The IP is in a published CDN edge range. Anything open there is the CDN's edge, not the origin — useful triage signal.

**Does portwave do SYN scanning?**
Not yet. TCP-connect only. SYN scanning needs raw sockets (root / CAP_NET_RAW / Npcap). Planned for a later release.

**My VPS shows fewer ports than I expect.**
Usually (a) service bound to `127.0.0.1` only, (b) provider firewall (AWS SG / Hetzner / DO Cloud), or (c) host firewall (`ufw`, `firewalld`). Run `ss -tlnp` on the VPS to confirm what's externally listening.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

## Credits & thanks

portwave's recon pipeline stands on the shoulders of [ProjectDiscovery](https://projectdiscovery.io/)'s excellent tooling:

- [**httpx**](https://github.com/projectdiscovery/httpx) — HTTP fingerprinting, status/size/title/location extraction. Resolved dynamically at scan time via `PATH` or `PORTWAVE_HTTPX_BIN` config key.
- [**nuclei**](https://github.com/projectdiscovery/nuclei) — template-driven vulnerability scanner. Resolved dynamically at scan time via `PATH` or `PORTWAVE_NUCLEI_BIN` config key.

Thanks to:

- [**@nittoSec**](https://github.com/nittoSec) — reported the tool-resolution issue that led to v0.8.3 (dynamic `which httpx` / `which nuclei` + interactive install prompt + Windows `where.exe`-style extension resolution).

---

## Contact

Developed by **[@assassin_marcos](https://twitter.com/assassin_marcos)** on X / Twitter. Issues + PRs: https://github.com/assassin-marcos/portwave/issues

## License

[MIT](LICENSE).

## Disclaimer

Security-research tool. **Only scan systems you own or have written permission to test.** Unauthorised scanning may be illegal in your jurisdiction.
