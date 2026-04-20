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

Four-way head-to-head: portwave vs rustscan vs naabu vs masscan on the same hardware, same TCP-connect technique, matched threads / timeout / retries across every tool. All four found the **same 15 `ip:port`** — zero false positives, zero false negatives on any side.

### `43.230.180.0/24 × {80, 443, 8443}` — 768 probes

| Tool (config) | Wall time | Peak RSS | Opens | Notes |
|---|---:|---:|:---:|---|
| **portwave (pure discovery)** | **1.72 s** | **8.3 MB** | 15 | `--no-banner --no-tls-sniff --no-adaptive` |
| rustscan 2.3.0 (`--tries 1`) | 1.35 s | 63.4 MB | 15 | Fewer attempts than others (not parity) |
| rustscan 2.3.0 (`--tries 2`, parity) | 1.98 s | 63.4 MB | 15 | Matched retries |
| **portwave (default, with Phase B)** | **3.03 s** | **8.5 MB** | 15 | Also produces banners + TLS tags + HTTP fingerprint |
| masscan (SYN, `--rate 2000`) | 6.47 s | 40.2 MB | 15 | SYN mode, requires root |
| naabu (`-s c`) | 133.92 s | 56.6 MB | 15 | Connect mode internal rate-limit |

**Takeaway**: with matched retries, portwave **wins speed AND memory** vs rustscan (1.72 s vs 1.98 s, 7.6× less RAM) in pure-discovery mode; default portwave spends an extra 1.3 s on banner + TLS + HTTP enrichment that no other tool here produces.

Exact command:
```bash
/usr/bin/time -v portwave -t 1500 -T 800 -r 1 -p 80,443,8443 \
    --no-httpx --no-nuclei --no-art --no-update-check --quiet \
    bench 43.230.180.0/24
```

---

## Feature matrix

|                                    | masscan | rustscan | naabu | **portwave** |
|------------------------------------|:---:|:---:|:---:|:---:|
| IPv4 + IPv6 TCP discovery          | ⚠️ | ⚠️ | ✅ | ✅ |
| Smart IPv6 scanning (RFC 7707 patterns) | ❌ | ❌ | ❌ | ✅ |
| Scope safety net (refuse 2^20+ hosts by default) | ❌ | ❌ | ❌ | ✅ |
| Adaptive concurrency (local-error) | ❌ | ❌ | ❌ | ✅ |
| Banner grab + protocol classify    | ❌ | ❌ | partial | ✅ |
| TLS sniff on non-443               | ❌ | ❌ | ❌ | ✅ |
| CDN / WAF edge tagging             | ❌ | ❌ | ❌ | ✅ |
| ASN expansion built in             | ❌ | ❌ | ❌ | ✅ |
| Top-20 priority port scan (early results) | ❌ | ❌ | ❌ | ✅ |
| Nmap-style `--top-ports N`         | ✅ | ✅ | ❌ | ✅ |
| UDP top-20 opt-in                  | partial | ❌ | partial | ✅ |
| Global packet-per-second cap (`--max-pps`) | ✅ | ❌ | ✅ | ✅ |
| Wallclock budget (`--max-scan-time`) | ❌ | ❌ | ❌ | ✅ |
| Dry-run / scan-plan preview        | ❌ | ❌ | ❌ | ✅ |
| `scan_diff.json` vs. prior run     | ❌ | ❌ | ❌ | ✅ |
| Webhook on completion              | ❌ | ❌ | ❌ | ✅ |
| Webhook only on diff change        | ❌ | ❌ | ❌ | ✅ |
| NDJSON stream to stdout            | ❌ | ❌ | partial | ✅ |
| Dynamic CDN list refresh           | ❌ | ❌ | ❌ | ✅ |
| Exclude list (scope discipline)    | ✅ | ❌ | ✅ | ✅ |
| Resume after crash / Ctrl+C        | ❌ | ❌ | ❌ | ✅ |
| Built-in httpx + nuclei chain      | ❌ | plugin | chain | ✅ |
| Structured JSON artefacts          | ❌ | ❌ | partial | ✅ |
| Self-update (`--update`)           | ❌ | ❌ | ❌ | ✅ |
| Self-uninstall (`--uninstall`)     | ❌ | ❌ | ❌ | ✅ |
| Clear input validation errors      | ❌ | partial | partial | ✅ |
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

Preferred — one command, all platforms:

```bash
portwave --uninstall           # interactive, shows plan + prompts [y/N]
portwave --uninstall --yes     # non-interactive (for scripts / CI)
```

Legacy (kept as a fallback if the binary is missing or broken):

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
| `<CIDR_INPUT>` positional | `203.0.113.0/24`, `1.2.3.4`, `5.6.7.10-5.6.7.20`, `2001:db8::/112`, or comma-separated mix |
| `-i, --input-file <FILE>` | One target per line, `#` for comments |
| `-a, --asn <LIST>` | `AS13335,AS15169` — expanded via RIPE stat (public, no API key) |
| `-e, --exclude <LIST>` | Same format as `<CIDR_INPUT>`; skipped in the producer |
| `--ipv4-only` | Drop IPv6 ranges from the expanded scope |
| `--ipv6-only` | Drop IPv4 ranges from the expanded scope |
| `--smart-ipv6` | Replace huge IPv6 ranges (> /108) with ~450 RFC-7707 likely addresses |
| `--allow-huge-scope` | Bypass the default 2²⁰-host scope safety net |

### Ports

| Flag | Default | Purpose |
|---|---|---|
| `-p, --ports <SPEC>` | — | `22,80,443,8000-9000` |
| `-f, --port-file <FILE>` | — | Comma / whitespace separated |
| `--top-ports <N>` | — | Use the first N ports from the loaded list (nmap-compat) |
| *(none of the above)* | **embedded 1433** | nmap top-1000 ∪ bug-bounty service ports |

Top-20 priority ports (`80, 443, 22, 21, 25, 53, 8080, 8443, 3389, 110, 143, 445, 3306, 5432, 6379, 27017, 9200, 1883, 5900, 11211`) are always scanned first regardless of source.

### Timing / concurrency

| Flag | Default | Purpose |
|---|---|---|
| `-t, --threads <N>` | `1500` | Max concurrent TCP probes; adaptive controller shrinks on actual local-resource pressure |
| `--timeout-ms <N>` | `800` | Phase-A (discovery) connect timeout |
| `--enrich-timeout-ms <N>` | `1500` | Phase-B (banner / TLS) connect timeout |
| `--retries <N>` | `1` | Retries on Phase-A timeout only (RSTs never retry) |

### Rate limiting / budget / dry-run

| Flag | Default | Purpose |
|---|---|---|
| `--max-pps <N>` | — | Global packets-per-second cap (polite scanning) |
| `--max-scan-time <DUR>` | — | Hard wallclock cap (`10m`, `1h`, `30s`, `2h15m`). Phase B still runs on whatever Phase A found; summary gets `timed_out: true` |
| `--dry-run` | off | Print the scan plan (target count, port count, estimated runtime) and exit — zero probes fired |

### UDP, output, httpx / nuclei

| Flag | Default | Purpose |
|---|---|---|
| `-U, --udp` | off | UDP discovery phase against ~15 well-known services |
| `-o, --output-dir <PATH>` | `./scans` | Base output directory |
| `--json-out` | off | Emit one NDJSON line per open port to stdout (in addition to files) |
| `--no-resume` | off | Don't load `open_ports.jsonl` as a skip-set |
| `-w, --webhook <URL>` | — | POST summary JSON (with `diff` merged) on completion |
| `--webhook-on-diff-only` | off | Skip the webhook unless the diff shows new opens or closes |
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
| `-u, --update` | Download latest release binary, replace in place, refresh any on-disk ports file. Prints a What's-new changelog on completion |
| `-c, --check-update` | Report whether a newer release exists (peeks both releases + tags API) |
| `-X, --uninstall` | Remove portwave (binary + share + cache + optional config), interactive `[y/N]` |
| `-y, --yes` | Skip the uninstall confirmation (for scripted removal) |
| `--refresh-cdn` | Re-fetch Cloudflare + Fastly edge ranges live, merge with embedded non-API providers, cache to `~/.cache/portwave/cdn-ranges.txt` |
| `--no-update-check` | Suppress startup "update available" banner |
| `--no-update-prompt` | Show the update banner + changelog but skip the `[Y/n]` prompt |
| `--no-install-prompt` | Don't prompt to install httpx/nuclei if missing (for CI) |
| `--no-art` / `-q, --quiet` | Suppress banner art / all banner output |
| `--no-banner` / `--no-tls-sniff` / `--no-adaptive` | Turn off individual Phase-B features |

The startup banner prints `(latest)` in green or `(outdated → vX.Y.Z)` in red next to the version — the cache is refreshed against GitHub on every startup (1 s budget, 5 min cache-hit fast path) so the tag is always accurate.

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

# Diff-only webhook — only post when something actually changed
portwave acme_daily 203.0.113.0/24 --webhook $SLACK_URL --webhook-on-diff-only

# Sanity-check a big ASN before committing to it
portwave preview --asn AS13335 --dry-run

# NDJSON stream for scripting
portwave acme 203.0.113.0/24 --json-out --no-httpx --no-nuclei --quiet | jq -c 'select(.tls)'

# Polite scan — global 200 pps cap
portwave gentle 203.0.113.0/24 --max-pps 200

# Hard time budget — stop after 10 minutes, Phase B runs on whatever Phase A found
portwave quick_bb --asn AS99999 --max-scan-time 10m
```

---

## IPv6 scanning

portwave treats IPv6 as a first-class target family. Inputs that are accepted without any extra flag:

```bash
portwave ipv6 2001:db8::1                   # single IP
portwave ipv6 2001:db8::1,2001:db8::2       # multiple
portwave ipv6 2001:db8::/112                # small CIDR (65 K hosts) — scans fully
portwave ipv6 --input-file v6-targets.txt
portwave dual  "203.0.113.0/24,2001:db8::/112"   # mixed IPv4 + IPv6
```

### The IPv6 scale problem

A single `/64` (one allocation to a typical home ISP) contains 2⁶⁴ ≈ **18 quintillion** addresses. A `/48` contains 2⁸⁰. Exhaustive enumeration is physically impossible at any speed.

portwave has three mechanisms to handle this:

**1. Scope safety net (on by default).** Any target set that would expand to more than **2²⁰ (≈ 1 million) hosts** is refused with a clear error:

```text
error: target scope would expand to 79228162514264337593543950336 host(s) — above the 2^20 safety cap.
  bypass options:
    --smart-ipv6         scan only RFC-7707 common IPv6 addresses
    --allow-huge-scope   explicitly proceed with the full expansion
    --top-ports 100      cut the per-host probe cost if the range is accurate
```

Threshold picked so a `/12` IPv4 (1 M hosts) or `/108` IPv6 (1 M hosts) still runs unprompted.

**2. Smart IPv6 (`--smart-ipv6`).** Replaces any IPv6 CIDR larger than `/108` with **~450 targeted addresses** following [RFC 7707](https://datatracker.ietf.org/doc/html/rfc7707) patterns:

- **Low sequential**: `::1`, `::2`, … `::ff` (admins routinely assign these)
- **Service decimal**: `::100` … `::2ff`
- **Hexspeak**: `::dead`, `::beef`, `::cafe`, `::babe`, `::f00d`, `::1337`, `::c0de`, `::feed`, `::face`, `::b00b`, …
- **Round decimals**: `::1000`, `::2000`, `::8080`, `::8443`, `::6379`, `::27017`
- **SLAAC landmarks**: `::fffe:xxxx` EUI-64 lowest-bit patterns

Scales a `/32` or `/48` from "impossible" to "~800 probes per port in under a minute". Same technique used by `scanrand6` and `thc-ipv6`.

```bash
# Google's allocated /32 — impossible exhaustively, fast with --smart-ipv6
portwave gcloud 2a00:1450::/32 --smart-ipv6 --top-ports 10 --no-httpx --no-nuclei
```

**3. `--allow-huge-scope` (explicit override).** For users who genuinely know what they're doing. Bypasses the safety net without rewriting the target list. Use with care.

### Family filters

When a mixed input naturally contains both families but you only want one:

```bash
portwave acme --asn AS13335 --ipv4-only     # drop all IPv6 ranges from scope
portwave acme --asn AS13335 --ipv6-only     # drop all IPv4 ranges from scope
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

## Limitations

What portwave deliberately doesn't do (by design or deferred):

- **No SYN scanning.** TCP-connect only — no raw sockets, no root required, no Npcap on Windows. Nmap's `-sS` is faster on the wire but invasive and privilege-bound. Planned for a future release as an opt-in `--syn` mode (root only).
- **No service-version fingerprinting beyond banner classify.** portwave reads the first passive response + does a short HTTP / TLS probe, and maps to 9 protocol labels (http, ssh, ftp, smtp, pop3, imap, smtp_or_ftp, ssl, unknown). For deep `-sV`-style probing use nmap on the open-port list portwave produces.
- **No IDS evasion** (decoys, fragmentation, source-port spoofing). Not the goal — use masscan or nmap if you need stealth.
- **No exhaustive IPv6 `/64` enumeration.** Physically impossible at any speed; `--smart-ipv6` covers the ~450 addresses real admins actually use (RFC 7707 patterns). Anything beyond that wants passive enumeration (CT logs, DNS brute-force, Shodan).
- **No ICMP host discovery pre-flight.** Every target gets TCP probes whether it's alive or not. On sparse ranges this wastes probes; on dense ranges it doesn't matter. `--max-scan-time` is the mitigation for huge sparse scopes.
- **HTTP/2 + HTTP/3 banners not parsed.** The HTTP probe speaks HTTP/1.1; h2/h3-only services show up as open ports with empty banners. httpx in Phase B handles h2/h3 via ALPN, so hits still surface in `httpx_results.txt`.
- **No scanner-side DNS resolution.** Input is IPs, CIDRs, ranges, or ASNs — never hostnames. Resolve with your enum tool (amass, subfinder) and pipe results in via `--input-file`.

## Input validation

portwave fails fast on obviously malformed inputs with a specific error + a hint so you don't have to open `--help`:

```text
error: --asn "notanasn" is not a valid ASN.
  hint: expected format "AS13335" or "AS13335,AS15169" (1-10 digits after optional AS prefix)

error: --max-scan-time invalid duration "5q" — unknown unit 'q'
  hint: valid units are s (seconds), m (minutes), h (hours), d (days)

error: --max-pps must be > 0 (got 0). Use --quiet to disable scanning noise instead.

error: --ipv4-only and --ipv6-only are mutually exclusive — pick one.

error: target scope would expand to 79228162514264337593543950336 host(s) — above the 2^20 safety cap.
  bypass options:
    --smart-ipv6         scan only RFC-7707 common IPv6 addresses in huge IPv6 ranges
    --allow-huge-scope   explicitly proceed with the full expansion (you really sure?)
    --top-ports 100      cut the per-host probe cost if the range is accurate
```

Exit code is **`2`** for every validation error so scripts can distinguish "user typo" from a scan that genuinely found nothing (exit `0`).

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

## Acknowledgements

### Integrated tooling

portwave's recon pipeline integrates two tools maintained by [ProjectDiscovery](https://projectdiscovery.io/), resolved dynamically at scan time via `PATH` or an optional config override:

| Tool | Purpose | Config override |
|---|---|---|
| [**httpx**](https://github.com/projectdiscovery/httpx) | HTTP fingerprinting — status, content length, title, redirect location | `PORTWAVE_HTTPX_BIN` |
| [**nuclei**](https://github.com/projectdiscovery/nuclei) | Template-driven vulnerability scanner | `PORTWAVE_NUCLEI_BIN` |

### Contributors

- [**@nittoSec**](https://github.com/nittoSec) — reported the tool-resolution issue addressed in v0.8.3 (dynamic `PATH` lookup for `httpx` / `nuclei`, interactive install prompt, and Windows `PATHEXT`-aware resolution).

---

## Contact

Developed by **[@assassin_marcos](https://twitter.com/assassin_marcos)** on X / Twitter. Issues + PRs: https://github.com/assassin-marcos/portwave/issues

## License

[MIT](LICENSE).

## Disclaimer

Security-research tool. **Only scan systems you own or have written permission to test.** Unauthorised scanning may be illegal in your jurisdiction.
