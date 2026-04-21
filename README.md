# portwave

**Ultra-fast IPv4/IPv6 port scanner with domain + subdomain support, automatic CDN filtering, and a built-in httpx + nuclei recon pipeline — written in async Rust.**

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

Takes CIDRs, IPs, IP ranges, domains, subdomains, or an ASN — mixed freely in one input. Finds open TCP (and optional UDP) ports, enriches hits with banner grabs + TLS sniff, tags CDN/WAF edges (auto-skips them by default), diffs against the last run, optionally POSTs to a webhook, then chains **httpx** + **nuclei** — all in a single binary.

---

## Benchmarks

Four-way head-to-head: portwave vs rustscan vs naabu vs masscan on the same hardware, same TCP-connect technique, matched threads / timeout / retries across every tool. All four found the **same 15 `ip:port`** — zero false positives, zero false negatives on any side.

### `43.230.180.0/24 × {80, 443, 8443}` — 768 probes

| Tool (config) | Wall time | Peak RSS | Opens | Notes |
|---|---:|---:|:---:|---|
| **portwave (default, Phase A ‖ B pipelined)** | **1.72 s** | **8.4 MB** | 15 | Produces banners + TLS tags + HTTP fingerprint — enrichment runs *concurrently* with discovery |
| rustscan 2.3.0 (`--tries 1`) | 1.35 s | 63.4 MB | 15 | Fewer attempts than parity — no enrichment |
| rustscan 2.3.0 (`--tries 2`, parity) | 1.98 s | 63.4 MB | 15 | Matched retries — no enrichment |
| **portwave (pure discovery)** | **1.00 s** | **8.0 MB** | 15 | `-r 0 --no-banner --no-tls-sniff --no-adaptive` — no enrichment |
| masscan (SYN, `--rate 2000`) | 6.47 s | 40.2 MB | 15 | SYN mode, requires root |
| naabu (`-s c`) | 133.92 s | 56.6 MB | 15 | Connect mode internal rate-limit |

**Takeaway**: **portwave wins speed on every matched comparison** *and* ships banner / TLS / HTTP-fingerprint enrichment that only portwave produces. Memory footprint is 5–8 × smaller than every competitor tested. Pipelining means the default config (full enrichment) is faster than rustscan's parity config (bare discovery) — a first for this tool class.

Exact command:
```bash
/usr/bin/time -v portwave -t 1500 -T 800 -r 1 -p 80,443,8443 \
    --no-httpx --no-nuclei --no-art --no-update-check --quiet \
    bench 43.230.180.0/24
```

---

## Feature matrix

Every cell verified against the current source of each tool. **Legend**: ✅ native · ⚠️ partial or via external tool · ❌ missing. Expandable sections below explain every ⚠️.

### Discovery & scope

| | masscan | rustscan | naabu | **portwave** |
|---|:-:|:-:|:-:|:-:|
| IPv4 + IPv6 TCP discovery           | ⚠️ | ✅ | ⚠️ | ✅ |
| Smart IPv6 scanning (RFC 7707)      | ❌ | ❌ | ❌ | ✅ |
| Scope safety net (huge-CIDR refuse) | ❌ | ❌ | ❌ | ✅ |
| ASN expansion built-in              | ❌ | ❌ | ✅ | ✅ |
| Domain / subdomain input            | ❌ | ✅ | ✅ | ✅ |
| Auto-skip CDN-fronted domains (20+ providers) | ❌ | ❌ | ❌ | ✅ |
| Mixed input (IP + CIDR + range + domain) auto-classify | ❌ | ❌ | ⚠️ | ✅ |
| Exclude list / exclude-file         | ✅ | ✅ | ✅ | ✅ |

### Probing intelligence

| | masscan | rustscan | naabu | **portwave** |
|---|:-:|:-:|:-:|:-:|
| Adaptive concurrency (local-error)   | ❌ | ⚠️ | ❌ | ✅ |
| Banner grab / protocol classify      | ✅ | ⚠️ | ⚠️ | ✅ |
| TLS sniff on non-443                 | ⚠️ | ❌ | ⚠️ | ✅ |
| CDN / WAF edge tagging               | ❌ | ❌ | ⚠️ | ✅ |
| Priority port early-results scan     | ❌ | ❌ | ❌ | ✅ |

### Port selection & rate control

| | masscan | rustscan | naabu | **portwave** |
|---|:-:|:-:|:-:|:-:|
| Nmap-style `--top-ports N` (arbitrary N) | ✅ | ⚠️ | ⚠️ | ✅ |
| UDP well-known-port opt-in               | ✅ | ✅ | ⚠️ | ✅ |
| Global packet-per-second cap             | ✅ | ❌ | ✅ | ✅ |
| Wallclock budget (`--max-scan-time`)     | ❌ | ❌ | ❌ | ✅ |
| Dry-run / scan-plan preview              | ✅ | ❌ | ❌ | ✅ |

### Output & integration

| | masscan | rustscan | naabu | **portwave** |
|---|:-:|:-:|:-:|:-:|
| `scan_diff.json` vs. prior run      | ❌ | ❌ | ❌ | ✅ |
| Webhook on completion               | ❌ | ❌ | ❌ | ✅ |
| Webhook only on diff change         | ❌ | ❌ | ❌ | ✅ |
| NDJSON output                       | ⚠️ | ❌ | ✅ | ✅ |
| Structured JSON files               | ✅ | ❌ | ✅ | ✅ |
| Built-in httpx + nuclei chain       | ❌ | ⚠️ | ⚠️ | ✅ |
| Dynamic CDN refresh at runtime      | ❌ | ❌ | ⚠️ | ✅ |

### Operations

| | masscan | rustscan | naabu | **portwave** |
|---|:-:|:-:|:-:|:-:|
| Resume after crash / Ctrl+C             | ✅ | ❌ | ✅ | ✅ |
| Self-update (`--update`)                | ❌ | ❌ | ✅ | ✅ |
| Self-uninstall (`--uninstall`)          | ❌ | ❌ | ❌ | ✅ |
| Clear input-validation errors           | ⚠️ | ✅ | ✅ | ✅ |
| Single static cross-platform binary     | ⚠️ | ✅ | ⚠️ | ✅ |

<details>
<summary><b>What each ⚠️ actually means (click to expand)</b></summary>

**masscan**
- *IPv4 + IPv6*: SYN-scan only, no TCP-connect mode (always `-sS`).
- *TLS on non-443*: `--hello ssl[PORT]` triggers TLS on any port + `--capture cert` reads the cert; no JA3/JA4-style fingerprint.
- *NDJSON*: file-based via `-oD`; not a stdout stream.
- *Validation errors*: some errors include `hint:` lines (see `main-conf.c:1388`), most are bare `FAIL:`.
- *Static binary*: must compile per platform — no pre-built releases shipped.

**rustscan**
- *Adaptive concurrency*: batch size picked once at startup from `ulimit -n` (`main.rs:262 infer_batch_size`), not runtime-adaptive to local errors.
- *Banner grab*: delegated to nmap via `-- <nmap args>` passthrough (`input.rs:146`); no native banner reader.
- *`--top-ports N`*: only a `--top` boolean (fixed ~1000 ports from `config.toml`), no integer argument.
- *Built-in recon chain*: chains to **nmap** only, not to httpx or nuclei.

**naabu**
- *IPv4 + IPv6*: dual-stack flagged "experimental" in README.
- *Banner grab*: uses `-nmap-cli` passthrough / `-sV` (via nmap); no native banner reader.
- *TLS on non-443*: `netutil.DetectTLS` exists (`scan.go:465`) but gated behind undocumented `ENABLE_TLS_DETECTION` env, off by default.
- *CDN tagging*: `-cdn` tags + `-exclude-cdn` skip, powered by `projectdiscovery/cdncheck` library.
- *Mixed input*: supports domains + IPs but without line-by-line auto-classification in one file.
- *`--top-ports N`*: only accepts preset `100`, `1000`, or `full` — not arbitrary N.
- *UDP*: via `-p u:port` syntax; no dedicated `-sU` flag.
- *Dynamic CDN refresh*: CDN list refreshes via upstream library release cycle, not at runtime.
- *Built-in recon chain*: chains to **nmap** only via `-nmap-cli`, not httpx/nuclei.
- *Static binary*: requires **libpcap** (Linux/macOS) or **Npcap** (Windows) at runtime for SYN scans.

</details>

---

## Install

**Linux / macOS:**
```bash
git clone https://github.com/assassin-marcos/portwave && cd portwave && bash install.sh
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/assassin-marcos/portwave; cd portwave; powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Installers auto-detect `httpx` / `nuclei` across `$PATH`, `~/go/bin`, `~/.pdtm/go/bin`, Homebrew, MacPorts, `~/.local/bin`; append PATH to the right shell rc. Non-interactive: `NONINTERACTIVE=1`.

**Update / uninstall** (all platforms):
```bash
portwave -u          # install latest release + print What's-new changelog
portwave -c          # check for updates (does not install)
portwave -X          # uninstall (binary + share + cache); -Xy to skip the prompt
```

---

## Quickstart

The first positional argument is just a **folder name** for results — pick anything (examples below use `acme`, `bb`, etc.); outputs land in `./scans/<folder>/`.

```bash
portwave acme 1.2.3.4                                 # one IP
portwave acme 203.0.113.0/24                          # a CIDR
portwave acme -d example.com                          # one domain
portwave bb -d "site.com,api.site.com,mail.site.com"  # multiple domains
subfinder -d target.com -silent | portwave bb -i -    # subdomain list via stdin
```

That's it — defaults are tuned for fast + accurate. Skip to [Recommended commands](#recommended-commands) for flags that squeeze out the last 5 %.

---

## Domain & subdomain scanning

**New in v0.14.0** — portwave accepts domains alongside IPs. Each domain resolves in parallel via hickory-resolver (direct queries to Cloudflare 1.1.1.1 / Google 8.8.8.8), and any domain whose A/AAAA records land on a known CDN edge (Cloudflare, Akamai, Fastly, CloudFront, Gcore, Imperva, and 18 others — 13,500+ CIDRs across 20 providers) is skipped by default. Only domains with exposed origin IPs get scanned.

```bash
portwave bb -d example.com                           # single domain
portwave bb -d "site.com,api.site.com,mail.site.com" # multiple
subfinder -d target.com -silent | portwave bb --input-file -
```

Mixed input files work automatically — each line is classified as IP, CIDR, IP range, IPv6, or domain and routed to the right resolver.

**Example output:**
```text
Resolving 5 domain(s) (50 concurrent, 3s timeout)…
  ✓ 3 domain(s) → 13 origin IP(s)
  ⚠ 2 domain(s) → CDN edge (cloudflare:1, fastly:1) — skipped
--- PHASE A: DISCOVERY ---
...
--- OPEN PORTS (17 total across 8 hosts) ---
  scanme.nmap.org → 45.33.32.156
      :22   [ssh]   SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  github.com → 20.205.243.166
      :22   [ssh]
      :80   [http]  HTTP/1.1 301 Moved Permanently
      :443  [https]
```

**Flags:**
- `-d, --domain <LIST>` — comma-separated domains to resolve + scan
- `--allow-cdn` — override the default skip and scan CDN edge IPs too (rarely useful; CDN only exposes 80/443)
- `--dns-timeout <SECONDS>` — per-query timeout (default `3`)
- `--dns-concurrency <N>` — parallel DNS lookups (default `50`)

**Refresh the CDN list before a scan session** to pick up the latest provider announcements:

```bash
portwave --refresh-cdn    # ~20 s; writes to ~/.cache/portwave/cdn-ranges.txt
```

---

## Recommended commands

### 🎯 Maximum coverage — don't miss any open port (CIDR)

```bash
portwave acme 203.0.113.0/24 \
    -t 1000 -T 1500 -r 2 --enrich-timeout-ms 3000 \
    --httpx-follow-redirects \
    --httpx-paths "/actuator,/.git/HEAD,/server-status,/robots.txt,/.env,/swagger-ui,/admin,/api/v1"
```

### 🎯 Maximum coverage — ASN (one company's full public infra)

```bash
portwave acme --asn AS13335 \
    -t 800 -T 1500 -r 2 --enrich-timeout-ms 3000 \
    --httpx-paths "/actuator,/.git/HEAD,/server-status,/robots.txt,/.env,/swagger-ui,/admin,/api/v1"
# --httpx-follow-redirects auto-enables under --asn
```

**Why these flags?**

| Flag | Value | What it buys |
|---|---|---|
| `-t 1000` (CIDR) / `-t 800` (ASN) | lower than default 1500 | Avoids ephemeral-port exhaustion on long ASN scans → fewer local-resource errors → fewer missed ports |
| `-T 1500` | 1.5 s discovery timeout | Catches slow / firewalled hosts that default 800 ms misses — common on gov / enterprise IPs |
| `-r 2` | 2 retries | Catches transient SYN drops (ISP rate-limits, router buffer overflow). Default 1 is fine for clean LAN; bump to 2 over internet |
| `--enrich-timeout-ms 3000` | 3 s enrichment timeout | Slow HTTP servers + TLS handshakes that default 1.5 s cuts off (gov / old embedded gear) |
| `--httpx-follow-redirects` | — | Most hosts 30x to login pages / WAFs; following gives meaningful status + title |
| `--httpx-paths` | list | Probes common leak / config / admin endpoints beyond `/` |

Nuclei severity defaults to `low,medium,high,critical` — `info` is filtered out because info-tier templates dominate noise on large scans. Override with `--nuclei-severity "critical"` for triage-only runs, or `--nuclei-severity "info,low,medium,high,critical"` to include everything.

### ⚡ Quick scan — defaults are already tuned for "fast + accurate"

```bash
portwave acme 203.0.113.0/24                                # full pipeline, defaults
portwave acme --input-file scope.txt                        # targets from file
portwave acme --asn AS13335                                 # entire ASN
portwave acme "203.0.113.0/24,2001:db8::/112"               # mixed IPv4 + IPv6
portwave acme 203.0.113.0/24 --ports "22,80,443,8000-9000"  # custom ports
portwave acme 203.0.113.0/24 --top-ports 100                # nmap-style top N
portwave acme 203.0.113.0/24 --exclude "203.0.113.64/26"    # skip subranges
portwave acme 203.0.113.0/24 --udp                          # also UDP discovery
portwave gcloud 2a00:1450::/32 --smart-ipv6 --top-ports 10  # massive IPv6 range
portwave preview --asn AS13335 --dry-run                    # plan without scanning
```

### 🤖 Automation / monitoring

```bash
portwave acme 203.0.113.0/24 --webhook $SLACK_URL                       # post on completion
portwave acme 203.0.113.0/24 --webhook $SLACK_URL --webhook-on-diff-only # only if opens changed
portwave acme 203.0.113.0/24 --json-out --no-httpx --no-nuclei | jq .   # NDJSON stream
portwave acme 203.0.113.0/24 --max-pps 200                              # polite (200 pps cap)
portwave big --asn AS99999 --max-scan-time 30m                          # hard time budget

# Full bug-bounty chain — one command replaces subfinder → dnsx → cdncheck → naabu → httpx
subfinder -d target.com -silent | portwave bb --input-file -
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
| `<CIDR_INPUT>` positional | `203.0.113.0/24`, `1.2.3.4`, `5.6.7.10-5.6.7.20`, `2001:db8::/112`, `example.com`, or comma-separated mix |
| `-i, --input-file <FILE>` | One target per line (IP / CIDR / range / domain), `#` for comments, auto-classified |
| `-d, --domain <LIST>` | Comma-separated domains. CDN-fronted hosts skipped by default. |
| `-a, --asn <LIST>` | `AS13335,AS15169` — expanded via RIPE stat (public, no API key) |
| `-e, --exclude <LIST>` | Same format as `<CIDR_INPUT>`; skipped in the producer |
| `--allow-cdn` | Scan a domain's origin IPs even when resolved to a known CDN edge |
| `--dns-timeout <SECONDS>` | Per-domain DNS timeout (default `3`) |
| `--dns-concurrency <N>` | Parallel DNS lookups (default `50`) |
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
| `--nuclei-severity <LIST>` | `low,medium,high,critical` | nuclei `-severity` filter. Default drops `info`-tier templates (noise reduction on large scans). Override with any nuclei-accepted value, e.g. `"critical"` or `"info,low,medium,high,critical"` |
| `--no-httpx` / `--no-nuclei` | — | Skip either step |

### Update / CDN / UX

| Flag | Purpose |
|---|---|
| `-u, --update` | Download latest release binary, replace in place, refresh any on-disk ports file. Prints a What's-new changelog on completion |
| `-c, --check-update` | Report whether a newer release exists (peeks both releases + tags API) |
| `-X, --uninstall` | Remove portwave (binary + share + cache + optional config), interactive `[y/N]` |
| `-y, --yes` | Skip the uninstall confirmation (for scripted removal) |
| `--refresh-cdn` | Re-fetch all 20 CDN providers live (11 direct URLs + 13 via RIPE stat ASN lookup — Cloudflare, Akamai, Fastly, CloudFront, Gcore, Imperva, and 14 others; ~13,500 CIDRs). Cache written to `~/.cache/portwave/cdn-ranges.txt` |
| `--no-update-check` | Suppress startup "update available" banner |
| `--no-update-prompt` | Show the update banner + changelog but skip the `[Y/n]` prompt |
| `--no-install-prompt` | Don't prompt to install httpx/nuclei if missing (for CI) |
| `--no-art` / `-q, --quiet` | Suppress banner art / all banner output |
| `--no-banner` / `--no-tls-sniff` / `--no-adaptive` | Turn off individual Phase-B features |

The startup banner prints `(latest)` in green or `(outdated → vX.Y.Z)` in red next to the version — the cache is refreshed against GitHub on every startup (1 s budget, 2 min cache-hit fast path) so the tag stays accurate within ~2 min of a new release.

---

## Output

Every scan writes to `<OUTPUT_DIR>/<FOLDER_NAME>/`:

| File | Contents |
|---|---|
| `http_targets.txt`   | URL form, HTTP-candidate filter. **Both httpx and nuclei read this file.** Domain-aware — when the scan was seeded from a domain, URLs use the domain name (not the resolved IP) so TLS SNI + virtual-host routing work. |
| `open_ports.jsonl`   | One JSON per line: `{ip, port, rtt_ms, tls, protocol, banner, cdn}` |
| `scan_summary.json`  | `{duration_ms, attempts, open, closed, timeouts, by_port, by_protocol, by_cdn, phase_a_ms, phase_b_ms, ...}` |
| `scan_diff.json`     | `{prior_opens, current_opens, new:[…], closed:[…], unchanged}` vs. previous run |
| `httpx_results.txt`  | httpx output |
| `nuclei_results.txt` | nuclei output |

Example live terminal (ANSI colors in a real TTY — here shown plain):
```text
[+] 151.101.1.1:80 opened
[+] 151.101.1.1:443 opened
[+] 203.0.113.42:22 opened
[+] 203.0.113.42:443 opened
⠙ [00:06:28] ████████████████████████ 363982/363982 (100%) 938/s · ETA 0s 75 open
Phase A done: 75 new open ports.

Totals — 363,982 probes · open: 75 · closed: 68 · filtered: 363,839 (99.94%) · local_err: 0

--- OPEN PORTS (75 total across 12 hosts) ---
  151.101.1.1
      :80   [http, cdn:fastly]     HTTP/1.1 200 OK
      :443  [https, cdn:fastly]
  203.0.113.42
      :22   [ssh]                  SSH-2.0-OpenSSH_8.9p1
      :443  [https]
  (...)

Results: 75 open · 6m30s · ./scans/acme
```

Live behavior:
- **`[+] IP:PORT opened`** — hits streamed as they're discovered (bright green). Disable with `--no-live-hits`.
- **Progress bar** shows `938/s` probe rate + ETA so you can spot a stuck scan instantly.
- **Totals** colored by state: open = green, closed = dim, filtered = yellow above 50 %, local_err = red when > 0.
- **OPEN PORTS** grouped by host (nmap-style); port labels colored by protocol — `http` green, `https` bright cyan, database protocols bright magenta, IoT/ICS bright red, TLS yellow.

Metric meanings:
- **open** — TCP handshake completed
- **closed** — RST / ICMP-unreachable (port closed, host alive)
- **filtered** — no reply within timeout (firewall dropped SYN or host down)
- **local_err** — our OS pushed back (ephemeral-port / FD / buffer full) — investigate if non-zero

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

Two-pass producer (top-20 priority ports first for early results, then remaining) feeds an MPMC queue → 1500 async Phase A workers → open-port hits stream into Phase B enrichment **concurrently** (banner grab + TLS sniff + HTTP probe + CDN lookup). Optional Phase C for UDP. Writer streams results to disk, then httpx + nuclei chain against the HTTP-candidate subset. Adaptive monitor shrinks concurrency only on local-resource errors (not timeouts — firewalled targets would otherwise be misread as "we're saturated").

Iterator-based producer is O(nets) in memory, not O(IPs) — same memory footprint on a single /32 or a /8.

---

## Limitations

What portwave deliberately doesn't do (by design or deferred):

- **No SYN scanning.** TCP-connect only — no raw sockets, no root required, no Npcap on Windows. Nmap's `-sS` is faster on the wire but invasive and privilege-bound. Planned for a future release as an opt-in `--syn` mode (root only).
- **No service-version fingerprinting beyond banner classify.** portwave reads the first passive response + does a short HTTP / TLS probe, and maps to 9 protocol labels (http, ssh, ftp, smtp, pop3, imap, smtp_or_ftp, ssl, unknown). For deep `-sV`-style probing use nmap on the open-port list portwave produces.
- **No IDS evasion** (decoys, fragmentation, source-port spoofing). Not the goal — use masscan or nmap if you need stealth.
- **No exhaustive IPv6 `/64` enumeration.** Physically impossible at any speed; `--smart-ipv6` covers the ~450 addresses real admins actually use (RFC 7707 patterns). Anything beyond that wants passive enumeration (CT logs, DNS brute-force, Shodan).
- **No ICMP host discovery pre-flight.** Every target gets TCP probes whether it's alive or not. On sparse ranges this wastes probes; on dense ranges it doesn't matter. `--max-scan-time` is the mitigation for huge sparse scopes.
- **HTTP/2 + HTTP/3 banners not parsed.** The HTTP probe speaks HTTP/1.1; h2/h3-only services show up as open ports with empty banners. httpx in Phase B handles h2/h3 via ALPN, so hits still surface in `httpx_results.txt`.
- **No passive subdomain enumeration** (CT logs / Shodan lookups). Pair with `subfinder -d target.com -silent | portwave bb -i -` for the full bug-bounty scope expansion. DNS resolution of domains you hand portwave IS built-in since v0.14.0.

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

**Does portwave accept domains / subdomains?**
Yes. Pass them via `-d example.com,sub.example.com` or mix them into an `-i` input file. Each domain is resolved in parallel (hickory DNS → Cloudflare / Google), and any host whose A/AAAA records land on a known CDN edge (Cloudflare, Akamai, Fastly, CloudFront, and 16 others) is auto-skipped, since a CDN IP only exposes 80/443 shared across thousands of tenants. Use `--allow-cdn` to override. Output labels hits as `domain → IP` so you can tell which subdomain each open port belongs to.

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
