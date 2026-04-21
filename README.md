# portwave

**Fast IPv4/IPv6 port scanner with built-in HTTP(S) enrichment and nuclei — one binary, no subprocess chain.**

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

Takes IPs, CIDRs, ranges, domains, or ASNs — mixed freely. Finds open TCP (+ optional UDP) ports, banner-grabs, does a full HTTP(S) probe with titles + redirects, auto-skips CDN-fronted domains, then runs nuclei on HTTP candidates. Resume-safe, diff-aware, single static binary.

---

## Install

**Linux / macOS:**
```bash
git clone https://github.com/assassin-marcos/portwave && cd portwave && bash install.sh
```

**Windows:**
```powershell
git clone https://github.com/assassin-marcos/portwave; cd portwave; powershell -ExecutionPolicy Bypass -File .\install.ps1
```

**Update / uninstall:**
```bash
portwave -u   # install latest
portwave -c   # check for updates
portwave -X   # uninstall
```

---

## Quickstart

First positional is a **folder name** for results (pick anything — outputs land in `./scans/<folder>/`):

```bash
portwave scan 1.2.3.4                              # one IP
portwave scan 203.0.113.0/24                       # CIDR
portwave scan -d example.com                       # domain
portwave scan -d "a.site.com,b.site.com"           # multiple domains
subfinder -d target.com -silent | portwave bb -i - # subdomain list via stdin
portwave scan -a AS13335 --ipv4-only               # full ASN, v4 only
portwave scan 203.0.113.0/24 -p 22,80,443          # custom ports
```

Defaults are tuned for fast + accurate. No flags needed for most scans.

---

## What it does

```
1. Phase A — TCP connect scan (3000 workers · 800 ms timeout · adaptive)
2. Phase B — banner grab + TLS sniff (pipelined, concurrent with Phase A)
3. Enrichment — native HTTP(S) probe (HTTP/2, title, redirects, lenient TLS)
4. nuclei — template-driven vulnscan on HTTP candidates (if installed)
```

All in one binary. HTTP/2 via ALPN, permissive TLS (bundled OpenSSL — accepts self-signed, expired, hostname-mismatched, and malformed X.509 certs so a scanner sees the response instead of a handshake error).

---

## Recommended scans

**Maximum coverage on a CIDR or ASN:**
```bash
portwave acme 203.0.113.0/24 -t 3000 -T 1500 -r 2 \
    --enrich-timeout-ms 3000 --follow-redirects
```

**Full bug-bounty chain — one command:**
```bash
subfinder -d target.com -silent | portwave bb -i - --ipv4-only
```

Flags in plain English:

| Flag | Why |
|---|---|
| `-t 3000` | Workers; higher on good networks (FD limit is already raised to 1M) |
| `-T 1500` | Longer Phase-A timeout catches slow/firewalled hosts |
| `-r 2` | 2 retries for flaky internet scans (default 1 is fine for LAN) |
| `--enrich-timeout-ms 3000` | Slow TLS handshakes / old servers |
| `--follow-redirects` | See real status + title past 30x chains (auto-on with `-a`) |
| `--ipv4-only` | Drop IPv6 from ASN expansion — huge time saver |
| `-C 100` | HTTP probe concurrency (default 100, raise for small scopes) |

---

## Domain & subdomain scanning

Each domain is resolved in parallel via hickory DNS (1.1.1.1 / 8.8.8.8). Any domain resolving to a known CDN edge (Cloudflare, Akamai, Fastly, CloudFront, Gcore, Imperva, and 14 others — 13 500+ CIDRs across 20 providers) is **skipped by default** — CDN edges only expose 80/443 and the findings belong to the CDN, not your target.

```bash
portwave bb -d example.com                # one
portwave bb -d "a.x.com,b.x.com"          # list
portwave bb -i subs.txt                   # file (auto-classifies each line)
portwave bb -i -                          # stdin
```

Override with `--allow-cdn`. Refresh the CDN list with `portwave --refresh-cdn` (~20 s; cached at `~/.cache/portwave/cdn-ranges.txt`).

---

## Output

`./scans/<folder>/`:

| File | Contents |
|---|---|
| `open_ports.jsonl` | One JSON per open port — ip, port, protocol, banner, title, final_url, cdn |
| `enrichment_results.txt` | `URL [status] [length] [title]` per HTTP target |
| `http_targets.txt` | URL list fed to nuclei |
| `nuclei_results.txt` | nuclei findings |
| `scan_summary.json` | Totals + timings + per-protocol/per-port/per-CDN counts |
| `scan_diff.json` | New / closed opens vs the last run in this folder |
| `domains.json` | Domain resolution + CDN detection (when `-d` used) |
| `origin_domains.txt` | Non-CDN domains that survived the filter |

Terminal output example:

```
--- OPEN PORTS (8 total across 1 hosts) ---
  example.com → 203.0.113.5
      :22    [ssh]
      :80    [http]   HTTP/1.1 301 Moved Permanently  · "301 Moved Permanently"
      :443   [https]  HTTP/1.1 200 OK                 · "Acme Dashboard"

─── enrichment 2 target(s) · 0.35s

http://example.com [301] [162] [301 Moved Permanently]
https://example.com [200] [4712] [Acme Dashboard]

✓ enrichment: 2 responding · 1 2xx · 1 3xx · 0 4xx · 0 5xx
```

---

## IPv6

A `/64` is 2⁶⁴ addresses. Exhaustive scanning is physically impossible.

- Any target set that would expand beyond **2²⁰ (≈1 M) hosts** is refused with a clear error and three bypass options.
- `--smart-ipv6` — replace any IPv6 range > /108 with ~450 RFC-7707 likely addresses (hexspeak, low-sequential, SLAAC landmarks). Turns a `/32` scan from impossible to a minute.
- `--allow-huge-scope` — explicit override.

```bash
portwave gcloud 2a00:1450::/32 --smart-ipv6 --top-ports 10
```

---

## Automation

```bash
portwave acme 203.0.113.0/24 --webhook $SLACK_URL --webhook-on-diff-only
portwave acme 203.0.113.0/24 --json-out --no-enrich --no-nuclei | jq .
portwave big -a AS99999 --max-scan-time 30m --max-pps 200
portwave preview -a AS13335 --dry-run
```

Exit codes: `0` on success, `2` on input validation error (scriptable).

---

## Flags (`portwave -h`)

Short where it matters. Full list via `portwave -h`. Common ones:

| Flag | Purpose |
|---|---|
| `-d, --domain` | Comma-separated domains |
| `-i, --input-file` | File of mixed targets (`-` for stdin) |
| `-a, --asn` | ASN list, expanded via RIPE stat |
| `-e, --exclude` | Ranges to skip |
| `-p, --ports` | Port list / ranges |
| `--top-ports N` | Use only top-N ports |
| `-t, --threads` | Phase-A concurrency (default 3000) |
| `-T, --timeout-ms` | Phase-A timeout (default 800 ms) |
| `-r, --retries` | Phase-A retries (default 1) |
| `-C, --probe-concurrency` | HTTP probe concurrency (default 100) |
| `--follow-redirects` | Follow redirects up to 3 hops |
| `--no-enrich` | Skip HTTP(S) enrichment |
| `--no-nuclei` | Skip nuclei |
| `--ipv4-only` / `--ipv6-only` | Family filter |
| `--smart-ipv6` | RFC-7707 addresses for huge IPv6 ranges |
| `--allow-cdn` | Scan CDN-fronted domains too |
| `-o, --output-dir` | Output dir (default `./scans`) |
| `-w, --webhook` | POST summary on completion |
| `--max-pps` / `--max-scan-time` | Rate / time budget |
| `--dry-run` | Print scan plan + exit |
| `-u` / `-c` / `-X` | update / check-update / uninstall |
| `--refresh-cdn` | Refresh CDN CIDR cache |

---

## Limitations

- **TCP-connect only** (no SYN scan — no raw sockets, no root required)
- **No service-version fingerprinting** past protocol classify (9 labels). Use nmap on portwave's open-port list if you need `-sV` depth
- **No IDS evasion** (decoys, fragments, source spoofing)
- **Exhaustive IPv6 /64 enumeration** is impossible; `--smart-ipv6` covers likely addresses
- **No ICMP host-discovery pre-flight** — every target gets TCP probes regardless
- **No passive subdomain enumeration** — pair with `subfinder -silent | portwave -i -`

---

## FAQ

**Does portwave accept domains / subdomains?**
Yes. `-d domain.com,sub.domain.com` or mix into `-i file`. Each is resolved in parallel (hickory DNS → Cloudflare / Google), and any host whose A/AAAA lands on a known CDN edge is auto-skipped. Output labels hits as `domain → IP`.

**What's `cdn:fastly` next to an open port?**
The IP is in a published CDN edge range. The open port belongs to the CDN, not the origin. Useful triage signal; `--allow-cdn` to scan anyway.

**My VPS shows fewer ports than expected.**
Usually: service bound to 127.0.0.1, provider firewall (AWS SG / Hetzner / DO), or host firewall. Run `ss -tlnp` on the VPS to see what's externally listening.

---

## Acknowledgements

[**nuclei**](https://github.com/projectdiscovery/nuclei) (ProjectDiscovery) — template-driven vulnerability scanner, resolved dynamically at scan time via `PATH` or `$PORTWAVE_NUCLEI_BIN`.

Contributors:
- [**@nittoSec**](https://github.com/nittoSec) — reported the tool-resolution issue in v0.8.3.

---

## License / Contact

MIT. Developed by [**@assassin_marcos**](https://twitter.com/assassin_marcos). Issues + PRs at https://github.com/assassin-marcos/portwave/issues.

**Disclaimer:** Security-research tool. **Only scan systems you own or have written permission to test.**
