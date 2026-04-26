# portwave

**Fast IPv4/IPv6 port scanner with built-in HTTP(S) enrichment, SSL recon, and nuclei — one binary, no subprocess chain.**

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

Takes IPs, CIDRs, ranges, domains, or ASNs — mixed freely. Wildcard-DNS pre-filter, parallel resolution, adaptive Phase-A scan, native HTTP(S) probe, SSL/SAN recon, nuclei. Resume-safe, diff-aware, single static binary.

---

## Install

```bash
# Linux / macOS
git clone https://github.com/assassin-marcos/portwave && cd portwave && bash install.sh

# Windows
git clone https://github.com/assassin-marcos/portwave; cd portwave; powershell -ExecutionPolicy Bypass -File .\install.ps1

# Self-manage
portwave -u    # install latest
portwave -c    # check for updates
portwave -X    # uninstall
```

---

## Quickstart

First positional is a **folder name** for results (`./scans/<folder>/`).

```bash
portwave scan 1.2.3.4                              # one IP
portwave scan 203.0.113.0/24                       # CIDR
portwave scan -d example.com                       # domain (CDN auto-skip)
portwave scan -d "a.site.com,b.site.com"           # multiple
subfinder -d target.com -silent | portwave bb -i - # subdomains via stdin
portwave scan -a AS13335 --ipv4-only               # full ASN, v4 only
portwave scan 203.0.113.0/24 -p 22,80,443          # custom ports
portwave scan x -i list.txt --top-ports 100        # mixed targets, top-100
portwave big -a AS99999 --max-scan-time 30m --max-pps 200   # rate-limited
```

Defaults are tuned for fast + accurate. No flags needed for most scans.

---

## Pipeline

```
0. DNS / wildcard filter — resolve domains in parallel; collapse wildcard zones
1. Phase A   — adaptive TCP connect (2000→3000 workers, 800 ms timeout, retry 1)
2. Phase B   — banner grab + TLS sniff (pipelined with Phase A)
3. Pass-C    — native HTTP(S) probe (HTTP/2, title, redirects, lenient TLS)
4. SSL recon — handshake reuse from Pass-C → SAN + issuer extraction
5. nuclei    — template-driven vulnscan on HTTP candidates (if installed)
```

HTTP/2 via ALPN, permissive TLS (bundled OpenSSL — accepts self-signed, expired, hostname-mismatched, malformed certs so the scanner sees responses, not handshake errors).

**Domains.** Resolved in parallel via hickory DNS (15 trusted upstreams). Wildcard zones (`*.example.com → 1.2.3.4`) are detected by 3 random-label probes per parent suffix and collapsed to one representative — typically skips ~90 % of DNS work on big subdomain lists. Domains landing on a known CDN edge (Cloudflare, Akamai, Fastly, CloudFront, Gcore, Imperva, etc.) are skipped — override with `--allow-cdn`. Refresh CDN list with `portwave --refresh-cdn`.

---

## Output (`./scans/<folder>/`)

| File | Contents |
|---|---|
| `open_ports.jsonl` | One JSON per open port — ip, port, protocol, banner, title, final_url, cdn |
| `enrichment_results.txt` | `URL [status] [length] [title]` per HTTP target |
| `http_targets.txt` | URL list fed to nuclei |
| `ssl_findings.txt` | `[ssl-dns-names]` lines per unique cert (nuclei-ssl format) |
| `ssl_root_domains.txt` | Unique eTLD+1 domains aggregated across SAN entries |
| `nuclei_results.txt` | nuclei findings |
| `scan_summary.json` | Totals + timings + per-protocol/per-port/per-CDN counts |
| `scan_diff.json` | New / closed opens vs the last run in this folder |
| `domains.json` / `origin_domains.txt` | Domain resolution + CDN tagging (when `-d`/`-i` used) |

```
--- OPEN PORTS (8 total across 1 host) ---
  example.com → 203.0.113.5
      :22    [ssh]
      :80    [http]   HTTP/1.1 301 Moved Permanently  · "301 Moved Permanently"
      :443   [https]  HTTP/1.1 200 OK                 · "Acme Dashboard"
─── enrichment 2 target(s) · 0.35s   ✓ 2 responding · 1 2xx · 1 3xx
─── ssl recon 1 unique cert · 0.00s  → ssl_findings.txt
```

---

## IPv6

A `/64` is 2⁶⁴ addresses. Exhaustive scanning is impossible.

- Any scope > **2²⁰ (≈1 M) hosts** is refused with three bypass options.
- `--smart-ipv6` replaces ranges > /108 with ~450 RFC-7707 likely-addresses (hexspeak, low-sequential, SLAAC landmarks). `/32` becomes a minute.
- `--allow-huge-scope` overrides explicitly.

```bash
portwave gcloud 2a00:1450::/32 --smart-ipv6 --top-ports 10
```

---

## Common flags

Full list via `portwave -h`. Most-used:

| Flag | Default | Purpose |
|---|---|---|
| `-d, --domain` | — | Comma-separated domains |
| `-i, --input-file` | — | Mixed-target file (`-` for stdin) |
| `-a, --asn` | — | ASN list, expanded via RIPE stat |
| `-e, --exclude` | — | Ranges to skip |
| `-p, --ports` / `--top-ports N` | bundled | Custom ports / top-N from bundled list |
| `-U, --udp` | off | UDP discovery on well-known ports |
| `-t, --threads` | 2000 | Phase-A pool (adaptive grows to 3000 / 1.5×) |
| `-T, --timeout-ms` | 800 | Phase-A connect timeout |
| `-r, --retries` | 1 | Retries on Phase-A timeouts |
| `--enrich-timeout-ms` | 1500 | Phase-B banner timeout |
| `-C, --probe-concurrency` | 150 | HTTP probe concurrency |
| `--no-follow-redirects` | follow | Disable 3-hop redirect chain |
| `--no-enrich` / `--no-banner` / `--no-tls-sniff` | all on | Disable Phase-B/C steps |
| `--no-ssl-scan` | on | Skip SAN/issuer extraction |
| `--no-wildcard-filter` | on | Resolve every input even on wildcard zones |
| `--no-nuclei` | on | Skip nuclei |
| `--ipv4-only` / `--ipv6-only` | both | Family filter |
| `--smart-ipv6` / `--allow-huge-scope` | off | IPv6 scope handling |
| `--allow-cdn` | skip | Scan CDN-fronted domains too |
| `--max-pps` / `--max-scan-time` | — | Packet-rate / wallclock cap |
| `--dry-run` | — | Print scan plan + exit |
| `-n, --no-resume` | resume | Wipe prior artefacts, start fresh |
| `-o, --output-dir` | `./scans` | Output root |
| `-w, --webhook` `--webhook-on-diff-only` | — | POST summary on completion |
| `--json-out` | — | NDJSON to stdout |
| `-q, --quiet` | — | `--no-art --no-update-check` |
| `-u` / `-c` / `-X` / `--refresh-cdn` | — | Self-management |

---

## Limitations

- TCP-connect only (no SYN scan — no raw sockets, no root)
- No service-version fingerprinting past 9-label protocol classify (chain `nmap -sV` if needed)
- No IDS evasion (no decoys, fragments, source spoofing)
- No ICMP host-discovery pre-flight
- No passive subdomain enumeration — pair with `subfinder -silent | portwave -i -`

---

## FAQ

**`cdn:fastly` next to a port?** The IP is in a published CDN edge range. The port belongs to the CDN, not the origin. `--allow-cdn` to scan anyway.

**Heavy `local_err` / adaptive shrinks on macOS?** Your shell's FD soft limit is too low (default 256 from `launchctl`). Run `ulimit -n 65535` before portwave, or upgrade — recent versions auto-target the kernel ceiling.

---

## License / Contact

MIT. Developed by [**@assassin_marcos**](https://twitter.com/assassin_marcos). Issues + PRs at https://github.com/assassin-marcos/portwave/issues. **nuclei** ([ProjectDiscovery](https://github.com/projectdiscovery/nuclei)) is resolved at scan time via `PATH` or `$PORTWAVE_NUCLEI_BIN`.

**Disclaimer:** Security-research tool. **Only scan systems you own or have written permission to test.**
