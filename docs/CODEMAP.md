# portwave code map

Generated against **portwave 0.15.0** (2026-04-24). Read this first
instead of scanning the full source — line numbers let you jump
straight to the area you need.

**When to regenerate:** if line numbers look >20 off after a big
change, rerun the `grep` at the bottom of this file and update.

## Files

- `src/main.rs` (~6048 lines) — everything except DNS
- `src/domain.rs` (~414 lines) — domain classification + DNS resolution
- `ports/portwave-top-ports.txt` — embedded via `include_str!`
- `ports/cdn-ranges.txt` — embedded CDN CIDR table
- `Cargo.toml` — version + deps

## main.rs

### CLI / config / setup
- `32`   `struct Args` — clap CLI definition (all flags)
- `251`  `struct OpenPort` — per-port finding (banner, TLS, cdn, title, final_url, redirect_chain, content_length)
- `295`  `struct ScanSummary`
- `342`  `struct Stats` — atomic counters: shutdown, attempts, opens, timeouts, local_errors, net_unreach, priority_done, adaptive_shrunk
- `383`  `default_config_path`
- `408`  `load_config`
- `426`  `resolve_path`
- `458`  `raise_fd_limit` (Unix setrlimit)
- `482`  `raise_fd_limit` (no-op non-Unix)

### Port / target parsing
- `488`  `EMBEDDED_PORTS`, `494` `TOP_PRIORITY_PORTS`
- `499`  `parse_port_list` / `545` `load_ports` / `562` `refresh_bundled_ports_files`
- `711`  `total_host_count` / `732` `smart_ipv6_addresses`
- `792`  `struct RateLimiter`
- `831`  `parse_target_token` / `868` `ipv4_range_to_cidrs` / `893` `expand_targets`
- `918`  `fetch_asn_prefixes`

### CDN / enrichment / HTTP probe
- `944`  `CDN_RANGES_RAW`, `947` `load_cdn_ranges`, `972` `cdn_tag_for`
- `981`  `is_usable_ipv4_host`
- `1007` `NON_HTTP_PORTS`, `1065` `is_http_candidate`
- `1069` `format_for_nuclei`
- `1118` `struct HttpProbeResult`
- `1129` `extract_title` / `1148` `resolve_redirect_url`
- `1188` `HTTP_CLIENT` static (reqwest::blocking — no UA on client, set per request)
- `1191` `http_client`
- `1214` `BROWSER_UAS` (rotation list), `1225` `UA_ROTATOR`, `1227` `next_browser_ua`
- `1232` `http_probe_single` (picks UA, up to 4 redirect hops)
- `1334` `http_probe_blocking` (retry-once + scheme-flip wrapper)

### Tool resolution
- `1374` `find_binary` / `1438` `resolve_tool` / `1460` `offer_install`

### TLS / banner classification
- `1528` `client_hello`
- `1553` `service_for_port` (port → protocol name table)
- `1820` `classify` (banner bytes → protocol)

### Async hot path
- `1874` `is_local_resource_error` / `1901` `is_net_unreachable_error`
- `1909` `tcp_probe`
- `1929` `phase_a` (connect-scan worker loop)
- `2030` `enrich` (TLS sniff + banner grab + Phase-B raw HTTP probe at ~2074 with hardcoded Chrome UA)
- `2202` `adaptive_monitor` (sig: `stats, sem, initial, max` — grows pool up to `max` on clean windows, shrinks on local errors)
- `2289` `fill_next_round` / `2317` `send_or_shutdown` / `2359` `producer`

### Output / color
- `2447` `STDOUT_IS_TTY` / `2449` `init_stdout_color` / `2457` `cfmt`
- `2470` `color_protocol` / `2520` `color_banner_status`
- `2541` `atty_like_stderr` / `2557` `BANNER_ART` / `2565` `print_banner`

### Update flow
- `2589` `REPO_OWNER` / `2590` `REPO_NAME`
- `2592-2820` update cache / fetch tag / banner
- `2932` `run_update` / `3028` `run_check_update`

### Webhook + UDP
- `3090` `post_webhook`
- `3105` `UDP_PROBES` / `3138` `udp_probe_one` / `3153` `run_udp_phase`

### CDN refresh / uninstall
- `3214` `cdn_cache_path`
- `3235` `uninstall_collect_targets` / `3324` `run_uninstall`
- `3460` `CDN_ASN_PROVIDERS` / `3491` `fetch_text` / `3503` `fetch_json` / `3517` `extract_cidrs_plain` / `3532` `run_refresh_cdn`

### Entry
- `3771` `check_deprecated_flags`
- `3805` `async fn main` — orchestrates Phase 0 (domain resolve) → Phase A (discovery) → Phase B (enrich) → Phase C (nuclei)

### Key offsets inside `main()` (approximate — re-grep before editing)
- `~4197` **Phase 0 Ctrl+C wrap:** `resolve_many` is raced against `tokio::signal::ctrl_c()` here. Before claiming resolve_many "doesn't handle Ctrl+C", verify this is still in place.
- `~4517` Phase A header print
- `~4630` `max_ceiling` / `initial_pool` computation
- `~4662` SIGINT handler (sets `stats.shutdown`)
- `~4690` `adaptive_monitor` spawn
- `~4796` Hit collector task (enrichment fan-out)
- `~4854` `enrich_set.spawn` (per-hit enrichment) — the `sink.lock().unwrap().push(op)` site
- `~4910` Phase-A worker spawn loop (spawns `max_ceiling` workers; semaphore gates actual concurrency)
- `~5200` Phase-B HTTP probe FuturesUnordered (spawn_blocking → http_probe_blocking)
- `~5280` JSONL output writer
- `~5303` Phase-B collection loop `tokio::select!` against `ctrl_c()`
- `~5834` nuclei `Command` spawn
- `~5887` webhook POST

## domain.rs

- `39`   `enum InputKind` (Ipv4, Ipv6, Cidr, Ipv4Range, Domain, Invalid)
- `51`   `classify_input_line`
- `116`  `looks_like_domain`
- `142`  `struct DomainResult { domain, ips, cdn, error }`
- `168`  `build_resolver` (Cloudflare + Google + Quad9, `attempts = 2`)
- `198`  `keep_scannable` (drops RFC1918 / loopback / link-local / ULA)
- `238`  `async fn resolve_one` (A+AAAA concurrent)
- `277`  `pub async fn resolve_many` — bounded-concurrency fan-out
  - `322` collector loop `while let Some(join) = set.next().await`
  - `330` `.flatten().collect()` (fixed in v0.15.0 — was `.map(|o| o.unwrap())` which panicked on task failure)
  - Ctrl+C handling lives at the **caller** (`main.rs:4197`), not here
- `336`  `cdn_tag_first` / `347` `cdn_breakdown`

## Smoke-test commands (CLAUDE.md rule #2)

```sh
./target/release/portwave t 109.123.239.180 -p 22,80,443 --no-nuclei
./target/release/portwave t -d hack.adityasec.com --no-nuclei
```

## Regenerating this map

From repo root:

```sh
grep -nE '^(pub )?(async )?fn |^(pub )?struct |^(pub )?enum |^static |^const [A-Z]' \
  src/main.rs src/domain.rs
```

Update the line numbers above to match.
