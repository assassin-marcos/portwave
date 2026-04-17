# Changelog

All notable changes to portwave are documented here.
Format is loosely based on [Keep a Changelog](https://keepachangelog.com/).
Versions follow semantic versioning (Major.Minor.Patch).

---

## [0.6.1] — 2026-04-17

### Fixed
- **Adaptive controller shrinking too aggressively.** With `--retries 1` (the
  new default), every timed-out probe incremented the `timeouts` counter
  twice (once per retry). The adaptive monitor's `timeouts / attempts`
  ratio exceeded 100 % (shown as "200 %" in logs) and shrank the worker
  pool exponentially — down to ~64 workers per scan against heavily
  firewalled /24s. Now a timed-out probe increments the counter exactly
  once, and the ratio stays in `[0.0, 1.0]` as intended.

## [0.6.0] — 2026-04-17

### Added
- **`--input-file PATH`** — one target per line (CIDR / IP / IP range, `#`
  comments). Accepts stdin via `-`.
- **`--asn AS13335,AS15169`** — expands ASN to announced prefixes via the
  public RIPE stat API (no API key needed). Multi-ASN comma-separated.
- **`--exclude LIST`** — skip CIDRs / IPs / IP ranges (scope discipline).
  Same input format as `<CIDR_INPUT>`.
- **`--ports "22,80,443,8000-9000"`** — inline port-range syntax.
  Overrides `--port-file` and the embedded list.
- **IP-range input everywhere**: `1.2.3.10-1.2.3.20` → minimal covering
  CIDR blocks, accepted anywhere a target is expected.
- **CDN / WAF edge tagging.** Every open port on an IP in a known CDN
  range is tagged `[cdn:<provider>]` (cloudflare, fastly, akamai,
  imperva, sucuri, stackpath, bunnycdn, cachefly, keycdn). Bundled
  static list of 89 IPv4 CIDRs compiled into the binary via
  `include_str!`. `scan_summary.json` gains `by_cdn` + `cdn_count`.
- **ASCII startup banner.** Cyan `portwave` art + "by assassin_marcos"
  byline, auto-suppressed on non-TTY stderr.
- **`--no-art` + `-q, --quiet`** flags.
- **`ureq` dep (~400 KB)** for the GitHub tags API peek (see below).

### Changed
- **`--check-update`** now peeks the GitHub tags API alongside the
  releases API. When a tag is pushed but CI hasn't uploaded release
  assets yet, reports "tag vX is pushed but CI is still building" —
  no more "says up-to-date, but `-u` finds newer" confusion.
- **README fully rewritten** for v0.6.x usage. No more install-section
  duplication from incremental edits across 0.5.x.

### Fixed
- **`refresh_bundled_ports_files()` now follows `PORTWAVE_PORTS`** from
  env + config. Older installs whose config pointed at the repo-clone
  `/ports/portwave-top-ports.txt` were never refreshed on `--update`.
  Now they are, canonicalised for de-dup.

## [0.5.6] — 2026-04-17

### Added
- **`--- OPEN PORTS (N) ---`** summary block printed between scan
  completion and the httpx step. Shows `ip:port [protocol, tls, cdn]
  banner` so it's obvious why httpx might report fewer URLs than the
  open-port count (non-HTTP services like SSH drop out silently).

## [0.5.5] — 2026-04-17

### Changed
- **Default `--threads` 4000 → 1500.** 4000 exhausts the ephemeral port
  range on long scans (99 %+ timeout rate observed). 1500 is the sweet
  spot across typical Linux / macOS / Windows defaults.
- **Default `--timeout-ms` 600 → 800.** Catches slow-but-responsive
  hosts without bloating total runtime on cold targets.
- **Default `--retries` 0 → 1.** Covers transient SYN drops without
  doubling scan time (only timeouts retry, never RST/refused).

### Added
- **`SO_LINGER = 0` on every TCP connect.** Sends RST on close,
  returning the ephemeral port to the OS immediately instead of
  waiting 60 s in TIME_WAIT. Fixes the ephemeral-port-exhaustion
  cascade at scale.
- **`TCP_NODELAY` on every TCP connect.** Disables Nagle; shaves
  ~40 ms of ACK coalescing latency off each successful connect.
- **New `tcp_probe()` helper** replaces `TcpStream::connect()`
  everywhere (Phase A, Phase B, TLS sniff).
- **+28 common service ports** added to the embedded list
  (1405 → 1433): MQTT 1883/8883, ZooKeeper 2181, Cassandra 9042,
  Kafka 9092–9094, Salt 4505/4506, Zabbix-trapper 10051, Redis
  Sentinel 26379, ActiveMQ 61616, kube-scheduler 10251, kube-
  controller 10252, kubelet-ro 10255, kube-proxy-health 10256,
  STUN 3478, Erlang EPMD 4369, VXLAN 4789, Logstash 5044, Vite
  5173, CoAP 5683, TeamViewer 5938, WebSphere 9060/9061.

### Fixed
- **`install.sh` + `install.ps1`** stop writing `PORTWAVE_PORTS=<repo-
  clone>/ports/portwave-top-ports.txt` by default. The embedded list
  is the default now; `--update` auto-refreshes it. Users can still
  enter a custom path when prompted.

## [0.5.4] — 2026-04-16

### Fixed
- **CI hang on macOS Intel.** GitHub-hosted `macos-13` runners had
  very limited availability (jobs sat in the queue 28+ minutes across
  v0.5.1/0.5.2/0.5.3 and never picked up). Switched to building
  *both* Mac architectures from a single `macos-14` (Apple Silicon)
  runner using `cargo build --target x86_64-apple-darwin` — the
  Apple-bundled toolchain cross-compiles natively. One job, two
  binaries, no queue wait.
- **`install.sh` picked a prefix not on `$PATH`.** On macOS the first
  writable candidate was `~/.local/bin` which isn't on bash's default
  `$PATH`, causing `portwave: command not found` after install. New
  order: `/opt/homebrew/bin` → `/usr/local/bin` → `~/.local/bin`. If
  the chosen prefix is still not on `$PATH`, the installer offers to
  append an `export PATH=...` line to the right shell rc (`~/.zshrc`
  / `~/.bash_profile` / `~/.bashrc`).
- **`install.sh` missed many tool locations.** Expanded auto-detect
  to `$HOME/go/bin`, `$HOME/.local/bin`, `/opt/homebrew/bin`,
  `/usr/local/bin`, `/usr/local/go/bin`, `/opt/local/bin` (MacPorts),
  `/home/go/bin`, `$GOBIN`, `$GOPATH/bin`, and any `/home/*/go/bin`.
  `~/.pdtm/go/bin` (ProjectDiscovery's tool manager) is picked up
  automatically via `$PATH`.

### Changed
- README rewritten end-to-end; removed install-section duplication
  introduced by incremental 0.5.0 → 0.5.3 edits.

## [0.5.3] — 2026-04-17

### Added
- **Default port list is now embedded** via `include_str!`. The binary
  *is* the port list — `--update` always ships the current list, no
  separate asset to manage.
- **`refresh_bundled_ports_files()` called after `--update`.** Rewrites
  every on-disk copy of `portwave-top-ports.txt` it finds under the
  install prefix's `share/portwave/ports/` — so configs pointing at
  the share copy stay in sync.

### Removed
- `find_bundled_ports()` runtime lookup — no longer needed.

## [0.5.2] — 2026-04-17

### Fixed
- **Producer bailed early on `/24+` ranges starting with the network
  address.** `any = true` was set *after* `is_usable_ipv4_host()` in
  the round-robin loop. For a `/24` the first IP yielded is `.0`
  (network), which is unusable → `continue` → `any` stayed `false` →
  outer loop bailed after consuming a single IP. Zero probes sent to
  workers, "open: 0" in 0 ms, progress bar forced to 100 % by
  `pb.finish_with_message`. Bug only manifested on `/24`–`/30` IPv4
  (our localhost `/32` smoke tests didn't trigger it). `any = true`
  is now set as soon as the iterator yields *any* value.

### Added
- **1405-port bundled list** (up from 443). The old list was HTTP-
  heavy and missing critical service ports — most damagingly **22
  (SSH)**, plus 25/53/110/143/445/587/993/995, 3389 (RDP), 5432
  (postgres), 5900 (VNC), 6379 (redis), 9200 (elasticsearch), 11211
  (memcached), 27017 (mongo), and many more. New list is the union
  of the old 443 + nmap-top-1000 + curated bug-bounty / modern-app
  additions (docker 2375/76, etcd 2379/80, k8s api 6443, hadoop
  50070/75/90, rabbitmq 15672, etc.).

## [0.5.1] — 2026-04-17

### Added
- **`-u, --update`** — downloads the prebuilt binary for the current
  OS+arch from the latest GitHub Release and atomically replaces the
  running executable. Powered by `self_update` over rustls + reqwest.
- **`--check-update`** — prints "Update available: X → Y" or "Up to
  date", then exits.
- **Startup update-available banner.** Cached under
  `~/.cache/portwave/last_check` (Unix) or
  `%LOCALAPPDATA%\portwave\last_check` (Windows), 24 h TTL, 3 s
  timeout so slow networks never block a scan.
- **`--no-update-check`** + `PORTWAVE_NO_UPDATE_CHECK=1` env.
- **`.github/workflows/release.yml`** — builds binaries for
  `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`,
  `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` on every `v*`
  tag. Each artefact is a `tar.gz` (Unix) or `zip` (Windows) named
  `portwave-<target-triple>.{tar.gz,zip}` so `self_update` auto-
  matches on the host.

### Changed
- Positional args `<FOLDER_NAME>` + `<CIDR_INPUT>` are now `Option`
  so `--update` / `--check-update` can run without them.

## [0.5.0] — 2026-04-16

### Added
- **Cross-platform support.** Linux, macOS (Apple Silicon + Intel),
  and Windows. Guarded `raise_fd_limit()` with `#[cfg(unix)]`,
  platform-aware config file path (`%APPDATA%` on Windows vs
  `$HOME/.config` on Unix), broader bundled-ports lookup covering
  `%LOCALAPPDATA%` and exe-relative paths.
- **`install.sh` + `install.ps1`** — interactive installers with
  rustup auto-install, tool auto-detect, path-prefix picker, config
  file writer, PATH hint.
- **`uninstall.sh` + `uninstall.ps1`**.
- **First GitHub public release.** Repo live at
  `https://github.com/assassin-marcos/portwave`, 20 SEO topics set,
  MIT licensed.

### Changed
- Renamed package + binary from `ipv6scanner` to `portwave`.
- `libc` moved to `[target.'cfg(unix)'.dependencies]`.

### Before v0.5.0

Tool lived as `ipv6scanner` internally at v0.3.x / v0.4.x. Big
rewrites:

#### v0.4.0 (internal) — Architectural overhaul
- Bounded worker pool with `flume` MPMC queue. Memory O(threads),
  not O(IPs × ports).
- Dedicated writer task; `Arc<Mutex<File>>` on the hot path removed.
- `JoinSet` instead of `Vec<JoinHandle>`.
- `indicatif` progress bar with ETA + spinner mode for > 10 M probes.
- Structural IPv6 URL formatting — `http://[::1]` not `http://[::1`.
- Graceful `Ctrl+C` (drain workers + flush writer before exit).
- Dropped `-path /actuator,/.git/HEAD` httpx hardcode.
- Resume via append-only `open_ports.jsonl`.
- Two-phase scan: fast discovery (Phase A) + banner/TLS enrichment
  (Phase B).

#### v0.3.0 (original)
- Hybrid IPv4/IPv6 scanner with full TCP connect + httpx + nuclei
  chain.
