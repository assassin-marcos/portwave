use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use ipnetwork::IpNetwork;
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

// v0.14.0 — domain / subdomain input + CDN-fronted auto-skip.
// Lives in a dedicated module so DNS + CDN concerns don't leak into
// the scanner hot path and so main.rs stays under 5 K lines.
mod domain;

// ────────────────────────── CLI ──────────────────────────

#[derive(Parser, Debug, Clone)]
#[command(
    name = "portwave",
    about = "Fast IPv4/IPv6 port scanner + native HTTP(S) enrichment + nuclei",
    version
)]
struct Args {
    // ── Positional ─────────────────────────────────────────
    #[arg(index = 1)]
    folder_name: Option<String>,

    /// IPs / CIDRs / ranges / domains, comma-separated (mixed ok)
    #[arg(index = 2)]
    cidr_input: Option<String>,

    // ── Targets ────────────────────────────────────────────
    /// Targets file (one per line; "-" for stdin)
    #[arg(short = 'i', long)]
    input_file: Option<String>,

    /// Domains to resolve + scan, comma-separated
    #[arg(short = 'd', long)]
    domain: Option<String>,

    /// ASNs (e.g. "AS13335,AS15169")
    #[arg(short = 'a', long)]
    asn: Option<String>,

    /// IPs / CIDRs / ranges to exclude from scope
    #[arg(short = 'e', long)]
    exclude: Option<String>,

    /// Scan CDN-fronted domains too (default: skip them)
    #[arg(long, default_value_t = false)]
    allow_cdn: bool,

    /// DNS timeout per domain, seconds
    #[arg(long, default_value_t = 3)]
    dns_timeout: u64,

    /// Concurrent DNS lookups
    #[arg(long, default_value_t = 50)]
    dns_concurrency: usize,

    /// Scan only IPv4
    #[arg(long, default_value_t = false)]
    ipv4_only: bool,

    /// Scan only IPv6
    #[arg(long, default_value_t = false)]
    ipv6_only: bool,

    /// Smart IPv6 for huge ranges (RFC 7707 likely-addresses)
    #[arg(long, default_value_t = false)]
    smart_ipv6: bool,

    /// Bypass 2^20-host scope safety net
    #[arg(long, default_value_t = false)]
    allow_huge_scope: bool,

    // ── Ports ──────────────────────────────────────────────
    /// Ports / ranges, e.g. "22,80,443,8000-9000"
    #[arg(short = 'p', long)]
    ports: Option<String>,

    /// Port-list file (comma / whitespace separated)
    #[arg(short = 'f', long)]
    port_file: Option<String>,

    /// Use only top-N ports from the bundled list
    #[arg(long)]
    top_ports: Option<usize>,

    /// Enable UDP discovery on well-known ports
    #[arg(short = 'U', long, default_value_t = false)]
    udp: bool,

    // ── Timing / concurrency ───────────────────────────────
    /// Max concurrent Phase-A probes
    #[arg(short = 't', long, default_value_t = 3000)]
    threads: usize,

    /// Phase-A connect timeout, ms
    #[arg(short = 'T', long, default_value_t = 800)]
    timeout_ms: u64,

    /// Phase-B banner timeout, ms
    #[arg(long, default_value_t = 1500)]
    enrich_timeout_ms: u64,

    /// Retries on Phase-A timeouts
    #[arg(short = 'r', long, default_value_t = 1)]
    retries: u8,

    /// Global packets-per-second cap
    #[arg(long)]
    max_pps: Option<u32>,

    /// Wallclock cap, e.g. "10m", "1h"
    #[arg(long)]
    max_scan_time: Option<String>,

    /// Print scan plan + exit (no probes)
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    // ── Enrichment (HTTP / nuclei) ─────────────────────────
    /// Concurrent HTTP probes
    #[arg(short = 'C', long, default_value_t = 100)]
    probe_concurrency: usize,

    /// Follow redirects up to 3 hops (auto-on with --asn)
    #[arg(long, default_value_t = false)]
    follow_redirects: bool,

    /// Skip native HTTP(S) enrichment
    #[arg(long, default_value_t = false)]
    no_enrich: bool,

    /// Disable banner grab (Phase B)
    #[arg(long, default_value_t = false)]
    no_banner: bool,

    /// Disable TLS sniff on non-443 ports
    #[arg(long, default_value_t = false)]
    no_tls_sniff: bool,

    /// Disable adaptive concurrency controller
    #[arg(long, default_value_t = false)]
    no_adaptive: bool,

    /// Skip nuclei
    #[arg(long, default_value_t = false)]
    no_nuclei: bool,

    /// nuclei concurrency
    #[arg(long, default_value_t = 25)]
    nuclei_concurrency: usize,

    /// nuclei per-host rate limit
    #[arg(long, default_value_t = 200)]
    nuclei_rate: usize,

    /// nuclei max-host-error
    #[arg(long, default_value_t = 25)]
    nuclei_max_host_error: usize,

    /// Run nuclei on non-HTTP ports too
    #[arg(long, default_value_t = false)]
    nuclei_all_ports: bool,

    /// nuclei severity filter (default skips `info`)
    #[arg(long, default_value = "low,medium,high,critical")]
    nuclei_severity: String,

    // ── Output / integrations ──────────────────────────────
    /// Output directory (default ./scans)
    #[arg(short = 'o', long)]
    output_dir: Option<String>,

    /// NDJSON to stdout (in addition to files)
    #[arg(long, default_value_t = false)]
    json_out: bool,

    /// Disable resume from previous open_ports.jsonl
    #[arg(long, default_value_t = false)]
    no_resume: bool,

    /// Webhook URL (POST summary on completion)
    #[arg(short = 'w', long)]
    webhook: Option<String>,

    /// Webhook only if diff shows changes
    #[arg(long, default_value_t = false)]
    webhook_on_diff_only: bool,

    /// Suppress "[+] IP:PORT opened" stream
    #[arg(long, default_value_t = false)]
    no_live_hits: bool,

    // ── Updates / uninstall / UX ───────────────────────────
    /// Install latest release
    #[arg(short = 'u', long, default_value_t = false)]
    update: bool,

    /// Check for updates + exit
    #[arg(short = 'c', long, default_value_t = false)]
    check_update: bool,

    /// Refresh CDN/WAF CIDR cache
    #[arg(long, default_value_t = false)]
    refresh_cdn: bool,

    /// Uninstall portwave
    #[arg(short = 'X', long, default_value_t = false)]
    uninstall: bool,

    /// Skip uninstall confirmation
    #[arg(short = 'y', long, default_value_t = false)]
    yes: bool,

    /// Don't prompt to install nuclei if missing
    #[arg(long, default_value_t = false)]
    no_install_prompt: bool,

    /// Suppress "update available" banner
    #[arg(long, default_value_t = false)]
    no_update_check: bool,

    /// Show update banner but skip [Y/n] prompt
    #[arg(long, default_value_t = false)]
    no_update_prompt: bool,

    /// Suppress ASCII banner art
    #[arg(long, default_value_t = false)]
    no_art: bool,

    /// Quiet mode (= --no-art --no-update-check)
    #[arg(short, long, default_value_t = false)]
    quiet: bool,
}

// ────────────────────────── Types ──────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
struct OpenPort {
    ip: String,
    port: u16,
    rtt_ms: u64,
    tls: bool,
    protocol: Option<String>,
    banner: Option<String>,
    /// CDN/WAF provider name if the IP matches a known edge network
    /// (cloudflare / fastly / akamai / imperva / sucuri / stackpath / …).
    /// None = presumed origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cdn: Option<String>,
    /// v0.14.0 — original domain this IP was resolved from, if the scan
    /// was seeded from `-d` / `--input-file` domain entries. `None` when
    /// the user supplied IPs directly. Drives the "domain → ip" grouping
    /// in the OPEN PORTS render and preserves the user's intent in the
    /// JSON / NDJSON output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_label: Option<String>,
    /// v0.14.9 — parsed `<title>` from HTML body (if response was HTML).
    /// 160-char cap, whitespace collapsed. Populated by the native
    /// title-parse in enrich() — previously this info only existed in
    /// httpx's -o file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    /// v0.14.9 — final URL after following redirects, if --follow-redirects
    /// was set AND the initial response was 3xx. Absent when no redirect
    /// was followed. The chain itself lives in `redirect_chain` if > 1 hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    final_url: Option<String>,
    /// v0.14.9 — sequence of intermediate URLs when more than one redirect
    /// hop was traversed. None for the common case (no redirects, or one
    /// redirect). Capped at 3 hops total so a misbehaving server can't
    /// spin us in a loop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redirect_chain: Option<Vec<String>>,
    /// v0.14.9 — Content-Length header from the HTTP response, if any.
    /// Useful for downstream triage (zero-length 200s are often default
    /// pages; large 3xxs carry the redirect body).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_length: Option<u64>,
}

#[derive(Serialize, Debug)]
struct ScanSummary {
    folder: String,
    started_at_unix: u64,
    duration_ms: u128,
    ranges: Vec<String>,
    ports: usize,
    scanned_estimate: u64,
    attempts: u64,
    timeouts: u64,
    open: u64,
    by_port: std::collections::BTreeMap<u16, u64>,
    by_protocol: std::collections::BTreeMap<String, u64>,
    by_cdn: std::collections::BTreeMap<String, u64>,
    cdn_count: u64,
    /// Probes that got RST / ICMP-unreachable back — i.e. port is closed
    /// but the host is alive (answering network). Computed as attempts
    /// minus opens minus timeouts minus local_errors.
    #[serde(default)]
    closed: u64,
    /// Local-resource errors (ephemeral port / FD / kernel buffer full).
    /// Drives the adaptive-concurrency controller.
    #[serde(default)]
    local_errors: u64,
    /// Phase-A (discovery) wall time.
    #[serde(default)]
    phase_a_ms: u128,
    /// Phase-B (enrichment) wall time. 0 if Phase B was skipped.
    #[serde(default)]
    phase_b_ms: u128,
    /// UDP phase wall time. 0 unless --udp was passed.
    #[serde(default)]
    udp_ms: u128,
    /// Native HTTP(S) enrichment wall time. 0 if skipped or no candidates.
    /// Kept a serde alias `httpx_ms` so downstream JSON consumers reading
    /// pre-v0.14.9 scan summaries still parse cleanly.
    #[serde(default, alias = "httpx_ms")]
    enrich_ms: u128,
    /// nuclei subprocess wall time. 0 unless nuclei ran to completion.
    #[serde(default)]
    nuclei_ms: u128,
    /// True when the scan was cut short by --max-scan-time before every
    /// target was probed. Lets downstream automation distinguish a
    /// "partial result" from a "complete clean run".
    #[serde(default)]
    timed_out: bool,
}

struct Stats {
    shutdown: AtomicBool,
    attempts: AtomicU64,
    timeouts: AtomicU64,
    opens: AtomicU64,
    /// Local resource exhaustion errors (ephemeral-port exhaustion /
    /// FD limit hit / kernel buffer full). These are the ONLY signal
    /// the adaptive controller uses to shrink — timeouts alone don't
    /// indicate local saturation, they often indicate a firewalled
    /// target dropping SYNs (where shrinking would only slow the
    /// scan without any benefit).
    local_errors: AtomicU64,
    /// v0.14.8: count of probes that failed with ENETUNREACH (network
    /// unreachable, errno 101 on Linux / 51 on macOS / 10051 on Windows).
    /// Unlike EHOSTUNREACH (which fires legitimately on sparse IPv6 scans)
    /// or timeouts (firewalled targets), ENETUNREACH means the local
    /// routing table itself can't reach the destination network — the
    /// only honest signal that "your WiFi dropped." When this passes a
    /// threshold the network-down monitor flips `shutdown`, triggering
    /// the same graceful save-and-exit flow as Ctrl+C. Resume works
    /// against whatever was flushed to disk.
    net_unreach: AtomicU64,
    /// Flips to true after the top-20 priority sweep completes.
    /// Lets phase_a workers print an interim summary before Pass 2
    /// starts chewing through the full port list.
    priority_done: AtomicBool,
    /// Set by `adaptive_monitor` when it has taken permits from the
    /// worker semaphore; cleared when the pool grows back to max.
    /// Lets workers skip `sem.acquire_owned()` on the hot path when
    /// the monitor hasn't shrunk — the semaphore has N permits for N
    /// workers, so acquire is guaranteed immediate in the unshrunk
    /// state. At 10–15 K probes/sec this saves 3–5 % CPU.
    adaptive_shrunk: AtomicBool,
}

// ────────────────────────── Helpers ──────────────────────────

// Platform-aware config file location:
//   $PORTWAVE_CONFIG override on all platforms
//   Unix:    $HOME/.config/portwave/config.env
//   Windows: %APPDATA%\portwave\config.env
fn default_config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PORTWAVE_CONFIG") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    #[cfg(windows)]
    {
        if let Ok(a) = std::env::var("APPDATA") {
            return Some(PathBuf::from(a).join("portwave").join("config.env"));
        }
        if let Ok(h) = std::env::var("USERPROFILE") {
            return Some(PathBuf::from(h).join(".config").join("portwave").join("config.env"));
        }
        None
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".config/portwave/config.env"))
    }
}

// Load the config file — simple KEY=VALUE lines, comments start with #.
fn load_config() -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Some(path) = default_config_path() else { return out };
    let Ok(txt) = fs::read_to_string(&path) else { return out };
    for line in txt.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            out.insert(k.trim().to_string(), v.to_string());
        }
    }
    out
}

// Resolve a path with precedence: CLI arg -> env var -> config file -> default.
fn resolve_path(
    cli: Option<&str>,
    env_key: &str,
    cfg: &std::collections::HashMap<String, String>,
    cfg_key: &str,
    fallback: &str,
) -> String {
    if let Some(p) = cli {
        return p.to_string();
    }
    if let Ok(p) = std::env::var(env_key) {
        if !p.is_empty() {
            return p;
        }
    }
    if let Some(p) = cfg.get(cfg_key) {
        if !p.is_empty() {
            return p.clone();
        }
    }
    fallback.to_string()
}

// Raise the file-descriptor soft limit so thousands of concurrent sockets work.
// On Windows this is a no-op: socket handles aren't bounded by RLIMIT_NOFILE.
//
// v0.12.4 bug fix: previously this hardcoded want=50_000 and always set
// rlim_cur to that min'd with hard_max. On systems where the user had
// already configured a *higher* soft limit (modern Linux defaults to
// 1 048 576 on many distros), we were silently *downgrading* them to
// 50 K, capping concurrency on large scans. Now we only upgrade.
#[cfg(unix)]
fn raise_fd_limit() {
    unsafe {
        let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) != 0 {
            return;
        }
        // If the existing soft limit is already generous, leave it alone.
        // Target 1 M — the Linux kernel ceiling since 5.x and enough
        // headroom for any scan portwave realistically runs.
        let want: libc::rlim_t = 1_048_576;
        if rlim.rlim_cur >= want {
            return;
        }
        // Never exceed the hard limit (we'd need CAP_SYS_RESOURCE for that).
        let new_cur = want.min(rlim.rlim_max);
        if new_cur <= rlim.rlim_cur {
            return; // can't improve — hard limit caps us below `want`
        }
        rlim.rlim_cur = new_cur;
        libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
    }
}

#[cfg(not(unix))]
fn raise_fd_limit() {}

// The default port list is baked into the binary so `--update` automatically
// ships the latest list — no separate asset, no path-resolution failure modes.
// On-disk copies (under <prefix>/share/portwave/ports/) are kept for
// editability and refreshed by `--update`; see refresh_bundled_ports_files.
const EMBEDDED_PORTS: &str = include_str!("../ports/portwave-top-ports.txt");
const EMBEDDED_SENTINEL: &str = "<embedded>";

// Top-20 most-common TCP ports (weighted by real-world hit rate across
// bug-bounty / internet-facing asset classes). Scanned FIRST so the user
// sees early results on long scans.
const TOP_PRIORITY_PORTS: &[u16] = &[
    80, 443, 22, 21, 25, 53, 8080, 8443, 3389, 110,
    143, 445, 3306, 5432, 6379, 27017, 9200, 1883, 5900, 11211,
];

fn parse_port_list(content: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = Vec::new();
    for tok in content.split(|c: char| c == ',' || c.is_whitespace()) {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        // Range form: "8000-9000"
        if let Some((lo, hi)) = tok.split_once('-') {
            let lo: u32 = match lo.trim().parse() { Ok(n) => n, Err(_) => continue };
            let hi: u32 = match hi.trim().parse() { Ok(n) => n, Err(_) => continue };
            if lo > hi || lo == 0 || hi > 65535 {
                continue;
            }
            for p in lo..=hi {
                ports.push(p as u16);
            }
            continue;
        }
        if let Ok(p) = tok.parse::<u16>() {
            if p != 0 {
                ports.push(p);
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    // Smart prioritization: put top-20 priority ports first (in their
    // priority order), then the remaining ports in numeric order. Users
    // see early hits on slow scans.
    let priority_set: std::collections::HashSet<u16> =
        TOP_PRIORITY_PORTS.iter().copied().collect();
    let mut out = Vec::with_capacity(ports.len());
    for p in TOP_PRIORITY_PORTS {
        if ports.contains(p) {
            out.push(*p);
        }
    }
    for p in &ports {
        if !priority_set.contains(p) {
            out.push(*p);
        }
    }
    out
}

fn load_ports(path: &str) -> Vec<u16> {
    if path == EMBEDDED_SENTINEL || path.is_empty() {
        return parse_port_list(EMBEDDED_PORTS);
    }
    match fs::read_to_string(path) {
        Ok(content) => parse_port_list(&content),
        Err(_) => {
            eprintln!("!! WARNING: could not read {} — falling back to embedded list.", path);
            parse_port_list(EMBEDDED_PORTS)
        }
    }
}

// Refresh on-disk ports files (for users whose config or workflow points at
// share/<...>/portwave-top-ports.txt — OR at a repo clone path left behind
// by an earlier install.sh) so they pick up the same list that's embedded
// in the freshly-installed binary.
fn refresh_bundled_ports_files() {
    let mut paths: Vec<PathBuf> = Vec::new();

    // Install-layout candidates relative to the running binary.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("../share/portwave/ports/portwave-top-ports.txt"));
            paths.push(dir.join("../ports/portwave-top-ports.txt"));
        }
    }
    if let Ok(h) = std::env::var("PORTWAVE_HOME") {
        paths.push(PathBuf::from(h).join("ports/portwave-top-ports.txt"));
    }
    #[cfg(windows)]
    {
        if let Ok(a) = std::env::var("LOCALAPPDATA") {
            paths.push(PathBuf::from(a).join("portwave/ports/portwave-top-ports.txt"));
        }
    }

    // Whatever PORTWAVE_PORTS resolves to (env or config). Critical for
    // configs that point at a repo-clone path outside the install prefix —
    // older install.sh versions wrote this. Without this step, --update
    // would silently leave users on the stale list.
    let cfg = load_config();
    if let Ok(p) = std::env::var("PORTWAVE_PORTS") {
        if !p.is_empty() {
            paths.push(PathBuf::from(p));
        }
    }
    if let Some(p) = cfg.get("PORTWAVE_PORTS") {
        if !p.is_empty() {
            paths.push(PathBuf::from(p));
        }
    }

    // De-duplicate so we don't log the same path twice.
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut refreshed = 0usize;
    let mut skipped_git = 0usize;
    for p in &paths {
        let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
        if !seen.insert(canon) {
            continue;
        }
        if !p.is_file() {
            continue; // only refresh files that already existed
        }
        // Never write inside a git working tree. Users who keep their
        // portwave clone checked out AND had an older install.sh point
        // PORTWAVE_PORTS at <repo>/ports/portwave-top-ports.txt would
        // otherwise see `git pull` fail every time because --update
        // rewrote a tracked file. Detect by walking the path's
        // ancestry looking for a `.git` directory or file.
        if is_inside_git_repo(p) {
            skipped_git += 1;
            continue;
        }
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::write(p, EMBEDDED_PORTS) {
            Ok(_) => {
                println!("Refreshed bundled ports: {}", p.display());
                refreshed += 1;
            }
            Err(e) => eprintln!("(could not refresh {}: {})", p.display(), e),
        }
    }
    if skipped_git > 0 {
        println!(
            "(skipped {} path(s) inside a git working tree — embedded list in the binary is already current)",
            skipped_git
        );
    }
    if refreshed == 0 && skipped_git == 0 {
        println!("(no on-disk ports files to refresh; embedded list is in the binary)");
    }
}

// Walk a file path's ancestors looking for a `.git` directory or file.
// Covers both regular clones and git-worktree checkouts (where `.git` is
// a file pointing at the worktree's shared metadata).
fn is_inside_git_repo(p: &Path) -> bool {
    let mut dir: Option<&Path> = p.parent();
    while let Some(d) = dir {
        let git = d.join(".git");
        if git.exists() {
            return true;
        }
        dir = d.parent();
    }
    false
}

// Parse a single input token into one or more IpNetworks. Accepts:
//   - single IP: "1.2.3.4"                    → 1.2.3.4/32
//   - CIDR:      "1.2.3.0/24"                 → 1.2.3.0/24
//   - IP range:  "1.2.3.10-1.2.3.20"          → minimal covering CIDR set
// Parse a human duration like "10m", "1h", "30s", "2h30m" → Duration.
// Returns an anyhow error with a hint for bad input so the user sees a
// helpful message instead of a parser spat.
fn parse_duration_human(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty duration string\n  hint: expected something like \"10m\", \"1h\", \"30s\", or \"1h30m\"");
    }
    let mut total_secs: u64 = 0;
    let mut current_num: u64 = 0;
    let mut saw_digit = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            current_num = current_num.saturating_mul(10).saturating_add((c as u8 - b'0') as u64);
            saw_digit = true;
        } else {
            if !saw_digit {
                anyhow::bail!(
                    "invalid duration \"{}\" — unit character '{}' without a preceding number\n  hint: use digits + unit, e.g. \"10m\" or \"1h30m\"",
                    s, c
                );
            }
            let mult = match c {
                's' | 'S' => 1u64,
                'm' | 'M' => 60,
                'h' | 'H' => 3_600,
                'd' | 'D' => 86_400,
                _ => anyhow::bail!(
                    "invalid duration \"{}\" — unknown unit '{}'\n  hint: valid units are s (seconds), m (minutes), h (hours), d (days)",
                    s, c
                ),
            };
            total_secs = total_secs.saturating_add(current_num.saturating_mul(mult));
            current_num = 0;
            saw_digit = false;
        }
    }
    if saw_digit {
        // Trailing bare number means "seconds" (Go-style).
        total_secs = total_secs.saturating_add(current_num);
    }
    if total_secs == 0 {
        anyhow::bail!("duration \"{}\" resolves to zero — scan would finish instantly", s);
    }
    Ok(Duration::from_secs(total_secs))
}

// Count the total number of host addresses across a set of IpNetworks.
// Returns u128 so even absurd IPv6 ranges (/0 through /128) fit without
// overflow. Used by the scope safety net and the --dry-run summary.
fn total_host_count(nets: &[IpNetwork]) -> u128 {
    let mut sum: u128 = 0;
    for n in nets {
        let s: u128 = match n.size() {
            ipnetwork::NetworkSize::V4(v) => v as u128,
            ipnetwork::NetworkSize::V6(v) => v,
        };
        sum = sum.saturating_add(s);
    }
    sum
}

// Generate targeted IPv6 addresses for a /CIDR using RFC 7707 patterns.
// Full /64 or /48 expansion is infeasible (2^64-2^80 addresses), so we
// probe the ~450 addresses in practical use on real IPv6 networks:
//   - Low sequential    :: .. ::00ff         (256)
//   - "Service decimal" ::100 .. ::02ff      (512) — admins often pick these
//   - Hexspeak          ::dead, ::beef etc.  (~20 well-known words)
//   - SLAAC landmark    ::fffe:xxxx patterns (~20 common vendor hints)
//   - Round decimals    ::1000, ::2000, ::a  (~20 common hand-picked)
// Called only for IPv6 CIDRs strictly larger (smaller prefix) than /108.
fn smart_ipv6_addresses(base: std::net::Ipv6Addr) -> Vec<IpAddr> {
    let base_segs = base.segments();
    let mut out: Vec<IpAddr> = Vec::with_capacity(800);
    // The CIDR's base address is the prefix part; we vary the low bits.
    // We'll keep the upper 96 bits of `base_segs` and vary the lowest 32
    // (segments 6 and 7) within the /96 implicit window. For larger CIDRs
    // this still exhaustively covers what real admins hand out.
    let mk = |seg6: u16, seg7: u16| -> IpAddr {
        let mut s = base_segs;
        s[6] = seg6;
        s[7] = seg7;
        IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]))
    };

    // ── Low sequential (::1 .. ::ff) — admins routinely assign these.
    for i in 1..=0xffu16 {
        out.push(mk(0, i));
    }
    // ── Decimal-feel (::100 .. ::2ff) — common service allocations.
    for i in 0x100..=0x2ffu16 {
        out.push(mk(0, i));
    }
    // ── Hexspeak words.
    for &w in &[
        0xdeadu16, 0xbeef, 0xcafe, 0xbabe, 0xf00d, 0xb00b, 0x1337, 0xc0de,
        0xfeed, 0xface, 0xbead, 0xdead, 0xc0c0, 0xfade, 0x0bad, 0xfa11,
    ] {
        out.push(mk(0, w));
    }
    // ── Round decimals that humans love picking (mix of hex patterns
    // like ::1000 and "service-port-shaped" segments like ::8080/::8443).
    for &w in &[
        0x1000u16, 0x2000, 0x5000, 0x8000, 0xa, 0x10, 0x50, 0x500, 0x1001,
        0x42, 0x80,
        // Common TCP service ports written as the last segment.
        8080, 8443, 3128, 6379, 27017,
    ] {
        out.push(mk(0, w));
    }
    // ── SLAAC landmark IIDs (segments 6 and 7). Common vendor MACs +
    // RFC 4291 EUI-64 hints. Not exhaustive — just enough to catch the
    // obvious suspects.
    for &(s6, s7) in &[
        (0x0000u16, 0x0001),     // DHCPv6-assigned "::1"-style
        (0xfffe, 0x0001),
        (0x02ff, 0xfe00),        // typical EUI-64 lowest bits
        (0xa0b1, 0xfffe),        // "admin" byte patterns
    ] {
        out.push(mk(s6, s7));
    }
    // Dedupe (cheap vs the probe cost).
    out.sort();
    out.dedup();
    out
}

// Simple token-bucket rate limiter for the producer's `--max-pps` mode.
// Not a cryptographic-grade limiter; just a "pace sends" helper that
// shares naturally via Arc across tasks. Using i64 math so a brief
// negative overdraft from bursty arrivals is OK.
struct RateLimiter {
    capacity: f64,
    tokens: Mutex<f64>,
    last_refill: Mutex<Instant>,
    rate_per_sec: f64,
}

impl RateLimiter {
    fn new(pps: u32) -> Self {
        let rate = pps as f64;
        Self {
            capacity: rate.max(1.0),
            tokens: Mutex::new(rate.max(1.0)),
            last_refill: Mutex::new(Instant::now()),
            rate_per_sec: rate,
        }
    }
    async fn acquire(&self) {
        loop {
            let wait_ms: u64 = {
                let now = Instant::now();
                let mut last = self.last_refill.lock().unwrap();
                let elapsed = now.saturating_duration_since(*last).as_secs_f64();
                let mut t = self.tokens.lock().unwrap();
                *t = (*t + elapsed * self.rate_per_sec).min(self.capacity);
                *last = now;
                if *t >= 1.0 {
                    *t -= 1.0;
                    return;
                }
                // Fractional tokens short — sleep for roughly 1 token worth.
                let need = 1.0 - *t;
                ((need / self.rate_per_sec) * 1000.0).ceil() as u64
            };
            tokio::time::sleep(Duration::from_millis(wait_ms.max(1))).await;
        }
    }
}

fn parse_target_token(tok: &str) -> Vec<IpNetwork> {
    let tok = tok.trim();
    if tok.is_empty() {
        return Vec::new();
    }
    // CIDR direct
    if tok.contains('/') {
        if let Ok(n) = tok.parse::<IpNetwork>() {
            return vec![n];
        }
    }
    // Range form "A-B"
    if let Some((a, b)) = tok.split_once('-') {
        let a = a.trim();
        let b = b.trim();
        if let (Ok(IpAddr::V4(a4)), Ok(IpAddr::V4(b4))) = (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
            let lo = u32::from(a4);
            let hi = u32::from(b4);
            if lo <= hi {
                return ipv4_range_to_cidrs(lo, hi);
            }
        }
    }
    // Plain IP → /32 or /128
    if let Ok(ip) = tok.parse::<IpAddr>() {
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if let Ok(n) = IpNetwork::new(ip, prefix) {
            return vec![n];
        }
    }
    Vec::new()
}

// Classic "range to CIDR blocks" algorithm — RFC3514 style greedy split.
fn ipv4_range_to_cidrs(mut lo: u32, hi: u32) -> Vec<IpNetwork> {
    let mut out = Vec::new();
    while lo <= hi {
        // Max prefix that doesn't extend past hi AND is aligned to lo.
        let align = if lo == 0 { 32 } else { lo.trailing_zeros().min(32) };
        let max_span_from_hi = (hi - lo + 1).checked_next_power_of_two().map(|n| n.trailing_zeros()).unwrap_or(32);
        // We want 2^k = smallest of (1<<align, (hi-lo+1) rounded down to power of two).
        let mut k = align.min(32);
        while k > 0 && (1u64 << k) > (hi as u64 - lo as u64 + 1) {
            k -= 1;
        }
        let prefix = 32 - k;
        let net = IpNetwork::new(IpAddr::V4(std::net::Ipv4Addr::from(lo)), prefix as u8).unwrap();
        out.push(net);
        let span = 1u64 << k;
        if lo as u64 + span > u32::MAX as u64 {
            break;
        }
        lo = lo.wrapping_add(span as u32);
        let _ = max_span_from_hi; // shut up unused warning on debug builds
    }
    out
}

// Expand a comma/whitespace-separated string of targets into IpNetworks.
fn expand_targets(input: &str) -> Vec<IpNetwork> {
    let mut out = Vec::new();
    for tok in input.split(|c: char| c == ',' || c.is_whitespace()) {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        let parsed = parse_target_token(t);
        if parsed.is_empty() {
            eprintln!("Skipping invalid target: {}", t);
        }
        out.extend(parsed);
    }
    out
}

// v0.14.0: `read_input_file` was removed — `main()` now reads the file
// inline through `domain::classify_input_line()` + `take_token()`, so
// domain / CIDR / IP / range rows can coexist in one file and each line
// routes to the correct target bucket.

// ────────────────────────── ASN expansion ──────────────────────────

// Call RIPE stat's announced-prefixes endpoint. No API key; public data.
// Returns the list of IpNetworks currently advertised by this ASN.
fn fetch_asn_prefixes(asn: &str) -> anyhow::Result<Vec<IpNetwork>> {
    let asn_num = asn.trim_start_matches(|c: char| c == 'A' || c == 'S' || c == 'a' || c == 's');
    let url = format!(
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}",
        asn_num
    );
    let resp = ureq::get(&url)
        .set("User-Agent", concat!("portwave/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15))
        .call()?;
    let j: serde_json::Value = resp.into_json()?;
    let mut out = Vec::new();
    if let Some(arr) = j.get("data").and_then(|d| d.get("prefixes")).and_then(|p| p.as_array()) {
        for p in arr {
            if let Some(pfx) = p.get("prefix").and_then(|s| s.as_str()) {
                if let Ok(n) = pfx.parse::<IpNetwork>() {
                    out.push(n);
                }
            }
        }
    }
    Ok(out)
}

// ────────────────────────── CDN / WAF tagging ──────────────────────────

const CDN_RANGES_RAW: &str = include_str!("../ports/cdn-ranges.txt");

// Loaded once at startup. (CIDR, provider-name).
fn load_cdn_ranges() -> Vec<(IpNetwork, &'static str)> {
    // Prefer the user's cache file (written by `portwave --refresh-cdn`)
    // over the compiled-in snapshot so users can keep the list current
    // without a portwave rebuild.
    let raw: String = if let Some(cache) = cdn_cache_path() {
        fs::read_to_string(&cache).unwrap_or_else(|_| CDN_RANGES_RAW.to_string())
    } else {
        CDN_RANGES_RAW.to_string()
    };
    let mut out = Vec::with_capacity(128);
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((cidr, provider)) = line.split_once('|') {
            if let Ok(n) = cidr.trim().parse::<IpNetwork>() {
                let p: &'static str = Box::leak(provider.trim().to_string().into_boxed_str());
                out.push((n, p));
            }
        }
    }
    out
}

fn cdn_tag_for(ip: IpAddr, table: &[(IpNetwork, &'static str)]) -> Option<&'static str> {
    for (net, name) in table {
        if net.contains(ip) {
            return Some(*name);
        }
    }
    None
}

fn is_usable_ipv4_host(net: &IpNetwork, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpNetwork::V4(n4), IpAddr::V4(v4)) => {
            if n4.prefix() >= 31 {
                return true;
            }
            v4 != n4.network() && v4 != n4.broadcast()
        }
        _ => true,
    }
}

// Ports where nuclei has ~zero useful template coverage — feeding them
// into the nuclei list burns wall-clock without any realistic chance
// of a finding.
//
// Kept DELIBERATELY NARROW. Protocols that nuclei DOES have templates
// for are NOT in this list, even if they're not HTTP:
//   SSH (22), FTP (21), SMTP (25/465/587), POP3 (110), IMAP (143),
//   LDAP (389), SMB (445), RDP (3389), VNC (5900), MSSQL (1433),
//   MySQL (3306), PostgreSQL (5432), Oracle (1521), Redis (6379),
//   MongoDB (27017), Memcached (11211), Cassandra (9042), MQTT (1883),
//   Kafka (9092), CouchDB (5984), ElasticSearch (9200), …
// — nuclei will try relevant network-level templates against those.
//
// Only ports with almost no nuclei coverage are blocked.
const NON_HTTP_PORTS: &[u16] = &[
    7,       // echo
    9,       // discard
    13,      // daytime
    17,      // qotd
    19,      // chargen
    37,      // time
    53,      // DNS (TCP fallback — nuclei has almost no TCP-DNS templates)
    67, 68,  // DHCP
    69,      // TFTP
    109,     // POP2 (not POP3)
    111,     // portmap / RPC
    123,     // NTP
    137, 138, // NetBIOS name / datagram (139 NetBIOS-SSN stays in)
    179,     // BGP
    514,     // syslog
    543, 544, // klogin / kshell
    4789,    // VXLAN
];

// Should this open port get a URL in nuclei_targets.txt?
// Default stance: trust nuclei — it has broader coverage than just HTTP.
// Only filter out ports with near-zero nuclei template coverage.
fn is_http_candidate(port: u16, _protocol: Option<&str>, _tls: bool) -> bool {
    !NON_HTTP_PORTS.binary_search(&port).is_ok()
}

fn format_for_nuclei(
    ip: &IpAddr,
    port: u16,
    tls: bool,
    source_label: Option<&str>,
) -> String {
    // v0.14.3 — when the scan was seeded from a domain input, the host
    // part of the URL should be the DOMAIN, not the resolved IP.
    // Reasons:
    //   1. TLS SNI — httpx/nuclei sending `Host: 1.2.3.4` vs
    //      `Host: example.com` gets entirely different server responses
    //      on virtual-hosted / multi-tenant servers.
    //   2. Many webservers serve a 400/default for raw-IP requests but
    //      serve the real app for hostname-based ones.
    //   3. Nuclei templates match on URL paths that the real app serves;
    //      the IP endpoint often 404s everything.
    let host = match source_label {
        Some(dom) => dom.to_string(),
        None => match ip {
            IpAddr::V4(v) => v.to_string(),
            IpAddr::V6(v) => format!("[{}]", v),
        },
    };
    // v0.13.3 — always emit explicit scheme. Previously returned bare
    // "ip:port" for ports we couldn't classify; that made httpx's
    // scheme-auto-detect probe BOTH http:// and https:// per target,
    // which could silently drop the user's intended port when TLS
    // failed (see v0.13.2 fix). With explicit scheme, httpx probes
    // exactly what we ask.
    let scheme = if tls || matches!(port, 443 | 4443 | 8443 | 9443 | 10443) {
        "https"
    } else {
        // Best-guess for non-TLS, non-canonical-HTTPS ports.
        // Users can see the actual tls flag in open_ports.jsonl if the
        // server unexpectedly negotiated TLS.
        "http"
    };
    // Omit the port only when it's the scheme's default (prettier URLs).
    if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        format!("{}://{}", scheme, host)
    } else {
        format!("{}://{}:{}", scheme, host, port)
    }
}

// v0.14.9 — native HTTP(S) probe replacing the httpx subprocess. Used by the
// Pass-C enrichment loop. Synchronous (runs in spawn_blocking) because
// ureq is sync and the alternative (tokio-rustls + hyper) would add a heavy
// dep for what is already a post-Phase-A step with bounded parallelism.
struct HttpProbeResult {
    // Status code lives inside `status_line` (and is re-parsed downstream
    // from OpenPort.banner) — no need to store it twice.
    status_line: String,           // "HTTP/1.1 200 OK" — shown in OPEN PORTS
    title: Option<String>,         // parsed <title>, whitespace-collapsed, ≤160 chars
    final_url: Option<String>,     // only set if > 0 redirects were followed
    chain: Vec<String>,            // intermediate URLs; empty if no / one-hop redirect
    via_https: bool,               // true if final successful probe used https:// scheme
    content_length: Option<u64>,   // from Content-Length header, for the httpx-compat line
}

fn extract_title(html: &str) -> Option<String> {
    // Case-insensitive find of <title...>...</title>. Manual because:
    //   - regex crate is used elsewhere but this is hot (runs per open HTTP port)
    //   - <title> tag attributes are rare but legal (e.g. <title xml:lang="en">)
    //   - we want a single forward scan, no DFA setup
    let lower = html.to_ascii_lowercase();
    let tag_start = lower.find("<title")?;
    // Find the '>' that closes the opening tag
    let after_open = tag_start + lower[tag_start..].find('>')? + 1;
    let end_rel = lower[after_open..].find("</title>")?;
    let raw = &html[after_open..after_open + end_rel];
    let collapsed: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed.chars().take(160).collect())
    }
}

fn resolve_redirect_url(base: &str, loc: &str) -> String {
    // Absolute URL? Done.
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    let scheme_end = match base.find("://") {
        Some(i) => i + 3,
        None => return loc.to_string(),
    };
    let host_end = base[scheme_end..]
        .find('/')
        .map(|i| scheme_end + i)
        .unwrap_or(base.len());
    let origin = &base[..host_end];
    if loc.starts_with('/') {
        // Origin-relative: /login → https://host/login
        format!("{}{}", origin, loc)
    } else {
        // Path-relative: login → https://host/<current-dir>/login
        let last_slash = base
            .rfind('/')
            .filter(|&i| i >= scheme_end + 2)
            .unwrap_or(host_end);
        format!("{}/{}", &base[..last_slash], loc)
    }
}

// Shared reqwest blocking client: native-tls-vendored (bundled OpenSSL, no
// runtime libssl dep), HTTP/2 via ALPN, permissive certs. OnceCell keeps
// one client for the whole run — saves per-probe TLS init overhead.
// Danger flags: scanner use-case. We WANT to see the server's response
// whether the cert is expired, self-signed, name-mismatched, or has a
// negative X.509 serial number from some 2006 Cisco appliance.
static HTTP_CLIENT: std::sync::OnceLock<reqwest::blocking::Client> =
    std::sync::OnceLock::new();

fn http_client() -> Option<&'static reqwest::blocking::Client> {
    HTTP_CLIENT
        .get_or_init(|| {
            reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .user_agent(concat!("portwave/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(5))
                .connect_timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .http1_title_case_headers()
                .build()
                .ok()
                .unwrap_or_else(|| reqwest::blocking::Client::new())
        })
        .into()
}

fn http_probe_single(url: &str, follow: bool) -> Option<HttpProbeResult> {
    let client = http_client()?;
    let started_https = url.starts_with("https://");
    let mut current = url.to_string();
    let mut chain: Vec<String> = Vec::new();
    let mut last: Option<(u16, String, Option<String>, Option<u64>)> = None;

    for hop in 0..=3 {
        let resp = match client.get(&current).send() {
            Ok(r) => r,
            Err(_) => {
                // TLS handshake failed / connection refused / etc.
                // First hop is fatal; intermediate we keep what we have.
                if hop == 0 {
                    return None;
                }
                break;
            }
        };

        let status = resp.status().as_u16();
        // reqwest gives us `canonical_reason()` which is a human-friendly
        // status text. Fall back to a blank if the code is non-standard.
        let status_text = resp
            .status()
            .canonical_reason()
            .unwrap_or("")
            .to_string();
        // Content-Length: prefer the raw wire header; fall back to the
        // body bytes we actually received. HTTP/2 responses often omit
        // the Content-Length header (H2 uses DATA frame lengths instead),
        // and reqwest strips it on auto-decompression — so we compute
        // from body length if the header is missing.
        let header_cl: Option<u64> = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Read body (streaming, capped at 64 KiB). We use `.bytes()` and
        // then truncate rather than chunked streaming — title is usually
        // in the first few KiB anyway, and reqwest's top-level timeout
        // (5 s) prevents runaway downloads.
        let body_bytes = resp.bytes().ok().unwrap_or_default();
        let body_len = body_bytes.len();
        let body_trunc = &body_bytes[..body_len.min(65536)];
        let body_str = String::from_utf8_lossy(body_trunc);
        let title = extract_title(&body_str);

        let content_length: Option<u64> = header_cl.or_else(|| {
            if body_len > 0 {
                Some(body_len as u64)
            } else {
                None
            }
        });

        last = Some((status, status_text, title, content_length));

        let is_redirect = (300..400).contains(&status);
        if !follow || !is_redirect {
            break;
        }
        match location {
            Some(loc) => {
                let next = resolve_redirect_url(&current, &loc);
                chain.push(current);
                current = next;
            }
            None => break,
        }
    }

    let (status_code, status_text, title, content_length) = last?;
    let final_url = if chain.is_empty() {
        None
    } else {
        Some(current.clone())
    };
    Some(HttpProbeResult {
        status_line: format!("HTTP/1.1 {} {}", status_code, status_text),
        title,
        final_url,
        chain,
        via_https: started_https,
        content_length,
    })
}

/// Try `url` as-is; if it fails AND the port is non-standard, retry with the
/// opposite scheme. Catches weird cases like HTTP on :8443 or HTTPS on :8080.
fn http_probe_blocking(url: &str, follow: bool) -> Option<HttpProbeResult> {
    if let Some(r) = http_probe_single(url, follow) {
        return Some(r);
    }
    // Scheme flip retry — only bother for non-standard ports, since :80/:443
    // rarely cross-speak.
    let is_http = url.starts_with("http://");
    let is_https = url.starts_with("https://");
    let non_standard_port = url
        .rsplit_once(':')
        .and_then(|(_, rest)| rest.split('/').next())
        .and_then(|p| p.parse::<u16>().ok())
        .map(|p| !matches!(p, 80 | 443))
        .unwrap_or(false);
    if !non_standard_port {
        return None;
    }
    let alt = if is_http {
        url.replacen("http://", "https://", 1)
    } else if is_https {
        url.replacen("https://", "http://", 1)
    } else {
        return None;
    };
    http_probe_single(&alt, follow)
}

// Cross-platform PATH resolver. Returns the full path to the first hit, not
// just a bool. Matches the semantics of `which` on Unix and `where.exe` on
// Windows (including .exe / .cmd / .bat extensions).
fn find_binary(name: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    let sep = ';';
    #[cfg(not(windows))]
    let sep = ':';

    // Windows resolves bare binary names by trying PATHEXT extensions. On
    // Unix we just test the literal name.
    #[cfg(windows)]
    let extensions: Vec<String> = {
        let mut out: Vec<String> = vec![String::new()]; // literal first
        if let Ok(pathext) = std::env::var("PATHEXT") {
            for ext in pathext.split(';') {
                let ext = ext.trim();
                if !ext.is_empty() {
                    out.push(ext.to_string());
                }
            }
        } else {
            out.extend(
                [".exe", ".bat", ".cmd", ".com"]
                    .iter()
                    .map(|s| s.to_string()),
            );
        }
        out
    };
    #[cfg(not(windows))]
    let extensions: Vec<String> = vec![String::new()];

    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(sep) {
        if dir.is_empty() {
            continue;
        }
        for ext in &extensions {
            let candidate = Path::new(dir).join(format!("{}{}", name, ext));
            if candidate.is_file() {
                // On Unix we also need the +x bit; on Windows `is_file()`
                // is enough since executables aren't mode-gated.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let exec = candidate
                        .metadata()
                        .ok()
                        .map(|m| m.permissions().mode() & 0o111 != 0)
                        .unwrap_or(false);
                    if !exec {
                        continue;
                    }
                }
                return Some(candidate);
            }
        }
    }
    None
}

// Resolve a tool to an absolute path. Precedence:
//   1. CLI flag env var (PORTWAVE_HTTPX_BIN / PORTWAVE_NUCLEI_BIN)
//   2. Config file key of the same name
//   3. PATH lookup via find_binary()
// Returns None only if all three miss.
fn resolve_tool(
    name: &str,
    cfg: &std::collections::HashMap<String, String>,
    env_key: &str,
) -> Option<PathBuf> {
    if let Ok(path) = std::env::var(env_key) {
        let p = path.trim();
        if !p.is_empty() && Path::new(p).is_file() {
            return Some(PathBuf::from(p));
        }
    }
    if let Some(path) = cfg.get(env_key) {
        let p = path.trim();
        if !p.is_empty() && Path::new(p).is_file() {
            return Some(PathBuf::from(p));
        }
    }
    find_binary(name)
}

// Interactive "install X?" prompt. Returns true if install succeeded.
// Respects --no-install-prompt and skips silently on non-TTY stdin.
fn offer_install(tool: &str, go_pkg: &str, allow_prompt: bool) -> bool {
    if !allow_prompt {
        return false;
    }
    // Only prompt on an actual TTY — CI / piped input auto-declines.
    #[cfg(unix)]
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };
    #[cfg(not(unix))]
    let is_tty = true; // best-effort on Windows

    if !is_tty {
        eprintln!(
            "[install] {} not found and stdin is not a TTY — skipping. \
             Install with:  go install -v {}@latest",
            tool, go_pkg
        );
        return false;
    }

    // Need `go` to install. If it's missing, tell the user where to get it.
    let go_path = find_binary("go");
    if go_path.is_none() {
        eprintln!(
            "[install] {} not found, and `go` is not on PATH either. \
             Install Go from https://go.dev/dl/ then retry, or install {} \
             manually: go install -v {}@latest",
            tool, tool, go_pkg
        );
        return false;
    }

    eprint!(
        "[install] {} not found. Install via `go install -v {}@latest` now? [Y/n] ",
        tool, go_pkg
    );
    use std::io::Write as _;
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    let ans = line.trim();
    if !(ans.is_empty() || ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes")) {
        eprintln!("[install] skipped.");
        return false;
    }

    eprintln!("[install] running: go install -v {}@latest", go_pkg);
    let status = Command::new(go_path.unwrap())
        .args(["install", "-v", &format!("{}@latest", go_pkg)])
        .status();
    match status {
        Ok(s) if s.success() => {
            eprintln!("[install] {} installed.", tool);
            true
        }
        Ok(s) => {
            eprintln!("[install] go install exited with status {}. Install {} manually.", s, tool);
            false
        }
        Err(e) => {
            eprintln!("[install] failed to launch `go install`: {}. Install {} manually.", e, tool);
            false
        }
    }
}

// Minimal TLS 1.0 ClientHello — we only care whether the peer *speaks* TLS.
fn client_hello() -> Vec<u8> {
    vec![
        0x16, 0x03, 0x01, 0x00, 0x2e, // TLS record header
        0x01, 0x00, 0x00, 0x2a, 0x03, 0x03,
        // 32 random bytes
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x00,             // session id length
        0x00, 0x02, 0xc0, 0x2f, // one cipher suite
        0x01, 0x00,       // compression methods
    ]
}

// Port-number-based service fallback. Used as the last resort in enrich()
// when passive + active probes didn't return a classifiable banner. Every
// entry here is a well-known service port per IANA + Wikipedia's curated
// "List of TCP and UDP port numbers" + nmap-services frequency data.
//
// Compiles to a single jump table via LLVM — O(1) lookup, <50 ns per call.
// Zero allocation (every string is &'static). No measurable impact on
// scan throughput even at 10 K opens.
//
// Priority rule: this NEVER overrides a real banner-based classification.
// An actual SSH or HTTP response wins even if the port number suggests
// something else. Only fires when protocol would otherwise be "unknown".
fn service_for_port(port: u16) -> Option<&'static str> {
    Some(match port {
        // ── Web / HTTP ──
        80 | 81 | 591 | 2080 | 3000 | 5080 | 7070 | 7080 | 8000 | 8008
            | 8042 | 8069 | 8080 | 8090 | 8180 | 8280 | 8800 | 8880 | 8888
            | 9080 => "http",
        8010 | 8085 | 8089 | 8181 | 8183 => "http-alt",
        9999 => "http-admin",

        // ── HTTPS ── (canonical HTTPS ports — also covered by the
        // separate HTTPS-refinement block in enrich() but mapped here
        // too so non-canonical-but-configured HTTPS ports resolve)
        832 | 981 | 1311 | 7443 | 8834 => "https",
        10443 => "https-alt",
        2053 => "cloudflare-https",

        // ── Web apps / admin panels / common dev stacks ──
        2082 => "cpanel",
        2083 | 2087 | 2096 => "cpanel-ssl",
        2086 => "whm",
        3001 => "grafana-alt",
        3030 => "sonarqube",
        5601 | 9243 => "kibana",
        7001 | 7002 => "weblogic",
        7777 => "oracle-http",
        8140 => "puppet",
        8161 => "activemq-admin",
        8200 => "vault",
        8291 => "mikrotik-winbox",
        8728 | 8729 => "mikrotik-api",
        9090 => "prometheus",
        9091 => "transmission",
        9093 => "alertmanager",
        10050 | 10051 => "zabbix",
        32400 => "plex",

        // ── Proxies / Tor / SOCKS ──
        1080 => "socks",
        3128 | 8118 => "http-proxy",
        8123 => "polipo",
        9001 | 9030 => "tor",
        9050 | 9051 => "tor-socks",

        // ── Remote access ──
        22 => "ssh",
        2222 => "ssh-alt",
        23 => "telnet",
        3389 => "rdp",
        5800..=5802 => "vnc-http",
        5900..=5910 => "vnc",
        5938 => "teamviewer",
        6000..=6009 => "x11",

        // ── Mail ──
        25 => "smtp",
        2525 => "smtp-alt",
        110 => "pop3",
        143 => "imap",
        465 => "smtps",
        587 => "submission",
        993 => "imaps",
        995 => "pop3s",

        // ── File / block / share ──
        20 => "ftp-data",
        21 => "ftp",
        115 => "sftp-legacy",
        139 => "netbios-ssn",
        445 => "smb",
        548 => "afp",
        873 => "rsync",
        989 => "ftps-data",
        990 => "ftps",
        2049 => "nfs",
        3260 => "iscsi",
        6881..=6889 => "bittorrent",

        // ── DNS / directory / auth ──
        53 => "dns",
        853 => "dns-over-tls",
        5353 => "mdns",
        88 => "kerberos",
        389 => "ldap",
        464 => "kpasswd",
        636 => "ldaps",
        749 => "kerberos-adm",
        3268 => "globalcat-ldap",
        3269 => "globalcat-ldaps",

        // ── Databases ──
        1433 | 1434 => "mssql",
        1521 | 1526 => "oracle",
        3050 => "firebird",
        3306 | 3307 => "mysql",
        5432 | 5433 => "postgres",
        5984 | 6984 => "couchdb",
        6379 | 6380 => "redis",
        7199 => "cassandra-jmx",
        7474 | 7687 => "neo4j",
        8086 => "influxdb",
        8087 => "riak",
        9042 => "cassandra",
        9160 => "cassandra-thrift",
        9200 | 9300 => "elasticsearch",
        11211 => "memcached",
        27017..=27019 => "mongodb",
        28017 => "mongodb-web",
        50000 => "db2",

        // ── Messaging / streaming ──
        1883 => "mqtt",
        8883 => "mqtts",
        4369 => "epmd",
        5671 => "amqps",
        5672 => "amqp",
        6123 => "flink",
        9092 => "kafka",
        15672 => "rabbitmq-mgmt",
        25672 => "rabbitmq-cluster",
        61613 => "stomp",
        61614 => "stomp-ssl",
        61616 => "activemq",

        // ── Container / orchestration ──
        2375 => "docker",
        2376 => "docker-tls",
        2377 => "docker-swarm",
        2379 | 2380 => "etcd",
        5000 => "docker-registry",
        6443 => "kubernetes-api",
        10250 => "kubelet",
        10255 => "kubelet-ro",
        10256 => "kube-proxy",
        10257 => "kube-controller",
        10259 => "kube-scheduler",

        // ── DevOps / monitoring ──
        4040 => "spark-ui",
        5044 => "logstash-beats",
        7077 => "spark",
        8125 => "statsd",
        8300..=8302 => "consul",
        8500 => "consul-http",
        8600 => "consul-dns",
        9094 => "alertmanager-cluster",
        9100 => "node-exporter",
        9115 => "blackbox-exporter",
        9187 => "postgres-exporter",
        9411 => "zipkin",
        9418 => "git",
        11434 => "ollama",
        50070 | 50075 | 50090 => "hadoop",
        // 8021 is ftp-proxy on macOS/FreeBSD /etc/services (default launchd
        // socket — hit most often on personal Macs). Hadoop-adjacent ports
        // (8020 NameNode IPC, 8032 YARN RM, 8088 YARN RM web UI) keep the
        // hadoop-alt label since those deployments specifically configure
        // them; bare port 8021 on a Mac is overwhelmingly ftp-proxy.
        8021 => "ftp-proxy",
        8020 | 8032 | 8088 => "hadoop-alt",

        // ── VPN / tunneling ──
        500 => "isakmp",
        1194 => "openvpn",
        1701 => "l2tp",
        1723 => "pptp",
        4500 => "ipsec-nat-t",
        51820 => "wireguard",

        // ── Windows / RPC / WinRM ──
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        593 => "rpc-over-http",
        1025..=1030 => "msrpc-dyn",
        5722 => "ms-dfsr",
        5985 => "winrm-http",
        5986 => "winrm-https",
        47001 => "winrm",

        // ── IoT / industrial control ──
        102 => "s7comm",
        502 => "modbus",
        623 => "ipmi",
        1911 => "niagara-fox",
        2404 => "iec-104",
        4840 => "opc-ua",
        20000 => "dnp3",
        44818 => "ethernet-ip",
        47808 => "bacnet",

        // ── Gaming / media ──
        25565 => "minecraft",
        19132 => "minecraft-bedrock",
        27015..=27030 => "steam",
        27960 => "quake3",
        28960 => "cod",
        3074 => "xbox-live",

        // ── Misc well-known ──
        7 => "echo",
        9 => "discard",
        13 => "daytime",
        17 => "qotd",
        19 => "chargen",
        37 => "time",
        43 => "whois",
        79 => "finger",
        111 => "rpcbind",
        113 => "ident",
        119 => "nntp",
        123 => "ntp",
        161 | 162 => "snmp",
        179 => "bgp",
        194 => "irc",
        427 => "slp",
        512 => "rexec",
        513 => "rlogin",
        514 => "syslog",
        515 => "lpd",
        520 => "rip",
        554 => "rtsp",
        631 => "ipp",
        666 => "doom",
        902 => "vmware-auth",
        1099 => "java-rmi",
        1352 => "lotus-notes",
        1414 => "ibm-mq",
        1604 => "citrix",
        1812 | 1813 => "radius",
        1900 => "upnp",
        2000 => "cisco-sccp",
        2181 => "zookeeper",
        2598 => "citrix-ica",
        3283 => "apple-remote",
        3632 => "distcc",
        3689 => "daap",
        3690 => "svn",
        3702 => "ws-discovery",
        4070 => "spotify",
        4200 => "ember",
        4444 => "metasploit",
        4786 => "cisco-smi",
        4848 => "glassfish-admin",
        5060 => "sip",
        5061 => "sips",
        5190 => "aol",
        5222 => "xmpp-client",
        5223 => "xmpp-client-ssl",
        5269 => "xmpp-server",
        5280 => "xmpp-bosh",
        5357 => "wsdapi",
        5500 => "vnc-reverse",
        5632 => "pcanywhere",
        5683 => "coap",
        5684 => "coaps",
        6514 => "syslog-tls",
        6566 => "sane",
        6667..=6669 => "irc-alt",
        7547 => "tr-069",
        8009 => "ajp13",
        11111 => "vce",
        17500 => "dropbox-lan",

        _ => return None,
    })
}

fn classify(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    if data.starts_with(b"SSH-") {
        return Some("ssh".into());
    }
    if data.starts_with(b"HTTP/") {
        return Some("http".into());
    }
    if data[0] == 0x16 && data.len() > 1 && data[1] == 0x03 {
        return Some("tls".into());
    }
    if data.starts_with(b"220 ") || data.starts_with(b"220-") {
        let s = String::from_utf8_lossy(data).to_lowercase();
        if s.contains("smtp") || s.contains("postfix") || s.contains("sendmail") {
            return Some("smtp".into());
        }
        if s.contains("ftp") {
            return Some("ftp".into());
        }
        return Some("smtp_or_ftp".into());
    }
    if data.starts_with(b"+OK") {
        return Some("pop3".into());
    }
    if data.starts_with(b"* OK") {
        return Some("imap".into());
    }
    None
}

// TCP connect with our tuned socket options:
//   * SO_LINGER = 0  → close() returns the ephemeral port to the OS
//                      immediately instead of leaving it in TIME_WAIT for 60 s.
//                      Critical for long scans that would otherwise exhaust
//                      the ephemeral port range at ~4 K concurrent probes.
//   * TCP_NODELAY    → disable Nagle. We close right after connect, so the
//                      default 40 ms ACK coalescing is pure latency.
// Classify a connect() error: is this *our* OS / stack pushing back (shrink
// the worker pool), or a remote-side response (just a normal scan outcome)?
//
// Local-pressure signals:
//   - AddrNotAvailable     → ephemeral port pool exhausted
//   - raw errno 24 (EMFILE)            → FD limit hit
//   - raw errno 23 (ENFILE)            → system-wide FD limit hit
//   - raw errno 105 (ENOBUFS)          → kernel ran out of socket buffers
//   - raw errno 11  (EAGAIN on connect) → nonblocking queue full
//
// ConnectionRefused / NetworkUnreachable / HostUnreachable are *remote* —
// they tell us "this port is closed / no route to host". Treating those as
// saturation would shrink the pool against any heavily-firewalled /24 or
// any target range with mostly-dead hosts (including 127.0.0.0/24 on
// localhost, where 255 of 256 IPs are unbound).
fn is_local_resource_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    match e.kind() {
        AddrNotAvailable => return true,
        _ => {}
    }
    if let Some(code) = e.raw_os_error() {
        // Linux errno. BSD codes differ but the practical names we care
        // about (EMFILE, ENFILE, ENOBUFS, EAGAIN) are the same low numbers
        // on macOS. Windows errors don't go through this path typically.
        matches!(code, 11 | 23 | 24 | 105)
    } else {
        false
    }
}

// v0.14.8: ENETUNREACH detection. Unlike timeouts (firewalled targets) or
// EHOSTUNREACH (legitimate on sparse IPv6), ENETUNREACH means the local
// routing table itself can't reach the destination network — the only
// clean signal that "your WiFi just dropped". Counts feed the network-
// down monitor, which flips `stats.shutdown` to save progress and exit
// gracefully when a burst of these shows up.
//
// Platform errnos:
//   Linux:   ENETUNREACH = 101
//   macOS:   ENETUNREACH = 51
//   Windows: WSAENETUNREACH = 10051
fn is_net_unreachable_error(e: &std::io::Error) -> bool {
    if let Some(code) = e.raw_os_error() {
        matches!(code, 101 | 51 | 10051)
    } else {
        false
    }
}

async fn tcp_probe(sa: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = match sa {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    // Tokio blanket-deprecates set_linger because SO_LINGER with a *non-zero*
    // timeout can block the runtime on close. We explicitly use Duration::ZERO,
    // which sends a RST and returns immediately — exactly what we want to
    // avoid TIME_WAIT ephemeral-port exhaustion on long scans.
    #[allow(deprecated)]
    {
        let _ = socket.set_linger(Some(Duration::ZERO));
    }
    let stream = socket.connect(sa).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

// ────────────────────────── Phase A (discovery) ──────────────────────────

async fn phase_a(
    rx: flume::Receiver<SocketAddr>,
    hit_tx: mpsc::Sender<SocketAddr>,
    sem: Arc<Semaphore>,
    stats: Arc<Stats>,
    pb: ProgressBar,
    timeout: Duration,
    retries: u8,
) {
    // Batched progress-bar update. indicatif's ProgressBar.inc() takes an
    // internal Mutex on every call — at 10–15 K probes/sec × 1500 workers
    // the contention shows up on profiles. Instead, keep a per-worker
    // local counter and flush every PB_BATCH probes (or on exit).
    //
    // v0.13.4: reduced 64 → 8. On firewalled scans (>99 % timeouts),
    // probes complete in 800 ms bursts. With batch=64 most workers would
    // accumulate <64 probes per burst and only flush to pb on worker
    // exit, making indicatif's per-second rate calculator under-report
    // (users saw "0.5/s · ETA 4d" on scans actually running at 700/s).
    // Batch=8 updates pb 8× more often with negligible lock contention
    // (still 8× fewer than unbatched); rate + ETA now track reality.
    const PB_BATCH: u64 = 8;
    let mut pb_accum: u64 = 0;
    // Throttle the "open: <addr>" message to once per second per worker —
    // otherwise a hot /24 with 100 opens drowns the bar in redraws.
    let mut last_msg = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);

    while let Ok(sa) = rx.recv_async().await {
        if stats.shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Fast path: only take a semaphore permit when the adaptive
        // controller has actually shrunk the pool. In the common case
        // (unshrunk) the semaphore has N permits for N workers and
        // acquire is a no-op — so we skip it entirely.
        let permit = if stats.adaptive_shrunk.load(Ordering::Relaxed) {
            match sem.clone().acquire_owned().await {
                Ok(p) => Some(p),
                Err(_) => break,
            }
        } else {
            None
        };

        let mut opened = false;
        let mut final_timeout = false;
        for attempt in 0..=retries {
            match tokio::time::timeout(timeout, tcp_probe(sa)).await {
                Ok(Ok(_)) => {
                    opened = true;
                    break;
                }
                Ok(Err(e)) => {
                    if is_local_resource_error(&e) {
                        stats.local_errors.fetch_add(1, Ordering::Relaxed);
                    } else if is_net_unreachable_error(&e) {
                        // v0.14.8: feeds the network-down monitor. Single
                        // relaxed atomic add, negligible on the hot path.
                        stats.net_unreach.fetch_add(1, Ordering::Relaxed);
                    }
                    break;
                }
                Err(_) => {
                    if attempt == retries {
                        final_timeout = true;
                        break;
                    }
                }
            }
        }
        drop(permit);

        stats.attempts.fetch_add(1, Ordering::Relaxed);
        if final_timeout {
            stats.timeouts.fetch_add(1, Ordering::Relaxed);
        }
        if opened {
            stats.opens.fetch_add(1, Ordering::Relaxed);
            let _ = hit_tx.send(sa).await;
            let now = Instant::now();
            if now.duration_since(last_msg) >= Duration::from_secs(1) {
                pb.set_message(format!("open: {}", sa));
                last_msg = now;
            }
        }
        pb_accum += 1;
        if pb_accum >= PB_BATCH {
            pb.inc(pb_accum);
            pb_accum = 0;
        }
    }
    if pb_accum > 0 {
        pb.inc(pb_accum);
    }
}

// ────────────────────────── Phase B (enrichment) ──────────────────────────

async fn enrich(sa: SocketAddr, timeout: Duration, tls_sniff: bool, want_banner: bool) -> OpenPort {
    let mut out = OpenPort {
        ip: sa.ip().to_string(),
        port: sa.port(),
        rtt_ms: 0,
        tls: sa.port() == 443,
        protocol: None,
        banner: None,
        cdn: None,
        source_label: None, // filled in post-enrichment from the domain→IP map
        title: None,
        final_url: None,
        redirect_chain: None,
        content_length: None,
    };

    let start = Instant::now();
    let mut stream = match tokio::time::timeout(timeout, tcp_probe(sa)).await {
        Ok(Ok(s)) => s,
        _ => return out,
    };
    out.rtt_ms = start.elapsed().as_millis() as u64;

    let mut buf = [0u8; 512];

    // Passive read — catches SSH/SMTP/FTP/IMAP/POP3 banners.
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await
    {
        if n > 0 {
            out.protocol = classify(&buf[..n]);
            if want_banner {
                out.banner = Some(
                    String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(160)
                        .collect(),
                );
            }
            return out;
        }
    }

    // Active HTTP probe.
    if stream
        .write_all(b"GET / HTTP/1.0\r\nHost: scan\r\nUser-Agent: portwave\r\n\r\n")
        .await
        .is_ok()
    {
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await
        {
            if n > 0 && buf.starts_with(b"HTTP/") {
                // If the port is canonically HTTPS but we somehow got a
                // plain HTTP reply (some targets speak HTTP on 443 for
                // redirect-to-https), label it "http" still — the TLS
                // refinement block below will override if we also detect
                // TLS bytes via the dedicated sniff path.
                out.protocol = Some("http".into());
                if want_banner {
                    out.banner = Some(
                        String::from_utf8_lossy(&buf[..n])
                            .lines()
                            .next()
                            .unwrap_or("")
                            .chars()
                            .take(160)
                            .collect(),
                    );
                }
                return out;
            }
        }
    }
    drop(stream);

    // TLS sniff — fresh socket, send ClientHello.
    if tls_sniff && sa.port() != 443 {
        if let Ok(Ok(mut s2)) =
            tokio::time::timeout(Duration::from_millis(500), tcp_probe(sa)).await
        {
            if s2.write_all(&client_hello()).await.is_ok() {
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(400), s2.read(&mut buf)).await
                {
                    if n >= 2 && (buf[0] == 0x16 || buf[0] == 0x15) && buf[1] == 0x03 {
                        out.tls = true;
                        out.protocol = Some("tls".into());
                    }
                }
            }
        }
    }

    // ── Port-aware classification refinement ──
    // Before v0.12.1 every TLS-confirmed port showed as "[unknown, tls]"
    // because our plaintext HTTP probe fails on a real TLS stack. And
    // port 8443 in particular showed plain "[unknown]" when TLS sniff
    // itself failed (the minimal ClientHello has no SNI, so strict
    // servers close on us). Both cases were confusing UX for what is
    // in practice almost always HTTPS.
    //
    // When we hit a port that's canonically HTTPS (443, 4443, 8443,
    // 9443, 10443) and didn't learn a better protocol, label it
    // "https". Leaves genuine ssh/smtp/etc. banners alone — those are
    // deliberate overrides and classifying them as https would be a
    // real error. Also leaves the "tls" label for non-canonical ports
    // where we only confirmed TLS but don't know what's on top.
    let is_canonical_https_port = matches!(sa.port(), 443 | 4443 | 8443 | 9443 | 10443);
    if is_canonical_https_port {
        match out.protocol.as_deref() {
            // "tls" → "https" on a canonical HTTPS port. No change to
            // out.tls (still true — we did confirm TLS).
            Some("tls") => out.protocol = Some("https".into()),
            // Unclassified open port on a canonical HTTPS port. Best
            // guess is HTTPS — a 10x better UX than "unknown". tls stays
            // whatever we actually learned (true if sniff succeeded /
            // auto-set on 443, false if sniff failed on 8443-style
            // SNI-requiring servers). Users reading scan_summary can
            // tell from (tls=false, banner=null) that the label is
            // inferred from port number, not verified at the protocol.
            None => out.protocol = Some("https".into()),
            _ => {}
        }
    }

    // ── Port-number fallback (v0.12.2) ──
    // Last-resort classifier: if banner / probe / TLS sniff all failed to
    // identify the service, fall back to the port-number's canonical
    // meaning. Covers ~300 well-known services — SSH tarpits (endlessh),
    // hardened nginx that drops non-matching Host headers, silent Postgres
    // / Redis / MongoDB, obscure IoT protocols, VPN endpoints, etc.
    //
    // Only fires when out.protocol is still None, so any real banner
    // classification (the common case) is preserved. Service-name strings
    // are &'static so zero allocation in the hot path.
    if out.protocol.is_none() {
        if let Some(svc) = service_for_port(sa.port()) {
            out.protocol = Some(svc.into());
        }
    }

    out
}

// ────────────────────────── Adaptive controller ──────────────────────────

// Adaptive concurrency controller.
//
// DESIGN:
//   Timeouts alone are a poor saturation signal — a firewalled target drops
//   every SYN and produces 100 % timeouts while our local kernel / uplink are
//   fine. Previous versions shrunk the worker pool on high timeout ratios and
//   crippled the scan. (See CHANGELOG v0.6.2.)
//
//   The only signal that actually means "MY host is running out of resources"
//   is a local-resource error from connect() — AddrNotAvailable (ephemeral
//   port exhaustion), EMFILE (FD limit), ENOBUFS (kernel buffer full),
//   EAGAIN (socket queue full). These are the signals we now watch.
//
// BEHAVIOUR:
//   - Shrink when local_error_ratio (local_errors / attempts) > 5 % in the
//     last 2-second window.
//   - Grow back toward `max` when there have been zero local errors for the
//     last two windows.
//   - No action when timeouts are high but local errors are zero — that's a
//     dead / firewalled target and shrinking wouldn't help anyway.
async fn adaptive_monitor(stats: Arc<Stats>, sem: Arc<Semaphore>, max: usize) {
    let mut prev_a: u64 = 0;
    let mut prev_l: u64 = 0;
    let mut current = max;
    let min = (max / 16).max(64);
    let mut clean_windows: u32 = 0;

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if stats.shutdown.load(Ordering::Relaxed) {
            break;
        }
        let a = stats.attempts.load(Ordering::Relaxed);
        let l = stats.local_errors.load(Ordering::Relaxed);
        let da = a.saturating_sub(prev_a);
        let dl = l.saturating_sub(prev_l);
        prev_a = a;
        prev_l = l;

        if da < 200 {
            continue; // too little traffic to make a decision on
        }

        let local_ratio = dl as f64 / da as f64;

        if local_ratio > 0.05 && current > min {
            // Real local pressure. Shrink.
            let shrink = (current / 4).max(1).min(current - min);
            if let Ok(p) = sem.clone().acquire_many_owned(shrink as u32).await {
                p.forget();
                current -= shrink;
                // Flip the shrunk flag so workers start gating on the
                // semaphore again — they bypass it in the unshrunk state
                // for a ~3–5 % hot-path CPU saving.
                stats.adaptive_shrunk.store(true, Ordering::Relaxed);
                eprintln!(
                    "[adaptive] local-resource errors {:.1}% ({} of {} probes) — shrinking to {}",
                    local_ratio * 100.0,
                    dl,
                    da,
                    current
                );
            }
            clean_windows = 0;
        } else if dl == 0 {
            // No local pressure. Grow back toward max after 2 clean windows.
            clean_windows += 1;
            if clean_windows >= 2 && current < max {
                let grow = ((max - current) / 4).max(1);
                sem.add_permits(grow);
                current += grow;
                if current >= max {
                    // Fully recovered — workers can skip the semaphore again.
                    stats.adaptive_shrunk.store(false, Ordering::Relaxed);
                }
            }
        } else {
            clean_windows = 0;
        }
    }
}

// ────────────────────────── Producer ──────────────────────────

// Yield the next batch of usable IPs from a set of CIDRs in round-robin
// order, re-using the same allocated Vec each call. Returns how many IPs
// were written. When 0, all iterators are exhausted.
//
// Iterator-based design — memory stays O(nets), not O(IPs). A /8 pre-
// v0.8.0 materialised 16M IPs (~64 MB); now it lives as a single IpIter
// state (24 bytes).
fn fill_next_round<'a>(
    iters: &mut [(IpNetwork, ipnetwork::IpNetworkIterator)],
    exclude: &[IpNetwork],
    out: &mut Vec<IpAddr>,
) -> usize {
    out.clear();
    for (net, it) in iters.iter_mut() {
        // Skip ahead through network/broadcast/excluded IPs within this
        // iterator until we find one usable host (or exhaust the iter).
        loop {
            let Some(ip) = it.next() else { break };
            if !is_usable_ipv4_host(net, ip) {
                continue;
            }
            if exclude.iter().any(|e| e.contains(ip)) {
                continue;
            }
            out.push(ip);
            break;
        }
    }
    out.len()
}

// Helper: send a SocketAddr while respecting shutdown. Returns Err(()) if
// the receiver is gone OR shutdown was requested — either way the producer
// should stop. Uses try_send fast path; on backpressure, races the send
// against a 100 ms timer so shutdown can be observed promptly.
async fn send_or_shutdown(
    tx: &flume::Sender<SocketAddr>,
    sa: SocketAddr,
    stats: &Stats,
) -> Result<(), ()> {
    // Fast path: immediate send.
    match tx.try_send(sa) {
        Ok(()) => return Ok(()),
        Err(flume::TrySendError::Disconnected(_)) => return Err(()),
        Err(flume::TrySendError::Full(sa2)) => {
            // Slow path: channel is full, wait — but poll shutdown every 100ms.
            let mut pending = sa2;
            loop {
                if stats.shutdown.load(Ordering::Relaxed) {
                    return Err(());
                }
                match tokio::time::timeout(
                    Duration::from_millis(100),
                    tx.send_async(pending),
                )
                .await
                {
                    Ok(Ok(())) => return Ok(()),
                    Ok(Err(_)) => return Err(()), // receiver dropped
                    Err(_) => {
                        // Timed out — re-check shutdown then retry the send.
                        pending = sa;
                    }
                }
            }
        }
    }
}

// Two-pass iterator-based producer.
//   Pass 1: top-20 priority ports × all IPs  (user sees early hits)
//   Pass 2: remaining ports × all IPs
// Within each pass we iterate ports-outer, IPs-inner, so all targets
// get probed on the same port before moving to the next port — which
// is what makes the "early results" promise real.
//
// Memory: a reusable Vec<IpAddr> of size <= nets.len() — not IPs.len().
async fn producer(
    tx: flume::Sender<SocketAddr>,
    nets: Vec<IpNetwork>,
    ports: Vec<u16>,
    skip: Arc<FxHashSet<SocketAddr>>,
    exclude: Arc<Vec<IpNetwork>>,
    stats: Arc<Stats>,
    rate_limiter: Option<Arc<RateLimiter>>,
) {
    let priority_set: std::collections::HashSet<u16> =
        TOP_PRIORITY_PORTS.iter().copied().collect();
    let priority_ports: Vec<u16> = ports
        .iter()
        .copied()
        .filter(|p| priority_set.contains(p))
        .collect();
    let other_ports: Vec<u16> = ports
        .iter()
        .copied()
        .filter(|p| !priority_set.contains(p))
        .collect();

    // Pass 1: priority ports
    for &port in &priority_ports {
        if stats.shutdown.load(Ordering::Relaxed) {
            return;
        }
        let mut iters: Vec<(IpNetwork, ipnetwork::IpNetworkIterator)> =
            nets.iter().map(|n| (*n, n.iter())).collect();
        let mut batch: Vec<IpAddr> = Vec::with_capacity(iters.len());
        loop {
            if fill_next_round(&mut iters, &exclude, &mut batch) == 0 {
                break;
            }
            for &ip in &batch {
                let sa = SocketAddr::new(ip, port);
                if skip.contains(&sa) {
                    continue;
                }
                // `--max-pps`: block on the token bucket before handing
                // the probe to a worker. No-op in the common case (flag
                // not set = rate_limiter is None). Sleeps briefly when
                // we're ahead of schedule.
                if let Some(rl) = &rate_limiter {
                    rl.acquire().await;
                }
                if send_or_shutdown(&tx, sa, &stats).await.is_err() {
                    return;
                }
            }
        }
    }
    stats.priority_done.store(true, Ordering::Relaxed);

    // Pass 2: everything else
    for &port in &other_ports {
        if stats.shutdown.load(Ordering::Relaxed) {
            return;
        }
        let mut iters: Vec<(IpNetwork, ipnetwork::IpNetworkIterator)> =
            nets.iter().map(|n| (*n, n.iter())).collect();
        let mut batch: Vec<IpAddr> = Vec::with_capacity(iters.len());
        loop {
            if fill_next_round(&mut iters, &exclude, &mut batch) == 0 {
                break;
            }
            for &ip in &batch {
                let sa = SocketAddr::new(ip, port);
                if skip.contains(&sa) {
                    continue;
                }
                if let Some(rl) = &rate_limiter {
                    rl.acquire().await;
                }
                if send_or_shutdown(&tx, sa, &stats).await.is_err() {
                    return;
                }
            }
        }
    }
}

// Returns true if stderr looks like a terminal (so ANSI colour + banner art
// are safe). On non-TTY (piped / redirected / CI) we stay plain.
// Tiny color helpers. Only emit ANSI codes when stdout is an actual
// terminal — piping to a file or another tool gives plain text so grep
// / jq / awk stay happy. Checked once at startup and stashed in a
// thread-local-ish Atomic so the per-port print loop doesn't syscall.
static STDOUT_IS_TTY: AtomicBool = AtomicBool::new(false);

fn init_stdout_color() {
    #[cfg(unix)]
    let tty = unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 };
    #[cfg(not(unix))]
    let tty = true;
    STDOUT_IS_TTY.store(tty, Ordering::Relaxed);
}

fn cfmt(code: &str, text: &str) -> String {
    if STDOUT_IS_TTY.load(Ordering::Relaxed) {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    } else {
        text.to_string()
    }
}

// Color palette for the OPEN PORTS table. Kept consistent across
// output so users build muscle memory: green = HTTP/open services,
// cyan = HTTPS/TLS-protected, yellow = TLS-only or known service
// banners, red = error-coded HTTP responses, magenta = CDN-edge,
// dim grey = unknown/opaque.
fn color_protocol(proto: &str) -> String {
    match proto {
        // Web / HTTP family → green / bright-cyan for TLS variants.
        "http" | "http-alt" | "http-admin" | "http-proxy"
                      => cfmt("32", proto),         // green
        "https" | "https-alt" | "cloudflare-https"
                      => cfmt("1;36", proto),       // bright cyan
        // Remote access / console → bright yellow.
        "ssh" | "ssh-alt" | "telnet" | "rdp" | "vnc" | "vnc-http"
            | "vnc-reverse" | "teamviewer" | "winrm-http" | "winrm-https"
            | "winrm" | "x11" | "pcanywhere"
                      => cfmt("1;33", proto),       // bright yellow
        // Mail / messaging / DNS / directory → yellow.
        "ftp" | "ftp-data" | "ftp-alt" | "ftps" | "ftps-data"
            | "smtp" | "smtp-alt" | "smtps" | "submission"
            | "pop3" | "pop3s" | "imap" | "imaps" | "smtp_or_ftp"
            | "dns" | "dns-over-tls" | "mdns"
            | "ldap" | "ldaps" | "kerberos" | "kerberos-adm" | "kpasswd"
            | "globalcat-ldap" | "globalcat-ldaps"
                      => cfmt("33", proto),         // yellow
        // Databases / caches → magenta (stand-out — these are high-value).
        "mysql" | "mysql-alt" | "postgres" | "postgres-alt"
            | "mssql" | "mssql-alt" | "oracle"
            | "redis" | "memcached" | "mongodb" | "mongodb-web"
            | "couchdb" | "elasticsearch" | "cassandra" | "cassandra-jmx"
            | "cassandra-thrift" | "neo4j" | "influxdb" | "riak"
            | "firebird" | "db2"
                      => cfmt("1;35", proto),       // bright magenta
        // Container / orchestration → cyan.
        "docker" | "docker-tls" | "docker-swarm" | "docker-registry"
            | "etcd" | "kubernetes-api" | "kubelet" | "kubelet-ro"
            | "kube-proxy" | "kube-controller" | "kube-scheduler"
                      => cfmt("36", proto),         // cyan
        // VPN / tunneling → bright magenta (often high-value).
        "openvpn" | "wireguard" | "isakmp" | "l2tp" | "pptp"
            | "ipsec-nat-t"
                      => cfmt("1;35", proto),
        // IoT / industrial control → red (often exposed-by-mistake targets).
        "s7comm" | "modbus" | "ipmi" | "niagara-fox" | "iec-104"
            | "opc-ua" | "dnp3" | "ethernet-ip" | "bacnet"
                      => cfmt("1;31", proto),       // bright red
        // TLS-only (unclassified above TLS) → cyan.
        "tls"         => cfmt("36", proto),
        // Explicit unknown → dim grey.
        "unknown"     => cfmt("2", proto),
        // Everything else (admin panels, messaging, monitoring, misc) → default.
        _             => proto.to_string(),
    }
}

fn color_banner_status(banner: &str) -> String {
    // Tag HTTP status codes by class: 2xx green, 3xx cyan, 4xx yellow, 5xx red.
    // Only applies when the banner looks like an HTTP status line.
    if let Some(rest) = banner.strip_prefix("HTTP/") {
        if let Some((_ver, after_ver)) = rest.split_once(' ') {
            let code = after_ver.chars().take(3).collect::<String>();
            let color = match code.chars().next() {
                Some('2') => "32",    // green
                Some('3') => "36",    // cyan
                Some('4') => "33",    // yellow
                Some('5') => "31",    // red
                _ => "",
            };
            if !color.is_empty() {
                return cfmt(color, banner);
            }
        }
    }
    banner.to_string()
}

fn atty_like_stderr() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::isatty(libc::STDERR_FILENO) != 0 }
    }
    #[cfg(not(unix))]
    {
        // Conservative default on non-Unix — always show the banner.
        true
    }
}

// ────────────────────────── Startup banner ──────────────────────────

// Standard figlet "portwave" — renders cleanly on every terminal width,
// no double-backslash pile-up, readable mixed-case output.
const BANNER_ART: &str = r"
                 _
  _ __   ___  _ __| |___      ____ __   _____
 | '_ \ / _ \| '__| __\ \ /\ / / _` |\ / / _ \
 | |_) | (_) | |  | |_ \ V  V / (_| | V /  __/
 | .__/ \___/|_|   \__| \_/\_/ \__,_|\_/ \___|
 |_|                                             ";

fn print_banner() {
    // ANSI cyan for the art, bold for the byline.
    eprintln!("\x1b[36m{}\x1b[0m", BANNER_ART);
    let current = env!("CARGO_PKG_VERSION");
    // Nuclei-style inline "(outdated → vX.Y.Z)" / "(latest)" tag derived
    // purely from the 24 h update cache — no network hit on startup.
    // Populated by maybe_show_update_banner (scan path) and by run_update
    // after a successful install, so users see drift the moment it exists.
    let tag = match cached_latest_version() {
        Some(latest) if version_is_newer(&latest, current) => {
            format!("  \x1b[31m(outdated → v{})\x1b[0m", latest)
        }
        Some(_) => "  \x1b[32m(latest)\x1b[0m".to_string(),
        None => String::new(),
    };
    eprintln!(
        "        \x1b[1mportwave {}\x1b[0m{}  \x1b[2m·\x1b[0m  \x1b[2mby assassin_marcos\x1b[0m  \x1b[2m·\x1b[0m  \x1b[2mgithub.com/assassin-marcos/portwave\x1b[0m",
        current, tag
    );
    eprintln!();
}

// ────────────────────────── Self-update ──────────────────────────

const REPO_OWNER: &str = "assassin-marcos";
const REPO_NAME: &str = "portwave";

fn update_cache_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|a| PathBuf::from(a).join("portwave").join("last_check"))
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".cache/portwave/last_check"))
    }
}

// Non-blocking cache-only lookup of the latest known release. Returns
// None if the cache is absent, unreadable, or older than 1 h. Used by
// the startup banner to tag the current version `(outdated)`/`(latest)`.
// TTL is deliberately short (1 h) because the banner makes a positive
// claim ("latest") that's hard to verify without a fresh network check —
// stale cache leads to lies like "v0.10.0 (latest)" when v0.11.0 is out.
// Combined with `refresh_update_cache_best_effort()` at startup, the
// cache is almost always freshly written by the time the banner reads it.
fn cached_latest_version() -> Option<String> {
    let p = update_cache_path()?;
    let meta = fs::metadata(&p).ok()?;
    let age = meta.modified().ok()?.elapsed().ok()?;
    // v0.14.6: TTL widened 1 h → 24 h. The previous 1 h cap, combined
    // with a too-tight banner-fetch budget on slow networks, left users
    // with no (outdated)/(latest) tag at all once the cache expired.
    // 24 h is still short enough that a day-old answer is only shown
    // until `refresh_update_cache_best_effort()` re-writes the cache,
    // which happens on every startup outside the 120 s fast path.
    if age > Duration::from_secs(24 * 3_600) {
        return None;
    }
    let s = fs::read_to_string(&p).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// Eager refresh of the update cache before the banner renders. Runs a
// 1-second-budget GitHub fetch so the `(outdated)` / `(latest)` banner
// tag reflects the *current* GitHub state, not a cached value from hours
// ago. Skipped on a cache-hit fast path (< 5 min old — nothing could
// have been published since). Silent on failure so offline users still
// see instant startup (the tag just falls back to whatever stale cache
// exists, or disappears if the cache is > 1 h old).
async fn refresh_update_cache_best_effort() {
    let p = match update_cache_path() {
        Some(p) => p,
        None => return,
    };
    // Fast path: cache fresh enough that we know any update within the
    // window has already been seen. No network call.
    //
    // v0.14.5: tightened window from 300s → 120s. With a 5-minute
    // fast path, a user who ran `portwave -u` right before a new
    // release dropped could see "(latest)" incorrectly for up to 5
    // minutes on subsequent invocations. 2 minutes is the narrowest
    // window that still avoids hammering GitHub's releases API when
    // the same user runs portwave multiple times in quick succession.
    if let Ok(meta) = fs::metadata(&p) {
        if let Some(age) = meta.modified().ok().and_then(|t| t.elapsed().ok()) {
            if age < Duration::from_secs(120) {
                return;
            }
        }
    }
    // Slow path: GitHub round-trip. v0.14.6 bumped 1s → 2500ms. 1s was
    // too tight on real-world Mac WiFi / hotel networks where the TLS
    // handshake + releases-API response routinely landed at 800-1500 ms;
    // the fetch would time out, no cache write, and after the 1 h TTL
    // lapsed the banner rendered with no (outdated)/(latest) tag at all.
    // 2500ms still feels instant on a fast link (fetch completes in
    // ~300 ms) but has enough headroom to actually complete on slow ones.
    let res = tokio::time::timeout(
        Duration::from_millis(2500),
        tokio::task::spawn_blocking(fetch_latest_version),
    )
    .await;
    if let Ok(Ok(Ok(Some(v)))) = res {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&p, v);
    }
}

// Sync helper — runs in spawn_blocking. Returns the latest release version
// (without leading 'v'). A "release" only exists once CI has uploaded at
// least one asset, so this lags tag creation by a few minutes.
fn fetch_latest_version() -> anyhow::Result<Option<String>> {
    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()?
        .fetch()?;
    Ok(releases.first().map(|r| r.version.clone()))
}

// Returns (version, body) tuples for every release newer than `current`,
// sorted newest-first. Body is the GitHub Release notes (markdown).
// Used by the startup banner to show users what changed since their
// install before prompting them to update.
fn fetch_release_notes_since(current: &str) -> anyhow::Result<Vec<(String, String)>> {
    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()?
        .fetch()?;
    let mut out: Vec<(String, String)> = Vec::new();
    for r in releases {
        if version_is_newer(&r.version, current) {
            out.push((r.version.clone(), r.body.clone().unwrap_or_default()));
        }
    }
    Ok(out)
}

// GitHub tags API peek — tags appear immediately on `git push --tags`, before
// CI has built release binaries. Used by --check-update to distinguish
// "you're up to date" from "a newer version is tagged but binaries are
// still being built".
fn fetch_latest_tag() -> anyhow::Result<Option<String>> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/tags?per_page=20",
        REPO_OWNER, REPO_NAME
    );
    let resp = ureq::get(&url)
        .set("User-Agent", concat!("portwave/", env!("CARGO_PKG_VERSION")))
        .set("Accept", "application/vnd.github+json")
        .timeout(std::time::Duration::from_secs(4))
        .call()?;
    let tags: serde_json::Value = resp.into_json()?;
    let mut best: Option<(Vec<u32>, String)> = None;
    if let Some(arr) = tags.as_array() {
        for t in arr {
            if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                let stripped = name.trim_start_matches('v').to_string();
                let parts: Vec<u32> = stripped
                    .split('.')
                    .map(|p| p.split('-').next().unwrap_or(""))
                    .filter_map(|p| p.parse::<u32>().ok())
                    .collect();
                if parts.is_empty() {
                    continue;
                }
                if best.as_ref().map_or(true, |(b, _)| parts > *b) {
                    best = Some((parts, stripped));
                }
            }
        }
    }
    Ok(best.map(|(_, s)| s))
}

fn version_is_newer(latest: &str, current: &str) -> bool {
    fn parse(s: &str) -> Vec<u32> {
        s.trim_start_matches('v')
            .split('.')
            .map(|p| p.split('-').next().unwrap_or(""))
            .filter_map(|p| p.parse::<u32>().ok())
            .collect()
    }
    let l = parse(latest);
    let c = parse(current);
    for i in 0..l.len().max(c.len()) {
        let a = *l.get(i).unwrap_or(&0);
        let b = *c.get(i).unwrap_or(&0);
        if a != b {
            return a > b;
        }
    }
    false
}

fn print_update_banner(latest: &str, notes: &[(String, String)]) {
    eprintln!();
    eprintln!(
        "\x1b[33m[!] portwave update available: {} → {}\x1b[0m",
        env!("CARGO_PKG_VERSION"),
        latest
    );
    if !notes.is_empty() {
        eprintln!();
        eprintln!("\x1b[1mWhat's new:\x1b[0m");
        // Cap to last 3 versions × 6 lines each so we don't drown the
        // scan output. Notes are GitHub release-notes markdown — strip
        // the "## What's Changed" / "## New Contributors" headers and
        // print the rest as plain text.
        for (ver, body) in notes.iter().take(3) {
            eprintln!("  \x1b[1mv{}\x1b[0m", ver);
            let mut printed = 0;
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty()
                    || line.starts_with("## ")
                    || line.starts_with("**Full Changelog**")
                {
                    continue;
                }
                if printed >= 6 {
                    eprintln!("    …");
                    break;
                }
                // Trim individual line length so super-long bullets don't wrap badly.
                let trimmed: String = line.chars().take(110).collect();
                eprintln!("    {}", trimmed);
                printed += 1;
            }
            if printed == 0 {
                eprintln!("    (no release notes attached)");
            }
            eprintln!();
        }
    }
    eprintln!("\x1b[2m    `portwave --update` installs the new binary in place.\x1b[0m");
    eprintln!();
}

// Fast, cached startup check. Skipped if disabled or in CI/test environments.
// On a TTY with a newer version detected, also prompts the user `[Y/n]` and
// runs the update inline if they accept. Suppress the prompt with
// --no-update-prompt while keeping the banner visible.
async fn maybe_show_update_banner(disabled: bool, no_prompt: bool) {
    if disabled || std::env::var("PORTWAVE_NO_UPDATE_CHECK").is_ok() {
        return;
    }
    let cache_path = update_cache_path();

    // Try cached value first (24 h TTL). The cache only stores the latest
    // version string — release notes are always fetched fresh when an
    // update is detected (rare event, worth the round-trip).
    let mut latest_from_cache: Option<String> = None;
    if let Some(p) = &cache_path {
        if let Ok(meta) = fs::metadata(p) {
            if let Ok(age) = meta.modified().ok().and_then(|t| t.elapsed().ok()).ok_or(()) {
                if age < Duration::from_secs(86_400) {
                    if let Ok(latest) = fs::read_to_string(p) {
                        let latest = latest.trim().to_string();
                        if !latest.is_empty() {
                            latest_from_cache = Some(latest);
                        }
                    }
                }
            }
        }
    }

    let latest = if let Some(v) = latest_from_cache {
        v
    } else {
        let res = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::task::spawn_blocking(fetch_latest_version),
        )
        .await;
        match res {
            Ok(Ok(Ok(Some(v)))) => {
                if let Some(p) = cache_path.clone() {
                    if let Some(parent) = p.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::write(&p, &v);
                }
                v
            }
            _ => return, // network slow / no release yet — silently skip
        }
    };

    if !version_is_newer(&latest, env!("CARGO_PKG_VERSION")) {
        return;
    }

    // We have a real update. Fetch release notes (best-effort, 4 s budget)
    // so the banner actually tells the user WHAT changed, not just THAT
    // something did.
    let notes_res = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::task::spawn_blocking({
            let cur = env!("CARGO_PKG_VERSION").to_string();
            move || fetch_release_notes_since(&cur)
        }),
    )
    .await;
    let notes: Vec<(String, String)> = match notes_res {
        Ok(Ok(Ok(v))) => v,
        _ => Vec::new(),
    };

    print_update_banner(&latest, &notes);

    // Interactive prompt — only on real TTY, only if the user hasn't asked
    // us to be quiet about it. Default action on Enter is YES (capital Y
    // in the [Y/n]) since the user just saw the changelog and presumably
    // wants the new version.
    if no_prompt {
        return;
    }
    #[cfg(unix)]
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };
    #[cfg(not(unix))]
    let is_tty = true;
    if !is_tty {
        return;
    }

    eprint!("Update now? [Y/n] ");
    use std::io::Write as _;
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return;
    }
    let ans = line.trim();
    if ans.eq_ignore_ascii_case("n") || ans.eq_ignore_ascii_case("no") {
        eprintln!("\x1b[2m    Skipped. You can run `portwave --update` later.\x1b[0m");
        eprintln!();
        return;
    }

    eprintln!();
    eprintln!("Updating now…");
    match run_update().await {
        Ok(()) => {
            eprintln!();
            eprintln!("\x1b[32mUpdated. Re-run your command to use the new version.\x1b[0m");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("\x1b[33m[!] update failed: {} — continuing with current version.\x1b[0m", e);
        }
    }
}

async fn run_update() -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    println!("portwave: checking GitHub releases for assassin-marcos/portwave…");
    let result = tokio::task::spawn_blocking(|| {
        self_update::backends::github::Update::configure()
            .repo_owner(REPO_OWNER)
            .repo_name(REPO_NAME)
            .bin_name("portwave")
            .show_download_progress(true)
            .show_output(true)
            .current_version(env!("CARGO_PKG_VERSION"))
            .build()?
            .update()
    })
    .await??;

    match result {
        self_update::Status::UpToDate(v) => println!("Already up to date: {}", v),
        self_update::Status::Updated(v) => {
            println!("Updated to: {}", v);
            // Refresh on-disk ports files so users whose config points at a
            // share/<...>/portwave-top-ports.txt still get the new list.
            refresh_bundled_ports_files();
            // Refresh the version-check cache so the next startup banner
            // doesn't re-prompt about the version we just installed.
            if let Some(p) = update_cache_path() {
                if let Some(parent) = p.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::write(&p, &v);
            }
            // Fetch + print What's-new changelog (nuclei-style) so the user
            // sees what they just got. Best-effort: failures are silent
            // because the update itself already succeeded and we don't want
            // to muddy the exit code on a flaky network.
            let notes_res = tokio::time::timeout(
                Duration::from_secs(4),
                tokio::task::spawn_blocking({
                    let cur = current.clone();
                    move || fetch_release_notes_since(&cur)
                }),
            )
            .await;
            if let Ok(Ok(Ok(notes))) = notes_res {
                if !notes.is_empty() {
                    print_post_update_changelog(&current, &v, &notes);
                }
            }
        }
    }
    Ok(())
}

// Prints a "What's new" block after a successful `portwave --update`,
// dumping GitHub release notes for every version between the user's old
// install and the one they just landed on. Mirrors the nuclei UX where
// the tool tells you what you got instead of leaving you to go read the
// release page manually.
fn print_post_update_changelog(from: &str, to: &str, notes: &[(String, String)]) {
    println!();
    println!(
        "\x1b[1m─────── What's new in portwave v{}  (was v{}) ───────\x1b[0m",
        to, from
    );
    // Cap at 5 intermediate versions × 10 lines each so updates that skip
    // many releases don't flood the terminal. Skips GitHub's auto-generated
    // section headers ("## What's Changed") and the boilerplate compare link.
    for (ver, body) in notes.iter().take(5) {
        println!();
        println!("  \x1b[1;36mv{}\x1b[0m", ver);
        let mut printed = 0;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with("## ")
                || line.starts_with("**Full Changelog**")
            {
                continue;
            }
            if printed >= 10 {
                println!("    …");
                break;
            }
            let trimmed: String = line.chars().take(120).collect();
            println!("    {}", trimmed);
            printed += 1;
        }
        if printed == 0 {
            println!("    (no release notes attached)");
        }
    }
    println!();
    println!("\x1b[2m    Full history: https://github.com/assassin-marcos/portwave/releases\x1b[0m");
    println!();
}

async fn run_check_update() -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    // Fetch release + tag concurrently (both are sync; each runs in its own
    // blocking task). Tags appear immediately on `git push --tags`; releases
    // only after CI uploads assets, so they can disagree for a few minutes.
    let (release, tag) = tokio::join!(
        tokio::task::spawn_blocking(fetch_latest_version),
        tokio::task::spawn_blocking(fetch_latest_tag),
    );
    let release = release.ok().and_then(|r| r.ok()).flatten();
    let tag = tag.ok().and_then(|r| r.ok()).flatten();

    let newest = match (&release, &tag) {
        (Some(r), Some(t)) => {
            if version_is_newer(t, r) {
                Some(t.clone())
            } else {
                Some(r.clone())
            }
        }
        (Some(v), None) | (None, Some(v)) => Some(v.clone()),
        (None, None) => None,
    };

    match newest {
        Some(v) if version_is_newer(&v, current) => {
            println!("Update available: {} → {}", current, v);
            // If the newest is only available as a tag (release not yet
            // built), tell the user exactly what's going on.
            let release_ok = release
                .as_ref()
                .map(|r| !version_is_newer(&v, r))
                .unwrap_or(false);
            if release_ok {
                println!("Run: portwave --update");
            } else {
                println!(
                    "(tag v{} is pushed but CI is still building release binaries;",
                    v
                );
                println!(" re-run `portwave --update` in a few minutes.)");
            }
        }
        Some(v) => {
            println!("Up to date (current: {}, latest: {}).", current, v);
            // Extra diagnostic if release < tag but tag == current.
            if let (Some(r), Some(t)) = (&release, &tag) {
                if r != t {
                    println!(
                        "(note: latest tag is {}, latest release is {} — CI lag between them is normal)",
                        t, r
                    );
                }
            }
        }
        None => println!("No releases found yet (current: {}).", current),
    }
    Ok(())
}

// ────────────────────────── Webhook ──────────────────────────

fn post_webhook(url: &str, payload: &serde_json::Value) -> anyhow::Result<()> {
    let body = serde_json::to_vec(payload)?;
    ureq::post(url)
        .set("User-Agent", concat!("portwave/", env!("CARGO_PKG_VERSION")))
        .set("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(8))
        .send_bytes(&body)?;
    Ok(())
}

// ────────────────────────── UDP discovery ──────────────────────────

// (port, probe-bytes, protocol-label). Probes chosen to elicit a response
// from a default configuration; hand-crafted minimal byte sequences so no
// extra deps are needed.
const UDP_PROBES: &[(u16, &[u8], &str)] = &[
    // DNS version.bind CHAOS TXT
    (53, b"\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03", "dns"),
    // NTPv4 client request (mode=3, version=4)
    (123, b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "ntp"),
    // SNMP v1 GetRequest community=public, OID=sysDescr.0
    (161, b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x71\x92\xee\x13\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", "snmp"),
    // SSDP M-SEARCH *
    (1900, b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\nMX: 1\r\n\r\n", "ssdp"),
    // mDNS query for _services._dns-sd._udp.local
    (5353, b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01", "mdns"),
    // NetBIOS name service query
    (137, b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01", "netbios"),
    // MSSQL browser (0x02 query)
    (1434, b"\x02", "mssql-browser"),
    // Sun RPC portmap null call
    (111, b"\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "portmap"),
    // TFTP read request for a probe filename
    (69, b"\x00\x01netascii\x00", "tftp"),
    // IKE v1 header (main mode init)
    (500, b"\x00\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00", "ike"),
    // OpenVPN hard-reset client v2
    (1194, b"\x38\x00\x00\x00\x00\x00\x00\x00\x00", "openvpn"),
    // memcached version\r\n
    (11211, b"version\r\n", "memcached"),
    // WireGuard handshake init probe (minimal)
    (51820, b"\x01\x00\x00\x00", "wireguard"),
    // NFS ping (rpc null)
    (2049, b"\x80\x00\x00\x28\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "nfs"),
    // QUIC / HTTP3 Initial (minimal — enough to elicit a Version Negotiation)
    (443, b"\xc0\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "quic"),
];

async fn udp_probe_one(sa: SocketAddr, probe: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let bind_addr = match sa {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr).await.ok()?;
    socket.connect(sa).await.ok()?;
    socket.send(probe).await.ok()?;
    let mut buf = [0u8; 2048];
    match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(buf[..n].to_vec()),
        _ => None,
    }
}

async fn run_udp_phase(
    nets: &[IpNetwork],
    exclude: &[IpNetwork],
    timeout: Duration,
    max_concurrency: usize,
) -> Vec<OpenPort> {
    let mut all_ips = Vec::new();
    for net in nets {
        for ip in net.iter() {
            if !is_usable_ipv4_host(net, ip) {
                continue;
            }
            if exclude.iter().any(|e| e.contains(ip)) {
                continue;
            }
            all_ips.push(ip);
        }
    }
    let sem = Arc::new(Semaphore::new(max_concurrency));
    let mut set: JoinSet<Option<OpenPort>> = JoinSet::new();
    // Labeled break so a closed semaphore (abnormal shutdown) exits both
    // the port-probe inner loop and the IP-iteration outer loop without
    // panicking. Mirrors the Phase B graceful-acquire pattern (v0.8.0).
    'outer: for ip in all_ips {
        for &(port, probe, label) in UDP_PROBES {
            let Ok(p) = sem.clone().acquire_owned().await else { break 'outer; };
            set.spawn(async move {
                let sa = SocketAddr::new(ip, port);
                let reply = udp_probe_one(sa, probe, timeout).await?;
                drop(p);
                let banner: String = reply
                    .iter()
                    .take(80)
                    .flat_map(|b| std::iter::once(if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' }))
                    .collect();
                Some(OpenPort {
                    ip: ip.to_string(),
                    port,
                    rtt_ms: 0,
                    tls: false,
                    protocol: Some(format!("udp/{}", label)),
                    banner: Some(banner),
                    cdn: None,
                    source_label: None,
                    title: None,
                    final_url: None,
                    redirect_chain: None,
                    content_length: None,
                })
            });
        }
    }
    let mut out = Vec::new();
    while let Some(Ok(Some(op))) = set.join_next().await {
        out.push(op);
    }
    out
}

// ────────────────────────── Dynamic CDN refresh ──────────────────────────

fn cdn_cache_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|a| PathBuf::from(a).join("portwave").join("cdn-ranges.txt"))
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".cache/portwave/cdn-ranges.txt"))
    }
}

// ────────────────────────── Self-uninstall ──────────────────────────

// Collect every filesystem target that belongs to a portwave install on
// this machine: binaries + share/ports dir + cache file + optional config
// directory. Used by `--uninstall`. Mirrors the bash uninstall.sh layout
// one-for-one.
fn uninstall_collect_targets() -> (Vec<PathBuf>, Vec<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
    #[cfg(unix)]
    let home = std::env::var("HOME").ok();
    #[cfg(not(unix))]
    let home: Option<String> = None;
    let _ = &home; // suppress unused warning on Windows targets

    // 1. Binaries
    let mut bin_candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = find_binary("portwave") {
        bin_candidates.push(p.clone());
        if let Ok(canon) = p.canonicalize() {
            if canon != p {
                bin_candidates.push(canon);
            }
        }
    }
    #[cfg(unix)]
    {
        if let Some(h) = &home {
            let h = PathBuf::from(h);
            bin_candidates.push(h.join(".local/bin/portwave"));
            bin_candidates.push(h.join("bin/portwave"));
            bin_candidates.push(h.join(".cargo/bin/portwave"));
        }
        bin_candidates.push(PathBuf::from("/usr/local/bin/portwave"));
        bin_candidates.push(PathBuf::from("/opt/homebrew/bin/portwave"));
        bin_candidates.push(PathBuf::from("/opt/local/bin/portwave"));
    }
    #[cfg(windows)]
    {
        if let Ok(up) = std::env::var("USERPROFILE") {
            let up = PathBuf::from(up);
            bin_candidates.push(up.join(".local\\bin\\portwave.exe"));
            bin_candidates.push(up.join("bin\\portwave.exe"));
            bin_candidates.push(up.join(".cargo\\bin\\portwave.exe"));
        }
        if let Ok(la) = std::env::var("LOCALAPPDATA") {
            bin_candidates.push(PathBuf::from(la).join("Programs\\portwave\\portwave.exe"));
        }
        if let Ok(pf) = std::env::var("ProgramFiles") {
            bin_candidates.push(PathBuf::from(pf).join("portwave\\portwave.exe"));
        }
    }

    // Dedupe existing files only.
    let mut bins: Vec<PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for c in bin_candidates {
        let canon = c.canonicalize().unwrap_or_else(|_| c.clone());
        if c.is_file() && seen.insert(canon) {
            bins.push(c);
        }
    }

    // 2. Share directories
    let mut shares: Vec<PathBuf> = Vec::new();
    #[cfg(unix)]
    {
        if let Some(h) = &home {
            shares.push(PathBuf::from(h).join(".local/share/portwave"));
        }
        shares.push(PathBuf::from("/usr/local/share/portwave"));
        shares.push(PathBuf::from("/opt/homebrew/share/portwave"));
        shares.push(PathBuf::from("/opt/local/share/portwave"));
    }
    #[cfg(windows)]
    {
        if let Ok(up) = std::env::var("USERPROFILE") {
            shares.push(PathBuf::from(up).join(".local\\share\\portwave"));
        }
        if let Ok(la) = std::env::var("LOCALAPPDATA") {
            shares.push(PathBuf::from(la).join("portwave"));
        }
        if let Ok(pf) = std::env::var("ProgramFiles") {
            shares.push(PathBuf::from(pf).join("share\\portwave"));
        }
    }
    let shares: Vec<PathBuf> = shares.into_iter().filter(|d| d.is_dir()).collect();

    // 3. Config directory (Unix: ~/.config/portwave; Windows: %APPDATA%/portwave)
    let cfg = default_config_path().and_then(|p| p.parent().map(|d| d.to_path_buf())).filter(|d| d.is_dir());

    // 4. Cache directory
    let cache = update_cache_path().and_then(|p| p.parent().map(|d| d.to_path_buf())).filter(|d| d.is_dir());

    (bins, shares, cfg, cache)
}

async fn run_uninstall(skip_prompt: bool) -> anyhow::Result<()> {
    let (bins, shares, cfg, cache) = uninstall_collect_targets();

    println!("portwave uninstaller");
    println!();

    if bins.is_empty() && shares.is_empty() && cfg.is_none() && cache.is_none() {
        eprintln!("[!] No portwave installation found on this system.");
        eprintln!("    Nothing to remove. If portwave isn't installed yet, run install.sh (or install.ps1 on Windows) first.");
        return Ok(());
    }

    // Show the plan
    println!("About to REMOVE:");
    for b in &bins {
        println!("  binary  : {}", b.display());
    }
    for s in &shares {
        println!("  share   : {}", s.display());
    }
    if let Some(c) = &cfg {
        println!("  config  : {}  (will ask per directory)", c.display());
    }
    if let Some(c) = &cache {
        println!("  cache   : {}", c.display());
    }
    println!();

    // Confirmation
    if !skip_prompt {
        #[cfg(unix)]
        let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };
        #[cfg(not(unix))]
        let is_tty = true;

        if !is_tty {
            eprintln!("[!] stdin is not a TTY and --yes was not passed — aborting to be safe.");
            eprintln!("    Re-run interactively or add --yes to proceed.");
            return Ok(());
        }

        eprint!("Proceed? [y/N] ");
        use std::io::Write as _;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !line.trim().eq_ignore_ascii_case("y") && !line.trim().eq_ignore_ascii_case("yes") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Execute
    let mut removed_bins = 0usize;
    for b in &bins {
        match fs::remove_file(b) {
            Ok(_) => {
                println!("removed {}", b.display());
                removed_bins += 1;
            }
            Err(e) => eprintln!("could not remove {}: {} (check permissions)", b.display(), e),
        }
    }
    for s in &shares {
        match fs::remove_dir_all(s) {
            Ok(_) => println!("removed {}", s.display()),
            Err(e) => eprintln!("could not remove {}: {}", s.display(), e),
        }
    }
    if let Some(c) = &cache {
        match fs::remove_dir_all(c) {
            Ok(_) => println!("removed {}", c.display()),
            Err(e) => eprintln!("could not remove {}: {}", c.display(), e),
        }
    }
    if let Some(c) = &cfg {
        if !skip_prompt {
            eprint!("Delete config directory {}? [y/N] ", c.display());
            use std::io::Write as _;
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            if line.trim().eq_ignore_ascii_case("y") || line.trim().eq_ignore_ascii_case("yes") {
                match fs::remove_dir_all(c) {
                    Ok(_) => println!("removed {}", c.display()),
                    Err(e) => eprintln!("could not remove {}: {}", c.display(), e),
                }
            } else {
                println!("kept {}", c.display());
            }
        } else {
            let _ = fs::remove_dir_all(c);
            println!("removed {}", c.display());
        }
    }

    println!();
    if removed_bins > 0 {
        println!("portwave uninstalled. ({} binary file(s) removed)", removed_bins);
    } else {
        println!("portwave uninstalled. (no binaries were removed — check permissions)");
    }

    #[cfg(windows)]
    {
        // On Windows you can't delete a running .exe. Warn if our binary is one of them.
        if let Ok(exe) = std::env::current_exe() {
            if bins.iter().any(|b| b.canonicalize().ok() == exe.canonicalize().ok()) {
                eprintln!();
                eprintln!("[!] On Windows you cannot delete a running .exe. If {} still exists,", exe.display());
                eprintln!("    close this terminal and manually remove the file, or reboot and retry.");
            }
        }
    }

    Ok(())
}

// v0.14.0 — expanded CDN provider coverage. Matches the scope of
// github.com/taythebot/cdn-ranges: 11 providers with public IP-range
// endpoints (direct fetch), 13 providers whose ranges are advertised
// only via ASN (resolved through RIPE stat using the existing
// `fetch_asn_prefixes()` helper). Total: 24 providers.
//
// Each direct provider is fetched independently; a failure for one
// doesn't abort the refresh (best-effort). The output file preserves
// the `CIDR|provider` pipe-delimited format from v0.13.x so the
// `load_cdn_ranges()` reader stays unchanged.
//
// ASN lookups hit RIPE stat (already used by the `--asn` CLI flag).
// Cost: ~20 s total for a cold refresh (24 HTTPS calls + 13 RIPE
// lookups in sequence). Users rarely run this — typically once per
// month to keep the CDN list current.

// ASN-based providers: (provider_tag, &[ASN]) — hits RIPE stat through
// fetch_asn_prefixes() for each ASN, tags every returned CIDR.
const CDN_ASN_PROVIDERS: &[(&str, &[&str])] = &[
    // Akamai CDN edge ASNs — the networks that actually serve CDN
    // content. Deliberately EXCLUDES AS63949 ("Akamai Connected Cloud",
    // the post-2022 rebrand of Linode IaaS) because those are general-
    // purpose VMs, not CDN edge — flagging a Linode-hosted target as
    // CDN-fronted would be a false positive (your scan should NOT be
    // skipped just because your app runs on Linode).
    ("akamai", &[
        "AS12222", "AS16625", "AS16702", "AS17204", "AS18680", "AS18717",
        "AS20189", "AS20940", "AS21342", "AS21357", "AS21399", "AS22207",
        "AS22452", "AS23454", "AS23455", "AS24319", "AS26008", "AS30675",
        "AS31108", "AS31109", "AS31110", "AS31377", "AS33047", "AS33905",
        "AS34164", "AS34850", "AS35204", "AS35993", "AS35994", "AS36183",
        "AS39836", "AS43639", "AS55409", "AS55770", "AS133103",
    ]),
    ("bunny",        &["AS200325"]),
    ("cdnetworks",   &["AS36408"]),
    ("ddos-guard",   &["AS57724"]),
    ("edgecast",     &["AS15133"]),
    ("edgenext",     &["AS139057", "AS149981"]),
    ("edgio",        &["AS60261"]),
    ("limelight",    &["AS22822"]),
    ("qrator",       &["AS200449"]),
    ("stackpath",    &["AS12989"]),
    ("stormwall",    &["AS59796"]),
    ("sucuri",       &["AS30148"]),
    ("x4b",          &["AS136165"]),
];

/// GET a URL with a 15s budget and return the body as a String, or an
/// error message suitable for surfacing to the user.
fn fetch_text(url: &str) -> Result<String, String> {
    match ureq::get(url)
        .set("User-Agent", concat!("portwave/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15))
        .call()
    {
        Ok(r) => r.into_string().map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// GET a URL and parse the body as JSON. Errors bubble up with context.
fn fetch_json(url: &str) -> Result<serde_json::Value, String> {
    match ureq::get(url)
        .set("User-Agent", concat!("portwave/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15))
        .call()
    {
        Ok(r) => r.into_json::<serde_json::Value>().map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Push every CIDR-looking token from `body` into `entries` under the
/// given provider tag. Used for plaintext / newline-separated feeds
/// (Cloudflare, Cachefly, ArvanCloud).
fn extract_cidrs_plain(body: &str, provider: &'static str, entries: &mut Vec<String>) -> usize {
    let mut n = 0;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.parse::<IpNetwork>().is_ok() {
            entries.push(format!("{}|{}", line, provider));
            n += 1;
        }
    }
    n
}

async fn run_refresh_cdn() -> anyhow::Result<()> {
    println!("portwave: refreshing CDN ranges from upstream (24 providers)…");
    let mut entries: Vec<String> = Vec::new();

    // ── 11 direct-URL fetchers ────────────────────────────────────

    // Cloudflare v4 + v6
    for (url, tag) in &[
        ("https://www.cloudflare.com/ips-v4", "cloudflare"),
        ("https://www.cloudflare.com/ips-v6", "cloudflare"),
    ] {
        match fetch_text(url) {
            Ok(body) => {
                let n = extract_cidrs_plain(&body, tag, &mut entries);
                println!("  cloudflare ({}): {} CIDRs", url.rsplit('/').next().unwrap_or(""), n);
            }
            Err(e) => eprintln!("  cloudflare fetch failed ({}): {}", url, e),
        }
    }

    // Fastly — JSON { "addresses": [...], "ipv6_addresses": [...] }
    match fetch_json("https://api.fastly.com/public-ip-list") {
        Ok(j) => {
            let mut n = 0;
            for key in &["addresses", "ipv6_addresses"] {
                if let Some(arr) = j.get(*key).and_then(|a| a.as_array()) {
                    for v in arr {
                        if let Some(cidr) = v.as_str() {
                            if cidr.parse::<IpNetwork>().is_ok() {
                                entries.push(format!("{}|fastly", cidr));
                                n += 1;
                            }
                        }
                    }
                }
            }
            println!("  fastly: {} CIDRs", n);
        }
        Err(e) => eprintln!("  fastly fetch failed: {}", e),
    }

    // CloudFront — AWS IP ranges JSON, filter service = CLOUDFRONT
    match fetch_json("https://ip-ranges.amazonaws.com/ip-ranges.json") {
        Ok(j) => {
            let mut n = 0;
            for key in &[("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")] {
                if let Some(arr) = j.get(key.0).and_then(|a| a.as_array()) {
                    for v in arr {
                        if v.get("service").and_then(|s| s.as_str()) == Some("CLOUDFRONT") {
                            if let Some(cidr) = v.get(key.1).and_then(|p| p.as_str()) {
                                if cidr.parse::<IpNetwork>().is_ok() {
                                    entries.push(format!("{}|cloudfront", cidr));
                                    n += 1;
                                }
                            }
                        }
                    }
                }
            }
            println!("  cloudfront: {} CIDRs", n);
        }
        Err(e) => eprintln!("  cloudfront fetch failed: {}", e),
    }

    // Gcore — JSON { "addresses": [...], "addresses_v6": [...] }
    match fetch_json("https://api.gcore.com/cdn/public-ip-list") {
        Ok(j) => {
            let mut n = 0;
            for key in &["addresses", "addresses_v6"] {
                if let Some(arr) = j.get(*key).and_then(|a| a.as_array()) {
                    for v in arr {
                        if let Some(cidr) = v.as_str() {
                            if cidr.parse::<IpNetwork>().is_ok() {
                                entries.push(format!("{}|gcore", cidr));
                                n += 1;
                            }
                        }
                    }
                }
            }
            println!("  gcore: {} CIDRs", n);
        }
        Err(e) => eprintln!("  gcore fetch failed: {}", e),
    }

    // CDN77 — JSON list of objects { "prefix": "1.2.3.0/24", ... }
    match fetch_json("https://prefixlists.tools.cdn77.com/public_lmax_prefixes.json") {
        Ok(j) => {
            let mut n = 0;
            let arr = j.as_array().or_else(|| j.get("prefixes").and_then(|v| v.as_array()));
            if let Some(arr) = arr {
                for v in arr {
                    let cidr = v.as_str()
                        .or_else(|| v.get("prefix").and_then(|p| p.as_str()))
                        .or_else(|| v.get("cidr").and_then(|p| p.as_str()));
                    if let Some(cidr) = cidr {
                        if cidr.parse::<IpNetwork>().is_ok() {
                            entries.push(format!("{}|cdn77", cidr));
                            n += 1;
                        }
                    }
                }
            }
            println!("  cdn77: {} CIDRs", n);
        }
        Err(e) => eprintln!("  cdn77 fetch failed: {}", e),
    }

    // Imperva — JSON { "ipRanges": [...], "ipv6Ranges": [...] }
    match fetch_json("https://my.imperva.com/api/integration/v1/ips") {
        Ok(j) => {
            let mut n = 0;
            for key in &["ipRanges", "ipv6Ranges"] {
                if let Some(arr) = j.get(*key).and_then(|a| a.as_array()) {
                    for v in arr {
                        if let Some(cidr) = v.as_str() {
                            if cidr.parse::<IpNetwork>().is_ok() {
                                entries.push(format!("{}|imperva", cidr));
                                n += 1;
                            }
                        }
                    }
                }
            }
            println!("  imperva: {} CIDRs", n);
        }
        Err(e) => eprintln!("  imperva fetch failed: {}", e),
    }

    // Cachefly — plaintext, newline-separated
    match fetch_text("https://cachefly.cachefly.net/ips/rproxy.txt") {
        Ok(body) => {
            let n = extract_cidrs_plain(&body, "cachefly", &mut entries);
            println!("  cachefly: {} CIDRs", n);
        }
        Err(e) => eprintln!("  cachefly fetch failed: {}", e),
    }

    // ArvanCloud — plaintext
    match fetch_text("https://www.arvancloud.ir/en/ips.txt") {
        Ok(body) => {
            let n = extract_cidrs_plain(&body, "arvancloud", &mut entries);
            println!("  arvancloud: {} CIDRs", n);
        }
        Err(e) => eprintln!("  arvancloud fetch failed: {}", e),
    }

    // Medianova — JSON { "data": [ {"cidr": "..."}, ... ] } or similar
    match fetch_json("https://cloud.medianova.com/api/v1/ip/blocks-list") {
        Ok(j) => {
            let mut n = 0;
            let arr = j.as_array()
                .or_else(|| j.get("data").and_then(|v| v.as_array()));
            if let Some(arr) = arr {
                for v in arr {
                    let cidr = v.as_str()
                        .or_else(|| v.get("cidr").and_then(|p| p.as_str()))
                        .or_else(|| v.get("prefix").and_then(|p| p.as_str()));
                    if let Some(cidr) = cidr {
                        if cidr.parse::<IpNetwork>().is_ok() {
                            entries.push(format!("{}|medianova", cidr));
                            n += 1;
                        }
                    }
                }
            }
            println!("  medianova: {} CIDRs", n);
        }
        Err(e) => eprintln!("  medianova fetch failed: {}", e),
    }

    // F5 — HTML doc; best-effort regex-pluck of CIDR-looking tokens.
    // If the endpoint format changes, we just lose F5 coverage that run.
    match fetch_text("https://docs.cloud.f5.com/docs-v2/platform/reference/network-cloud-ref") {
        Ok(body) => {
            let mut n = 0;
            // Simple CIDR-pattern extraction; accepts both v4 and v6 forms.
            for tok in body.split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != ':' && c != '/') {
                if tok.contains('/') && (tok.contains('.') || tok.contains(':')) {
                    if tok.parse::<IpNetwork>().is_ok() {
                        entries.push(format!("{}|f5", tok));
                        n += 1;
                    }
                }
            }
            println!("  f5: {} CIDRs", n);
        }
        Err(e) => eprintln!("  f5 fetch failed: {}", e),
    }

    // ── 13 ASN-based providers via RIPE stat ──────────────────────
    for (tag, asns) in CDN_ASN_PROVIDERS {
        let mut total = 0usize;
        for asn in *asns {
            let asn = *asn;
            let res = tokio::task::spawn_blocking({
                let asn = asn.to_string();
                move || fetch_asn_prefixes(&asn)
            })
            .await;
            match res {
                Ok(Ok(prefixes)) => {
                    for p in prefixes {
                        entries.push(format!("{}|{}", p, tag));
                        total += 1;
                    }
                }
                Ok(Err(e)) => eprintln!("  {} [{}] fetch failed: {}", tag, asn, e),
                Err(e) => eprintln!("  {} [{}] join error: {}", tag, asn, e),
            }
        }
        println!("  {}: {} CIDRs (via {} ASN{})",
            tag, total, asns.len(), if asns.len() == 1 { "" } else { "s" });
    }

    // Dedupe (an IP can be advertised by multiple ASNs / providers; keep
    // the first tag seen so the most-authoritative provider label wins).
    entries.sort();
    entries.dedup();

    let path = cdn_cache_path()
        .ok_or_else(|| anyhow::anyhow!("could not resolve cache directory"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = entries.join("\n") + "\n";
    fs::write(&path, &content)?;
    println!("\nWrote {} unique entries across 24 providers to {}", entries.len(), path.display());
    println!("portwave will use this file on next scan. Delete it to revert to embedded.");
    Ok(())
}

// ────────────────────────── Main ──────────────────────────

// v0.14.9 — the httpx subprocess was removed (portwave does its own native
// HTTP(S) enrichment now). Old `--httpx-*` / `--no-httpx` flags would silently
// be rejected by clap with a generic "unexpected argument" message. Scan this
// list BEFORE clap parses and fail with a specific migration hint so scripts
// fail loudly, not mysteriously.
fn check_deprecated_flags() {
    let argv: Vec<String> = std::env::args().collect();
    const RETIRED: &[(&str, &str)] = &[
        (
            "--no-httpx",
            "httpx subprocess is gone in v0.14.9 — portwave does HTTP(S) enrichment natively. Drop the flag.",
        ),
        (
            "--httpx-follow-redirects",
            "renamed to --follow-redirects.",
        ),
        (
            "--httpx-threads",
            "gone — Phase-A uses --threads; HTTP probe uses -C / --probe-concurrency.",
        ),
        (
            "--httpx-paths",
            "gone — pipe http_targets.txt to httpx -path \"/a,/b\" manually if you need custom paths.",
        ),
    ];
    for arg in argv.iter().skip(1) {
        // Accept both `--flag` and `--flag=value` forms.
        let stem = arg.split('=').next().unwrap_or(arg);
        for (dep, hint) in RETIRED {
            if stem == *dep {
                eprintln!("error: {} removed in v0.14.9.", dep);
                eprintln!("  hint: {}", hint);
                std::process::exit(2);
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    check_deprecated_flags();
    let mut args = Args::parse();

    // Initialize the stdout-TTY flag used by the color helpers.
    // Checked once here so per-port-print loop skips the syscall.
    init_stdout_color();

    // ASN scans typically 30x to portals / WAFs; following redirects gives
    // meaningful status + title instead of "[302] [Moved]". Only auto-enable
    // if the user didn't already pass it.
    if args.asn.is_some() && !args.follow_redirects {
        args.follow_redirects = true;
        if !args.quiet {
            eprintln!("[asn] auto-enabled --follow-redirects");
        }
    }

    // ────────────── Early input validation (fail fast, helpful messages) ──────────────
    // Check every new-flag value for validity *before* we start building
    // scan state or making network calls. Each message names the bad flag
    // and shows an example of the expected format so the user doesn't
    // have to dig through --help.
    if args.ipv4_only && args.ipv6_only {
        eprintln!("error: --ipv4-only and --ipv6-only are mutually exclusive — pick one.");
        std::process::exit(2);
    }
    if let Some(pps) = args.max_pps {
        if pps == 0 {
            eprintln!("error: --max-pps must be > 0 (got {}). Use --quiet to disable scanning noise instead.", pps);
            std::process::exit(2);
        }
    }
    if let Some(n) = args.top_ports {
        if n == 0 {
            eprintln!("error: --top-ports must be > 0 (got {}).\n  hint: try --top-ports 100 or --top-ports 1000", n);
            std::process::exit(2);
        }
    }
    let scan_time_budget: Option<Duration> = match args.max_scan_time.as_deref() {
        Some(s) => match parse_duration_human(s) {
            Ok(d) => Some(d),
            Err(e) => {
                eprintln!("error: --max-scan-time {}", e);
                std::process::exit(2);
            }
        },
        None => None,
    };
    // ASN format: AS followed by 1-10 digits (or just digits). Reject obviously
    // malformed tokens before hitting RIPE stat with a bogus URL.
    if let Some(ref list) = args.asn {
        for tok in list.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let digits = tok.trim_start_matches(|c: char| c == 'A' || c == 'S' || c == 'a' || c == 's');
            if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) || digits.len() > 10 {
                eprintln!(
                    "error: --asn {:?} is not a valid ASN.\n  hint: expected format \"AS13335\" or \"AS13335,AS15169\" (1-10 digits after optional AS prefix)",
                    tok
                );
                std::process::exit(2);
            }
        }
    }

    // Banner art — first thing on screen (but skip when piped or quieted).
    let show_art = !args.quiet && !args.no_art && atty_like_stderr();
    if show_art {
        // Refresh the update cache just before the banner renders so the
        // `(outdated)` / `(latest)` tag reflects GitHub's current state,
        // not a cached value from the last scan hours ago. Budgeted at
        // 1 s with a 5-min cache-hit fast path — silent on failure.
        if !args.no_update_check {
            refresh_update_cache_best_effort().await;
        }
        print_banner();
    }

    // Update flows short-circuit early — they don't need positional args.
    if args.update {
        return run_update().await;
    }
    if args.check_update {
        return run_check_update().await;
    }
    if args.refresh_cdn {
        return run_refresh_cdn().await;
    }
    if args.uninstall {
        return run_uninstall(args.yes).await;
    }

    // Positional args required for a real scan, unless --input-file / --asn supplies them.
    let folder_name = match &args.folder_name {
        Some(f) => f.clone(),
        None => {
            eprintln!("error: <FOLDER_NAME> is required for a scan.");
            eprintln!("usage:");
            eprintln!("  portwave <FOLDER_NAME> <CIDR_INPUT> [OPTIONS]");
            eprintln!("  portwave <FOLDER_NAME> -d example.com,sub.example.com");
            eprintln!("  portwave <FOLDER_NAME> -i targets.txt");
            eprintln!("  portwave <FOLDER_NAME> -a AS13335");
            eprintln!("  portwave -u | -c | -X | --refresh-cdn");
            eprintln!();
            eprintln!("examples:");
            eprintln!("  portwave bb 203.0.113.0/24                     # CIDR");
            eprintln!("  portwave bb -d adityasec.com                   # single domain");
            eprintln!("  portwave bb -i subdomains.txt --no-enrich --no-nuclei");
            eprintln!("  portwave bb -a AS13335 -e 203.0.113.64/26      # ASN + exclude");
            eprintln!();
            eprintln!("see all flags with: portwave -h");
            std::process::exit(2);
        }
    };

    raise_fd_limit();
    let cfg = load_config();

    // Non-blocking startup update check (cached 24 h, 3 s timeout).
    maybe_show_update_banner(
        args.no_update_check || args.quiet,
        args.no_update_prompt || args.quiet,
    ).await;

    let output_root = resolve_path(
        args.output_dir.as_deref(),
        "PORTWAVE_OUTPUT_DIR",
        &cfg,
        "PORTWAVE_OUTPUT_DIR",
        "./scans",
    );
    let base = PathBuf::from(&output_root);
    let out_dir = base.join(&folder_name);
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("CRITICAL: cannot create {:?}: {}", out_dir, e);
        return Ok(());
    }

    // v0.14.4 — `targets.txt` (bare ip:port) removed. Any consumer can
    // derive ip:port from open_ports.jsonl via
    //   jq -r '"\(.ip):\(.port)"' open_ports.jsonl
    // `nuclei_targets.txt` renamed to `http_targets.txt` since httpx
    // reads it too (has since v0.13.3); the old name was historical.
    let http_targets_path = out_dir.join("http_targets.txt");
    let jsonl_path = out_dir.join("open_ports.jsonl");
    let summary_path = out_dir.join("scan_summary.json");
    let diff_path = out_dir.join("scan_diff.json");
    let enrich_out = out_dir.join("enrichment_results.txt");
    let nuclei_out = out_dir.join("nuclei_results.txt");
    // v0.14.2 — per-concern domain artefacts, written only when a scan
    // actually had domain input. Each is bare-per-line for trivial
    // piping into jq / grep / another tool — the classic Unix shape.
    let domains_json_path = out_dir.join("domains.json");      // full structured dump
    let origin_domains_path = out_dir.join("origin_domains.txt"); // resolved, not-CDN, scanned
    let cdn_skipped_path = out_dir.join("cdn_skipped.txt");    // CDN-fronted, skipped
    let dns_failed_path = out_dir.join("dns_failed.txt");      // NXDOMAIN / timeout / no records

    // Always capture prior opens (independent of --no-resume) so scan_diff
    // can compare this run against the last one.
    let mut prior_set: FxHashSet<SocketAddr> = FxHashSet::default();
    if jsonl_path.exists() {
        if let Ok(f) = fs::File::open(&jsonl_path) {
            for line in BufReader::new(f).lines().flatten() {
                if let Ok(op) = serde_json::from_str::<OpenPort>(&line) {
                    if let Ok(ip) = op.ip.parse::<IpAddr>() {
                        prior_set.insert(SocketAddr::new(ip, op.port));
                    }
                }
            }
        }
    }

    // Resume — read existing jsonl into skip set.
    let mut skip_set: FxHashSet<SocketAddr> = FxHashSet::default();
    let mut preserved: Vec<OpenPort> = Vec::new();
    if !args.no_resume && jsonl_path.exists() {
        if let Ok(f) = fs::File::open(&jsonl_path) {
            for line in BufReader::new(f).lines().flatten() {
                if let Ok(op) = serde_json::from_str::<OpenPort>(&line) {
                    if let Ok(ip) = op.ip.parse::<IpAddr>() {
                        skip_set.insert(SocketAddr::new(ip, op.port));
                        preserved.push(op);
                    }
                }
            }
            println!("Resume: {} prior open ports loaded; will skip re-probing.", skip_set.len());
        }
    } else {
        // Fresh run: clear derived files.
        let _ = fs::remove_file(&jsonl_path);
    }
    let _ = fs::remove_file(&http_targets_path);
    // v0.14.4 — stale targets.txt from pre-0.14.4 scans gets removed so
    // the folder stays clean after the file was dropped.
    let _ = fs::remove_file(out_dir.join("targets.txt"));
    // Same cleanup for the old nuclei_targets.txt name (renamed to
    // http_targets.txt in v0.14.4).
    let _ = fs::remove_file(out_dir.join("nuclei_targets.txt"));

    // Default port source priority:
    //   1. CLI --port-file
    //   2. $PORTWAVE_PORTS env
    //   3. PORTWAVE_PORTS in config
    //   4. EMBEDDED list (compiled into the binary)
    // The on-disk find_bundled_ports() lookup is no longer the default —
    // it's only meaningful when the user explicitly sets PORTWAVE_PORTS to
    // such a path. This ensures `--update` ships the latest list automatically.
    // Port source precedence:
    //   1. --ports "22,80,443,8000-9000"   (inline range syntax)
    //   2. --port-file / $PORTWAVE_PORTS / config PORTWAVE_PORTS
    //   3. Embedded 1400+ port list baked into the binary
    let mut ports = if let Some(spec) = &args.ports {
        println!("Loading ports from: --ports {}", spec);
        parse_port_list(spec)
    } else {
        let default_ports = String::from(EMBEDDED_SENTINEL);
        let port_path = resolve_path(
            args.port_file.as_deref(),
            "PORTWAVE_PORTS",
            &cfg,
            "PORTWAVE_PORTS",
            &default_ports,
        );
        println!("Loading ports from: {}", port_path);
        load_ports(&port_path)
    };
    if ports.is_empty() {
        eprintln!("error: port list empty after parsing.\n  hint: --ports expects a comma-separated list like \"22,80,443,8000-9000\"");
        std::process::exit(2);
    }
    // `--top-ports N`: nmap-compatible shorthand. Keep only the first N
    // ports from the loaded list. Applied *after* parsing so it composes
    // cleanly with --ports / --port-file (user can still hand-pick a list
    // and then cap it). The bundled list is already sorted by hit-frequency
    // so "top 100" genuinely means the 100 most-likely-open ports.
    if let Some(n) = args.top_ports {
        if n < ports.len() {
            ports.truncate(n);
            println!("--top-ports {}: using the first {} ports from the loaded list.", n, n);
        }
    }

    // Target sources: positional <CIDR_INPUT>, --input-file, --asn, and
    // (new in v0.14.0) --domain. Every token gets classified by
    // domain::classify_input_line so a single --input-file can mix IPs,
    // CIDRs, IP ranges, and domain names. Domains are collected into a
    // separate Vec and resolved in parallel after all sources are loaded.
    let mut nets: Vec<IpNetwork> = Vec::new();
    let mut domains: Vec<String> = Vec::new();
    let mut invalid_lines: Vec<(String, &'static str)> = Vec::new();
    let take_token = |tok: &str,
                      nets: &mut Vec<IpNetwork>,
                      domains: &mut Vec<String>,
                      invalid_lines: &mut Vec<(String, &'static str)>| {
        let tok = tok.trim();
        if tok.is_empty() {
            return;
        }
        match domain::classify_input_line(tok) {
            domain::InputKind::Ipv4(v) => {
                if let Ok(n) = IpNetwork::new(IpAddr::V4(v), 32) {
                    nets.push(n);
                }
            }
            domain::InputKind::Ipv6(v) => {
                if let Ok(n) = IpNetwork::new(IpAddr::V6(v), 128) {
                    nets.push(n);
                }
            }
            domain::InputKind::Cidr(n) => nets.push(n),
            domain::InputKind::Ipv4Range(a, b) => {
                nets.extend(ipv4_range_to_cidrs(u32::from(a), u32::from(b)));
            }
            domain::InputKind::Domain(d) => domains.push(d),
            domain::InputKind::Invalid { raw, reason } => {
                invalid_lines.push((raw, reason));
            }
        }
    };
    if let Some(raw) = &args.cidr_input {
        for tok in raw.split(|c: char| c == ',' || c.is_whitespace()) {
            take_token(tok, &mut nets, &mut domains, &mut invalid_lines);
        }
    }
    if let Some(path) = &args.input_file {
        // v0.14.4 — support `-` as stdin, Unix-tool convention.
        // Enables `subfinder -d target.com -silent | portwave bb -i -`
        // without a temp file in the middle.
        let from_stdin = path == "-";
        let content_result: std::io::Result<String> = if from_stdin {
            use std::io::Read as _;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf).map(|_| buf)
        } else {
            fs::read_to_string(path)
        };
        match content_result {
            Ok(content) => {
                let mut file_tokens = 0usize;
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    for tok in line.split(|c: char| c == ',' || c.is_whitespace()) {
                        if !tok.trim().is_empty() {
                            take_token(tok, &mut nets, &mut domains, &mut invalid_lines);
                            file_tokens += 1;
                        }
                    }
                }
                // v0.14.5: help the user when `-i -` reads an empty stream.
                // Most common cause: upstream producer (subfinder, etc.)
                // emitted nothing, or the user typed `portwave bb -i -` with
                // no pipe and then hit Ctrl+D. Surface this explicitly so the
                // eventual "No valid targets" later doesn't look like a bug.
                if file_tokens == 0 && from_stdin {
                    eprintln!(
                        "[!] --input-file - received 0 targets on stdin. \
                         Did the upstream command produce output? \
                         Example: subfinder -d example.com -silent | portwave bb -i -"
                    );
                } else {
                    println!("Loaded {} entries from {}", file_tokens, path);
                }
            }
            Err(e) => eprintln!("Failed to read --input-file {}: {}", path, e),
        }
    }
    if let Some(list) = &args.domain {
        for tok in list.split(|c: char| c == ',' || c.is_whitespace()) {
            take_token(tok, &mut nets, &mut domains, &mut invalid_lines);
        }
    }
    if let Some(list) = &args.asn {
        for a in list.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            print!("Looking up {} prefixes via RIPE stat… ", a);
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
            match tokio::task::spawn_blocking({
                let a = a.to_string();
                move || fetch_asn_prefixes(&a)
            })
            .await
            {
                Ok(Ok(v)) => {
                    println!("{} prefixes.", v.len());
                    nets.extend(v);
                }
                Ok(Err(e)) => println!("failed: {}", e),
                Err(e) => println!("join error: {}", e),
            }
        }
    }

    // Report invalid lines once, compactly.
    if !invalid_lines.is_empty() {
        eprintln!(
            "[!] {} input line(s) were skipped — not a valid CIDR / IP / range / domain:",
            invalid_lines.len()
        );
        for (raw, reason) in invalid_lines.iter().take(5) {
            eprintln!("    {:?} — {}", raw, reason);
        }
        if invalid_lines.len() > 5 {
            eprintln!("    ({} more hidden)", invalid_lines.len() - 5);
        }
    }

    // Dedupe domains (handles overlap between --domain + --input-file).
    domains.sort();
    domains.dedup();

    // ── Domain resolution phase (v0.14.0) ─────────────────────────
    // For every domain collected above, resolve A/AAAA in parallel,
    // check each resolved IP against the CDN table, and either:
    //   - skip it with a summary line (default behavior — CDN-fronted)
    //   - add its resolved IPs to `nets` and remember the domain label
    //     in `domain_origin_map` for later output labeling
    //
    // Empty-after-skip guard: if every domain gets skipped AND there
    // were no direct IPs, exit cleanly with a clear message.
    let mut domain_origin_map: std::collections::HashMap<IpAddr, String> =
        std::collections::HashMap::new();
    if !domains.is_empty() {
        let cdn_table = load_cdn_ranges();
        let dns_timeout = Duration::from_secs(args.dns_timeout.max(1));
        println!(
            "Resolving {} domain(s) ({} concurrent, {}s timeout)…",
            domains.len(),
            args.dns_concurrency,
            args.dns_timeout
        );
        // v0.14.5: Ctrl+C during DNS would otherwise block on the resolver
        // until every in-flight lookup hit its `dns_timeout` — up to 3s
        // per stalled query even on small domain lists, worse on huge
        // bug-bounty scopes (5000 subdomains × 3s = "why isn't Ctrl+C
        // working?"). Race the resolution future against ctrl_c and
        // exit cleanly if the user interrupts.
        let results = tokio::select! {
            r = domain::resolve_many(
                &domains,
                args.dns_concurrency.max(1),
                dns_timeout,
                &cdn_table,
            ) => r,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n[!] Interrupted during DNS resolution — exiting.");
                return Ok(());
            }
        };

        // Collect (domain → outcome) triples so we can print a per-domain
        // list, not just aggregate counts. Users triaging a big
        // bug-bounty scope want to see exactly which subdomains got
        // dropped and why.
        let mut origin_domains = 0usize;
        let mut cdn_skipped: Vec<(String, &'static str)> = Vec::new();
        let mut error_list: Vec<(String, String)> = Vec::new();
        let breakdown = domain::cdn_breakdown(&results);

        for r in &results {
            if let Some(err) = &r.error {
                error_list.push((r.domain.clone(), err.clone()));
                continue;
            }
            if r.ips.is_empty() {
                error_list.push((
                    r.domain.clone(),
                    "no usable A/AAAA records".to_string(),
                ));
                continue;
            }
            if let Some(tag) = r.cdn {
                if !args.allow_cdn {
                    cdn_skipped.push((r.domain.clone(), tag));
                    continue;
                }
            }
            origin_domains += 1;
            for ip in &r.ips {
                let prefix: u8 = if ip.is_ipv4() { 32 } else { 128 };
                if let Ok(n) = IpNetwork::new(*ip, prefix) {
                    nets.push(n);
                }
                // First domain wins if multiple domains resolve to the
                // same IP (rare but possible with wildcard DNS setups).
                domain_origin_map
                    .entry(*ip)
                    .or_insert_with(|| r.domain.clone());
            }
        }

        println!(
            "  {} {} domain(s) → {} origin IP(s)",
            cfmt("1;32", "✓"),
            origin_domains,
            domain_origin_map.len()
        );

        if !cdn_skipped.is_empty() {
            let breakdown_str: Vec<String> = breakdown
                .iter()
                .map(|(tag, n)| format!("{}:{}", tag, n))
                .collect();
            println!(
                "  {} {} domain(s) → CDN edge ({}) — skipped:",
                cfmt("33", "⚠"),
                cdn_skipped.len(),
                breakdown_str.join(", ")
            );
            // Sort by provider so reports stay stable across runs.
            let mut sorted = cdn_skipped.clone();
            sorted.sort_by(|a, b| a.1.cmp(b.1).then(a.0.cmp(&b.0)));
            for (d, tag) in &sorted {
                println!(
                    "      {} {} {}",
                    cfmt("33", d),
                    cfmt("2", "→"),
                    cfmt("35", tag),
                );
            }
        }

        if !error_list.is_empty() {
            println!(
                "  {} {} domain(s) → DNS failure / no records — skipped:",
                cfmt("1;31", "✗"),
                error_list.len()
            );
            for (d, reason) in &error_list {
                println!(
                    "      {} {} {}",
                    cfmt("31", d),
                    cfmt("2", "→"),
                    cfmt("2", reason),
                );
            }
        }

        // Persist the domain-resolution outcome to disk in forms that
        // are easy to pipe into other tools (subfinder → portwave →
        // curl / ffuf / etc.). Each file is bare-per-line so `cat file
        // | other-tool` works without jq. The structured `domains.json`
        // carries the full record for programmatic use.
        {
            // origin_domains.txt — still-in-scope after CDN filter
            let live: Vec<String> = results
                .iter()
                .filter(|r| r.error.is_none() && !r.ips.is_empty() && (r.cdn.is_none() || args.allow_cdn))
                .map(|r| r.domain.clone())
                .collect();
            if !live.is_empty() {
                let _ = fs::write(&origin_domains_path, live.join("\n") + "\n");
            }
            // cdn_skipped.txt — domains that got CDN-skipped (not
            // written when --allow-cdn overrode the skip, since nothing
            // was actually skipped in that case)
            if !args.allow_cdn {
                let cdn_lines: Vec<String> = cdn_skipped
                    .iter()
                    .map(|(d, tag)| format!("{}\t{}", d, tag))
                    .collect();
                if !cdn_lines.is_empty() {
                    let _ = fs::write(&cdn_skipped_path, cdn_lines.join("\n") + "\n");
                }
            }
            // dns_failed.txt — NXDOMAIN / timeout / no records
            if !error_list.is_empty() {
                let err_lines: Vec<String> = error_list
                    .iter()
                    .map(|(d, reason)| format!("{}\t{}", d, reason))
                    .collect();
                let _ = fs::write(&dns_failed_path, err_lines.join("\n") + "\n");
            }
            // domains.json — complete structured record: [{domain, ips,
            // cdn, scanned, error}, ...] — consumers can jq this.
            let full: Vec<serde_json::Value> = results
                .iter()
                .map(|r| {
                    let scanned = r.error.is_none()
                        && !r.ips.is_empty()
                        && (r.cdn.is_none() || args.allow_cdn);
                    serde_json::json!({
                        "domain": r.domain,
                        "ips": r.ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                        "cdn": r.cdn,
                        "scanned": scanned,
                        "error": r.error,
                    })
                })
                .collect();
            if let Ok(txt) = serde_json::to_string_pretty(&full) {
                let _ = fs::write(&domains_json_path, txt);
            }
        }

        if origin_domains == 0 && nets.is_empty() {
            eprintln!();
            eprintln!("All domains are CDN-fronted or failed to resolve. Nothing to scan.");
            eprintln!("  --allow-cdn   scan CDN edge IPs anyway (rarely useful)");
            eprintln!();
            eprintln!("Domain artefacts written:");
            eprintln!("  {}", domains_json_path.display());
            if !args.allow_cdn && cdn_skipped_path.exists() {
                eprintln!("  {}", cdn_skipped_path.display());
            }
            if dns_failed_path.exists() {
                eprintln!("  {}", dns_failed_path.display());
            }
            return Ok(());
        }
    }

    // Dedupe / skip duplicates by string form.
    {
        let mut seen = std::collections::HashSet::new();
        nets.retain(|n| seen.insert(n.to_string()));
    }

    // ───────── Family filter (--ipv4-only / --ipv6-only) ─────────
    // Applied post-merge so ASN expansion + CIDR input + file input all
    // get filtered uniformly. Mutual-exclusion was checked at startup.
    if args.ipv4_only {
        let before = nets.len();
        nets.retain(|n| matches!(n, IpNetwork::V4(_)));
        let dropped = before - nets.len();
        if dropped > 0 {
            println!("--ipv4-only: dropped {} IPv6 range(s) from scope.", dropped);
        }
    } else if args.ipv6_only {
        let before = nets.len();
        nets.retain(|n| matches!(n, IpNetwork::V6(_)));
        let dropped = before - nets.len();
        if dropped > 0 {
            println!("--ipv6-only: dropped {} IPv4 range(s) from scope.", dropped);
        }
    }

    // ───────── Smart IPv6 substitution (before safety net) ─────────
    // For every IPv6 CIDR larger than /108 (> 2^20 hosts), replace the
    // exhaustive expansion with ~450 RFC-7707 likely addresses. Each
    // becomes its own /128 "network" so the downstream producer sees
    // one scannable range per address and all the existing plumbing
    // (exclude check, skip set, Phase A/B pipeline) keeps working.
    // IPv4 ranges are never touched by this flag — use --ports + the
    // normal producer instead.
    if args.smart_ipv6 {
        let mut rewritten: Vec<IpNetwork> = Vec::new();
        let mut rewrote_any = false;
        for n in nets.drain(..) {
            match n {
                IpNetwork::V6(v6) if v6.prefix() < 108 => {
                    rewrote_any = true;
                    let addrs = smart_ipv6_addresses(v6.network());
                    for a in addrs {
                        if let Ok(net) = IpNetwork::new(a, 128) {
                            rewritten.push(net);
                        }
                    }
                }
                other => rewritten.push(other),
            }
        }
        if rewrote_any {
            println!(
                "--smart-ipv6: expanded to {} targeted address(es) from RFC-7707 patterns.",
                rewritten.len()
            );
        }
        nets = rewritten;
    }

    // ───────── Scope safety net (max 2^20 hosts by default) ─────────
    // Prevents a user who types `2a00:1450::/32` from asking the scanner
    // to enumerate 2^96 addresses. Threshold picked to allow /12 IPv4
    // (1M hosts) and /108 IPv6 (1M hosts) — large but finite.
    // Bypasses:
    //   --allow-huge-scope  explicit override for users who know what they're doing
    //   --smart-ipv6        already rewrote IPv6 CIDRs to ~450 /128s each, count is fine
    {
        let total = total_host_count(&nets);
        const SAFETY_CAP: u128 = 1 << 20; // 1 048 576
        if total > SAFETY_CAP && !args.allow_huge_scope {
            eprintln!(
                "error: target scope would expand to {} host(s) across {} range(s) — above the 2^20 safety cap.",
                total, nets.len()
            );
            eprintln!("  bypass options:");
            eprintln!("    --smart-ipv6         scan only RFC-7707 common IPv6 addresses in huge IPv6 ranges");
            eprintln!("    --allow-huge-scope   explicitly proceed with the full expansion (you really sure?)");
            eprintln!("    --top-ports 100      cut the per-host probe cost if the range is accurate");
            std::process::exit(2);
        }
    }

    // Build the exclude list.
    let exclude_nets: Vec<IpNetwork> = args
        .exclude
        .as_deref()
        .map(expand_targets)
        .unwrap_or_default();
    if !exclude_nets.is_empty() {
        println!("Excluding {} range(s) from scan scope.", exclude_nets.len());
    }

    if nets.is_empty() {
        eprintln!(
            "No valid targets. Provide <CIDR_INPUT>, -d/--domain, -i/--input-file, \
             or -a/--asn (use -i - to read targets from stdin)."
        );
        return Ok(());
    }

    // Scope-filter the resume + diff state to just IPs that fall inside
    // the current <CIDR_INPUT> minus --exclude. Without this, an older
    // scan of a totally different CIDR persisted in the same folder
    // would leak into OPEN PORTS, the writer output, and scan_diff. Very
    // real footgun when the same folder name gets reused across targets.
    let in_scope = |ip: IpAddr| -> bool {
        nets.iter().any(|n| n.contains(ip))
            && !exclude_nets.iter().any(|e| e.contains(ip))
    };
    let sockaddr_in_scope = |sa: &SocketAddr| in_scope(sa.ip());

    let preserved_before = preserved.len();
    preserved.retain(|op| {
        op.ip.parse::<IpAddr>().map(in_scope).unwrap_or(false)
    });
    if preserved_before != preserved.len() {
        println!(
            "Resume: discarded {} prior open port(s) outside the current scan scope.",
            preserved_before - preserved.len()
        );
    }

    let skip_before = skip_set.len();
    skip_set.retain(sockaddr_in_scope);
    if skip_before != skip_set.len() {
        println!(
            "Resume: trimmed skip-set from {} → {} (scope-filtered).",
            skip_before, skip_set.len()
        );
    }

    // Also scope-filter the diff baseline, so scan_diff reflects changes
    // *within the current scope only*.
    prior_set.retain(sockaddr_in_scope);

    let total_estimate: u64 = nets
        .iter()
        .map(|n| {
            let h: u128 = match n.size() {
                ipnetwork::NetworkSize::V4(v) => v as u128,
                ipnetwork::NetworkSize::V6(v) => v,
            };
            h.saturating_mul(ports.len() as u128).min(u64::MAX as u128) as u64
        })
        .fold(0u64, |a, b| a.saturating_add(b));
    let scanned_estimate = total_estimate.saturating_sub(skip_set.len() as u64);

    println!("--- PHASE A: DISCOVERY ---");
    println!(
        "Ranges: {}  Ports: {}  Workers(max): {}  Timeout: {}ms  Retries: {}  Est. probes: {}",
        nets.len(),
        ports.len(),
        args.threads,
        args.timeout_ms,
        args.retries,
        scanned_estimate
    );

    // `--dry-run`: print the plan we just described + family breakdown +
    // a rough duration estimate, then exit cleanly. No sockets opened,
    // no files written beyond the already-created folder. Perfect for
    // sanity-checking a huge ASN scan before you commit to it.
    if args.dry_run {
        let v4 = nets.iter().filter(|n| matches!(n, IpNetwork::V4(_))).count();
        let v6 = nets.iter().filter(|n| matches!(n, IpNetwork::V6(_))).count();
        let host_count = total_host_count(&nets);
        let est_seconds = (scanned_estimate as f64
            / (args.threads as f64).max(1.0)
            * (args.timeout_ms as f64 / 1000.0).max(0.05))
        .max(1.0);
        println!();
        println!("--- DRY RUN ---");
        println!("  IPv4 ranges: {}", v4);
        println!("  IPv6 ranges: {}", v6);
        println!("  Total hosts: {}", host_count);
        println!("  Total probes (pre-skip): {}", scanned_estimate);
        println!(
            "  Rough time estimate: ~{:.1} min (threads={}, timeout={}ms — actual will vary with network)",
            est_seconds / 60.0,
            args.threads,
            args.timeout_ms
        );
        println!();
        println!("  No probes fired. Run without --dry-run to actually scan.");
        return Ok(());
    }

    // Always use a real progress bar — indicatif handles arbitrarily large
    // totals. The old spinner-mode template (engaged above 10M probes) had
    // a hardcoded "open" token that collided with the {msg} ("open: <sa>")
    // and rendered as "scanned 0 open open: 1.2.3.4:80". Gone.
    //
    // v0.13.5: Replaced indicatif's built-in `{per_sec}` and `{eta}` format
    // keys with our own computed values piped into `{msg}`. indicatif's
    // rate estimator uses a sliding window that breaks under bursty
    // loads — on firewalled /24s where 1500 workers all time out in
    // 800 ms bursts, the window sees either 0 or 1500 events and reports
    // bogus rates (users saw "0.005/s · ETA 2y" on scans running at
    // 500/s). Our computed rate uses the global average (position /
    // elapsed) which is always sensible, refreshed every 500 ms by a
    // dedicated ticker task.
    let pb = ProgressBar::new(scanned_estimate.max(1));
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner} [{elapsed_precise}] {bar:40} {pos}/{len} ({percent}%) {msg}",
        )
        .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(200));

    // Own rate / ETA ticker. Computes global-average rate (pos / elapsed)
    // — which is ALWAYS accurate — and pushes it into the bar's {msg}
    // slot every 500 ms. Replaces indicatif's unreliable window-based
    // {per_sec} + {eta}. Aborts naturally when the bar finishes.
    let rate_ticker = {
        let pb = pb.clone();
        let rate_started = Instant::now();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let elapsed = rate_started.elapsed().as_secs_f64();
                let pos = pb.position();
                let len = pb.length().unwrap_or(0);
                if elapsed < 0.1 {
                    continue;
                }
                let rate = pos as f64 / elapsed;
                let remaining = len.saturating_sub(pos) as f64;
                let eta_secs = if rate > 0.1 {
                    (remaining / rate) as u64
                } else {
                    u64::MAX
                };
                let eta_str = if eta_secs == u64::MAX || eta_secs > 86_400 * 30 {
                    // cap unreasonable ETAs (slow start; will reconverge)
                    "~".to_string()
                } else if eta_secs >= 3600 {
                    format!("{}h{}m", eta_secs / 3600, (eta_secs % 3600) / 60)
                } else if eta_secs >= 60 {
                    format!("{}m{}s", eta_secs / 60, eta_secs % 60)
                } else {
                    format!("{}s", eta_secs)
                };
                // pb.message() may already hold a live-hit "open: ip:port"
                // from Phase A workers — append/replace instead of overwrite
                // so both bits of info stay visible.
                pb.set_message(format!("{:.0}/s · ETA {}", rate, eta_str));
            }
        })
    };

    let stats = Arc::new(Stats {
        shutdown: AtomicBool::new(false),
        attempts: AtomicU64::new(0),
        timeouts: AtomicU64::new(0),
        opens: AtomicU64::new(0),
        local_errors: AtomicU64::new(0),
        net_unreach: AtomicU64::new(0),
        priority_done: AtomicBool::new(false),
        adaptive_shrunk: AtomicBool::new(false),
    });
    let sem = Arc::new(Semaphore::new(args.threads));

    // SIGINT handler.
    {
        let stats = stats.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("\n[!] Ctrl+C received — draining workers and flushing output...");
            stats.shutdown.store(true, Ordering::Relaxed);
        });
    }

    // `--max-scan-time`: optional wallclock budget. When the duration
    // elapses we flip the same shutdown flag the Ctrl+C handler uses, so
    // downstream draining + Phase-B backfill + scan_summary writing all
    // fire through the existing "graceful abort" code path. scan_summary
    // gets a `timed_out: true` marker (see below) so automation can tell
    // the difference between a natural finish and a time-limited cutoff.
    let timed_out_flag = Arc::new(AtomicBool::new(false));
    if let Some(budget) = scan_time_budget {
        let stats = stats.clone();
        let tflag = timed_out_flag.clone();
        println!("--max-scan-time: hard budget set to {:?}", budget);
        tokio::spawn(async move {
            tokio::time::sleep(budget).await;
            if !stats.shutdown.load(Ordering::Relaxed) {
                eprintln!("\n[!] --max-scan-time expired — draining workers and flushing output...");
                stats.shutdown.store(true, Ordering::Relaxed);
                tflag.store(true, Ordering::Relaxed);
            }
        });
    }

    // Adaptive monitor.
    let monitor = if !args.no_adaptive {
        let s = stats.clone();
        let sm = sem.clone();
        let max = args.threads;
        Some(tokio::spawn(async move { adaptive_monitor(s, sm, max).await }))
    } else {
        None
    };

    // MPMC work queue + hit channel.
    // v0.12.4: bumped from threads*4 to threads*8. With the FD-limit fix
    // letting us run genuinely wide concurrency, the old bound could
    // starve workers momentarily between producer batches on large scans.
    // Doubling the capacity smooths the producer-worker handoff with ~5 KB
    // extra memory at threads=1500 (SocketAddr is 28 B on 64-bit Linux).
    let (work_tx, work_rx) = flume::bounded::<SocketAddr>(args.threads * 8);
    // Bounded so Phase A workers can't let the hit-receive queue grow
    // unbounded if the writer is slow. 2048 is generous — opens are rare
    // relative to probes (even a hot /24 rarely hits double-digit
    // open-rate per second).
    let (hit_tx, mut hit_rx) = mpsc::channel::<SocketAddr>(2048);

    // Pipelined dispatcher (v0.13.0): replaces both the former "collector"
    // task AND the separate Phase B enrichment block that used to run
    // AFTER Phase A finished.
    //
    // Old flow: Phase A → collect hits → Phase B enrichment. Two phases
    // in series; enrichment couldn't start until Phase A's last probe
    // timed out. On the 43.230.180.0/24 × 3-port benchmark that meant
    // 1.74 s Phase A + 1.29 s Phase B = 3.03 s total.
    //
    // New flow: the moment a Phase A worker finds an open port, we spawn
    // its enrichment task here — concurrently with the remaining Phase A
    // probes. By the time Phase A's last timeout settles, most enrichments
    // are already done. Same benchmark now runs ~1.8 s with identical
    // results (no probes missed, no races, same Ctrl+C backfill logic).
    //
    // Live "[+] IP:PORT opened" stream (v0.12.3 feature) still fires here
    // on every hit as it arrives, before the enrichment spawn.
    let phase_a_hits: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
    let open_records_shared: Arc<Mutex<Vec<OpenPort>>> = Arc::new(Mutex::new(preserved));
    let enrich_sem = Arc::new(Semaphore::new(args.threads.min(1000)));
    let phase_b_started_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let t_b = Duration::from_millis(args.enrich_timeout_ms);
    let want_banner = !args.no_banner;
    let sniff = !args.no_tls_sniff;

    // v0.14.8: network-down monitor. Polls `stats.net_unreach` every second
    // and flips `stats.shutdown` if it crosses a threshold, triggering the
    // same graceful drain + save-and-exit path as Ctrl+C / --max-scan-time.
    // Threshold is conservative (500) because a healthy scan should see
    // zero ENETUNREACH errors — hosts timeout or RST, they don't produce
    // "no route to destination network". Zero perf impact on workers (the
    // error path already does an atomic add; the monitor is a 1 Hz ticker).
    let net_monitor = {
        let stats = stats.clone();
        tokio::spawn(async move {
            const NET_UNREACH_THRESHOLD: u64 = 500;
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.tick().await; // consume the immediate tick
            loop {
                ticker.tick().await;
                if stats.shutdown.load(Ordering::Relaxed) {
                    return;
                }
                let n = stats.net_unreach.load(Ordering::Relaxed);
                if n >= NET_UNREACH_THRESHOLD {
                    eprintln!(
                        "\n[!] Network looks unreachable — {} probes failed with \
                         ENETUNREACH. Saving progress and exiting gracefully. \
                         Re-run the same command to resume from where this stopped.",
                        n
                    );
                    stats.shutdown.store(true, Ordering::Relaxed);
                    return;
                }
            }
        })
    };

    // v0.14.8: periodic partial-results flush. Every 15 s we snapshot the
    // shared open_records vec and rewrite open_ports.jsonl — so a hard crash
    // (kill -9, power loss, OOM) loses at most 15 s of discoveries instead
    // of everything since scan start. The final writer later does the same
    // truncate+rewrite with the complete state, so no file-content drift.
    //
    // Design: we abort this task BEFORE the final writer opens the file,
    // so there's no race with it. The `truncate+rewrite` order means even
    // if the abort catches the task mid-write, the half-written file gets
    // immediately overwritten by the final writer.
    let flush_task = {
        let records = open_records_shared.clone();
        let path = jsonl_path.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(15));
            ticker.tick().await; // consume the immediate tick
            loop {
                ticker.tick().await;
                if stats.shutdown.load(Ordering::Relaxed) {
                    // Shutdown in progress — main thread will do the final
                    // write. Bail out to avoid racing it.
                    return;
                }
                // Clone under lock (fast), write without lock held (slow).
                let snapshot: Vec<OpenPort> = {
                    match records.lock() {
                        Ok(g) => g.clone(),
                        Err(_) => return, // poisoned — main task died; bail
                    }
                };
                if snapshot.is_empty() {
                    continue;
                }
                if let Ok(f) = OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&path)
                {
                    let mut w = BufWriter::new(f);
                    for r in &snapshot {
                        if let Ok(s) = serde_json::to_string(r) {
                            let _ = writeln!(w, "{}", s);
                        }
                    }
                    let _ = w.flush();
                }
            }
        })
    };

    let collector = {
        let sink_hits = phase_a_hits.clone();
        let sink_ops = open_records_shared.clone();
        let pb_for_hits = pb.clone();
        let live = !args.no_live_hits && !args.quiet;
        let stats = stats.clone();
        let sem = enrich_sem.clone();
        let phase_b_flag = phase_b_started_at.clone();
        tokio::spawn(async move {
            let mut enrich_set: JoinSet<()> = JoinSet::new();
            while let Some(sa) = hit_rx.recv().await {
                sink_hits.lock().unwrap().push(sa);

                // Stamp Phase B start on the first hit so scan_summary's
                // phase_b_ms measures real enrichment time (not wall time
                // since scan launch).
                {
                    let mut guard = phase_b_flag.lock().unwrap();
                    if guard.is_none() {
                        *guard = Some(Instant::now());
                    }
                }

                // Live hit line (v6 addresses need bracket-wrapping so
                // "IP:PORT" disambiguates the final colon).
                if live {
                    let host = match sa.ip() {
                        IpAddr::V6(v) => format!("[{}]", v),
                        _ => sa.ip().to_string(),
                    };
                    pb_for_hits.println(cfmt("1;32", &format!("[+] {}:{} opened", host, sa.port())));
                }

                // Ctrl+C path: stop spawning new enrichment. The Phase A
                // hit still lands in phase_a_hits (above) so the backfill
                // step after the dispatcher returns can add a bare record
                // with "(Ctrl+C — enrichment skipped)" banner.
                if stats.shutdown.load(Ordering::Relaxed) {
                    continue;
                }

                // --no-banner: record a bare OpenPort immediately; no
                // enrichment subprocess. Keeps existing --no-banner
                // semantics intact.
                if !want_banner {
                    sink_ops.lock().unwrap().push(OpenPort {
                        ip: sa.ip().to_string(),
                        port: sa.port(),
                        rtt_ms: 0,
                        tls: sa.port() == 443,
                        protocol: service_for_port(sa.port()).map(|s| s.to_string()),
                        banner: None,
                        cdn: None,
                        source_label: None,
                        title: None,
                        final_url: None,
                        redirect_chain: None,
                        content_length: None,
                    });
                    continue;
                }

                // Normal path: spawn enrichment for this hit concurrently.
                // Semaphore caps enrichment parallelism (~1000 by default)
                // so a scan of a heavily-open target doesn't exhaust FDs
                // with enrich tasks.
                let Ok(p) = sem.clone().acquire_owned().await else { break; };
                let sink = sink_ops.clone();
                enrich_set.spawn(async move {
                    let op = enrich(sa, t_b, sniff, want_banner).await;
                    drop(p);
                    sink.lock().unwrap().push(op);
                });
            }

            // Phase A has closed the hit channel. Drain remaining
            // in-flight enrichments; abort any that hang if Ctrl+C fires
            // during this tail phase.
            while enrich_set.join_next().await.is_some() {
                if stats.shutdown.load(Ordering::Relaxed) {
                    enrich_set.abort_all();
                    while enrich_set.join_next().await.is_some() {}
                    break;
                }
            }
        })
    };

    // Phase-A workers.
    let mut workers: JoinSet<()> = JoinSet::new();
    let timeout_a = Duration::from_millis(args.timeout_ms);
    for _ in 0..args.threads {
        let rx = work_rx.clone();
        let ht = hit_tx.clone();
        let sm = sem.clone();
        let st = stats.clone();
        let pb = pb.clone();
        workers.spawn(async move { phase_a(rx, ht, sm, st, pb, timeout_a, args.retries).await });
    }
    drop(work_rx);
    drop(hit_tx);

    // Producer. Thread the optional rate limiter (from --max-pps) so the
    // producer can pace its sends without touching worker code. None when
    // the flag is unset → zero overhead on the hot path.
    let exclude_arc = Arc::new(exclude_nets);
    let rate_limiter: Option<Arc<RateLimiter>> =
        args.max_pps.map(|pps| Arc::new(RateLimiter::new(pps)));
    if let Some(pps) = args.max_pps {
        println!("--max-pps {}: global rate cap enabled.", pps);
    }
    let prod = {
        let st = stats.clone();
        let skip = Arc::new(skip_set);
        let nets = nets.clone();
        let ports = ports.clone();
        let exclude = exclude_arc.clone();
        let rl = rate_limiter.clone();
        tokio::spawn(async move { producer(work_tx, nets, ports, skip, exclude, st, rl).await })
    };

    let started = Instant::now();
    let started_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let phase_a_started = Instant::now();

    // Priority-pass watcher — prints one interim line the moment the
    // top-20 priority sweep has been fully enqueued. Gives users a
    // heartbeat on long scans ("top-20 done, Y open so far, continuing
    // with remaining ports"). Runs until shutdown or priority_done flips.
    let priority_watcher = {
        let stats = stats.clone();
        tokio::spawn(async move {
            loop {
                if stats.shutdown.load(Ordering::Relaxed) {
                    return;
                }
                if stats.priority_done.load(Ordering::Relaxed) {
                    let opens = stats.opens.load(Ordering::Relaxed);
                    eprintln!(
                        "[priority] top-20 ports enqueued — {} open so far, continuing",
                        opens
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
    };

    let _ = prod.await;
    while workers.join_next().await.is_some() {}
    let _ = collector.await;
    let phase_a_ms = phase_a_started.elapsed().as_millis();

    // Stop the rate ticker before writing the final bar message, otherwise
    // its 500 ms loop can overwrite the "N open" finish message.
    rate_ticker.abort();
    let _ = rate_ticker.await;

    pb.finish_with_message(format!("{} open", stats.opens.load(Ordering::Relaxed)));
    // Wake the watcher if it hasn't already returned (scan may have had
    // only priority ports, or ended before priority_done flipped).
    priority_watcher.abort();
    let _ = priority_watcher.await;
    // Stop the adaptive monitor by aborting its JoinHandle directly,
    // NOT by setting stats.shutdown — because Phase B (and Ctrl+C
    // handling) now use that flag for "abort the whole scan". We only
    // want the monitor loop to exit here; the rest of the pipeline
    // still runs.
    if let Some(m) = monitor {
        m.abort();
        let _ = m.await;
    }

    // Pipelined enrichment has already been collecting as Phase A ran.
    // Pull out the final open_records + report Phase A count.
    let pa_hits_final = phase_a_hits.lock().unwrap().len();
    println!("Phase A done: {} new open ports.", pa_hits_final);

    // v0.14.8: stop the net-monitor + periodic-flush tasks BEFORE the final
    // writer opens open_ports.jsonl, to avoid a file-open race with the
    // 15 s flush tick. `abort()` cancels at the next await point; we then
    // await the JoinHandle to make the cancellation synchronous with us.
    net_monitor.abort();
    flush_task.abort();
    let _ = net_monitor.await;
    let _ = flush_task.await;

    // Unwrap the shared open_records. If the dispatcher future is still
    // holding its Arc (shouldn't happen post-await but be safe), fall back
    // to a clone.
    let mut open_records: Vec<OpenPort> = match Arc::try_unwrap(open_records_shared) {
        Ok(m) => m.into_inner().unwrap_or_default(),
        Err(arc) => arc.lock().unwrap().clone(),
    };

    // phase_b_ms measures real enrichment time: from the first hit
    // arriving at the dispatcher until the dispatcher finished draining
    // all in-flight enrichments. Zero if no hits were enriched.
    let phase_b_ms: u128 = phase_b_started_at
        .lock()
        .unwrap()
        .map(|t| t.elapsed().as_millis())
        .unwrap_or(0);

    // Ctrl+C backfill: if shutdown fired during the scan, any Phase A
    // hit that we *found* but didn't get around to enriching would
    // otherwise be missing from open_records. Add a bare record for each
    // so "Phase A done: N" and the final OPEN PORTS count agree.
    if stats.shutdown.load(Ordering::Relaxed) {
        let enriched_set: std::collections::HashSet<SocketAddr> = open_records
            .iter()
            .filter_map(|op| {
                op.ip.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, op.port))
            })
            .collect();
        let pa_hits_snapshot = phase_a_hits.lock().unwrap().clone();
        let mut backfilled = 0usize;
        for sa in &pa_hits_snapshot {
            if !enriched_set.contains(sa) {
                open_records.push(OpenPort {
                    ip: sa.ip().to_string(),
                    port: sa.port(),
                    rtt_ms: 0,
                    tls: sa.port() == 443,
                    protocol: service_for_port(sa.port()).map(|s| s.to_string()),
                    banner: Some("(Ctrl+C — enrichment skipped)".to_string()),
                    cdn: None,
                    source_label: None,
                    title: None,
                    final_url: None,
                    redirect_chain: None,
                    content_length: None,
                });
                backfilled += 1;
            }
        }
        if backfilled > 0 {
            println!(
                "Phase B interrupted — kept {} raw Phase A hit(s) without enrichment.",
                backfilled
            );
        }
    }

    // ── UDP phase (opt-in) ──
    let mut udp_ms: u128 = 0;
    if args.udp {
        let udp_started = Instant::now();
        println!(
            "--- UDP DISCOVERY ({} probes × {} IPs) ---",
            UDP_PROBES.len(),
            {
                let mut cnt = 0usize;
                for net in &nets {
                    for ip in net.iter() {
                        if is_usable_ipv4_host(net, ip)
                            && !exclude_arc.iter().any(|e| e.contains(ip))
                        {
                            cnt += 1;
                        }
                    }
                }
                cnt
            }
        );
        let udp_concurrency = args.threads.min(500);
        let udp_hits = run_udp_phase(
            &nets,
            exclude_arc.as_slice(),
            Duration::from_millis(args.enrich_timeout_ms.max(800)),
            udp_concurrency,
        )
        .await;
        println!("UDP: {} service(s) responded.", udp_hits.len());
        open_records.extend(udp_hits);
        udp_ms = udp_started.elapsed().as_millis();
    }

    // Sort numerically by (parsed IpAddr, port). String compare of IPs
    // orders "10.0.0.1" before "9.0.0.1" — wrong. sort_by_cached_key
    // parses each IP once instead of on every comparison.
    open_records.sort_by_cached_key(|op| {
        (
            op.ip.parse::<IpAddr>().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            op.port,
        )
    });
    // Tag each open port with its CDN/WAF provider if it falls in a known edge range.
    // v0.14.0: also tag with the originating domain (if scan was seeded
    // from --domain / --input-file domain entries). The domain label is
    // used by the OPEN PORTS renderer to show "example.com → 1.2.3.4"
    // grouping, and lands in the JSONL for downstream tooling.
    let cdn_table = load_cdn_ranges();
    for op in &mut open_records {
        if op.cdn.is_none() {
            if let Ok(ip) = op.ip.parse::<IpAddr>() {
                if let Some(tag) = cdn_tag_for(ip, &cdn_table) {
                    op.cdn = Some(tag.to_string());
                }
            }
        }
        if op.source_label.is_none() {
            if let Ok(ip) = op.ip.parse::<IpAddr>() {
                if let Some(label) = domain_origin_map.get(&ip) {
                    op.source_label = Some(label.clone());
                }
            }
        }
    }
    open_records.dedup_by(|a, b| a.ip == b.ip && a.port == b.port);

    // ── Pass-C: native HTTP(S) probe (replaces the old httpx subprocess) ──
    // v0.14.9. For every HTTP-candidate open port we issue a real HTTP(S)
    // GET via ureq (SNI-aware, TLS-verified) inside spawn_blocking so the
    // async runtime stays responsive. Parses status code, <title>, follows
    // redirects if requested. Overwrites enrich()'s bare-bones banner with
    // the richer response line.
    //
    // Concurrency is independent of --threads (which drives the 3000-worker
    // Phase A pool): --probe-concurrency (short -C) defaults to 100, with
    // an auto-halve to 50 on ASN scans to stay under WAF burst thresholds
    // that blocked httpx coverage on the 164.121.0.0/16 scan.
    let http_probe_ms: u128 = if args.no_enrich || args.no_banner || open_records.is_empty() {
        0
    } else {
        let probe_targets: Vec<(usize, String)> = open_records
            .iter()
            .enumerate()
            .filter_map(|(i, op)| {
                // Only probe HTTP-plausible ports — `ssh`, `rdp`, `vnc`,
                // database protocols etc. are already banner-classified
                // and probing them via HTTP just wastes a round-trip.
                // Positive-list match: the SAME filter used below when
                // rendering the enrichment section, so the two views agree.
                if !is_http_candidate(op.port, op.protocol.as_deref(), op.tls) {
                    return None;
                }
                match op.protocol.as_deref() {
                    None => {}
                    Some(p) => {
                        if !matches!(
                            p,
                            "http"
                                | "http-alt"
                                | "http-admin"
                                | "http-proxy"
                                | "https"
                                | "https-alt"
                                | "cloudflare-https"
                                | "tls"
                                | "ssl"
                                | "unknown"
                                | "cpanel"
                                | "cpanel-ssl"
                                | "whm"
                                | "grafana-alt"
                                | "sonarqube"
                                | "kibana"
                                | "weblogic"
                                | "oracle-http"
                                | "puppet"
                                | "activemq-admin"
                                | "vault"
                                | "prometheus"
                                | "transmission"
                                | "alertmanager"
                                | "zabbix"
                                | "plex"
                                | "vnc-http"
                        ) {
                            return None;
                        }
                    }
                }
                let ip = op.ip.parse::<IpAddr>().ok()?;
                Some((
                    i,
                    format_for_nuclei(&ip, op.port, op.tls, op.source_label.as_deref()),
                ))
            })
            .collect();

        if probe_targets.is_empty() {
            0
        } else {
            let concurrency = args.probe_concurrency.max(1);
            let follow = args.follow_redirects;
            let started = Instant::now();
            // One-line progress note only — the real output lives in the
            // OPEN PORTS table (titles/redirects inline) and in the
            // post-OPEN-PORTS enrichment dump (httpx-style per-URL lines).
            eprintln!(
                "Enriching {} HTTP target(s)… (-C {}{})",
                probe_targets.len(),
                concurrency,
                if follow { ", follow redirects" } else { "" }
            );

            let sem = Arc::new(Semaphore::new(concurrency));
            let mut handles = Vec::with_capacity(probe_targets.len());
            for (idx, url) in probe_targets {
                let sem = sem.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire_owned().await.ok();
                    let res = tokio::task::spawn_blocking(move || {
                        http_probe_blocking(&url, follow)
                    })
                    .await
                    .ok()
                    .flatten();
                    (idx, res)
                }));
            }

            for h in handles {
                if let Ok((idx, Some(r))) = h.await {
                    // Overwrite enrich()'s banner with the real status line;
                    // keep the existing enrich() protocol classification
                    // unless the scheme-flip retry promoted us to HTTPS.
                    open_records[idx].banner = Some(r.status_line);
                    open_records[idx].title = r.title;
                    open_records[idx].final_url = r.final_url;
                    open_records[idx].content_length = r.content_length;
                    if !r.chain.is_empty() {
                        open_records[idx].redirect_chain = Some(r.chain);
                    }
                    if r.via_https {
                        open_records[idx].tls = true;
                        match open_records[idx].protocol.as_deref() {
                            Some("https") | Some("ssh") | Some("ssl") => {}
                            _ => open_records[idx].protocol = Some("https".into()),
                        }
                    }
                }
            }
            started.elapsed().as_millis()
        }
    };

    // ── Write artifacts ──
    let mut jsonl = BufWriter::new(
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&jsonl_path)?,
    );
    let mut nuc = BufWriter::new(fs::File::create(&http_targets_path)?);
    // v0.14.3 — dedupe nuclei_targets.txt entries. When a scan is seeded
    // from a domain that resolves to N IPs, we'd otherwise write the
    // same https://example.com URL N times (once per IP). httpx / nuclei
    // handle duplicates fine but the files look messy and bloat up.
    let mut nuclei_written: std::collections::HashSet<String> = Default::default();
    let mut by_port: std::collections::BTreeMap<u16, u64> = Default::default();
    let mut by_proto: std::collections::BTreeMap<String, u64> = Default::default();
    let mut by_cdn: std::collections::BTreeMap<String, u64> = Default::default();

    let mut nuclei_skipped = 0usize;
    for op in &open_records {
        writeln!(jsonl, "{}", serde_json::to_string(op)?)?;
        // v0.14.5: parse errors must NOT abort the writer loop. If a
        // bug anywhere upstream produced an OpenPort with a malformed
        // ip string, the record is kept in the JSONL (for visibility)
        // but skipped for downstream artefacts. Previously used `?`
        // which returned early and left truncated http_targets.txt.
        let ip: IpAddr = match op.ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!(
                    "[!] skipping OpenPort with unparseable ip {:?} (port={})",
                    op.ip, op.port
                );
                continue;
            }
        };
        let _ = SocketAddr::new(ip, op.port); // (kept as a validity check; raw targets.txt removed in v0.14.4)
        // Filter non-HTTP services out of the http_targets list unless --nuclei-all-ports.
        let include_in_nuclei = args.nuclei_all_ports
            || is_http_candidate(op.port, op.protocol.as_deref(), op.tls);
        if include_in_nuclei {
            let url = format_for_nuclei(&ip, op.port, op.tls, op.source_label.as_deref());
            if nuclei_written.insert(url.clone()) {
                writeln!(nuc, "{}", url)?;
            }
        } else {
            nuclei_skipped += 1;
        }
        *by_port.entry(op.port).or_insert(0) += 1;
        *by_proto
            .entry(op.protocol.clone().unwrap_or_else(|| "unknown".into()))
            .or_insert(0) += 1;
        if let Some(c) = &op.cdn {
            *by_cdn.entry(c.clone()).or_insert(0) += 1;
        }
    }
    if nuclei_skipped > 0 {
        println!(
            "Nuclei filter: skipped {} non-HTTP target(s). Override with --nuclei-all-ports.",
            nuclei_skipped
        );
    }
    let cdn_count_total: u64 = by_cdn.values().sum();
    jsonl.flush()?;
    nuc.flush()?;

    let summary = ScanSummary {
        folder: folder_name.clone(),
        started_at_unix: started_unix,
        duration_ms: started.elapsed().as_millis(),
        ranges: nets.iter().map(|n| n.to_string()).collect(),
        ports: ports.len(),
        scanned_estimate,
        attempts: stats.attempts.load(Ordering::Relaxed),
        timeouts: stats.timeouts.load(Ordering::Relaxed),
        open: open_records.len() as u64,
        by_port,
        by_protocol: by_proto.clone(),
        by_cdn,
        cdn_count: cdn_count_total,
        closed: {
            let attempts_v = stats.attempts.load(Ordering::Relaxed);
            let timeouts_v = stats.timeouts.load(Ordering::Relaxed);
            let local_v = stats.local_errors.load(Ordering::Relaxed);
            let opens_v = stats.opens.load(Ordering::Relaxed);
            attempts_v
                .saturating_sub(timeouts_v)
                .saturating_sub(local_v)
                .saturating_sub(opens_v)
        },
        local_errors: stats.local_errors.load(Ordering::Relaxed),
        phase_a_ms,
        phase_b_ms,
        udp_ms,
        enrich_ms: 0,
        nuclei_ms: 0,
        timed_out: timed_out_flag.load(Ordering::Relaxed),
    };
    // Initial summary write — httpx/nuclei timings are filled in after
    // those subprocesses finish (see rewrite below).
    let mut summary = summary;
    fs::write(&summary_path, serde_json::to_string_pretty(&summary)?)?;
    println!("Summary: {:?}", summary_path);

    // Colored Totals line — at-a-glance scan health check:
    //   open     → bright green (hits are what the user came for)
    //   closed   → dim grey (neutral signal)
    //   filtered → yellow above 50 % (firewalled or SYN-dropped target)
    //   local_err→ bright red when > 0 (local-resource pressure, means
    //              the scanner couldn't send as fast as intended — user
    //              should lower --threads or add --max-pps)
    let filt_pct = if summary.attempts > 0 {
        (summary.timeouts as f64 / summary.attempts as f64) * 100.0
    } else {
        0.0
    };
    let open_col = if summary.open > 0 { "1;32" } else { "2" };
    let closed_col = "2";
    let filt_col = if filt_pct > 50.0 { "33" } else { "2" };
    let le_col = if summary.local_errors > 0 { "1;31" } else { "32" };
    println!(
        "Totals — {} probes  ·  {}  ·  {}  ·  {}  ·  {}",
        summary.attempts,
        cfmt(open_col, &format!("open: {}", summary.open)),
        cfmt(closed_col, &format!("closed: {}", summary.closed)),
        cfmt(filt_col, &format!("filtered: {} ({:.1}%)", summary.timeouts, filt_pct)),
        cfmt(le_col, &format!("local_err: {}", summary.local_errors)),
    );
    // Quick legend for first-time users:
    //   open     = TCP 3-way handshake completed
    //   closed   = RST / ICMP-unreachable (port closed but host replied)
    //   filtered = no reply within timeout (firewall dropped SYN, or host down)
    //   local_err= our OS pushed back (ephemeral-port / FD / buffer full)

    // Diff this run against the prior open_ports.jsonl (if any) and emit
    // scan_diff.json. ALWAYS write — even when both sets are empty —
    // so a stale diff from a different-scope previous run isn't left
    // on disk to mislead the next reader.
    {
        let current_set: std::collections::BTreeSet<SocketAddr> = open_records
            .iter()
            .filter_map(|op| {
                op.ip.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, op.port))
            })
            .collect();
        let prior_btree: std::collections::BTreeSet<SocketAddr> = prior_set.iter().copied().collect();
        let new_opens: Vec<String> = current_set.difference(&prior_btree).map(|s| s.to_string()).collect();
        let closed: Vec<String> = prior_btree.difference(&current_set).map(|s| s.to_string()).collect();
        let unchanged: usize = current_set.intersection(&prior_btree).count();
        let diff = serde_json::json!({
            "folder": folder_name,
            "generated_at_unix": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            "prior_opens": prior_btree.len(),
            "current_opens": current_set.len(),
            "new": new_opens,
            "closed": closed,
            "unchanged": unchanged,
        });
        fs::write(&diff_path, serde_json::to_string_pretty(&diff)?)?;
        let new_n = diff["new"].as_array().map(|a| a.len()).unwrap_or(0);
        let closed_n = diff["closed"].as_array().map(|a| a.len()).unwrap_or(0);
        if prior_set.is_empty() && open_records.is_empty() {
            println!("Diff: no opens this run (and no prior in scope) → {:?}", diff_path);
        } else if prior_set.is_empty() {
            println!("Diff: first scan (no prior baseline) → {:?}", diff_path);
        } else {
            println!(
                "Diff: +{} new, -{} closed, {} unchanged → {:?}",
                new_n, closed_n, unchanged, diff_path
            );
        }
    }

    if open_records.is_empty() {
        println!("No open ports. Done.");
        // Even on 0-open runs, prune the zero-byte files
        // (http_targets.txt, open_ports.jsonl) so the folder isn't
        // polluted with empty husks. Summary + diff are kept — they
        // carry the "I ran but found nothing" signal.
        for p in [&http_targets_path, &jsonl_path] {
            if let Ok(meta) = fs::metadata(p) {
                if meta.len() == 0 {
                    let _ = fs::remove_file(p);
                }
            }
        }
        return Ok(());
    }

    // Print every open port with its detected protocol + banner so the user
    // can see exactly what's being fed to httpx/nuclei and understand why
    // httpx might report fewer hits (non-HTTP services like SSH show up here
    // but don't produce httpx output).
    let cdn_count = open_records.iter().filter(|o| o.cdn.is_some()).count();
    // Count unique hosts for the header. open_records is already sorted
    // by (IpAddr, port) so hosts-with-opens form contiguous runs.
    let unique_hosts = {
        let mut ips: Vec<&str> = open_records.iter().map(|o| o.ip.as_str()).collect();
        ips.sort();
        ips.dedup();
        ips.len()
    };
    let host_suffix = if unique_hosts > 1 {
        format!(" across {} hosts", unique_hosts)
    } else {
        String::new()
    };
    let cdn_suffix = if cdn_count > 0 {
        format!(", {} on CDN edge", cdn_count)
    } else {
        String::new()
    };
    // Bold-green header when there's at least one open; dim grey otherwise.
    // Makes the "did this find anything?" question answerable at a glance.
    let header_color = if open_records.is_empty() { "2" } else { "1;32" };
    println!(
        "\n{}",
        cfmt(
            header_color,
            &format!(
                "--- OPEN PORTS ({} total{}{}) ---",
                open_records.len(), host_suffix, cdn_suffix,
            ),
        )
    );

    // Per-host grouping (v0.12.3): emit the IP once, then list every port
    // on that host indented beneath it — same layout as `nmap` uses.
    // Drastically easier to visually parse on multi-host scans where the
    // same IP used to repeat on every line. open_records is sorted by
    // (IpAddr, port) so we walk it linearly and track the "current host".
    let mut current_ip: Option<String> = None;
    for op in &open_records {
        let host = match op.ip.parse::<IpAddr>() {
            Ok(IpAddr::V6(v)) => format!("[{}]", v),
            _ => op.ip.clone(),
        };
        let proto = op.protocol.as_deref().unwrap_or("unknown");
        let banner = op.banner.as_deref().unwrap_or("");

        // Emit a host header when the IP changes. v0.14.0: when the scan
        // came from a domain input, the header reads "example.com → 1.2.3.4"
        // so the user's intent is preserved in the output; otherwise we
        // keep the bare-IP header from v0.12.3+.
        if current_ip.as_ref() != Some(&op.ip) {
            if current_ip.is_some() {
                println!();
            }
            match &op.source_label {
                Some(dom) => {
                    println!(
                        "  {} {} {}",
                        cfmt("1", dom),
                        cfmt("2", "→"),
                        cfmt("1", &host),
                    );
                }
                None => {
                    println!("  {}", cfmt("1", &host));
                }
            }
            current_ip = Some(op.ip.clone());
        }

        // Colored [proto, tls, cdn:x] tag bundle. TLS is only printed as
        // a separate tag when the protocol isn't already "https" (which
        // implies TLS) — avoids the redundant "[https, tls]".
        let mut tags: Vec<String> = Vec::with_capacity(3);
        tags.push(color_protocol(proto));
        if op.tls && proto != "https" {
            tags.push(cfmt("33", "tls"));
        }
        if let Some(c) = &op.cdn {
            tags.push(cfmt("35", &format!("cdn:{}", c)));
        }
        let tag_bundle = format!("[{}]", tags.join(cfmt("2", ", ").as_str()));

        // Port column in dim white, tag bundle colored, banner colored
        // by HTTP-status class (2xx green, 3xx cyan, 4xx yellow, 5xx red).
        let port_col = cfmt("2", &format!(":{:<5}", op.port));

        // v0.14.9 — render title and redirect target after the banner.
        // Title is dimmed italic-ish; redirect target appended with an arrow.
        // Keeps non-HTTP rows (SSH banners etc.) visually unchanged.
        let title_suffix = match &op.title {
            Some(t) if !t.is_empty() => format!("  {}", cfmt("2", &format!("· \"{}\"", t))),
            _ => String::new(),
        };
        let redirect_suffix = match &op.final_url {
            Some(u) => format!("  {} {}", cfmt("2", "→"), cfmt("36", u)),
            None => String::new(),
        };

        if banner.is_empty() {
            println!(
                "      {} {}{}{}",
                port_col, tag_bundle, title_suffix, redirect_suffix
            );
        } else {
            let b: String = banner.chars().take(110).collect();
            println!(
                "      {} {}  {}{}{}",
                port_col,
                tag_bundle,
                color_banner_status(&b),
                title_suffix,
                redirect_suffix
            );
        }
    }

    // `--json-out`: emit one NDJSON line per open port to stdout so users
    // can pipe portwave straight into jq, another scanner, or a collector.
    // Printed *after* the human-readable table so the table still renders
    // when the user doesn't pipe, and after all files are written so
    // consumers can rely on `jq -s . | length == summary.open_count`.
    // Additive — file outputs (open_ports.jsonl etc.) are still produced.
    if args.json_out {
        use std::io::Write as _;
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        for op in &open_records {
            if let Ok(line) = serde_json::to_string(op) {
                let _ = writeln!(stdout, "{}", line);
            }
        }
        let _ = stdout.flush();
    }

    // ── httpx ──
    // Skip the subprocess entirely if no open port passed the HTTP-
    // candidate filter (everything was SSH / BGP / MySQL / Redis etc.)
    // or if there were zero opens at all. Spawning httpx on an empty /
    // non-HTTP-only hit list just burns a subprocess and produces an
    // empty file that auto-prune deletes.
    // v0.14.9 — the post-OPEN-PORTS section that used to be `httpx` is now
    // `enrichment`. Same file format (`httpx_results.txt` still exists for
    // downstream tooling) and same visual shape (per-URL `[status] [length]
    // [title]`, then a summary line) — but produced natively, no subprocess.
    // Helper: a row is "HTTP-candidate" for the Pass-C probe only when both
    //   1. it passes the coarse non-HTTP-ports filter (echo, discard, BGP…)
    //   2. its Phase-B protocol tag is HTTP-plausible (http / https / tls /
    //      unknown / None) — a confirmed SSH/SMTP/FTP/RDP/VNC/MySQL/etc.
    //      banner means we'd just waste a ureq round-trip probing HTTP.
    let is_enrich_candidate = |op: &OpenPort| -> bool {
        if !is_http_candidate(op.port, op.protocol.as_deref(), op.tls) {
            return false;
        }
        match op.protocol.as_deref() {
            None => true,
            Some(p) => matches!(
                p,
                "http"
                    | "http-alt"
                    | "http-admin"
                    | "http-proxy"
                    | "https"
                    | "https-alt"
                    | "cloudflare-https"
                    | "tls"
                    | "ssl"
                    | "unknown"
                    | "cpanel"
                    | "cpanel-ssl"
                    | "whm"
                    | "grafana-alt"
                    | "sonarqube"
                    | "kibana"
                    | "weblogic"
                    | "oracle-http"
                    | "puppet"
                    | "activemq-admin"
                    | "vault"
                    | "prometheus"
                    | "transmission"
                    | "alertmanager"
                    | "zabbix"
                    | "plex"
                    | "vnc-http"
            ),
        }
    };

    if open_records.iter().any(is_enrich_candidate) {
        use std::io::Write as _;

        let mut file_writer = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&enrich_out)
            .ok()
            .map(BufWriter::new);

        // Collect all HTTP-candidate records into a sorted, printable form.
        let mut rows: Vec<(String, Option<u16>, Option<u64>, Option<String>, Option<String>)> =
            Vec::new();
        for op in &open_records {
            if !is_enrich_candidate(op) {
                continue;
            }
            let Ok(ip) = op.ip.parse::<IpAddr>() else { continue };
            let url = format_for_nuclei(&ip, op.port, op.tls, op.source_label.as_deref());
            let status: Option<u16> = op
                .banner
                .as_deref()
                .and_then(|b| b.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok());
            let cl = op.content_length;
            let title = op.title.clone();
            let final_url = op.final_url.clone();
            rows.push((url, status, cl, title, final_url));
        }

        // Only render the section if there are rows to show.
        if !rows.is_empty() {
            println!();
            println!(
                "{} {} {} target(s) · {:.2}s",
                cfmt("1;36", "───"),
                cfmt("1;36", "enrichment"),
                cfmt("1", &rows.len().to_string()),
                http_probe_ms as f64 / 1000.0
            );
            println!();

            let mut c_2xx = 0usize;
            let mut c_3xx = 0usize;
            let mut c_4xx = 0usize;
            let mut c_5xx = 0usize;
            let mut responding = 0usize;

            for (url, status, cl, title, final_url) in &rows {
                // File line: plain, httpx-format for grep-friendliness.
                if let Some(w) = file_writer.as_mut() {
                    let s = status.map(|n| n.to_string()).unwrap_or_else(|| "-".into());
                    let l = cl.map(|n| n.to_string()).unwrap_or_else(|| "-".into());
                    match title.as_deref() {
                        Some(t) if !t.is_empty() => {
                            let _ = writeln!(w, "{} [{}] [{}] [{}]", url, s, l, t);
                        }
                        _ => {
                            let _ = writeln!(w, "{} [{}] [{}]", url, s, l);
                        }
                    }
                }

                // Terminal line: colored, with redirect target if present.
                let status_str = match status {
                    Some(n) => {
                        responding += 1;
                        match n {
                            200..=299 => c_2xx += 1,
                            300..=399 => c_3xx += 1,
                            400..=499 => c_4xx += 1,
                            500..=599 => c_5xx += 1,
                            _ => {}
                        }
                        let color = match n {
                            200..=299 => "32",
                            300..=399 => "33",
                            400..=499 => "36",
                            500..=599 => "31",
                            _ => "0",
                        };
                        cfmt(color, &n.to_string())
                    }
                    None => cfmt("2", "-"),
                };
                let cl_str = match cl {
                    Some(n) => cfmt("35", &n.to_string()),
                    None => cfmt("2", "-"),
                };
                let title_part = match title.as_deref() {
                    Some(t) if !t.is_empty() => format!(" [{}]", cfmt("36", t)),
                    _ => String::new(),
                };
                let redirect_part = match final_url.as_deref() {
                    Some(u) => format!(" {} {}", cfmt("2", "→"), cfmt("36", u)),
                    None => String::new(),
                };
                println!(
                    "{} [{}] [{}]{}{}",
                    url, status_str, cl_str, title_part, redirect_part
                );
            }

            if let Some(mut w) = file_writer {
                let _ = w.flush();
            }

            println!();
            println!(
                "{} {} responding · {} 2xx · {} 3xx · {} 4xx · {} 5xx · → {}",
                cfmt("1;32", "✓ enrichment:"),
                responding,
                cfmt("32", &c_2xx.to_string()),
                cfmt("33", &c_3xx.to_string()),
                cfmt("36", &c_4xx.to_string()),
                cfmt("31", &c_5xx.to_string()),
                cfmt("2", &enrich_out.display().to_string())
            );
        }
    }
    summary.enrich_ms = http_probe_ms;

    // ── nuclei ──
    // Same guard as httpx: if the filtered nuclei target list is empty
    // (everything was non-HTTP like SSH/BGP/MySQL), skip the subprocess
    // entirely. Addresses the case where e.g. a range exposes only port
    // 179 (BGP) — there's nothing for nuclei to do and spawning it just
    // produces empty artefacts.
    let nuclei_targets_nonempty = std::fs::metadata(&http_targets_path)
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    if args.no_nuclei {
        println!("Skipping nuclei (--no-nuclei).");
    } else if !nuclei_targets_nonempty {
        println!("Skipping nuclei — no HTTP-candidate ports to probe (non-HTTP services filtered out).");
    } else {
        let mut nuclei_bin = resolve_tool("nuclei", &cfg, "PORTWAVE_NUCLEI_BIN");
        if nuclei_bin.is_none() {
            let installed = offer_install(
                "nuclei",
                "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
                !args.no_install_prompt,
            );
            if installed {
                nuclei_bin = resolve_tool("nuclei", &cfg, "PORTWAVE_NUCLEI_BIN");
            }
        }
        if let Some(bin) = nuclei_bin {
            let target_count = std::fs::read_to_string(&http_targets_path)
                .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0);
            println!();
            println!(
                "{} {} {} target(s) · severity={} · {} threads",
                cfmt("1;35", "───"),
                cfmt("1;35", "nuclei"),
                cfmt("1", &target_count.to_string()),
                cfmt("35", &args.nuclei_severity),
                args.nuclei_concurrency
            );
            println!("{}", cfmt("2", &format!("  binary: {}", bin.display())));
            println!();
            let nuclei_started = Instant::now();
            let mut cmd = Command::new(&bin);
            cmd.arg("-l").arg(&http_targets_path)
                .arg("-c").arg(args.nuclei_concurrency.to_string())
                .arg("-rl").arg(args.nuclei_rate.to_string())
                .arg("-mhe").arg(args.nuclei_max_host_error.to_string())
                // -severity (v0.14.7): default "low,medium,high,critical"
                // deliberately drops `info` — on ASN / 5K-subdomain scans
                // info-tier templates produce 90%+ of the noise and almost
                // none of the actionable findings. User can override with
                // --nuclei-severity (e.g. pass "critical" for triage-only
                // runs, or "info,low,medium,high,critical" to get everything).
                .arg("-severity").arg(&args.nuclei_severity)
                // -silent suppresses nuclei's ASCII banner + progress spam
                // while still writing findings to stdout + -o.
                .arg("-silent")
                .arg("-o").arg(&nuclei_out);
            let status = cmd.status();
            // Count findings in the -o file for the post-run summary.
            let finding_count = std::fs::read_to_string(&nuclei_out)
                .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0);
            println!();
            match status {
                Ok(s) if s.success() => {
                    println!(
                        "{} {} finding(s) · → {}",
                        cfmt("1;35", "✓ nuclei:"),
                        finding_count,
                        cfmt("2", &nuclei_out.display().to_string())
                    );
                }
                Ok(s) => eprintln!("{} {}", cfmt("1;31", "✗ nuclei exited"), s),
                Err(e) => eprintln!("{} {}", cfmt("1;31", "✗ nuclei launch failed:"), e),
            }
            summary.nuclei_ms = nuclei_started.elapsed().as_millis();
        } else {
            eprintln!("nuclei not found on PATH or in config — skipping. Set PORTWAVE_NUCLEI_BIN or install nuclei.");
        }
    }

    // Rewrite summary so final enrich_ms / nuclei_ms land on disk.
    let _ = fs::write(&summary_path, serde_json::to_string_pretty(&summary)?);

    // Optional webhook — POSTs summary JSON (with diff merged in) once
    // everything else is on disk. Silent on failure by design so a flaky
    // collector never breaks the scan's exit code.
    if let Some(url) = args.webhook.as_deref() {
        let mut payload = serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null);
        // Attempt to merge the scan_diff JSON into the webhook payload so
        // downstream collectors (Slack etc.) see what changed. Also lets
        // --webhook-on-diff-only gate on whether there's anything to report.
        let mut diff_has_changes = false;
        if diff_path.exists() {
            if let Ok(diff_str) = fs::read_to_string(&diff_path) {
                if let Ok(diff_val) = serde_json::from_str::<serde_json::Value>(&diff_str) {
                    // Count additions/removals: if both arrays are empty
                    // (or missing), there's nothing new since the last scan.
                    let opened = diff_val.get("opened").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                    let closed = diff_val.get("closed").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                    if opened > 0 || closed > 0 {
                        diff_has_changes = true;
                    }
                    if let Some(obj) = payload.as_object_mut() {
                        obj.insert("diff".into(), diff_val);
                    }
                }
            }
        }
        if args.webhook_on_diff_only && !diff_has_changes {
            println!("Webhook: skipped — --webhook-on-diff-only and no new opens/closes since last scan.");
        } else {
            match tokio::task::spawn_blocking({
                let url = url.to_string();
                move || post_webhook(&url, &payload)
            })
            .await
            {
                Ok(Ok(())) => println!("Webhook: posted summary to {}", url),
                Ok(Err(e)) => eprintln!("Webhook: failed ({}) — continuing.", e),
                Err(e) => eprintln!("Webhook: join error ({}) — continuing.", e),
            }
        }
    }

    // Auto-remove any zero-byte output files so the user isn't left with
    // clutter like an empty httpx_results.txt when httpx found nothing.
    // Keeps the output folder focused on data that actually has content.
    let cleanup_candidates = [
        &http_targets_path,
        &enrich_out,
        &nuclei_out,
        &jsonl_path,
        &diff_path,
    ];
    let mut removed: Vec<&PathBuf> = Vec::new();
    for p in cleanup_candidates {
        if let Ok(meta) = fs::metadata(p) {
            if meta.len() == 0 {
                if fs::remove_file(p).is_ok() {
                    removed.push(p);
                }
            }
        }
    }
    if !removed.is_empty() {
        println!(
            "Cleaned up {} empty file(s) from {:?}:",
            removed.len(),
            out_dir
        );
        for p in removed {
            if let Some(name) = p.file_name() {
                println!("  - {}", name.to_string_lossy());
            }
        }
    }

    // Compact end-of-scan summary line. Puts the output path where eyes
    // naturally land (bottom of terminal) + one-line recap of what
    // happened. Colored by result count: bright green if anything opened,
    // dim if the scan came up empty.
    let total_s = started.elapsed().as_secs_f64();
    let line_color = if summary.open > 0 { "1;32" } else { "2" };
    println!(
        "\n{}",
        cfmt(
            line_color,
            &format!(
                "Results: {} open · {:.2}s · {}",
                summary.open,
                total_s,
                out_dir.display(),
            ),
        )
    );

    // v0.14.2 — list every artefact we wrote, one per line, so users can
    // copy-paste the paths straight into their next pipeline stage
    // (jq / grep / curl / ffuf / xargs / …). Each is annotated with its
    // purpose + line count so the user knows at a glance which file to
    // reach for. Only shown when any artefact is non-empty.
    let mut artefacts: Vec<(&PathBuf, &str)> = Vec::new();
    let candidates: &[(&PathBuf, &str)] = &[
        (&jsonl_path,           "open_ports.jsonl    — per-port JSON records (the canonical output; all enrichment here)"),
        (&http_targets_path,    "http_targets.txt    — URL list of HTTP candidates (nuclei input)"),
        (&enrich_out,            "enrichment_results.txt — URL / status / length / title per HTTP target"),
        (&nuclei_out,           "nuclei_results.txt  — nuclei scan findings"),
        (&summary_path,         "scan_summary.json   — totals + counts + timings"),
        (&diff_path,            "scan_diff.json      — opens/closes since last run"),
        (&domains_json_path,    "domains.json        — domain resolution + CDN detection (structured)"),
        (&origin_domains_path,  "origin_domains.txt  — domains that survived CDN filter (pipe to httpx/ffuf)"),
        (&cdn_skipped_path,     "cdn_skipped.txt     — domains skipped as CDN-fronted (domain<TAB>provider)"),
        (&dns_failed_path,      "dns_failed.txt      — domains with NXDOMAIN / timeout (domain<TAB>reason)"),
    ];
    for (p, desc) in candidates {
        if let Ok(meta) = std::fs::metadata(p) {
            if meta.len() > 0 {
                artefacts.push((*p, *desc));
            }
        }
    }
    if !artefacts.is_empty() {
        println!("\n{}", cfmt("1", "Artefacts written:"));
        for (p, desc) in &artefacts {
            println!("  {}", cfmt("2", &format!("{:<60} {}", p.display(), desc)));
        }
    }

    println!("\n{}", cfmt("1;32", "--- WORKFLOW COMPLETE ---"));
    Ok(())
}
