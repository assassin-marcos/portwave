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

// ────────────────────────── CLI ──────────────────────────

#[derive(Parser, Debug, Clone)]
#[command(
    name = "portwave",
    about = "portwave — hybrid IPv4/IPv6 port scanner + httpx + nuclei recon pipeline",
    version
)]
struct Args {
    #[arg(index = 1)]
    folder_name: Option<String>,

    /// Comma-separated CIDRs, IPs, or IP ranges
    #[arg(index = 2)]
    cidr_input: Option<String>,

    /// Targets file (one per line); merges with <CIDR_INPUT>
    #[arg(short = 'i', long)]
    input_file: Option<String>,

    /// Comma-separated ASNs (e.g. "AS13335") — expanded via RIPE stat
    #[arg(short = 'a', long)]
    asn: Option<String>,

    /// Comma-separated CIDRs/IPs/ranges to exclude from scope
    #[arg(short = 'e', long)]
    exclude: Option<String>,

    /// Comma-separated ports/ranges (e.g. "22,80,443,8000-9000")
    #[arg(short = 'p', long)]
    ports: Option<String>,

    /// Path to a comma-separated port-list file
    #[arg(short = 'f', long)]
    port_file: Option<String>,

    /// Max concurrent probes (adaptive controller may shrink)
    #[arg(short = 't', long, default_value_t = 1500)]
    threads: usize,

    /// Phase-A (discovery) connect timeout, ms
    #[arg(short = 'T', long, default_value_t = 800)]
    timeout_ms: u64,

    /// Phase-B (banner) connect timeout, ms
    #[arg(long, default_value_t = 1500)]
    enrich_timeout_ms: u64,

    /// Retries for Phase-A timeouts only
    #[arg(short = 'r', long, default_value_t = 1)]
    retries: u8,

    /// Output directory (default: ./scans)
    #[arg(short = 'o', long)]
    output_dir: Option<String>,

    /// httpx -threads concurrency
    #[arg(long, default_value_t = 150)]
    httpx_threads: usize,

    /// Extra paths for httpx besides `/` (comma-separated)
    #[arg(long)]
    httpx_paths: Option<String>,

    /// Follow HTTP redirects in httpx (auto with --asn)
    #[arg(long, default_value_t = false)]
    httpx_follow_redirects: bool,

    /// nuclei -c (concurrency)
    #[arg(long, default_value_t = 25)]
    nuclei_concurrency: usize,

    /// nuclei -rl (per-host rate limit)
    #[arg(long, default_value_t = 200)]
    nuclei_rate: usize,

    /// nuclei -max-host-error
    #[arg(long, default_value_t = 25)]
    nuclei_max_host_error: usize,

    /// Run nuclei against every open port (skip HTTP filter)
    #[arg(long, default_value_t = false)]
    nuclei_all_ports: bool,

    /// POST scan summary to this URL on completion
    #[arg(short = 'w', long)]
    webhook: Option<String>,

    /// Enable UDP discovery on well-known ports (opt-in)
    #[arg(short = 'U', long, default_value_t = false)]
    udp: bool,

    /// Refresh CDN/WAF edge CIDRs from upstream sources
    #[arg(long, default_value_t = false)]
    refresh_cdn: bool,

    /// Don't prompt to install httpx/nuclei if missing
    #[arg(long, default_value_t = false)]
    no_install_prompt: bool,

    /// Uninstall portwave (binary + share + cache)
    #[arg(short = 'X', long, default_value_t = false)]
    uninstall: bool,

    /// Skip the uninstall confirmation prompt
    #[arg(short = 'y', long, default_value_t = false)]
    yes: bool,

    /// Skip the httpx HTTP-fingerprint step
    #[arg(long, default_value_t = false)]
    no_httpx: bool,

    /// Skip the nuclei vulnerability-scan step
    #[arg(long, default_value_t = false)]
    no_nuclei: bool,

    /// Disable resume from previous open_ports.jsonl
    #[arg(long, default_value_t = false)]
    no_resume: bool,

    /// Disable banner grab (Phase B)
    #[arg(long, default_value_t = false)]
    no_banner: bool,

    /// Disable TLS sniff on non-443 ports
    #[arg(long, default_value_t = false)]
    no_tls_sniff: bool,

    /// Disable the adaptive concurrency controller
    #[arg(long, default_value_t = false)]
    no_adaptive: bool,

    /// Filter nuclei templates by detected protocol (auto with --asn)
    #[arg(long, default_value_t = false)]
    tags_from_banner: bool,

    /// Download + install the latest portwave release
    #[arg(short = 'u', long, default_value_t = false)]
    update: bool,

    /// Check for a newer version, then exit
    #[arg(short = 'c', long, default_value_t = false)]
    check_update: bool,

    /// Suppress the "update available" startup banner
    #[arg(long, default_value_t = false)]
    no_update_check: bool,

    /// Suppress only the interactive update prompt
    #[arg(long, default_value_t = false)]
    no_update_prompt: bool,

    /// Suppress the ASCII banner art
    #[arg(long, default_value_t = false)]
    no_art: bool,

    /// Suppress banner + update notice (= --no-art --no-update-check)
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
    /// httpx subprocess wall time. 0 unless httpx ran to completion.
    #[serde(default)]
    httpx_ms: u128,
    /// nuclei subprocess wall time. 0 unless nuclei ran to completion.
    #[serde(default)]
    nuclei_ms: u128,
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
#[cfg(unix)]
fn raise_fd_limit() {
    unsafe {
        let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
            let want: libc::rlim_t = 50_000;
            if rlim.rlim_max < want {
                rlim.rlim_max = want;
            }
            rlim.rlim_cur = want.min(rlim.rlim_max);
            libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
        }
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

// Read --input-file: one target per line, comments (#) + blanks ignored.
fn read_input_file(path: &str) -> anyhow::Result<Vec<IpNetwork>> {
    let content = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // A single line may itself contain comma-separated entries.
        out.extend(expand_targets(line));
    }
    Ok(out)
}

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

fn format_for_nuclei(ip: &IpAddr, port: u16, tls: bool) -> String {
    let host = match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => format!("[{}]", v),
    };
    if tls {
        if port == 443 {
            format!("https://{}", host)
        } else {
            format!("https://{}:{}", host, port)
        }
    } else if port == 80 {
        format!("http://{}", host)
    } else if port == 443 {
        format!("https://{}", host)
    } else {
        format!("{}:{}", host, port)
    }
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
    const PB_BATCH: u64 = 64;
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
        .write_all(b"GET / HTTP/1.0\r\nHost: scan\r\nUser-Agent: ipv6scanner\r\n\r\n")
        .await
        .is_ok()
    {
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await
        {
            if n > 0 && buf.starts_with(b"HTTP/") {
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
                if send_or_shutdown(&tx, sa, &stats).await.is_err() {
                    return;
                }
            }
        }
    }
}

// Returns true if stderr looks like a terminal (so ANSI colour + banner art
// are safe). On non-TTY (piped / redirected / CI) we stay plain.
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
    if age > Duration::from_secs(3_600) {
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
    if let Ok(meta) = fs::metadata(&p) {
        if let Some(age) = meta.modified().ok().and_then(|t| t.elapsed().ok()) {
            if age < Duration::from_secs(300) {
                return;
            }
        }
    }
    // Slow path: GitHub round-trip. 1 s is enough for typical latencies
    // (~200-400 ms) and doesn't make the banner feel laggy.
    let res = tokio::time::timeout(
        Duration::from_secs(1),
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

async fn run_refresh_cdn() -> anyhow::Result<()> {
    println!("portwave: refreshing CDN ranges from upstream…");
    let mut entries: Vec<String> = Vec::new();

    // Cloudflare
    match ureq::get("https://www.cloudflare.com/ips-v4")
        .timeout(Duration::from_secs(15))
        .call()
    {
        Ok(r) => {
            let body = r.into_string().unwrap_or_default();
            let mut n = 0;
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                entries.push(format!("{}|cloudflare", line));
                n += 1;
            }
            println!("  cloudflare: {} CIDRs", n);
        }
        Err(e) => eprintln!("  cloudflare fetch failed: {}", e),
    }

    // Fastly
    match ureq::get("https://api.fastly.com/public-ip-list")
        .timeout(Duration::from_secs(15))
        .call()
    {
        Ok(r) => {
            let j: serde_json::Value = r.into_json().unwrap_or(serde_json::Value::Null);
            let mut n = 0;
            if let Some(arr) = j.get("addresses").and_then(|a| a.as_array()) {
                for v in arr {
                    if let Some(cidr) = v.as_str() {
                        entries.push(format!("{}|fastly", cidr));
                        n += 1;
                    }
                }
            }
            println!("  fastly: {} CIDRs", n);
        }
        Err(e) => eprintln!("  fastly fetch failed: {}", e),
    }

    // Non-API providers: carry forward the compiled-in snapshot entries
    // for providers we can't hit live (akamai/sucuri/imperva/stackpath/
    // bunnycdn/cachefly/keycdn).
    let mut forwarded = 0;
    for line in CDN_RANGES_RAW.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((_, provider)) = line.split_once('|') {
            if !matches!(provider.trim(), "cloudflare" | "fastly") {
                entries.push(line.to_string());
                forwarded += 1;
            }
        }
    }
    println!("  embedded providers carried over: {} CIDRs", forwarded);

    let path = cdn_cache_path()
        .ok_or_else(|| anyhow::anyhow!("could not resolve cache directory"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = entries.join("\n") + "\n";
    fs::write(&path, &content)?;
    println!("Wrote {} entries to {}", entries.len(), path.display());
    println!("portwave will use this file on next scan. Delete it to revert to embedded.");
    Ok(())
}

// ────────────────────────── Main ──────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();

    // ASN scans touch a much wider, noisier target set than hand-picked
    // CIDRs. Auto-enable the two flags that give the most useful results
    // in that context:
    //   --tags-from-banner      → nuclei only runs templates matching
    //                             detected protocols, avoiding template
    //                             floods against 10 K+ random hosts.
    //   --httpx-follow-redirects → most ASN hosts return 30x chains to
    //                             a portal / WAF; following them gives
    //                             meaningful status + title, not just
    //                             "[302] [Moved]".
    // The user can still disable these by editing their invocation; the
    // clap default_value_t means they don't need to be passed manually
    // under --asn. We print a one-line info note so the behaviour is
    // not surprising.
    if args.asn.is_some() {
        let mut notes: Vec<&str> = Vec::new();
        if !args.tags_from_banner {
            args.tags_from_banner = true;
            notes.push("--tags-from-banner");
        }
        if !args.httpx_follow_redirects {
            args.httpx_follow_redirects = true;
            notes.push("--httpx-follow-redirects");
        }
        if !notes.is_empty() && !args.quiet {
            eprintln!(
                "[asn] auto-enabled {} for maximum result coverage",
                notes.join(" + ")
            );
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
            eprintln!("usage: portwave <FOLDER_NAME> <CIDR_INPUT> [OPTIONS]");
            eprintln!("       portwave <FOLDER_NAME> --input-file targets.txt");
            eprintln!("       portwave <FOLDER_NAME> --asn AS13335");
            eprintln!("       portwave --update | --check-update");
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

    let raw_path = out_dir.join("targets.txt");
    let nuclei_path = out_dir.join("nuclei_targets.txt");
    let jsonl_path = out_dir.join("open_ports.jsonl");
    let summary_path = out_dir.join("scan_summary.json");
    let diff_path = out_dir.join("scan_diff.json");
    let httpx_out = out_dir.join("httpx_results.txt");
    let nuclei_out = out_dir.join("nuclei_results.txt");

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
    let _ = fs::remove_file(&raw_path);
    let _ = fs::remove_file(&nuclei_path);

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
    let ports = if let Some(spec) = &args.ports {
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
        eprintln!("Error: port list empty.");
        return Ok(());
    }

    // Merge targets from positional <CIDR_INPUT>, --input-file, and --asn.
    let mut nets: Vec<IpNetwork> = Vec::new();
    if let Some(raw) = &args.cidr_input {
        nets.extend(expand_targets(raw));
    }
    if let Some(path) = &args.input_file {
        match read_input_file(path) {
            Ok(v) => {
                println!("Loaded {} entries from {}", v.len(), path);
                nets.extend(v);
            }
            Err(e) => eprintln!("Failed to read --input-file {}: {}", path, e),
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

    // Dedupe / skip duplicates by string form.
    {
        let mut seen = std::collections::HashSet::new();
        nets.retain(|n| seen.insert(n.to_string()));
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
        eprintln!("No valid targets. Provide <CIDR_INPUT>, --input-file, or --asn.");
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

    // Always use a real progress bar — indicatif handles arbitrarily large
    // totals. The old spinner-mode template (engaged above 10M probes) had
    // a hardcoded "open" token that collided with the {msg} ("open: <sa>")
    // and rendered as "scanned 0 open open: 1.2.3.4:80". Gone.
    let pb = ProgressBar::new(scanned_estimate.max(1));
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner} [{elapsed_precise}] {bar:40} {pos}/{len} ({percent}%) {msg}",
        )
        .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(200));

    let stats = Arc::new(Stats {
        shutdown: AtomicBool::new(false),
        attempts: AtomicU64::new(0),
        timeouts: AtomicU64::new(0),
        opens: AtomicU64::new(0),
        local_errors: AtomicU64::new(0),
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
    let (work_tx, work_rx) = flume::bounded::<SocketAddr>(args.threads * 4);
    // Bounded so Phase A workers can't let the hit-receive queue grow
    // unbounded if the writer is slow. 2048 is generous — opens are rare
    // relative to probes (even a hot /24 rarely hits double-digit
    // open-rate per second).
    let (hit_tx, mut hit_rx) = mpsc::channel::<SocketAddr>(2048);

    // Writer: collects Phase-A hits into a shared Vec for Phase B.
    let phase_a_hits: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
    let collector = {
        let sink = phase_a_hits.clone();
        tokio::spawn(async move {
            while let Some(sa) = hit_rx.recv().await {
                sink.lock().unwrap().push(sa);
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

    // Producer.
    let exclude_arc = Arc::new(exclude_nets);
    let prod = {
        let st = stats.clone();
        let skip = Arc::new(skip_set);
        let nets = nets.clone();
        let ports = ports.clone();
        let exclude = exclude_arc.clone();
        tokio::spawn(async move { producer(work_tx, nets, ports, skip, exclude, st).await })
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

    // Collect & sort hits.
    let mut hits = {
        let mut v = phase_a_hits.lock().unwrap().clone();
        v.sort();
        v.dedup();
        v
    };
    println!("Phase A done: {} new open ports.", hits.len());

    // ── Phase B: enrichment ──
    let phase_b_started = Instant::now();
    let mut open_records: Vec<OpenPort> = preserved; // from resume
    let mut phase_b_ms: u128 = 0;
    if !hits.is_empty() && !args.no_banner {
        println!("--- PHASE B: ENRICHMENT ({} hits) ---", hits.len());
        // Snapshot the raw Phase A hits BEFORE enrichment runs, so that if
        // Ctrl+C aborts Phase B mid-way, we can still record the opens we
        // definitely found (just without banner/TLS detail). Without this,
        // v0.8.3 silently lost every Phase A hit that wasn't yet enriched
        // when a scan was cancelled — "Phase A done: 20" then "Totals —
        // open: 0" afterwards. See issue #16 style failure.
        let phase_a_hits_snapshot: Vec<SocketAddr> = hits.clone();
        let enrich_sem = Arc::new(Semaphore::new(args.threads.min(1000)));
        let mut set: JoinSet<OpenPort> = JoinSet::new();
        let t_b = Duration::from_millis(args.enrich_timeout_ms);
        let sniff = !args.no_tls_sniff;
        let want_banner = !args.no_banner;
        for sa in hits.drain(..) {
            if stats.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let Ok(p) = enrich_sem.clone().acquire_owned().await else { break; };
            set.spawn(async move {
                let r = enrich(sa, t_b, sniff, want_banner).await;
                drop(p);
                r
            });
        }
        // Shutdown-aware drain. Under Ctrl+C we abort any not-yet-finished
        // enrichment tasks so the scan exits within a second or two
        // instead of blocking on possibly-hanging banner reads.
        let mut shutdown_hit = false;
        while let Some(res) = set.join_next().await {
            if let Ok(op) = res {
                open_records.push(op);
            }
            if stats.shutdown.load(Ordering::Relaxed) {
                shutdown_hit = true;
                set.abort_all();
                // Drain whatever aborts resolve immediately, then bail.
                while let Some(res) = set.join_next().await {
                    if let Ok(op) = res {
                        open_records.push(op);
                    }
                }
                break;
            }
        }
        // If Phase B was cut short, back-fill any Phase A hit whose
        // enrichment task didn't complete with a minimal OpenPort record.
        // Otherwise we'd show "Phase A done: N" then "Totals — open: 0".
        if shutdown_hit {
            let enriched: std::collections::HashSet<SocketAddr> = open_records
                .iter()
                .filter_map(|op| {
                    op.ip.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, op.port))
                })
                .collect();
            let mut backfilled = 0usize;
            for sa in &phase_a_hits_snapshot {
                if !enriched.contains(sa) {
                    open_records.push(OpenPort {
                        ip: sa.ip().to_string(),
                        port: sa.port(),
                        rtt_ms: 0,
                        tls: sa.port() == 443,
                        protocol: None,
                        banner: Some("(Ctrl+C — enrichment skipped)".to_string()),
                        cdn: None,
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
    } else {
        // --no-banner: still need basic OpenPort entries.
        for sa in hits.drain(..) {
            open_records.push(OpenPort {
                ip: sa.ip().to_string(),
                port: sa.port(),
                rtt_ms: 0,
                tls: sa.port() == 443,
                protocol: None,
                banner: None,
                cdn: None,
            });
        }
    }
    if !hits.is_empty() || !args.no_banner {
        phase_b_ms = phase_b_started.elapsed().as_millis();
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
    let cdn_table = load_cdn_ranges();
    for op in &mut open_records {
        if op.cdn.is_some() {
            continue;
        }
        if let Ok(ip) = op.ip.parse::<IpAddr>() {
            if let Some(tag) = cdn_tag_for(ip, &cdn_table) {
                op.cdn = Some(tag.to_string());
            }
        }
    }
    open_records.dedup_by(|a, b| a.ip == b.ip && a.port == b.port);

    // ── Write artifacts ──
    let mut jsonl = BufWriter::new(
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&jsonl_path)?,
    );
    let mut raw = BufWriter::new(fs::File::create(&raw_path)?);
    let mut nuc = BufWriter::new(fs::File::create(&nuclei_path)?);
    let mut by_port: std::collections::BTreeMap<u16, u64> = Default::default();
    let mut by_proto: std::collections::BTreeMap<String, u64> = Default::default();
    let mut by_cdn: std::collections::BTreeMap<String, u64> = Default::default();

    let mut nuclei_skipped = 0usize;
    for op in &open_records {
        writeln!(jsonl, "{}", serde_json::to_string(op)?)?;
        let ip: IpAddr = op.ip.parse()?;
        let sa = SocketAddr::new(ip, op.port);
        writeln!(raw, "{}", sa)?;
        // Filter non-HTTP services out of the nuclei list unless --nuclei-all-ports.
        let include_in_nuclei = args.nuclei_all_ports
            || is_http_candidate(op.port, op.protocol.as_deref(), op.tls);
        if include_in_nuclei {
            writeln!(nuc, "{}", format_for_nuclei(&ip, op.port, op.tls))?;
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
    raw.flush()?;
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
        httpx_ms: 0,
        nuclei_ms: 0,
    };
    // Initial summary write — httpx/nuclei timings are filled in after
    // those subprocesses finish (see rewrite below).
    let mut summary = summary;
    fs::write(&summary_path, serde_json::to_string_pretty(&summary)?)?;
    println!("Summary: {:?}", summary_path);
    println!(
        "Totals — {} probes  ·  open: {}  ·  closed: {}  ·  filtered: {} ({:.1}%)  ·  local_err: {}",
        summary.attempts,
        summary.open,
        summary.closed,
        summary.timeouts,
        if summary.attempts > 0 {
            (summary.timeouts as f64 / summary.attempts as f64) * 100.0
        } else {
            0.0
        },
        summary.local_errors,
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
        // Even on 0-open runs, prune the zero-byte files (targets.txt,
        // nuclei_targets.txt, open_ports.jsonl) so the folder isn't
        // polluted with empty husks. Summary + diff are kept — they
        // carry the "I ran but found nothing" signal.
        for p in [&raw_path, &nuclei_path, &jsonl_path] {
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
    println!(
        "\n--- OPEN PORTS ({} total{}) ---",
        open_records.len(),
        if cdn_count > 0 {
            format!(", {} on CDN edge", cdn_count)
        } else {
            String::new()
        }
    );
    for op in &open_records {
        let host = match op.ip.parse::<IpAddr>() {
            Ok(IpAddr::V6(v)) => format!("[{}]", v),
            _ => op.ip.clone(),
        };
        let proto = op.protocol.as_deref().unwrap_or("unknown");
        let tls_tag = if op.tls { ", tls" } else { "" };
        let cdn_tag = match &op.cdn {
            Some(c) => format!(", cdn:{}", c),
            None => String::new(),
        };
        let banner = op.banner.as_deref().unwrap_or("");
        if banner.is_empty() {
            println!("  {}:{}  [{}{}{}]", host, op.port, proto, tls_tag, cdn_tag);
        } else {
            // Trim banner to one line, max 120 cols for terminal sanity.
            let b: String = banner.chars().take(120).collect();
            println!("  {}:{}  [{}{}{}]  {}", host, op.port, proto, tls_tag, cdn_tag, b);
        }
    }

    // ── httpx ──
    if args.no_httpx {
        println!("Skipping httpx (--no-httpx).");
    } else {
        // Resolve: env → config → PATH. Offer to install if still missing.
        let mut httpx_bin = resolve_tool("httpx", &cfg, "PORTWAVE_HTTPX_BIN");
        if httpx_bin.is_none() {
            let installed = offer_install(
                "httpx",
                "github.com/projectdiscovery/httpx/cmd/httpx",
                !args.no_install_prompt,
            );
            if installed {
                httpx_bin = resolve_tool("httpx", &cfg, "PORTWAVE_HTTPX_BIN");
            }
        }
        if let Some(bin) = httpx_bin {
            println!("\n--- httpx ({}) ---", bin.display());
            let httpx_started = Instant::now();
            let mut cmd = Command::new(&bin);
            cmd.arg("-l").arg(&raw_path)
                .arg("-sc")
                .arg("-cl")
                .arg("-location")
                .arg("-title")
                .arg("-nc")
                // -silent suppresses the ASCII banner + [WRN] dashboard noise
                // while still writing real findings to both stdout and -o.
                .arg("-silent")
                .arg("-threads").arg(args.httpx_threads.to_string())
                .arg("-timeout").arg("10")
                .arg("-retries").arg("1")
                .arg("-o").arg(&httpx_out);
            if args.httpx_follow_redirects {
                cmd.arg("-fr");
            }
            if let Some(p) = &args.httpx_paths {
                cmd.arg("-path").arg(p);
            }
            match cmd.status() {
                Ok(s) if s.success() => println!("httpx OK -> {:?}", httpx_out),
                Ok(s) => eprintln!("httpx exited {}", s),
                Err(e) => eprintln!("httpx launch failed: {}", e),
            }
            summary.httpx_ms = httpx_started.elapsed().as_millis();
        } else {
            eprintln!("httpx not found on PATH or in config — skipping. Set PORTWAVE_HTTPX_BIN or install httpx.");
        }
    }

    // ── nuclei ──
    if args.no_nuclei {
        println!("Skipping nuclei (--no-nuclei).");
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
            println!("\n--- nuclei ({}) ---", bin.display());
            let nuclei_started = Instant::now();
            let mut cmd = Command::new(&bin);
            cmd.arg("-l").arg(&nuclei_path)
                .arg("-c").arg(args.nuclei_concurrency.to_string())
                .arg("-rl").arg(args.nuclei_rate.to_string())
                .arg("-mhe").arg(args.nuclei_max_host_error.to_string())
                // -silent suppresses nuclei's ASCII banner + progress spam
                // while still writing findings to stdout + -o.
                .arg("-silent")
                .arg("-o").arg(&nuclei_out);
            if args.tags_from_banner && !by_proto.is_empty() {
            // Cover every protocol the banner classifier can emit (see
            // classify() in src/main.rs). Previously missed pop3 / imap /
            // smtp_or_ftp / udp/* and silently sent fewer tags than
            // warranted. Now we map or split each explicit protocol into
            // one or more nuclei `-tags` values.
            let mut tag_set: std::collections::BTreeSet<&'static str> =
                std::collections::BTreeSet::new();
            for p in by_proto.keys() {
                match p.as_str() {
                    "http" => { tag_set.insert("http"); }
                    "ssh"  => { tag_set.insert("ssh"); }
                    "smtp" => { tag_set.insert("smtp"); }
                    "ftp"  => { tag_set.insert("ftp"); }
                    "pop3" => { tag_set.insert("pop3"); }
                    "imap" => { tag_set.insert("imap"); }
                    "smtp_or_ftp" => {
                        tag_set.insert("smtp");
                        tag_set.insert("ftp");
                    }
                    "tls" => {
                        tag_set.insert("ssl");
                        // TLS on an open port very often fronts HTTPS,
                        // so include http templates too.
                        tag_set.insert("http");
                    }
                    _ => {
                        // "unknown", "udp/dns", "udp/*" etc. Don't add
                        // a tag — nuclei will still probe these targets
                        // but no extra filter from us.
                    }
                }
            }
            let tags: Vec<&str> = tag_set.into_iter().collect();
            if !tags.is_empty() {
                cmd.arg("-tags").arg(tags.join(","));
                println!("Nuclei tags: {}", tags.join(","));
            }
        }
            match cmd.status() {
                Ok(s) if s.success() => println!("nuclei OK -> {:?}", nuclei_out),
                Ok(s) => eprintln!("nuclei exited {}", s),
                Err(e) => eprintln!("nuclei launch failed: {}", e),
            }
            summary.nuclei_ms = nuclei_started.elapsed().as_millis();
        } else {
            eprintln!("nuclei not found on PATH or in config — skipping. Set PORTWAVE_NUCLEI_BIN or install nuclei.");
        }
    }

    // Rewrite summary so final httpx_ms / nuclei_ms land on disk.
    let _ = fs::write(&summary_path, serde_json::to_string_pretty(&summary)?);

    // Optional webhook — POSTs summary JSON (with diff merged in) once
    // everything else is on disk. Silent on failure by design so a flaky
    // collector never breaks the scan's exit code.
    if let Some(url) = args.webhook.as_deref() {
        let mut payload = serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null);
        if diff_path.exists() {
            if let Ok(diff_str) = fs::read_to_string(&diff_path) {
                if let Ok(diff_val) = serde_json::from_str::<serde_json::Value>(&diff_str) {
                    if let Some(obj) = payload.as_object_mut() {
                        obj.insert("diff".into(), diff_val);
                    }
                }
            }
        }
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

    // Auto-remove any zero-byte output files so the user isn't left with
    // clutter like an empty httpx_results.txt when httpx found nothing.
    // Keeps the output folder focused on data that actually has content.
    let cleanup_candidates = [
        &raw_path,
        &nuclei_path,
        &httpx_out,
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

    println!("\n--- WORKFLOW COMPLETE ---");
    Ok(())
}
