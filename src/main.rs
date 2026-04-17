use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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

    /// Comma-separated CIDRs, IPs, or IP ranges (e.g. "203.0.113.0/24,1.2.3.4,5.6.7.10-5.6.7.20")
    #[arg(index = 2)]
    cidr_input: Option<String>,

    /// File with one target per line (CIDR, single IP, or IP range). Merged with <CIDR_INPUT>.
    #[arg(long)]
    input_file: Option<String>,

    /// Comma-separated ASNs (e.g. "AS13335,AS15169"). Expanded to CIDRs via RIPE stat.
    #[arg(long)]
    asn: Option<String>,

    /// Comma-separated CIDRs / IPs / IP ranges to SKIP (scope exclusions).
    #[arg(long)]
    exclude: Option<String>,

    /// Comma-separated ports and port ranges (e.g. "22,80,443,8000-9000").
    /// Takes precedence over --port-file and the embedded list.
    #[arg(long)]
    ports: Option<String>,

    /// Path to comma-separated port list. Falls back to $PORTWAVE_PORTS, config file, then bundled list.
    #[arg(long)]
    port_file: Option<String>,

    /// Max concurrent probes (adaptive controller may shrink this).
    /// 1500 is a sweet spot on most systems — higher values cause
    /// ephemeral-port exhaustion on long scans.
    #[arg(short, long, default_value_t = 1500)]
    threads: usize,

    /// Phase-A connect timeout (ms) — discovery. 800 ms catches slow
    /// firewalled hosts without bloating total runtime on cold targets.
    #[arg(long, default_value_t = 800)]
    timeout_ms: u64,

    /// Phase-B connect timeout (ms) — enrichment/banner
    #[arg(long, default_value_t = 1500)]
    enrich_timeout_ms: u64,

    /// Retry count for Phase-A timeouts only. 1 catches transient SYN
    /// drops without doubling scan time (only timeouts retry, not RSTs).
    #[arg(long, default_value_t = 1)]
    retries: u8,

    /// Base output directory. Falls back to $PORTWAVE_OUTPUT_DIR, config file, then ./scans.
    #[arg(long)]
    output_dir: Option<String>,

    #[arg(long, default_value_t = 150)]
    httpx_threads: usize,

    #[arg(long)]
    httpx_paths: Option<String>,

    #[arg(long, default_value_t = false)]
    httpx_follow_redirects: bool,

    #[arg(long, default_value_t = 50)]
    nuclei_concurrency: usize,

    #[arg(long, default_value_t = 200)]
    nuclei_rate: usize,

    #[arg(long, default_value_t = false)]
    no_httpx: bool,

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

    /// Disable adaptive concurrency controller
    #[arg(long, default_value_t = false)]
    no_adaptive: bool,

    /// Pass nuclei -tags based on detected protocols
    #[arg(long, default_value_t = false)]
    tags_from_banner: bool,

    /// Download the latest portwave release for this OS+arch and replace the
    /// running binary in place (no rebuild needed). Requires no positional args.
    #[arg(long, short = 'u', default_value_t = false)]
    update: bool,

    /// Just check if a newer version is available, then exit.
    #[arg(long, default_value_t = false)]
    check_update: bool,

    /// Suppress the startup "update available" banner.
    #[arg(long, default_value_t = false)]
    no_update_check: bool,

    /// Suppress the startup ASCII banner art.
    #[arg(long, default_value_t = false)]
    no_art: bool,

    /// Suppress both the banner and the update notice (equivalent to --no-art --no-update-check).
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
}

struct Stats {
    shutdown: AtomicBool,
    attempts: AtomicU64,
    timeouts: AtomicU64,
    opens: AtomicU64,
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
    ports
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
    for p in &paths {
        let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
        if !seen.insert(canon) {
            continue;
        }
        if !p.is_file() {
            continue; // only refresh files that already existed
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
    if refreshed == 0 {
        println!("(no on-disk ports files to refresh; embedded list is in the binary)");
    }
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
    let mut out = Vec::with_capacity(128);
    for line in CDN_RANGES_RAW.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((cidr, provider)) = line.split_once('|') {
            if let Ok(n) = cidr.trim().parse::<IpNetwork>() {
                // Leak the provider name to get a &'static str — the list is
                // small and lives for process lifetime anyway.
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

fn which(bin: &str) -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if Path::new(dir).join(bin).is_file() {
                return true;
            }
        }
    }
    false
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
    hit_tx: mpsc::UnboundedSender<SocketAddr>,
    sem: Arc<Semaphore>,
    stats: Arc<Stats>,
    pb: ProgressBar,
    timeout: Duration,
    retries: u8,
) {
    while let Ok(sa) = rx.recv_async().await {
        if stats.shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Ok(permit) = sem.clone().acquire_owned().await else {
            break;
        };
        let mut opened = false;
        for attempt in 0..=retries {
            match tokio::time::timeout(timeout, tcp_probe(sa)).await {
                Ok(Ok(_)) => {
                    opened = true;
                    break;
                }
                Ok(Err(_)) => break, // refused / unreachable
                Err(_) => {
                    stats.timeouts.fetch_add(1, Ordering::Relaxed);
                    if attempt == retries {
                        break;
                    }
                }
            }
        }
        drop(permit);
        stats.attempts.fetch_add(1, Ordering::Relaxed);
        if opened {
            stats.opens.fetch_add(1, Ordering::Relaxed);
            let _ = hit_tx.send(sa);
            pb.set_message(format!("open: {}", sa));
        }
        pb.inc(1);
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

async fn adaptive_monitor(stats: Arc<Stats>, sem: Arc<Semaphore>, max: usize) {
    let mut prev_a = 0u64;
    let mut prev_t = 0u64;
    let mut current = max;
    let min = (max / 16).max(64);

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if stats.shutdown.load(Ordering::Relaxed) {
            break;
        }
        let a = stats.attempts.load(Ordering::Relaxed);
        let t = stats.timeouts.load(Ordering::Relaxed);
        let da = a.saturating_sub(prev_a);
        let dt = t.saturating_sub(prev_t);
        prev_a = a;
        prev_t = t;
        if da < 200 {
            continue;
        }
        let ratio = dt as f64 / da as f64;
        if ratio > 0.30 && current > min {
            let shrink = (current / 4).max(1).min(current - min);
            if let Ok(p) = sem.clone().acquire_many_owned(shrink as u32).await {
                p.forget();
                current -= shrink;
                eprintln!("[adaptive] timeout ratio {:.0}% — shrinking to {}", ratio * 100.0, current);
            }
        } else if ratio < 0.05 && current < max {
            let grow = ((max - current) / 4).max(1);
            sem.add_permits(grow);
            current += grow;
        }
    }
}

// ────────────────────────── Producer ──────────────────────────

async fn producer(
    tx: flume::Sender<SocketAddr>,
    nets: Vec<IpNetwork>,
    ports: Vec<u16>,
    skip: Arc<HashSet<SocketAddr>>,
    exclude: Arc<Vec<IpNetwork>>,
    stats: Arc<Stats>,
) {
    // Round-robin across subnets at IP granularity.
    let mut iters: Vec<_> = nets.iter().map(|n| (n.clone(), n.iter())).collect();
    loop {
        if stats.shutdown.load(Ordering::Relaxed) {
            return;
        }
        let mut any = false;
        for (net, it) in iters.iter_mut() {
            if let Some(ip) = it.next() {
                any = true;
                if !is_usable_ipv4_host(net, ip) {
                    continue;
                }
                // Skip IPs that fall in any --exclude range.
                if exclude.iter().any(|e| e.contains(ip)) {
                    continue;
                }
                for &port in &ports {
                    let sa = SocketAddr::new(ip, port);
                    if skip.contains(&sa) {
                        continue;
                    }
                    if tx.send_async(sa).await.is_err() {
                        return;
                    }
                    if stats.shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                }
            }
        }
        if !any {
            break;
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

const BANNER_ART: &str = r"
 ____   ___  ____ _______        ___   __     ___________
|  _ \ / _ \|  _ \_   _\ \      / / \ \ \ \   / / ____ __|
| |_) | | | | |_) || |  \ \ /\ / / _ \ \ \ \ / / |__|  _|
|  __/| |_| |  _ < | |   \ V  V / / \ \ \ \ V /|  __||
|_|    \___/|_| \_\|_|    \_/\_/_/   \_\ \_\_/ |_____|";

fn print_banner() {
    // ANSI cyan for the art, bold for the byline.
    eprintln!("\x1b[36m{}\x1b[0m", BANNER_ART);
    eprintln!(
        "        \x1b[1mportwave {}\x1b[0m  \x1b[2m·\x1b[0m  \x1b[2mby assassin_marcos\x1b[0m  \x1b[2m·\x1b[0m  \x1b[2mgithub.com/assassin-marcos/portwave\x1b[0m",
        env!("CARGO_PKG_VERSION")
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

fn print_update_banner(latest: &str) {
    eprintln!();
    eprintln!(
        "\x1b[33m[!] portwave update available: {} → {}.\x1b[0m",
        env!("CARGO_PKG_VERSION"),
        latest
    );
    eprintln!("\x1b[33m    Run `portwave --update` to install (no rebuild needed).\x1b[0m");
    eprintln!();
}

// Fast, cached startup check. Skipped if disabled or in CI/test environments.
async fn maybe_show_update_banner(disabled: bool) {
    if disabled || std::env::var("PORTWAVE_NO_UPDATE_CHECK").is_ok() {
        return;
    }
    let cache_path = update_cache_path();

    // Try cached value first (24 h TTL).
    if let Some(p) = &cache_path {
        if let Ok(meta) = fs::metadata(p) {
            if let Ok(age) = meta.modified().ok().and_then(|t| t.elapsed().ok()).ok_or(()) {
                if age < Duration::from_secs(86_400) {
                    if let Ok(latest) = fs::read_to_string(p) {
                        let latest = latest.trim().to_string();
                        if !latest.is_empty()
                            && version_is_newer(&latest, env!("CARGO_PKG_VERSION"))
                        {
                            print_update_banner(&latest);
                        }
                        return;
                    }
                }
            }
        }
    }

    // No fresh cache — fetch with a short timeout so a slow network never
    // blocks the actual scan.
    let res = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(fetch_latest_version),
    )
    .await;

    if let Ok(Ok(Ok(Some(latest)))) = res {
        if let Some(p) = cache_path {
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&p, &latest);
        }
        if version_is_newer(&latest, env!("CARGO_PKG_VERSION")) {
            print_update_banner(&latest);
        }
    }
}

async fn run_update() -> anyhow::Result<()> {
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
        }
    }
    Ok(())
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

// ────────────────────────── Main ──────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Banner art — first thing on screen (but skip when piped or quieted).
    let show_art = !args.quiet && !args.no_art && atty_like_stderr();
    if show_art {
        print_banner();
    }

    // Update flows short-circuit early — they don't need positional args.
    if args.update {
        return run_update().await;
    }
    if args.check_update {
        return run_check_update().await;
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
    maybe_show_update_banner(args.no_update_check || args.quiet).await;

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
    let httpx_out = out_dir.join("httpx_results.txt");
    let nuclei_out = out_dir.join("nuclei_results.txt");

    // Resume — read existing jsonl into skip set.
    let mut skip_set: HashSet<SocketAddr> = HashSet::new();
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

    // Progress bar — spinner for huge totals, bar otherwise.
    let pb = if scanned_estimate > 10_000_000 {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner} [{elapsed_precise}] scanned {pos} open {msg}",
            )
            .unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(200));
        pb
    } else {
        let pb = ProgressBar::new(scanned_estimate.max(1));
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner} [{elapsed_precise}] {bar:40} {pos}/{len} ({percent}%) {msg}",
            )
            .unwrap(),
        );
        pb
    };

    let stats = Arc::new(Stats {
        shutdown: AtomicBool::new(false),
        attempts: AtomicU64::new(0),
        timeouts: AtomicU64::new(0),
        opens: AtomicU64::new(0),
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
    let (hit_tx, mut hit_rx) = mpsc::unbounded_channel::<SocketAddr>();

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

    let _ = prod.await;
    while workers.join_next().await.is_some() {}
    let _ = collector.await;

    pb.finish_with_message(format!("{} open", stats.opens.load(Ordering::Relaxed)));
    stats.shutdown.store(true, Ordering::Relaxed); // stop monitor
    if let Some(m) = monitor {
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
    let mut open_records: Vec<OpenPort> = preserved; // from resume
    if !hits.is_empty() && !args.no_banner {
        println!("--- PHASE B: ENRICHMENT ({} hits) ---", hits.len());
        let enrich_sem = Arc::new(Semaphore::new(args.threads.min(1000)));
        let mut set: JoinSet<OpenPort> = JoinSet::new();
        let t_b = Duration::from_millis(args.enrich_timeout_ms);
        let sniff = !args.no_tls_sniff;
        let want_banner = !args.no_banner;
        for sa in hits.drain(..) {
            let p = enrich_sem.clone().acquire_owned().await.unwrap();
            set.spawn(async move {
                let r = enrich(sa, t_b, sniff, want_banner).await;
                drop(p);
                r
            });
        }
        while let Some(Ok(op)) = set.join_next().await {
            open_records.push(op);
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

    open_records.sort_by(|a, b| (a.ip.as_str(), a.port).cmp(&(b.ip.as_str(), b.port)));
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

    for op in &open_records {
        writeln!(jsonl, "{}", serde_json::to_string(op)?)?;
        let ip: IpAddr = op.ip.parse()?;
        let sa = SocketAddr::new(ip, op.port);
        writeln!(raw, "{}", sa)?;
        writeln!(nuc, "{}", format_for_nuclei(&ip, op.port, op.tls))?;
        *by_port.entry(op.port).or_insert(0) += 1;
        *by_proto
            .entry(op.protocol.clone().unwrap_or_else(|| "unknown".into()))
            .or_insert(0) += 1;
        if let Some(c) = &op.cdn {
            *by_cdn.entry(c.clone()).or_insert(0) += 1;
        }
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
    };
    fs::write(&summary_path, serde_json::to_string_pretty(&summary)?)?;
    println!("Summary: {:?}", summary_path);
    println!(
        "Totals — attempts: {}, timeouts: {}, open: {}",
        summary.attempts, summary.timeouts, summary.open
    );

    if open_records.is_empty() {
        println!("No open ports. Done.");
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
    if !args.no_httpx && which("httpx") {
        println!("\n--- httpx ---");
        let mut cmd = Command::new("httpx");
        cmd.arg("-l").arg(&raw_path)
            .arg("-sc")
            .arg("-cl")
            .arg("-location")
            .arg("-title")
            .arg("-nc")
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
    } else if args.no_httpx {
        println!("Skipping httpx (--no-httpx).");
    } else {
        eprintln!("httpx not in PATH; skipping.");
    }

    // ── nuclei ──
    if !args.no_nuclei && which("nuclei") {
        println!("\n--- nuclei ---");
        let mut cmd = Command::new("nuclei");
        cmd.arg("-l").arg(&nuclei_path)
            .arg("-c").arg(args.nuclei_concurrency.to_string())
            .arg("-rl").arg(args.nuclei_rate.to_string())
            .arg("-o").arg(&nuclei_out);
        if args.tags_from_banner && !by_proto.is_empty() {
            let tags: Vec<&str> = by_proto
                .keys()
                .filter_map(|p| match p.as_str() {
                    "http" => Some("http"),
                    "ssh" => Some("ssh"),
                    "smtp" => Some("smtp"),
                    "ftp" => Some("ftp"),
                    "tls" => Some("ssl"),
                    _ => None,
                })
                .collect();
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
    } else if args.no_nuclei {
        println!("Skipping nuclei (--no-nuclei).");
    } else {
        eprintln!("nuclei not in PATH; skipping.");
    }

    println!("\n--- WORKFLOW COMPLETE ---");
    Ok(())
}
