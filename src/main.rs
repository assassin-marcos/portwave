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
use tokio::net::TcpStream;
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
    folder_name: String,

    #[arg(index = 2)]
    cidr_input: String,

    /// Path to comma-separated port list. Falls back to $PORTWAVE_PORTS, config file, then bundled list.
    #[arg(long)]
    port_file: Option<String>,

    /// Max concurrent probes (adaptive controller may shrink this)
    #[arg(short, long, default_value_t = 4000)]
    threads: usize,

    /// Phase-A connect timeout (ms) — discovery
    #[arg(long, default_value_t = 600)]
    timeout_ms: u64,

    /// Phase-B connect timeout (ms) — enrichment/banner
    #[arg(long, default_value_t = 1500)]
    enrich_timeout_ms: u64,

    /// Retry count for Phase-A timeouts only
    #[arg(long, default_value_t = 0)]
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

// Find the bundled ports file. Checks, in order:
//   $PORTWAVE_HOME/ports/portwave-top-ports.txt
//   <exe>/../share/portwave/ports/portwave-top-ports.txt   (Unix install layout)
//   <exe>/../ports/portwave-top-ports.txt                  (Windows install layout)
//   %LOCALAPPDATA%\portwave\ports\portwave-top-ports.txt   (Windows per-user install)
//   ./ports/portwave-top-ports.txt                         (running from repo root)
fn find_bundled_ports() -> Option<String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(h) = std::env::var("PORTWAVE_HOME") {
        candidates.push(PathBuf::from(h).join("ports/portwave-top-ports.txt"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("../share/portwave/ports/portwave-top-ports.txt"));
            candidates.push(dir.join("../ports/portwave-top-ports.txt"));
            candidates.push(dir.join("ports/portwave-top-ports.txt"));
        }
    }
    #[cfg(windows)]
    {
        if let Ok(a) = std::env::var("LOCALAPPDATA") {
            candidates.push(PathBuf::from(a).join("portwave/ports/portwave-top-ports.txt"));
        }
    }
    candidates.push(PathBuf::from("ports/portwave-top-ports.txt"));
    for c in candidates {
        if c.is_file() {
            return c.to_str().map(|s| s.to_string());
        }
    }
    None
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

fn load_ports(path: &str) -> Vec<u16> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let mut ports: Vec<u16> = content
                .split(|c: char| c == ',' || c.is_whitespace())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .filter_map(|p| p.parse::<u16>().ok())
                .collect();
            ports.sort_unstable();
            ports.dedup();
            ports
        }
        Err(_) => {
            eprintln!("!! WARNING: could not read {}. Using fallback top ports.", path);
            vec![21, 22, 80, 443, 8080, 8443]
        }
    }
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
            match tokio::time::timeout(timeout, TcpStream::connect(&sa)).await {
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
    };

    let start = Instant::now();
    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(&sa)).await {
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
            tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(&sa)).await
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
                // Mark "still alive" as soon as the iterator yields *anything*.
                // (Bug fix: previously `any = true` was below the usability
                // check, so a /24 starting with .0 the network address would
                // make us bail out after consuming a single IP.)
                any = true;
                if !is_usable_ipv4_host(net, ip) {
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

// ────────────────────────── Main ──────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    raise_fd_limit();
    let cfg = load_config();

    let output_root = resolve_path(
        args.output_dir.as_deref(),
        "PORTWAVE_OUTPUT_DIR",
        &cfg,
        "PORTWAVE_OUTPUT_DIR",
        "./scans",
    );
    let base = PathBuf::from(&output_root);
    let out_dir = base.join(&args.folder_name);
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

    let bundled = find_bundled_ports().unwrap_or_else(|| String::new());
    let default_ports = if !bundled.is_empty() { bundled } else { String::from("<builtin-top-6>") };
    let port_path = resolve_path(
        args.port_file.as_deref(),
        "PORTWAVE_PORTS",
        &cfg,
        "PORTWAVE_PORTS",
        &default_ports,
    );
    println!("Loading ports from: {}", port_path);
    let ports = load_ports(&port_path);
    if ports.is_empty() {
        eprintln!("Error: port list empty.");
        return Ok(());
    }

    let nets: Vec<IpNetwork> = args
        .cidr_input
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.parse::<IpNetwork>() {
            Ok(n) => Some(n),
            Err(_) => {
                eprintln!("Skipping invalid CIDR: {}", s);
                None
            }
        })
        .collect();
    if nets.is_empty() {
        eprintln!("No valid CIDRs.");
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
    let prod = {
        let st = stats.clone();
        let skip = Arc::new(skip_set);
        let nets = nets.clone();
        let ports = ports.clone();
        tokio::spawn(async move { producer(work_tx, nets, ports, skip, st).await })
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
            });
        }
    }

    open_records.sort_by(|a, b| (a.ip.as_str(), a.port).cmp(&(b.ip.as_str(), b.port)));
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
    }
    jsonl.flush()?;
    raw.flush()?;
    nuc.flush()?;

    let summary = ScanSummary {
        folder: args.folder_name.clone(),
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
