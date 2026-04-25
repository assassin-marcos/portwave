// ────────────────────────── src/ssl_scan.rs ──────────────────────────
//
// Native SSL/TLS recon. Replaces the historical "shell out to nuclei
// -tags ssl" approach with a direct OpenSSL handshake + peer-cert
// inspection. Same lenient X.509 parsing as the rest of the toolchain
// (reuses the vendored OpenSSL from native-tls-vendored), so it behaves
// identically to reqwest on quirky legacy certs.
//
// Output goal: nuclei-style bracketed lines so users can pipe the file
// into the same downstream tooling they already use:
//
//   [ssl-dns-names] [ssl] [info] adityasec.com:443 ["adityasec.com"]
//   [ssl-issuer]    [ssl] [info] adityasec.com:443 ["GoDaddy.com"]
//
// Why these two templates only:
//   - ssl-dns-names: the SAN list — primary signal for "what other
//     root domains live behind this IP"
//   - ssl-issuer: helps identify the hosting/CDN (Cloudflare,
//     Let's Encrypt, GoDaddy, …) which often reveals the asset owner

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// One probe target. `sni` is what we send in the TLS ClientHello —
/// usually a resolved hostname; falls back to the IP literal when the
/// scan came from a bare CIDR / IP arg with no domain context.
#[derive(Debug, Clone)]
pub struct SslTarget {
    pub addr: SocketAddr,
    pub sni: String,
}

/// One probe outcome. Empty `sans` means the cert had no SAN extension
/// (rare on modern certs — pre-2017 leaf certs sometimes used CN only;
/// in that case probe_blocking falls back to the CN as a synthetic SAN
/// so the field is never empty for a successful probe).
#[derive(Debug, Clone)]
pub struct SslRecord {
    pub addr: SocketAddr,
    pub sni: String,
    pub sans: Vec<String>,
}

/// Run SSL probes against `targets` with bounded concurrency. Each
/// probe is a single TLS handshake on a `spawn_blocking` thread —
/// portwave's runtime is configured with max_blocking_threads = 2048
/// (see main.rs), so concurrency above that just queues.
///
/// Per-probe timeout is fixed at 5 s (TCP + TLS handshake combined).
/// Returns one record per successful probe; failed handshakes
/// (connection refused, timeout, non-TLS port, etc.) are silently
/// dropped — they're not findings.
pub async fn run(targets: Vec<SslTarget>, concurrency: usize) -> Vec<SslRecord> {
    if targets.is_empty() {
        return Vec::new();
    }
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(targets.len());
    for t in targets {
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let res = tokio::task::spawn_blocking(move || probe_blocking(&t)).await.ok()?;
            res
        }));
    }
    let mut out = Vec::new();
    for h in handles {
        if let Ok(Some(rec)) = h.await {
            out.push(rec);
        }
    }
    out
}

/// Single blocking TLS probe. Connects, handshakes with NO verification
/// (we just want the cert metadata, not to validate it), pulls the
/// peer cert, extracts SANs + issuer-org. Times out at 5 s combined.
fn probe_blocking(t: &SslTarget) -> Option<SslRecord> {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).ok()?;
    // Scanner use case: we WANT to see the cert no matter what (expired,
    // self-signed, name-mismatched, IoT quirks). Same posture as the
    // existing reqwest client (danger_accept_invalid_certs).
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let sock = TcpStream::connect_timeout(&t.addr, Duration::from_secs(5)).ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(5))).ok();

    // SNI — empty / IP-literal SNI makes some servers RST the handshake,
    // so we always send the configured SNI string. Servers that reject
    // unknown SNIs return their default cert; we still get something.
    let mut stream = connector.connect(&t.sni, sock).ok()?;

    let cert = stream.ssl().peer_certificate()?;

    // SAN list — the primary signal. Modern certs have it; older
    // CN-only certs return None and we synthesize from CN below.
    let mut sans: Vec<String> = Vec::new();
    if let Some(stack) = cert.subject_alt_names() {
        for n in stack.iter() {
            if let Some(s) = n.dnsname() {
                sans.push(s.to_string());
            }
        }
    }
    if sans.is_empty() {
        // Fallback: use the CN as a single-element SAN list. Same
        // behaviour as nuclei's ssl-dns-names template when the cert
        // predates RFC 6125.
        for entry in cert.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME) {
            if let Ok(s) = entry.data().as_utf8() {
                sans.push(s.to_string());
            }
        }
    }

    // Trigger a graceful shutdown so the server's socket can close
    // cleanly; ignore errors (we already have what we need.)
    let _ = stream.shutdown();

    Some(SslRecord {
        addr: t.addr,
        sni: t.sni.clone(),
        sans,
    })
}

/// Compose the host:port label used in both the file output and the
/// terminal tree. Prefers the SNI (resolved hostname) over the bare
/// IP; falls back to IP for direct-IP scans without DNS context.
pub fn host_label(rec: &SslRecord) -> String {
    if rec.sni.is_empty() || rec.sni == rec.addr.ip().to_string() {
        format!("{}:{}", rec.addr.ip(), rec.addr.port())
    } else {
        format!("{}:{}", rec.sni, rec.addr.port())
    }
}

/// Format one record as a single nuclei-style `[ssl-dns-names]` line for
/// the file output (`ssl_findings.txt`). Matches the exact line shape
/// `nuclei -tags ssl -severity info` produces, so the file slots into
/// the same downstream tooling. v0.16.0 dropped the `[ssl-issuer]` line
/// per user request — only DNS names are useful for "find more root
/// domains from this IP" recon.
pub fn format_file_line(rec: &SslRecord) -> Option<String> {
    if rec.sans.is_empty() {
        return None;
    }
    let sans_quoted: Vec<String> = rec.sans.iter().map(|s| format!("\"{}\"", s)).collect();
    Some(format!(
        "[ssl-dns-names] [ssl] [info] {} [{}]",
        host_label(rec),
        sans_quoted.join(",")
    ))
}
