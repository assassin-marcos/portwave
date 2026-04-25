// ────────────────────────── src/domain.rs ──────────────────────────
//
// Domain / subdomain support for portwave (v0.14.0+).
//
// Responsibilities:
//   1. Classify an input line (one of CIDR, IP range, IPv4/IPv6 literal,
//      domain, or invalid) — lets a single `--input-file` hold mixed
//      content and route each line correctly.
//   2. Resolve a batch of domains to their A/AAAA records in parallel,
//      with a bounded-concurrency async pool.
//   3. Flag domains whose resolved IPs land on a known CDN edge range,
//      so the main scanner can skip them by default (no point probing
//      Cloudflare's edge when the user asked about origin.example.com).
//
// DNS resolver: `hickory-resolver` with direct UDP queries to Cloudflare
// (1.1.1.1) + Google (8.8.8.8). Faster and more predictable than the
// system resolver for bulk lookups; avoids surprises from misconfigured
// /etc/resolv.conf on scanning VPSes.
//
// Private-IP filter: A/AAAA records that point at RFC1918 / loopback /
// link-local / ULA space are dropped. These often appear in wildcard
// DNS sinkholes (e.g., `*.dev.internal → 10.0.0.1`) or misconfigured
// zones, and scanning them would either hit the scanner's own host or
// traverse the wrong network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use ipnetwork::IpNetwork;

/// One parsed entry from user input (CLI positional, `--input-file`, or
/// `--domain`). Each kind gets routed differently by `main()` — IP-ish
/// kinds go straight into the existing target-expansion path, Domain
/// kinds get resolved first.
#[derive(Debug, Clone)]
pub enum InputKind {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Cidr(IpNetwork),
    Ipv4Range(Ipv4Addr, Ipv4Addr),
    Domain(String),
    Invalid { raw: String, reason: &'static str },
}

/// Strip URL scheme + path + port (and userinfo, ports, brackets) from
/// a line, returning the bare host. Returns None if the line doesn't
/// look like a URL (no `://`). Lets users pipe httpx / gau / waymore
/// output straight into `-i` without preprocessing.
fn strip_url_to_host(raw: &str) -> Option<String> {
    let after_scheme = raw.split_once("://")?.1;
    // Drop path / query / fragment.
    let host_port = after_scheme.split(['/', '?', '#']).next().unwrap_or(after_scheme);
    // Drop userinfo (user:pass@host).
    let host_port = host_port.split_once('@').map_or(host_port, |(_, h)| h);
    // [ipv6]:port → just the IPv6 literal.
    if let Some(stripped) = host_port.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return Some(stripped[..end].to_string());
        }
    }
    // host:port (single colon, port is numeric) → just host.
    if let Some((host, port)) = host_port.rsplit_once(':') {
        if !host.contains(':') && port.parse::<u16>().is_ok() {
            return Some(host.to_string());
        }
    }
    Some(host_port.to_string())
}

/// Best-effort classification of one trimmed input line. Does not touch
/// the network. Order of checks matters — CIDR first (has `/`), then
/// range (`A-B` with both sides parseable), then bare IP, then domain.
pub fn classify_input_line(raw: &str) -> InputKind {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return InputKind::Invalid {
            raw: raw.to_string(),
            reason: "empty line",
        };
    }

    // v0.16.1: smart input. If the line looks like a URL
    // (http://, https://, ws://, wss://, ftp://, …), pull just the host
    // out so users can feed httpx / gau / waymore lists directly.
    let host_only = strip_url_to_host(trimmed);
    let tok: &str = host_only.as_deref().unwrap_or(trimmed);

    // CIDR — contains `/` and parses as IpNetwork
    if tok.contains('/') {
        if let Ok(n) = tok.parse::<IpNetwork>() {
            return InputKind::Cidr(n);
        }
        // Something like `example.com/path` — treat as invalid so we
        // don't mis-classify it as a domain and send a DNS query for
        // a URL.
        return InputKind::Invalid {
            raw: tok.to_string(),
            reason: "contains '/' but isn't a valid CIDR",
        };
    }

    // IPv4 range — `A-B` where both sides parse as IPv4
    if let Some((a, b)) = tok.split_once('-') {
        let a = a.trim();
        let b = b.trim();
        // Guard: only treat as a range if BOTH halves parse — otherwise
        // `sub-domain.example.com` would incorrectly match the range arm.
        if let (Ok(IpAddr::V4(a4)), Ok(IpAddr::V4(b4))) =
            (a.parse::<IpAddr>(), b.parse::<IpAddr>())
        {
            if u32::from(a4) <= u32::from(b4) {
                return InputKind::Ipv4Range(a4, b4);
            }
            return InputKind::Invalid {
                raw: tok.to_string(),
                reason: "IPv4 range A-B has A > B",
            };
        }
    }

    // Bare IP
    if let Ok(ip) = tok.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v) => InputKind::Ipv4(v),
            IpAddr::V6(v) => InputKind::Ipv6(v),
        };
    }

    // Domain — looks plausible: contains a dot, non-empty labels, no spaces.
    // We don't try to validate against RFC 1035 beyond the minimum that
    // keeps obvious garbage out. hickory will reject truly-malformed names.
    if looks_like_domain(tok) {
        return InputKind::Domain(tok.to_ascii_lowercase());
    }

    InputKind::Invalid {
        raw: tok.to_string(),
        reason: "not a valid CIDR, IP, range, or domain",
    }
}

/// Cheap syntactic check — saves a DNS round-trip on obvious garbage.
/// We allow IDN / Unicode letters (hickory + libidn handle Punycode).
fn looks_like_domain(s: &str) -> bool {
    if s.len() < 3 || s.len() > 253 {
        return false;
    }
    if !s.contains('.') {
        return false;
    }
    if s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    if s.contains(' ') || s.contains('\t') {
        return false;
    }
    // No ".." (empty label)
    if s.contains("..") {
        return false;
    }
    // At least one label must contain an alphabetic character — rules
    // out stuff like "192.0.2.999" that failed the IP parse but is
    // still numeric.
    s.split('.').any(|label| label.chars().any(|c| c.is_alphabetic()))
}

/// One domain's resolution outcome. Returned in the same order as
/// input so callers can zip / lookup without tracking IDs.
#[derive(Debug, Clone)]
pub struct DomainResult {
    pub domain: String,
    /// A + AAAA records merged; private / reserved / sinkhole IPs
    /// already filtered out.
    pub ips: Vec<IpAddr>,
    /// First CDN provider name that matched any of `ips`. `None` if
    /// every resolved IP is a real origin (or if `ips` is empty).
    pub cdn: Option<&'static str>,
    /// Human-readable error for NXDOMAIN / timeout / other resolver
    /// failures. Empty if resolution succeeded (even with zero records —
    /// `ips.is_empty() && error.is_none()` means "domain exists but
    /// returned no usable A/AAAA").
    pub error: Option<String>,
}

/// Build a hickory resolver pointing at 15 trusted public upstreams
/// with the caller's timeout budget. Fresh resolver per call so state
/// (cache / in-flight) is scoped to the scan.
///
/// v0.16.2: expanded from 6 → 15 upstreams. The new set was empirically
/// tested (each resolver answered google.com correctly under 250 ms);
/// failed/slow resolvers from the trusted-resolvers list were excluded.
/// More upstream diversity means: (a) better resilience when CF/Google
/// are blocked/rate-limited on a network, (b) hickory has more parallel
/// capacity to spread bursty queries across — useful for the v0.16.2
/// wildcard-detection probes which fire 3 queries per zone in parallel,
/// (c) catches geo-DNS wildcards that vary by resolver location.
pub fn build_resolver(timeout: Duration) -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    opts.attempts = 2; // v0.14.15: one retry per server (was 1)
    opts.num_concurrent_reqs = 2; // A and AAAA in parallel per domain
    opts.cache_size = 0; // scan-scoped; no reason to persist across domains

    // 15 trusted public upstreams. Latencies measured 2026-04-25
    // (all under 250 ms). Hickory round-robins, so any blocked /
    // throttled provider still leaves 14 others reachable.
    let nameservers = NameServerConfigGroup::from_ips_clear(
        &[
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),         // Cloudflare
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),         // Cloudflare
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),         // Google
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),         // Google
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),         // Quad9
            IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)), // Quad9
            IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),  // OpenDNS
            IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)),  // OpenDNS
            IpAddr::V4(Ipv4Addr::new(74, 82, 42, 42)),     // Hurricane Electric
            IpAddr::V4(Ipv4Addr::new(64, 6, 65, 6)),       // Verisign
            IpAddr::V4(Ipv4Addr::new(8, 20, 247, 20)),     // Comodo Secure
            IpAddr::V4(Ipv4Addr::new(8, 26, 56, 26)),      // Comodo Secure
            IpAddr::V4(Ipv4Addr::new(134, 195, 4, 2)),     // Mullvad
            IpAddr::V4(Ipv4Addr::new(84, 200, 69, 80)),    // DNS.WATCH
            IpAddr::V4(Ipv4Addr::new(84, 200, 70, 40)),    // DNS.WATCH
        ],
        53,
        true, // trust_negative_responses — NXDOMAIN is fatal per query
    );
    let cfg = ResolverConfig::from_parts(None, vec![], nameservers);
    TokioAsyncResolver::tokio(cfg, opts)
}

/// Drop private / loopback / link-local / ULA / sinkhole addresses from
/// a resolution result. Rejecting these prevents the scanner from
/// wasting probes on the operator's own LAN (wildcard `*.dev.internal`
/// DNS sinkholes are common in corp DNS setups).
fn keep_scannable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let octets = v.octets();
            // v0.14.5: explicit CGNAT (100.64.0.0/10, RFC6598) filter.
            // std's is_private() only covers RFC1918 (10/8, 172.16/12,
            // 192.168/16) and misses this. ISPs use CGNAT for subscriber
            // aggregation; DNS sinkholes occasionally return addresses
            // in this range. Scanning them would either hit the wrong
            // host entirely or waste probes on the user's ISP router.
            let is_cgnat = octets[0] == 100 && (octets[1] & 0xc0) == 64;
            !(v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_documentation()
                || is_cgnat)
        }
        IpAddr::V6(v) => {
            let seg = v.segments();
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                // fc00::/7 — ULA
                || (seg[0] & 0xfe00) == 0xfc00
                // fe80::/10 — link-local
                || (seg[0] & 0xffc0) == 0xfe80
                // 2001:db8::/32 — documentation prefix
                || (seg[0] == 0x2001 && seg[1] == 0x0db8)
                // 2001:20::/28 — ORCHIDv2 (RFC7343, cryptographic hash IDs)
                || (seg[0] == 0x2001 && (seg[1] & 0xfff0) == 0x0020))
        }
    }
}

/// Resolve one domain — queries A and AAAA in parallel, merges results,
/// applies the private-IP filter. Returns an empty Vec (not an error)
/// if the domain exists but has no usable records.
async fn resolve_one(
    resolver: &TokioAsyncResolver,
    domain: &str,
) -> Result<Vec<IpAddr>, String> {
    let (a_res, aaaa_res) = tokio::join!(
        resolver.ipv4_lookup(domain),
        resolver.ipv6_lookup(domain),
    );

    let mut ips: Vec<IpAddr> = Vec::new();
    match a_res {
        Ok(lookup) => ips.extend(lookup.iter().map(|r| IpAddr::V4(r.0))),
        Err(e) => {
            // AAAA might still succeed, so we don't bail yet — but we do
            // record the A-side error for reporting if both sides fail.
            let aaaa_err_hint = matches!(
                e.kind(),
                hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. }
            );
            if aaaa_err_hint {
                // NoRecordsFound is benign for A; IPv6-only hosts hit this.
            } else if aaaa_res.is_err() {
                return Err(format!("{}", e));
            }
        }
    }
    if let Ok(lookup) = aaaa_res {
        ips.extend(lookup.iter().map(|r| IpAddr::V6(r.0)));
    }

    ips.retain(keep_scannable);
    ips.sort();
    ips.dedup();
    Ok(ips)
}

/// Resolve many domains in parallel with bounded concurrency, tagging
/// each result with a CDN provider name if any resolved IP lands in
/// `cdn_table`. Order of returned results matches input order.
///
/// v0.16.1: optional `pb` parameter. When provided, each completed
/// domain (resolved or failed) increments the bar, and a one-line
/// summary of resolved hits is printed above it via `pb.println` so
/// users see progress live on huge scopes (5k+ domains).
pub async fn resolve_many(
    domains: &[String],
    concurrency: usize,
    timeout: Duration,
    cdn_table: std::sync::Arc<crate::CdnTables>,
    pb: Option<indicatif::ProgressBar>,
) -> Vec<DomainResult> {
    if domains.is_empty() {
        return Vec::new();
    }
    let resolver = build_resolver(timeout);
    let concurrency = concurrency.max(1);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));

    // Spawn one task per domain, permit-gated by `sem` so at most
    // `concurrency` are in flight simultaneously. Each returns
    // `JoinHandle<(usize, DomainResult)>` — one concrete type, so
    // `FuturesUnordered` is happy.
    let mut set: FuturesUnordered<tokio::task::JoinHandle<(usize, DomainResult)>> =
        FuturesUnordered::new();

    for (idx, d) in domains.iter().enumerate() {
        let d = d.clone();
        let r = resolver.clone();
        let sem = sem.clone();
        // Arc clone — O(1) atomic increment, no Vec allocation.
        let cdn_table = cdn_table.clone();
        set.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let outcome = resolve_one(&r, &d).await;
            let (ips, error) = match outcome {
                Ok(v) => (v, None),
                Err(e) => (Vec::new(), Some(e)),
            };
            let cdn = ips.iter().find_map(|ip| cdn_tag_first(*ip, &cdn_table));
            (
                idx,
                DomainResult {
                    domain: d,
                    ips,
                    cdn,
                    error,
                },
            )
        }));
    }

    let mut results: Vec<Option<DomainResult>> = (0..domains.len()).map(|_| None).collect();
    while let Some(join) = set.next().await {
        if let Ok((idx, r)) = join {
            // Live progress: emit a one-line summary for each completed
            // domain ABOVE the progress bar (via pb.println). Resolved
            // hits print their IPs + CDN tag; failures print the reason
            // truncated. NXDOMAIN noise on huge scopes is suppressed —
            // we only print the useful signal: "what resolved + where".
            if let Some(p) = &pb {
                if r.error.is_none() && !r.ips.is_empty() {
                    let ip_preview: Vec<String> =
                        r.ips.iter().take(3).map(|i| i.to_string()).collect();
                    let extra = if r.ips.len() > 3 {
                        format!(" (+{} more)", r.ips.len() - 3)
                    } else {
                        String::new()
                    };
                    let cdn_tag = match r.cdn {
                        Some(t) => format!("  [CDN: {}]", t),
                        None => String::new(),
                    };
                    p.println(format!(
                        "[+] {} → {}{}{}",
                        r.domain,
                        ip_preview.join(","),
                        extra,
                        cdn_tag
                    ));
                }
                p.inc(1);
            }
            results[idx] = Some(r);
        } else if let Some(p) = &pb {
            // Task failed (panic/abort) — still tick the bar so the
            // count stays accurate.
            p.inc(1);
        }
    }
    if let Some(p) = pb {
        p.finish_and_clear();
    }
    // flatten (not unwrap): a panicked / aborted DNS task leaves its
    // slot None — drop it instead of crashing the whole scan.
    results.into_iter().flatten().collect()
}

/// Linear scan against the CDN CIDR table, dispatched by IP family so
/// IPv4 lookups don't walk the ~3.9k v6 entries (and vice versa).
/// Mirrors `cdn_tag_for()` in main.rs — first provider match wins.
fn cdn_tag_first(ip: IpAddr, table: &crate::CdnTables) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            for (net, tag) in &table.v4 {
                if net.contains(v4) {
                    return Some(*tag);
                }
            }
            None
        }
        IpAddr::V6(v6) => {
            for (net, tag) in &table.v6 {
                if net.contains(v6) {
                    return Some(*tag);
                }
            }
            None
        }
    }
}

/// Collapse many `DomainResult`s into a compact "by CDN provider"
/// histogram, for the pre-scan summary.
pub fn cdn_breakdown(results: &[DomainResult]) -> Vec<(&'static str, usize)> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<&'static str, usize> = BTreeMap::new();
    for r in results {
        if let Some(tag) = r.cdn {
            *map.entry(tag).or_insert(0) += 1;
        }
    }
    map.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_ipv4() {
        assert!(matches!(
            classify_input_line("1.2.3.4"),
            InputKind::Ipv4(_)
        ));
    }

    #[test]
    fn classify_cidr() {
        assert!(matches!(
            classify_input_line("10.0.0.0/24"),
            InputKind::Cidr(_)
        ));
    }

    #[test]
    fn classify_range() {
        assert!(matches!(
            classify_input_line("1.2.3.4-1.2.3.10"),
            InputKind::Ipv4Range(_, _)
        ));
    }

    #[test]
    fn classify_domain() {
        assert!(matches!(
            classify_input_line("example.com"),
            InputKind::Domain(_)
        ));
        assert!(matches!(
            classify_input_line("sub.Example.COM"),
            InputKind::Domain(d) if d == "sub.example.com"
        ));
    }

    #[test]
    fn classify_invalid() {
        assert!(matches!(
            classify_input_line("not a target"),
            InputKind::Invalid { .. }
        ));
        assert!(matches!(
            classify_input_line("example.com/admin"),
            InputKind::Invalid { .. }
        ));
    }

    #[test]
    fn private_ip_filtered() {
        assert!(!keep_scannable(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!keep_scannable(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(keep_scannable(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    // v0.16.1 — URL-style inputs from httpx / gau / waymore lists.
    #[test]
    fn url_http_strips_to_host() {
        assert!(matches!(
            classify_input_line("http://example.com"),
            InputKind::Domain(d) if d == "example.com"
        ));
    }

    #[test]
    fn url_https_with_path_strips() {
        assert!(matches!(
            classify_input_line("https://example.com/admin/users.php?id=1"),
            InputKind::Domain(d) if d == "example.com"
        ));
    }

    #[test]
    fn url_with_port_strips_port() {
        assert!(matches!(
            classify_input_line("https://example.com:8443/login"),
            InputKind::Domain(d) if d == "example.com"
        ));
    }

    #[test]
    fn url_with_userinfo_strips() {
        assert!(matches!(
            classify_input_line("https://user:pass@example.com/path"),
            InputKind::Domain(d) if d == "example.com"
        ));
    }

    #[test]
    fn url_to_ip_strips() {
        assert!(matches!(
            classify_input_line("http://1.2.3.4:8080/login"),
            InputKind::Ipv4(_)
        ));
    }

    #[test]
    fn url_to_ipv6_strips_brackets() {
        assert!(matches!(
            classify_input_line("https://[2606:4700::1111]:443/"),
            InputKind::Ipv6(_)
        ));
    }

    #[test]
    fn bare_host_with_path_still_invalid() {
        // No `://` → NOT a URL → existing "contains '/'" rule applies.
        // We don't auto-strip bare paths to avoid mis-handling
        // CIDR-looking inputs.
        assert!(matches!(
            classify_input_line("example.com/admin"),
            InputKind::Invalid { .. }
        ));
    }

    #[test]
    fn cidr_still_works() {
        // Sanity: URL-stripper must not touch valid CIDRs.
        assert!(matches!(
            classify_input_line("10.0.0.0/24"),
            InputKind::Cidr(_)
        ));
    }
}
